import { useEffect, useState } from 'react';
import { ShieldQuestion, RefreshCw, UploadCloud, Lock, ChevronDown, ChevronRight, Sparkles, ListChecks, Square } from 'lucide-react';
import { Button, Card, CardContent, CardHeader, Badge, Input } from '@/components/ui/primitives';
import {
  getSession, vexEnabled, vexFindings, putAnalysis, publishVex, bffLogin, aiStatus, aiVexDraft, vexKev,
  aiVexBatch, aiVexBatchStart, aiVexBatchCancel,
  type Session, type Finding, type VexDraftResult, type KevInfo, type VexBatch, type VexRemedy
} from '@/lib/api';

// CycloneDX 분석 상태 어휘 (BFF가 DT enum 으로 매핑)
const STATES = [
  { v: '', label: '— 미분류 —' },
  { v: 'under_investigation', label: '조사중 (under_investigation)' },
  { v: 'not_affected', label: '영향 없음 (not_affected)' },
  { v: 'affected', label: '영향 있음 (affected)' },
  { v: 'fixed', label: '수정됨 (fixed)' }
];
const JUSTIFICATIONS = [
  { v: '', label: '— 근거 선택 —' },
  { v: 'component_not_present', label: '컴포넌트 미포함' },
  { v: 'vulnerable_code_not_present', label: '취약코드 미포함' },
  { v: 'vulnerable_code_not_in_execute_path', label: '실행경로에 없음' },
  { v: 'vulnerable_code_cannot_be_controlled_by_adversary', label: '공격자가 제어 불가' },
  { v: 'inline_mitigations_already_exist', label: '완화책 이미 존재' }
];
// CycloneDX 대응(response) — affected 일 때
const RESPONSES = [
  { v: '', label: '— 대응 선택 —' },
  { v: 'update', label: '업데이트 (update)' },
  { v: 'workaround_available', label: '임시 완화 (workaround_available)' },
  { v: 'rollback', label: '롤백 (rollback)' },
  { v: 'will_not_fix', label: '수정 안 함 (will_not_fix)' },
  { v: 'can_not_fix', label: '수정 불가 (can_not_fix)' }
];

const sevVariant = (s?: string): 'danger' | 'warn' | 'muted' => {
  const u = (s || '').toUpperCase();
  if (u === 'CRITICAL' || u === 'HIGH') return 'danger';
  if (u === 'MEDIUM') return 'warn';
  return 'muted';
};

// DT references(마크다운)에서 URL 추출
function refUrls(s?: string): string[] {
  if (!s) return [];
  return Array.from(new Set(s.match(/https?:\/\/[^\s)\]]+/g) || [])).slice(0, 6);
}

// 우선순위(규칙, 서버 vexPriority 와 같음): KEV 등재 > 공개 익스플로잇·EPSS 10%↑·CRITICAL > HIGH > 나머지
type Kev = NonNullable<KevInfo['items']>[string];
function priority(f: Finding, kev?: Kev): number {
  const sev = (f.vulnerability.severity || '').toUpperCase();
  if (kev?.kev) return 1;
  if (kev?.exploit || (f.vulnerability.epssScore ?? 0) >= 0.1 || sev === 'CRITICAL') return 2;
  if (sev === 'HIGH') return 3;
  return 4;
}
const PRIO_LABEL: Record<number, string> = { 1: 'P1 실제 악용(KEV)', 2: 'P2 긴급', 3: 'P3 높음', 4: 'P4' };
const CONF_LABEL = { low: '근거 부족', medium: '근거 일부', high: '근거 충분' };
const labelOf = (list: { v: string; label: string }[], v: string) => list.find((x) => x.v === v)?.label || v;

type Applied = { status: string; just: string; response: string; details: string; comment: string };

// 규칙 계산 결과(AI 아님): 목표 버전·KEV 기한·공개 익스플로잇·OSV 영향 범위
function RemedyFacts({ r, version }: { r: VexRemedy; version?: string }) {
  const ex = r.exploits;
  const exParts = [
    ex.edb?.length ? `Exploit-DB ${ex.edb.length}건` : '',
    ex.msf?.length ? `Metasploit ${ex.msf.length}개` : '',
    ex.nuclei ? 'Nuclei 템플릿' : ''
  ].filter(Boolean);
  return (
    <div className="grid gap-1 rounded bg-background/70 p-2 sm:grid-cols-2">
      <div>
        <b>목표 버전</b>: {r.targetVersion
          ? <span className="font-mono text-emerald-700">{version} → {r.targetVersion}</span>
          : <span className="text-muted-foreground">{r.osvNote || (r.inRange === 'no' ? 'OSV 영향 범위 밖' : '수정 버전 미공개')}</span>}
        {r.osvId && <span className="text-muted-foreground"> ({r.osvId})</span>}
      </div>
      <div><b>조치 기한</b>: {r.dueBy ? <span className="text-red-700">KEV 기한 {r.dueBy}</span> : <span className="text-muted-foreground">정책 기준</span>}</div>
      <div><b>공개 익스플로잇</b>: {exParts.length ? <span className="text-red-700">{exParts.join(' · ')}</span> : <span className="text-muted-foreground">{ex.checked ? '찾지 못함' : '사본 없음'}</span>}</div>
      {r.ranges && r.ranges.length > 0 && <div><b>영향 범위</b>: <span className="font-mono">{r.ranges.join(' / ')}</span></div>}
    </div>
  );
}

// AI 초안 상자: 사용 맥락(선택)을 적고 요청 → 판정·대응 초안·근거·경고 표시 → "초안 적용"은 입력칸만 채운다(저장은 사람이).
function AIDraftBox({ uuid, f, repo, tag, initial, onApply }: {
  uuid: string; f: Finding; repo: string; tag: string; initial?: VexDraftResult;
  onApply: (a: Applied) => void;
}) {
  const [ctx, setCtx] = useState('');
  const [busy, setBusy] = useState(false);
  const [asked, setAsked] = useState<VexDraftResult | null>(null);
  const [err, setErr] = useState('');
  const res = asked || initial || null; // 직접 요청한 초안이 일괄 판정 결과보다 우선
  async function ask() {
    setBusy(true); setErr('');
    try {
      setAsked(await aiVexDraft({ project: uuid, component: f.component.uuid, vulnerability: f.vulnerability.uuid, context: ctx, repo, tag }));
    } catch (e) { setErr(String(e)); }
    setBusy(false);
  }
  const factText = (id: string) => res?.facts.find((x) => x.id === id)?.text || '';
  function apply(r: VexDraftResult) {
    const d = r.draft;
    const lines = [d.detail];
    if (d.plan.length) lines.push('', '대응 계획:', ...d.plan.map((p, i) => `${i + 1}. ${p}`));
    if (d.workaround) lines.push('', `임시 완화: ${d.workaround}`);
    if (r.remedy.targetVersion && d.status === 'affected') lines.push('', `목표 버전(OSV ${r.remedy.osvId}): ${r.remedy.targetVersion}`);
    if (r.remedy.dueBy) lines.push(`KEV 조치 기한: ${r.remedy.dueBy}`);
    onApply({
      status: d.status, just: d.justification, response: d.response, details: lines.join('\n'),
      comment: `AI 초안(${r.meta.model}, 근거 ${d.citations.join(',')}) 검토 후 저장`
    });
  }
  return (
    <div className="mt-2 space-y-2 rounded-md border border-violet-200 bg-violet-50/40 p-3 text-xs">
      <div className="flex flex-wrap items-end gap-2">
        <textarea value={ctx} onChange={(e) => setCtx(e.target.value)} rows={2}
          placeholder="사용 맥락(선택) — 예: 이 라이브러리는 설정 파일 파싱에만 쓰고 외부 입력은 받지 않음. '영향 없음' 초안은 이런 근거나 OSV 버전 범위 근거가 있을 때만 나옵니다."
          className="min-w-[260px] flex-1 rounded-md border bg-background p-2 text-xs" />
        <Button size="sm" variant="outline" onClick={ask} disabled={busy}>
          <Sparkles size={14} /> {busy ? '작성 중… (CPU, 1~2분)' : res ? 'AI 초안 다시 요청' : 'AI 초안 요청'}
        </Button>
      </div>
      {err && <div className="rounded bg-red-100 p-2 text-red-700">{err}</div>}
      {res && (
        <div className="space-y-2">
          <RemedyFacts r={res.remedy} version={f.component.version} />
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant={res.draft.status === 'affected' ? 'danger' : res.draft.status === 'not_affected' ? 'muted' : 'warn'}>
              {labelOf(STATES, res.draft.status)}
            </Badge>
            {res.draft.justification && <Badge variant="muted">{labelOf(JUSTIFICATIONS, res.draft.justification)}</Badge>}
            {res.draft.response && <Badge variant="muted">대응: {labelOf(RESPONSES, res.draft.response)}</Badge>}
            <span className="text-muted-foreground">
              {CONF_LABEL[res.draft.confidence]} · {res.meta.model} · {(res.meta.elapsedMs / 1000).toFixed(0)}초
              {res.at ? ` · ${new Date(res.at).toLocaleString()}` : ''}
            </span>
          </div>
          <p className="leading-relaxed">{res.draft.detail}</p>
          {res.draft.plan.length > 0 && (
            <div>
              <b>대응 계획</b>
              <ol className="list-decimal pl-5">{res.draft.plan.map((p, i) => <li key={i}>{p}</li>)}</ol>
            </div>
          )}
          {res.draft.workaround && <div><b>임시 완화</b>: {res.draft.workaround}</div>}
          <div className="flex flex-wrap gap-1">
            <span className="text-muted-foreground">근거:</span>
            {res.draft.citations.map((c) => (
              <span key={c} title={factText(c)} className="cursor-help rounded bg-secondary px-1.5 font-mono">{c}</span>
            ))}
          </div>
          {res.draft.missing.length > 0 && (
            <ul className="list-disc pl-5 text-muted-foreground">
              {res.draft.missing.map((m, i) => <li key={i}>확인 필요: {m}</li>)}
            </ul>
          )}
          {res.warnings.map((w, i) => <div key={i} className="rounded bg-amber-50 p-2 text-amber-800">{w}</div>)}
          <div className="flex items-center gap-2">
            <Button size="sm" onClick={() => apply(res)}>초안 적용</Button>
            <span className="text-muted-foreground">입력칸만 채웁니다. 내용을 확인하고 '저장'을 눌러야 기록됩니다. 요청 기록은 원장에 남습니다.</span>
          </div>
        </div>
      )}
    </div>
  );
}

function VulnDetail({ v, analyzer }: { v: Finding['vulnerability']; analyzer?: string }) {
  const epss = v.epssScore != null ? `${(v.epssScore * 100).toFixed(1)}%` : '—';
  const pub = v.published ? new Date(v.published).toISOString().slice(0, 10) : '—';
  const urls = refUrls(v.references);
  return (
    <div className="mt-2 space-y-2 rounded-md bg-secondary/50 p-3 text-xs">
      <div className="grid gap-1 sm:grid-cols-2">
        <div><b>CVSS v3</b>: {v.cvssV3BaseScore ?? '—'} {v.cvssV3Vector ? `(${v.cvssV3Vector})` : ''}</div>
        <div><b>EPSS</b>(악용확률): {epss}</div>
        <div><b>CWE</b>: {v.cweId ? `CWE-${v.cweId} ${v.cweName || ''}` : '—'}</div>
        <div><b>출처</b>: {v.source || '—'}{analyzer ? ` · 분석기 ${analyzer}` : ''} · 공개 {pub}</div>
      </div>
      {v.description && <p className="leading-relaxed text-muted-foreground">{v.description}</p>}
      {urls.length > 0 && (
        <div className="flex flex-wrap gap-x-3 gap-y-1">
          {urls.map((u, i) => (
            <a key={i} href={u} target="_blank" rel="noreferrer" className="break-all text-primary underline">참고{i + 1}</a>
          ))}
        </div>
      )}
    </div>
  );
}

function FindingRow({ uuid, f, onSaved, repo, tag, ai, kev, draft }: {
  uuid: string; f: Finding; onSaved: () => void; repo: string; tag: string; ai: boolean; kev?: Kev; draft?: VexDraftResult;
}) {
  const [status, setStatus] = useState('');
  const [just, setJust] = useState('');
  const [resp, setResp] = useState('');
  const [details, setDetails] = useState('');
  const [comment, setComment] = useState('');
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState('');
  const [detail, setDetail] = useState(false);
  const [aiOpen, setAiOpen] = useState(false);
  const pr = priority(f, kev);

  async function save() {
    if (!status) { setMsg('상태를 선택하세요'); return; }
    setSaving(true); setMsg('');
    try {
      await putAnalysis({
        project: uuid, component: f.component.uuid, vulnerability: f.vulnerability.uuid,
        status, justification: (status === 'not_affected' && just) || undefined,
        response: (status === 'affected' && resp) || undefined, details: details || undefined, comment: comment || undefined,
        suppressed: status === 'not_affected'
      });
      setMsg('저장됨'); onSaved();
    } catch (e) { setMsg(String(e)); }
    setSaving(false);
  }

  return (
    <div className="border-t py-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant={pr <= 2 ? 'danger' : pr === 3 ? 'warn' : 'muted'}>{PRIO_LABEL[pr]}</Badge>
        <Badge variant={sevVariant(f.vulnerability.severity)}>{f.vulnerability.severity || '?'}</Badge>
        <span className="font-mono text-sm font-medium">{f.vulnerability.vulnId}</span>
        <span className="text-xs text-muted-foreground">{f.component.name}{f.component.version ? ` @ ${f.component.version}` : ''}</span>
        {f.analysis?.state && <Badge variant="muted">현재: {f.analysis.state}</Badge>}
        {kev?.kev && <span className="text-xs text-red-700">KEV 등재 {kev.kevAdded}{kev.kevDue ? ` · 기한 ${kev.kevDue}` : ''}{kev.ransomware ? ' · 랜섬웨어 사용' : ''}</span>}
        {kev?.exploit && <span className="text-xs text-red-700">공개 익스플로잇</span>}
        <div className="flex-1" />
        {draft && !aiOpen && (
          <button onClick={() => setAiOpen(true)} className="rounded bg-violet-100 px-1.5 text-xs text-violet-800">
            AI 초안: {labelOf(STATES, draft.draft.status).split(' (')[0]}{draft.remedy.targetVersion ? ` → ${draft.remedy.targetVersion}` : ''}
          </button>
        )}
        {(ai || draft) && (
          <button onClick={() => setAiOpen(!aiOpen)} className="flex items-center gap-0.5 text-xs text-violet-700 hover:underline">
            <Sparkles size={13} /> AI 판정·대응
          </button>
        )}
        <button onClick={() => setDetail(!detail)} className="flex items-center gap-0.5 text-xs text-primary hover:underline">
          {detail ? <ChevronDown size={13} /> : <ChevronRight size={13} />} 상세
        </button>
      </div>
      {detail && <VulnDetail v={f.vulnerability} analyzer={f.attribution?.analyzerIdentity} />}
      {aiOpen && <AIDraftBox uuid={uuid} f={f} repo={repo} tag={tag} initial={draft}
        onApply={(a) => {
          setStatus(a.status); setJust(a.just); setResp(a.response); setDetails(a.details); setComment(a.comment);
          setMsg('AI 초안을 채웠습니다 — 확인 후 저장');
        }} />}
      <div className="mt-2 flex flex-wrap items-end gap-2">
        <select value={status} onChange={(e) => setStatus(e.target.value)}
          className="h-9 rounded-md border bg-background px-2 text-sm">
          {STATES.map((s) => <option key={s.v} value={s.v}>{s.label}</option>)}
        </select>
        {status === 'not_affected' && (
          <select value={just} onChange={(e) => setJust(e.target.value)}
            className="h-9 rounded-md border bg-background px-2 text-sm">
            {JUSTIFICATIONS.map((j) => <option key={j.v} value={j.v}>{j.label}</option>)}
          </select>
        )}
        {status === 'affected' && (
          <select value={resp} onChange={(e) => setResp(e.target.value)}
            className="h-9 rounded-md border bg-background px-2 text-sm">
            {RESPONSES.map((r) => <option key={r.v} value={r.v}>{r.label}</option>)}
          </select>
        )}
        <Input className="h-9 max-w-xs" placeholder="코멘트(선택)" value={comment} onChange={(e) => setComment(e.target.value)} />
        <Button size="sm" onClick={save} disabled={saving}>{saving ? '저장중…' : '저장'}</Button>
        {msg && <span className="text-xs text-muted-foreground">{msg}</span>}
      </div>
      {(details || status) && (
        <textarea value={details} onChange={(e) => setDetails(e.target.value)} rows={details ? 5 : 2}
          placeholder="분석 내용(details) — VEX 문서의 analysis.detail 로 나갑니다"
          className="mt-2 w-full rounded-md border bg-background p-2 text-xs" />
      )}
    </div>
  );
}

export default function VexPanel({ repo, tag }: { repo: string; tag: string }) {
  const project = repo.split('/').pop() || repo; // DT 프로젝트명 = 레포 basename
  const [sess, setSess] = useState<Session | null | undefined>(undefined);
  const [enabled, setEnabled] = useState(false);
  const [data, setData] = useState<{ uuid: string; findings: Finding[] } | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState('');
  const [pub, setPub] = useState('');
  const [ai, setAi] = useState(false);
  const [kev, setKev] = useState<KevInfo | null>(null);
  const [batch, setBatch] = useState<VexBatch | null>(null);
  const [batchErr, setBatchErr] = useState('');

  // 일괄 판정 진행 중이면 3초마다 갱신
  useEffect(() => {
    if (!data || batch?.state !== 'running') return;
    const t = setTimeout(() => { aiVexBatch(data.uuid).then(setBatch).catch(() => {}); }, 3000);
    return () => clearTimeout(t);
  }, [data, batch]);

  async function startBatch() {
    if (!data) return;
    setBatchErr('');
    try {
      const r = await aiVexBatchStart({ project: data.uuid, repo, tag, limit: 20 });
      if (r.state === 'done' && !r.total) { setBatchErr(r.message || '미분석 항목이 없습니다'); return; }
      setBatch(await aiVexBatch(data.uuid));
    } catch (e) { setBatchErr(String(e)); }
  }

  useEffect(() => {
    getSession().then((s) => {
      setSess(s);
      if (s?.canEditVex) {
        vexEnabled().then(setEnabled);
        aiStatus().then((a) => setAi(a.enabled && a.reachable)).catch(() => setAi(false));
      }
    }).catch(() => setSess(null));
  }, []);

  async function load() {
    setLoading(true); setErr(''); setData(null);
    try {
      const d = await vexFindings(project, tag, repo, tag);
      let k: KevInfo | null = null;
      try { k = await vexKev(Array.from(new Set(d.findings.map((f) => f.vulnerability.vulnId)))); } catch { /* 미러 없음 */ }
      setKev(k);
      d.findings.sort((a, b) => priority(a, k?.items?.[a.vulnerability.vulnId]) - priority(b, k?.items?.[b.vulnerability.vulnId]) ||
        (b.vulnerability.epssScore ?? 0) - (a.vulnerability.epssScore ?? 0));
      setData(d);
      aiVexBatch(d.uuid).then(setBatch).catch(() => setBatch(null));
    }
    catch (e) { setErr(String(e)); }
    setLoading(false);
  }

  async function publish() {
    setPub('발행 중…');
    try {
      const r = await publishVex({ repo, tag, project, version: tag });
      setPub(`발행 완료 — 새 VEX referrer: ${r.digest.slice(0, 19)}… (새로고침하면 목록에 표시)`);
    } catch (e) { setPub(`발행 실패: ${e}`); }
  }

  if (sess === undefined) return null; // 로딩

  return (
    <Card className="mb-5">
      <CardHeader className="flex items-center gap-2 font-semibold">
        <ShieldQuestion size={16} /> 취약점 분석 · VEX 편집
      </CardHeader>
      <CardContent>
        {sess === null ? (
          <div className="flex items-center gap-3 text-sm">
            <Lock size={16} className="text-muted-foreground" />
            <span className="text-muted-foreground">VEX 분류·발행은 로그인이 필요합니다.</span>
            <Button size="sm" onClick={() => bffLogin(window.location.pathname)}>로그인</Button>
          </div>
        ) : !sess.canEditVex ? (
          <p className="text-sm text-muted-foreground">
            VEX 편집 권한이 없습니다. (security / developers / admins 그룹 필요 · 현재: {sess.groups.join(', ') || '없음'})
          </p>
        ) : !enabled ? (
          <p className="text-sm text-muted-foreground">Dependency-Track 미설정 — 분석 기능 비활성화.</p>
        ) : (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <Button size="sm" variant="outline" onClick={load} disabled={loading}>
                <RefreshCw size={14} /> {loading ? '불러오는 중…' : '취약점 분석 불러오기'}
              </Button>
              <Button size="sm" variant="accent" onClick={publish}>
                <UploadCloud size={14} /> VEX 발행 (새 referrer)
              </Button>
              <span className="text-xs text-muted-foreground">DT 프로젝트: {project} @ {tag}</span>
              {data && <span className="text-xs text-muted-foreground">· 우선순위 순 정렬 {kev?.available ? `(KEV 사본 ${kev.asOf?.slice(0, 10)})` : '(KEV 사본 없음 — 미러 확인)'}</span>}
              {ai && <span className="text-xs text-violet-700">· AI 초안 사용 가능</span>}
            </div>
            {!ai && (
              <div className="flex flex-wrap items-center gap-2 rounded-md border border-dashed border-violet-300 bg-violet-50/30 p-2 text-xs text-violet-900">
                <Sparkles size={14} />
                <span>AI 판정 초안(상태·근거·대응·목표 버전)과 AI 일괄 판정은 서버의 AI 연결(VEX 용도)이 켜지면 이 자리에 나타납니다.</span>
                {sess.groups.includes('admins')
                  ? <a href="/admin/ai" className="font-medium underline">AI 연결 설정</a>
                  : <span className="text-muted-foreground">관리자에게 요청하세요.</span>}
              </div>
            )}
            {data && ai && (
              <div className="flex flex-wrap items-center gap-2 rounded-md border border-violet-200 bg-violet-50/40 p-2 text-xs">
                {batch?.state === 'running' ? (
                  <>
                    <span className="text-violet-800">AI 일괄 판정 중 {batch.done}/{batch.total}{batch.current ? ` — ${batch.current}` : ''}</span>
                    <Button size="sm" variant="outline" onClick={() => aiVexBatchCancel(data.uuid).then(() => aiVexBatch(data.uuid)).then(setBatch)}>
                      <Square size={13} /> 중지
                    </Button>
                  </>
                ) : (
                  <>
                    <Button size="sm" variant="outline" onClick={startBatch}><ListChecks size={14} /> AI 일괄 판정 (미분석 최대 20건)</Button>
                    <span className="text-muted-foreground">우선순위 순으로 한 건씩 초안을 만듭니다(건당 1~2분). DT 에는 쓰지 않으며, 각 항목에서 확인 후 저장합니다.</span>
                  </>
                )}
                {batch && batch.state !== 'none' && batch.state !== 'running' && (
                  <span className="text-muted-foreground">
                    · 마지막 일괄 판정 {batch.finished ? new Date(batch.finished).toLocaleString() : ''}: 초안 {Object.keys(batch.results || {}).length}건
                    {batch.failed && Object.keys(batch.failed).length ? `, 실패 ${Object.keys(batch.failed).length}건` : ''}
                    {batch.state === 'cancelled' ? ' (중지됨)' : ''}{batch.error ? ` — ${batch.error}` : ''}
                  </span>
                )}
                {batchErr && <span className="text-red-700">{batchErr}</span>}
              </div>
            )}
            {pub && <div className="rounded bg-secondary p-2 text-xs">{pub}</div>}
            {err && <div className="rounded bg-red-100 p-2 text-xs text-red-700">{err}</div>}
            {data && (
              data.findings.length === 0
                ? <p className="text-sm text-muted-foreground">취약점이 없습니다.</p>
                : <div>{data.findings.map((f, i) => <FindingRow key={i} uuid={data.uuid} f={f} onSaved={load} repo={repo} tag={tag} ai={ai} kev={kev?.items?.[f.vulnerability.vulnId]}
                  draft={batch?.results?.[`${f.component.uuid}|${f.vulnerability.uuid}`]} />)}</div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
