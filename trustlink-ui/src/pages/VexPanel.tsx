import { useEffect, useState } from 'react';
import { ShieldQuestion, RefreshCw, UploadCloud, Lock, ChevronDown, ChevronRight } from 'lucide-react';
import { Button, Card, CardContent, CardHeader, Badge, Input } from '@/components/ui/primitives';
import {
  getSession, vexEnabled, vexFindings, putAnalysis, publishVex, bffLogin,
  type Session, type Finding
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

function FindingRow({ uuid, f, onSaved }: { uuid: string; f: Finding; onSaved: () => void }) {
  const [status, setStatus] = useState('');
  const [just, setJust] = useState('');
  const [comment, setComment] = useState('');
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState('');
  const [detail, setDetail] = useState(false);

  async function save() {
    if (!status) { setMsg('상태를 선택하세요'); return; }
    setSaving(true); setMsg('');
    try {
      await putAnalysis({
        project: uuid, component: f.component.uuid, vulnerability: f.vulnerability.uuid,
        status, justification: just || undefined, comment: comment || undefined,
        suppressed: status === 'not_affected'
      });
      setMsg('저장됨'); onSaved();
    } catch (e) { setMsg(String(e)); }
    setSaving(false);
  }

  return (
    <div className="border-t py-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant={sevVariant(f.vulnerability.severity)}>{f.vulnerability.severity || '?'}</Badge>
        <span className="font-mono text-sm font-medium">{f.vulnerability.vulnId}</span>
        <span className="text-xs text-muted-foreground">{f.component.name}{f.component.version ? ` @ ${f.component.version}` : ''}</span>
        {f.analysis?.state && <Badge variant="muted">현재: {f.analysis.state}</Badge>}
        <div className="flex-1" />
        <button onClick={() => setDetail(!detail)} className="flex items-center gap-0.5 text-xs text-primary hover:underline">
          {detail ? <ChevronDown size={13} /> : <ChevronRight size={13} />} 상세
        </button>
      </div>
      {detail && <VulnDetail v={f.vulnerability} analyzer={f.attribution?.analyzerIdentity} />}
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
        <Input className="h-9 max-w-xs" placeholder="코멘트(선택)" value={comment} onChange={(e) => setComment(e.target.value)} />
        <Button size="sm" onClick={save} disabled={saving}>{saving ? '저장중…' : '저장'}</Button>
        {msg && <span className="text-xs text-muted-foreground">{msg}</span>}
      </div>
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

  useEffect(() => {
    getSession().then((s) => {
      setSess(s);
      if (s?.canEditVex) vexEnabled().then(setEnabled);
    }).catch(() => setSess(null));
  }, []);

  async function load() {
    setLoading(true); setErr(''); setData(null);
    try { setData(await vexFindings(project, tag, repo, tag)); }
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
            </div>
            {pub && <div className="rounded bg-secondary p-2 text-xs">{pub}</div>}
            {err && <div className="rounded bg-red-100 p-2 text-xs text-red-700">{err}</div>}
            {data && (
              data.findings.length === 0
                ? <p className="text-sm text-muted-foreground">취약점이 없습니다.</p>
                : <div>{data.findings.map((f, i) => <FindingRow key={i} uuid={data.uuid} f={f} onSaved={load} />)}</div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
