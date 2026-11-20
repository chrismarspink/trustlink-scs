import { useEffect, useState } from 'react';
import { Busy } from '@/components/Progress';
import { Send, ShieldCheck, ShieldAlert, Wrench, Eye, History, ArrowRight, ArrowLeft, Trash2, CheckCircle2, XCircle, MinusCircle, Building2 } from 'lucide-react';
import {
  adminCustNotifyVulns, adminCustNotifyCreate, adminCustNotifyAI, adminCustNotifySend, adminCustNotifyList, adminCustNotifyGet, adminCustNotifyDelete,
  type CustNotice, type CustVulnCand, type CustNoticeRow, type CustTarget, type CustAIText
} from '@/lib/api';
import { Button, Badge, Card, CardContent } from '@/components/ui/primitives';
import { AIBadge, AIIcon } from '@/components/AIBadge';
import { SourceBadge, Steps, type StepState } from '@/components/SourceBadge';
import { PageHeader, SectionTitle, Loading, Alert, Table, Th, Td } from './_ui';
import { cn } from '@/lib/utils';

// 관리 › 고객 통지: ① 취약점 선택 → ② 영향 고객 → ③ 패치 버전 찾기(규칙) + AI 설명 → ④ 미리보기 → ⑤ 발송.
// 패치 버전은 규칙(DT 분석·SBOM)이 정하고 AI 는 쉬운 설명만 쓴다. 메일 허용 목록 밖 주소는 보내지 않고 "건너뜀"으로 남는다.

const fmt = (t?: string) => (t ? new Date(t).toLocaleString('ko-KR') : '—');
const base = (r: string) => r.split('/').pop() || r;
const KIND = { patch: '패치 권고', notaffected: '영향 없음 확인서' } as const;
const STATUS: Record<CustNotice['status'], { l: string; v: 'muted' | 'success' | 'warn' | 'danger' }> = {
  draft: { l: '초안', v: 'muted' }, sent: { l: '발송 완료', v: 'success' }, partial: { l: '일부 발송', v: 'warn' }, dropped: { l: '허용 목록 밖 — 건너뜀', v: 'warn' }, failed: { l: '실패', v: 'danger' }
};

function Sev({ s }: { s: string }) {
  const cls = s === 'CRITICAL' ? 'bg-red-600 text-white' : s === 'HIGH' ? 'bg-orange-500 text-white' : s === 'MEDIUM' ? 'bg-amber-100 text-amber-800' : 'bg-slate-100 text-slate-700';
  return <span className={cn('rounded px-1.5 py-0.5 text-[11px] font-semibold', cls)}>{s || '미상'}</span>;
}

function SendState({ t }: { t: CustTarget }) {
  const r = t.result;
  if (!r) return <span className="text-xs text-muted-foreground">미발송</span>;
  return (
    <div className="space-y-0.5 text-xs">
      {!!r.sent?.length && <div className="flex items-center gap-1 text-emerald-700"><CheckCircle2 size={12} />보냄 {r.sent.join(', ')}</div>}
      {!!r.dropped?.length && <div className="flex items-center gap-1 text-amber-700" title={r.dropped.join(', ')}><MinusCircle size={12} />허용 목록 밖이라 건너뜀 {r.dropped.length}</div>}
      {r.error && <div className="flex items-center gap-1 text-red-600"><XCircle size={12} />{r.error}</div>}
    </div>
  );
}

export default function CustomerNotify() {
  const [tab, setTab] = useState<'flow' | 'history'>('flow');
  const [kind, setKind] = useState<CustNotice['kind']>('patch');
  const [cands, setCands] = useState<CustVulnCand[] | null>(null);
  // 후보가 많을 때(수십~수백 건) 구성요소·심각도로 좁힌다. 기본: 치명·높음 + KEV
  const [fComp, setFComp] = useState('');
  const [fSev, setFSev] = useState<'top' | 'all'>('top');
  const [fq, setFq] = useState('');
  const [candErr, setCandErr] = useState('');
  const [n, setN] = useState<CustNotice | null>(null);
  const [stage, setStage] = useState(1);
  const [busy, setBusy] = useState<'' | 'plan' | 'ai' | 'send'>('');
  const [err, setErr] = useState('');
  const [sel, setSel] = useState<string[]>([]);

  useEffect(() => {
    let live = true;
    adminCustNotifyVulns(kind).then((r) => { if (live) { setCands(r.items); setCandErr(r.error || ''); } }).catch((e) => live && setCandErr(String(e)));
    return () => { live = false; };
  }, [kind]);

  const open = (x: CustNotice) => {
    setN(x); setErr(''); setTab('flow'); setKind(x.kind);
    setSel(x.targets.filter((t) => !t.result?.sent?.length).map((t) => t.key));
    setStage(x.status === 'draft' ? 2 : 5);
  };
  const pick = async (c: CustVulnCand) => {
    setBusy('plan'); setErr('');
    try { open(await adminCustNotifyCreate({ kind, repo: c.repo, vulnId: c.vulnId })); } catch (e) { setErr(String(e)); }
    setBusy('');
  };
  // AI 설명은 서버가 뒤에서 만든다(로컬 LLM 은 언어당 1~3분) — 3초마다 상태를 읽어 진행을 보여 준다.
  const runAI = async () => {
    if (!n) return;
    setErr('');
    try { setN(await adminCustNotifyAI(n.id)); } catch (e) { setErr(String(e)); }
  };
  const aiRunning = n?.aiState === 'running';
  useEffect(() => {
    if (!n || n.aiState !== 'running') return;
    const t = setTimeout(() => adminCustNotifyGet(n.id).then(setN).catch(() => {}), 3000);
    return () => clearTimeout(t);
  }, [n]);
  const [now, setNow] = useState(0);
  useEffect(() => {
    if (!aiRunning) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [aiRunning]);
  const aiSec = n?.aiStarted && now ? Math.max(0, Math.floor((now - new Date(n.aiStarted).getTime()) / 1000)) : 0;
  const send = async () => {
    if (!n || !sel.length || !confirm(`${sel.length}곳에 메일을 보낼까요?`)) return;
    setBusy('send'); setErr('');
    try { const r = await adminCustNotifySend(n.id, sel); setN(r); setSel([]); } catch (e) { setErr(String(e)); }
    setBusy('');
  };
  const reset = () => { setN(null); setStage(1); setErr(''); };

  const sent = n && n.status !== 'draft';
  const st = (i: number): StepState => (err && i === stage ? 'error' : (i === 3 && aiRunning) || (i === 2 && busy === 'plan') || (i === 5 && busy === 'send') ? 'active' : i < stage || (i === 5 && sent) ? 'done' : i === stage ? 'active' : 'todo');
  const steps = [
    { label: '취약점 선택', state: st(1) },
    { label: '영향 고객', state: st(2), note: n ? `대상 ${n.targets.length} · 제외 ${n.skipped.length}` : undefined },
    { label: kind === 'patch' ? '패치 버전 찾기 + AI 설명' : '판정 근거 + AI 설명', state: st(3), ai: aiRunning },
    { label: '미리보기', state: st(4) },
    { label: '발송', state: st(5) }
  ];

  return (
    <>
      <PageHeader title="고객 통지" description="고객 등록부의 설치 버전 기준으로 영향 고객을 찾아 패치 권고(또는 영향 없음 확인서)를 보냅니다. 패치 버전은 분석 규칙이, 설명 문구는 AI 가 씁니다."
        actions={<div className="flex gap-1">
          <Button variant={tab === 'flow' ? 'default' : 'outline'} size="sm" onClick={() => setTab('flow')}><Send size={13} />새 통지</Button>
          <Button variant={tab === 'history' ? 'default' : 'outline'} size="sm" onClick={() => setTab('history')}><History size={13} />이력</Button>
        </div>} />
      {tab === 'history' ? <HistoryList onOpen={(id) => adminCustNotifyGet(id).then(open).catch((e) => setErr(String(e)))} /> : (
        <>
          <Card className="mb-4"><CardContent className="flex flex-wrap items-center justify-between gap-3 p-4">
            <Steps steps={steps} />
            {n && <Button size="sm" variant="ghost" onClick={reset}>처음부터</Button>}
          </CardContent></Card>
          {err && <Alert tone="crit">{err}</Alert>}

          {stage === 1 && (
            <>
              <div className="mb-3 flex gap-1">
                {(['patch', 'notaffected'] as const).map((k) => (
                  <Button key={k} size="sm" variant={kind === k ? 'default' : 'outline'} onClick={() => { setKind(k); setCands(null); }}>
                    {k === 'patch' ? <ShieldAlert size={13} /> : <ShieldCheck size={13} />}{KIND[k]}
                  </Button>
                ))}
              </div>
              {candErr && <Alert tone="warn">{candErr}</Alert>}
              {cands && cands.length > 0 && (() => {
                const comps: Record<string, number> = {};
                cands.forEach((c) => { const k = c.component.split(' ')[0]; comps[k] = (comps[k] || 0) + 1; });
                return (
                  <div className="mb-3 flex flex-wrap items-center gap-1.5 text-xs">
                    <span className="text-muted-foreground">구성요소</span>
                    {[['', `전체 ${cands.length}`], ...Object.entries(comps).sort((a, b) => b[1] - a[1]).map(([k, v]) => [k, `${k} ${v}`])].map(([k, l]) => (
                      <button key={k} onClick={() => setFComp(k)} className={cn('rounded-full border px-2.5 py-1', fComp === k ? 'border-primary bg-primary/10 font-medium text-primary' : 'hover:bg-secondary')}>{l}</button>
                    ))}
                    <span className="ml-3 text-muted-foreground">심각도</span>
                    {([['top', '치명·높음·KEV'], ['all', '전체']] as const).map(([k, l]) => (
                      <button key={k} onClick={() => setFSev(k)} className={cn('rounded-full border px-2.5 py-1', fSev === k ? 'border-primary bg-primary/10 font-medium text-primary' : 'hover:bg-secondary')}>{l}</button>
                    ))}
                    <input value={fq} onChange={(e) => setFq(e.target.value)} placeholder="CVE 검색" className="ml-auto h-7 w-40 rounded-md border px-2" />
                  </div>
                );
              })()}
              {!cands ? <Loading /> : (
                <Table>
                  <thead><tr><Th>취약점</Th><Th>제품·버전</Th><Th>구성요소</Th><Th>고객</Th><Th>상태</Th><Th /></tr></thead>
                  <tbody>
                    {cands.length === 0 ? <tr><Td colSpan={6} className="text-center text-muted-foreground">
                      {kind === 'patch' ? '등록된 고객 설치 버전에 걸린 취약점이 없습니다.' : '영향 없음(VEX)으로 판정된 취약점이 없습니다.'}</Td></tr> : cands.filter((c) =>
                      (!fComp || c.component.split(' ')[0] === fComp) &&
                      (fSev === 'all' || c.kev || ['CRITICAL', 'HIGH'].includes((c.severity || '').toUpperCase())) &&
                      (!fq || c.vulnId.toLowerCase().includes(fq.toLowerCase()))).map((c) => (
                      <tr key={c.repo + c.vulnId}>
                        <Td><div className="flex flex-wrap items-center gap-1"><b className="text-sm">{c.vulnId}</b><Sev s={c.severity} />{c.kev && <SourceBadge src="kev" />}</div></Td>
                        <Td className="text-xs">{base(c.repo)} · {c.tags.join(', ')}</Td>
                        <Td className="text-xs">{c.component}</Td>
                        <Td className="text-xs"><span title={c.customers.join(', ')}>{c.customers.length}곳</span></Td>
                        <Td className="text-xs">{c.states.join(', ')}{c.notified && <div className="text-emerald-700">통지함 {fmt(c.notified)}</div>}</Td>
                        <Td><Button size="sm" variant="outline" disabled={!!busy} onClick={() => pick(c)}>{busy === 'plan' ? '계산 중…' : '선택'}<ArrowRight size={12} /></Button></Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              )}
            </>
          )}

          {n && stage >= 2 && <NoticeHead n={n} />}

          {n && stage === 2 && (
            <>
              <SectionTitle>② 영향 고객 {n.targets.length}</SectionTitle>
              <TargetTable n={n} sel={sel} setSel={setSel} />
              {n.skipped.length > 0 && (
                <details className="mt-3 text-sm"><summary className="cursor-pointer text-muted-foreground">제외된 고객 {n.skipped.length}</summary>
                  <ul className="mt-1 space-y-0.5 text-xs">{n.skipped.map((s, i) => <li key={i}><b>{s.customer}</b> — {s.reason}</li>)}</ul>
                </details>
              )}
              <Nav next={() => setStage(3)} />
            </>
          )}

          {n && stage === 3 && (
            <>
              {n.kind === 'patch' && <FixPanel n={n} />}
              <SectionTitle><span className="inline-flex items-center gap-2"><AIIcon size={22} spin={aiRunning} />AI 설명</span></SectionTitle>
              <div className="mb-3 flex flex-wrap items-center gap-2">
                <Button onClick={runAI} disabled={!!busy || !!sent || aiRunning} className="bg-gradient-to-r from-violet-600 to-fuchsia-500 text-white hover:opacity-90">
                  {aiRunning ? 'AI 가 쓰는 중…' : 'AI 설명 만들기'}
                </Button>
                <span className="text-xs text-muted-foreground">AI 는 아래 사실(ID)만 근거로 쓰고, 사실에 없는 버전을 쓰면 버리고 규칙 문구를 씁니다. 담당자 이메일은 AI 에 보내지 않습니다.</span>
              </div>
              {aiRunning && (
                <div className="mb-3 rounded-lg border border-violet-200 bg-gradient-to-r from-violet-50 to-fuchsia-50 p-3 text-sm">
                  <div className="mb-2 flex items-center gap-2"><AIBadge pulse label="작성 중" />
                    <span>언어별로 차례로 씁니다({Object.keys(n.ai).join(' · ')}) · 경과 <b className="tabular-nums">{`${Math.floor(aiSec / 60)}:${String(aiSec % 60).padStart(2, '0')}`}</b></span></div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-violet-100"><div className="h-full w-1/3 animate-pulse rounded-full bg-gradient-to-r from-violet-600 to-fuchsia-500" /></div>
                  <div className="mt-1 text-xs text-muted-foreground">서버 내부 LLM 은 언어당 1~3분 걸립니다. 자동 초안이 돌고 있으면 그 건만 끝내고 이 요청을 먼저 처리합니다. 이 화면을 떠나도 계속 진행됩니다.</div>
                </div>
              )}
              {n.aiError && !aiRunning && <Alert tone="warn">{n.aiError}</Alert>}
              <div className="grid gap-3 md:grid-cols-2">{Object.entries(n.ai).map(([l, t]) => <AIText key={l} lang={l} t={t} />)}</div>
              <details className="mt-3 text-xs"><summary className="cursor-pointer text-muted-foreground">AI 에 준 사실 {n.facts.length}</summary>
                <ul className="mt-1 space-y-0.5">{n.facts.map((f) => <li key={f.id}><b className="font-mono">[{f.id}]</b> {f.untrusted && <Badge variant="warn">외부 원문</Badge>} {f.text}</li>)}</ul>
              </details>
              <Nav back={() => setStage(2)} next={() => setStage(4)} />
            </>
          )}

          {n && stage === 4 && (
            <>
              <SectionTitle>④ 미리보기 — 고객·언어별 메일</SectionTitle>
              <div className="space-y-3">{n.targets.map((t) => <Preview key={t.key} t={t} ai={n.ai[t.lang]} checked={sel.includes(t.key)} onCheck={(v) => setSel(v ? [...sel, t.key] : sel.filter((x) => x !== t.key))} />)}</div>
              <Nav back={() => setStage(3)} next={() => setStage(5)} />
            </>
          )}

          {n && stage === 5 && (
            <>
              <SectionTitle>⑤ 발송</SectionTitle>
              <TargetTable n={n} sel={sel} setSel={setSel} showResult />
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <Button onClick={send} disabled={!!busy || sel.length === 0}><Send size={14} />{busy === 'send' ? '보내는 중…' : `선택한 ${sel.length}곳에 발송`}</Button>
                <Badge variant={STATUS[n.status].v}>{STATUS[n.status].l}</Badge>
                {n.status === 'draft' && <Button size="sm" variant="ghost" onClick={async () => { if (confirm('초안을 지울까요?')) { await adminCustNotifyDelete(n.id).catch(() => {}); reset(); } }}><Trash2 size={13} />초안 삭제</Button>}
                <span className="text-xs text-muted-foreground">이미 보낸 고객은 다시 보내지 않습니다. 결과는 감사 기록에 남습니다.</span>
              </div>
              <Busy className="mt-2" active={busy === 'send'} label={`${sel.length}곳에 고객별 언어로 메일 보내는 중`} />
              <Nav back={() => setStage(4)} />
            </>
          )}
        </>
      )}
    </>
  );
}

function Nav({ back, next }: { back?: () => void; next?: () => void }) {
  return (
    <div className="mt-4 flex gap-2">
      {back && <Button variant="outline" size="sm" onClick={back}><ArrowLeft size={13} />이전</Button>}
      {next && <Button size="sm" onClick={next}>다음<ArrowRight size={13} /></Button>}
    </div>
  );
}

function NoticeHead({ n }: { n: CustNotice }) {
  return (
    <Card className="mb-3"><CardContent className="flex flex-wrap items-center gap-2 p-4 text-sm">
      <Badge variant={n.kind === 'patch' ? 'danger' : 'success'}>{KIND[n.kind]}</Badge>
      <b>{n.vulnId}</b><Sev s={n.severity} />{n.cvss != null && <span className="text-xs text-muted-foreground">CVSS {n.cvss}</span>}
      {n.kev && <SourceBadge src="kev" />}
      <span className="text-muted-foreground">·</span><span>{n.repo}</span>
      <span className="text-muted-foreground">· 구성요소 {n.component} {n.compVersion}</span>
      <Badge variant={STATUS[n.status].v} className="ml-auto">{STATUS[n.status].l}</Badge>
    </CardContent></Card>
  );
}

function TargetTable({ n, sel, setSel, showResult }: { n: CustNotice; sel: string[]; setSel: (v: string[]) => void; showResult?: boolean }) {
  const open = n.targets.filter((t) => !t.result?.sent?.length).map((t) => t.key);
  return (
    <Table>
      <thead><tr>
        <Th><input type="checkbox" checked={open.length > 0 && open.every((k) => sel.includes(k))} onChange={(e) => setSel(e.target.checked ? open : [])} /></Th>
        <Th>고객</Th><Th>설치 버전</Th>{n.kind === 'patch' && <Th>권장 버전</Th>}<Th>받는 사람</Th><Th>계약·지원</Th>{showResult && <Th>결과</Th>}
      </tr></thead>
      <tbody>
        {n.targets.length === 0 ? <tr><Td colSpan={7} className="text-center text-muted-foreground">보낼 고객이 없습니다(제외 사유 참고).</Td></tr> : n.targets.map((t) => (
          <tr key={t.key}>
            <Td><input type="checkbox" disabled={!!t.result?.sent?.length} checked={sel.includes(t.key)} onChange={(e) => setSel(e.target.checked ? [...sel, t.key] : sel.filter((x) => x !== t.key))} /></Td>
            <Td><div className="flex items-center gap-1.5"><Building2 size={13} className="text-muted-foreground" /><b>{t.customer}</b>{t.lang === 'en' && <Badge variant="outline">EN</Badge>}</div></Td>
            <Td className="text-xs">{t.tags.join(', ')}</Td>
            {n.kind === 'patch' && <Td>{t.recommend ? <Badge variant="success">{t.recommend}</Badge> : <span className="text-xs text-amber-700">없음 — 완화 조치</span>}</Td>}
            <Td className="text-xs">
              <div>{t.contacts.join(', ')}</div>
              <div className="text-muted-foreground">{t.to.join(', ')}</div>
              {!!t.cc?.length && <div className="text-muted-foreground">참조 {t.cc.join(', ')}</div>}
            </Td>
            <Td className="text-xs">
              {t.notes?.map((x, i) => <div key={i} className="text-amber-800">{x}</div>)}
              {t.internal?.map((x, i) => <div key={i} className="text-muted-foreground">내부: {x}</div>)}
              {!t.notes?.length && !t.internal?.length && '—'}
            </Td>
            {showResult && <Td><SendState t={t} /></Td>}
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

const STEP_CLS: Record<string, string> = { fixed: 'bg-emerald-600 text-white', affected: 'bg-red-100 text-red-800', present: 'bg-amber-100 text-amber-800', unknown: 'bg-slate-100 text-slate-600' };
const STEP_L: Record<string, string> = { fixed: '해결', affected: '취약', present: '남아 있음', unknown: '판단 보류' };

function FixPanel({ n }: { n: CustNotice }) {
  const f = n.fix;
  return (
    <>
      <SectionTitle><span className="inline-flex items-center gap-2"><Wrench size={16} />③ 패치 버전 찾기 <Badge variant="muted">규칙 판정 · AI 아님</Badge></span></SectionTitle>
      <Card className={cn('mb-3 border-2', f.found ? 'border-emerald-300' : 'border-amber-300')}><CardContent className="space-y-2 p-4">
        {f.found ? (
          <div className="text-base">권장 패치 버전 <b className="text-emerald-700">{base(n.repo)} {f.tag}</b>
            {f.compVersion && <span className="text-sm text-muted-foreground"> — 그 버전의 {n.component} {f.compVersion}</span>}
            {f.note && <span className="text-sm text-muted-foreground"> ({f.note})</span>}</div>
        ) : <div className="text-base font-semibold text-amber-800">{f.message || '아직 패치 버전 없음 — 완화 조치 안내'}</div>}
        <div className="text-xs text-muted-foreground">근거: 설치 버전 {f.from} 보다 새 버전을 순서대로 보며, 분석 결과(DT)에 {n.vulnId} 가 없고 SBOM 의 구성요소 버전이 달라진 첫 버전.</div>
        <div className="flex flex-wrap items-center gap-1">
          {f.steps.map((s) => (
            <span key={s.tag} title={[s.compVersion && `구성요소 ${s.compVersion}`, s.note].filter(Boolean).join(' · ')} className={cn('rounded-full px-2 py-0.5 text-[11px] font-medium', STEP_CLS[s.status])}>
              {s.tag} {STEP_L[s.status]}
            </span>
          ))}
          {f.steps.length === 0 && <span className="text-xs text-muted-foreground">더 새 버전이 없습니다.</span>}
        </div>
        <div className="flex flex-wrap items-center gap-2 border-t pt-2 text-xs">
          {f.osv ? (
            <><SourceBadge src="osv" label={`OSV ${f.osv.id}`} /><span>구성요소 수정 버전 {f.osv.fixed?.join(', ') || '—'}{f.osv.target && <> · 현재보다 높은 최소 수정 <b>{f.osv.target}</b></>}</span><span className="text-muted-foreground">(참고 근거 — 권장 버전은 위 규칙이 정함)</span></>
          ) : <><SourceBadge src="mirror" /><span className="text-muted-foreground">OSV 근거 없음: {f.osvNote || '—'}</span></>}
          {n.kev && <SourceBadge src="kev" label="KEV 등재" />}
        </div>
      </CardContent></Card>
    </>
  );
}

function AIText({ lang, t }: { lang: string; t: CustAIText }) {
  return (
    <Card className={cn(t.source === 'ai' && 'border-violet-300')}><CardContent className="space-y-2 p-4 text-sm">
      <div className="flex items-center gap-2">
        <Badge variant="outline">{lang === 'en' ? '영어' : '한국어'}</Badge>
        {t.source === 'ai' ? <AIBadge label={`AI 작성${t.model ? ' · ' + t.model : ''}`} /> : <Badge variant="muted">규칙 문구</Badge>}
      </div>
      {([['요약', t.summary], ['영향', t.impact], ['조치', t.action]] as const).map(([k, v]) => <div key={k}><div className="text-xs font-semibold text-muted-foreground">{k}</div><p>{v}</p></div>)}
      {t.citations.length > 0 && <div className="flex flex-wrap gap-1 text-[11px]">근거 {t.citations.map((c) => <span key={c} className="rounded bg-violet-50 px-1 font-mono text-violet-700">[{c}]</span>)}</div>}
      {t.warnings?.map((w, i) => <div key={i} className="text-xs text-red-600">{w}</div>)}
    </CardContent></Card>
  );
}

function Preview({ t, ai, checked, onCheck }: { t: CustTarget; ai?: CustAIText; checked: boolean; onCheck: (v: boolean) => void }) {
  const [html, setHtml] = useState(true);
  return (
    <Card><CardContent className="space-y-2 p-4">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <input type="checkbox" checked={checked} disabled={!!t.result?.sent?.length} onChange={(e) => onCheck(e.target.checked)} />
        <b>{t.customer}</b><Badge variant="outline">{t.lang.toUpperCase()}</Badge>
        {ai?.source === 'ai' ? <AIBadge label="AI 설명 포함" /> : <Badge variant="muted">규칙 문구</Badge>}
        <span className="text-xs text-muted-foreground">받는 사람 {t.to.join(', ')}{t.cc?.length ? ` · 참조 ${t.cc.join(', ')}` : ''}</span>
        <Button size="sm" variant="ghost" className="ml-auto" onClick={() => setHtml(!html)}><Eye size={12} />{html ? '평문 보기' : 'HTML 보기'}</Button>
      </div>
      <div className="text-sm font-medium">제목: {t.subject}</div>
      {html ? <iframe title={t.key} sandbox="" srcDoc={t.html} className="h-80 w-full rounded border bg-white" />
        : <pre className="max-h-80 overflow-auto whitespace-pre-wrap rounded border bg-secondary/40 p-3 text-xs">{t.text}</pre>}
      <SendState t={t} />
    </CardContent></Card>
  );
}

function HistoryList({ onOpen }: { onOpen: (id: string) => void }) {
  const [rows, setRows] = useState<CustNoticeRow[] | null>(null);
  const [err, setErr] = useState('');
  useEffect(() => { adminCustNotifyList().then(setRows).catch((e) => setErr(String(e))); }, []);
  if (err) return <Alert tone="crit">{err}</Alert>;
  if (!rows) return <Loading />;
  return (
    <Table>
      <thead><tr><Th>만든 시각</Th><Th>종류</Th><Th>취약점</Th><Th>제품</Th><Th>권장 버전</Th><Th>대상·결과</Th><Th>상태</Th><Th /></tr></thead>
      <tbody>
        {rows.length === 0 ? <tr><Td colSpan={8} className="text-center text-muted-foreground">통지 이력이 없습니다.</Td></tr> : rows.map((r) => (
          <tr key={r.id}>
            <Td className="whitespace-nowrap text-xs">{fmt(r.created)}<div className="text-muted-foreground">{r.createdBy}</div></Td>
            <Td><Badge variant={r.kind === 'patch' ? 'danger' : 'success'}>{KIND[r.kind]}</Badge></Td>
            <Td><div className="flex items-center gap-1"><b className="text-sm">{r.vulnId}</b><Sev s={r.severity} />{r.kev && <SourceBadge src="kev" />}</div></Td>
            <Td className="text-xs">{r.repo}</Td>
            <Td>{r.recommend ? <Badge variant="success">{r.recommend}</Badge> : '—'}</Td>
            <Td className="text-xs">대상 {r.targets} · 보냄 {r.sent}{r.dropped > 0 && <span className="text-amber-700"> · 건너뜀 {r.dropped}</span>}{r.failed > 0 && <span className="text-red-600"> · 실패 {r.failed}</span>}</Td>
            <Td><Badge variant={STATUS[r.status].v}>{STATUS[r.status].l}</Badge>{r.sentAt && <div className="text-[11px] text-muted-foreground">{fmt(r.sentAt)}</div>}</Td>
            <Td><Button size="sm" variant="outline" onClick={() => onOpen(r.id)}>열기</Button></Td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}
