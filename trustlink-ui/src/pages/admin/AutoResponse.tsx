import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Bot, Play, CheckCircle2, XCircle, Mail, Wrench, ShieldAlert, Eye } from 'lucide-react';
import {
  adminAutoResponse, adminAutoSettings, adminAutoRun, adminAutoApprove, adminAutoReject, adminCustNotifyGet,
  type AutoRun, type AutoSettings, type CustNotice
} from '@/lib/api';
import { Button, Input, Badge, Card, CardContent } from '@/components/ui/primitives';
import { Steps, type StepState } from '@/components/SourceBadge';
import { DelayPicker, OutboxPanel } from '@/components/Outbox';
import { useSendDelay } from '@/lib/sendDelay';
import { PageHeader, Alert, Loading, selectCls } from './_ui';
import { cn } from '@/lib/utils';

// 관리 › 자동 대응: 새 취약점 → AI 분석 → 패치 버전 확인 → (있음) 관리자 승인 → 고객 통지 / (없음) 개발자 통보.
// 고객에게 나가는 메일은 반드시 관리자가 받는 사람을 확인하고 승인해야 나간다(승인 뒤에도 발송함 대기 동안 취소 가능).

const OUT: Record<NonNullable<AutoRun['outcome']>, [string, string]> = {
  approval: ['관리자 승인 대기', 'bg-amber-100 text-amber-800'], sent: ['고객 통지 승인·발송', 'bg-emerald-100 text-emerald-800'],
  rejected: ['반려', 'bg-slate-200 text-slate-700'], 'dev-request': ['개발자 수정 요청', 'bg-sky-100 text-sky-800'],
  'not-affected': ['AI: 영향 없음 — 사람 확인', 'bg-slate-100 text-slate-700'], 'no-customers': ['영향 고객 없음', 'bg-slate-100 text-slate-700'], error: ['오류', 'bg-red-100 text-red-700'],
};
const stState = (s: AutoRun['stages'][number]['state']): StepState => (s === 'wait' ? 'active' : s);
const t = (x?: string) => (x ? new Date(x).toLocaleString('ko-KR', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '');

function Flow() {
  const box = (icon: React.ReactNode, title: string, sub: string, cls = '') => (
    <div className={cn('flex min-w-[118px] flex-1 flex-col items-center rounded-lg border bg-white px-2 py-2 text-center', cls)}>
      <div className="mb-0.5">{icon}</div><div className="text-xs font-semibold">{title}</div><div className="text-[10px] text-muted-foreground">{sub}</div>
    </div>
  );
  const arrow = <span className="self-center text-slate-300">→</span>;
  return (
    <div className="flex flex-wrap items-stretch gap-1.5">
      {box(<ShieldAlert size={16} className="text-red-600" />, '① 탐지', '새 취약점(KEV·치명)')}{arrow}
      {box(<Bot size={16} className="text-fuchsia-600" />, '② AI 분석', '영향 여부·근거')}{arrow}
      {box(<Wrench size={16} className="text-slate-600" />, '③ 패치 확인', '새 버전에서 해결됐나')}{arrow}
      <div className="flex min-w-[250px] flex-[2] flex-col gap-1">
        {box(<CheckCircle2 size={16} className="text-amber-600" />, '④ 있음: 관리자 승인 → 고객 통지', '받는 사람 확인 후 승인, 발송 전 취소 가능', 'border-amber-200 bg-amber-50/50')}
        {box(<Mail size={16} className="text-sky-600" />, '④ 없음: 개발자 수정 요청', '사내 메일 — 바로 발송', 'border-sky-200 bg-sky-50/50')}
      </div>
    </div>
  );
}

function Approval({ run, onDone }: { run: AutoRun; onDone: () => void }) {
  const [n, setN] = useState<CustNotice | null>(null);
  const [sel, setSel] = useState<string[]>([]);
  const [peek, setPeek] = useState('');
  const [delay, setDelay] = useSendDelay();
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => { if (run.noticeId) adminCustNotifyGet(run.noticeId).then((x) => { setN(x); setSel(x.targets.map((tg) => tg.key)); }).catch((e) => setErr(String(e))); }, [run.noticeId]);
  if (!n) return err ? <Alert tone="crit">{err}</Alert> : <Loading />;
  const approve = async () => {
    if (!sel.length || !confirm(`${sel.length}곳에 보안 권고 메일을 보냅니다.${delay ? `\n${delay}초 동안 발송함에서 기다리며 그 사이 취소할 수 있습니다.` : ''}`)) return;
    setBusy(true); setErr('');
    try { await adminAutoApprove(run.id, sel, delay); onDone(); } catch (e) { setErr(String(e)); }
    setBusy(false);
  };
  const reject = async () => {
    const why = prompt('반려 사유(선택) — 예: VEX 로 영향 없음 확정 예정');
    if (why === null) return;
    setBusy(true); try { await adminAutoReject(run.id, why); onDone(); } catch (e) { setErr(String(e)); } setBusy(false);
  };
  const cur = n.targets.find((x) => x.key === peek);
  return (
    <div className="mt-3 rounded-lg border-2 border-amber-300 bg-amber-50/60 p-3">
      <div className="mb-2 text-sm font-semibold text-amber-900">관리자 승인 — 추천된 받는 사람을 확인하고 승인하면 고객에게 나갑니다</div>
      <div className="space-y-1.5">
        {n.targets.map((tg) => (
          <label key={tg.key} className="flex flex-wrap items-center gap-2 rounded-md border bg-white px-3 py-2 text-xs">
            <input type="checkbox" checked={sel.includes(tg.key)} onChange={(e) => setSel(e.target.checked ? [...sel, tg.key] : sel.filter((k) => k !== tg.key))} />
            <b className="text-sm">{tg.customer}</b>{tg.lang === 'en' && <Badge variant="outline">EN</Badge>}
            <span className="text-muted-foreground">설치 {tg.tags.join(', ')} → 권장 <b className="text-emerald-700">{tg.recommend}</b></span>
            <span className="min-w-0 flex-1 truncate">받는 사람: {tg.contacts.join(', ')} <span className="text-muted-foreground">({tg.to.join(', ')})</span></span>
            <button type="button" className="inline-flex items-center gap-1 text-violet-700 hover:underline" onClick={(e) => { e.preventDefault(); setPeek(peek === tg.key ? '' : tg.key); }}><Eye size={12} />메일 보기</button>
          </label>
        ))}
      </div>
      {cur && (
        <div className="mt-2 rounded-md border bg-white p-3 text-xs">
          <div className="mb-1 font-semibold">{cur.subject}</div>
          <pre className="max-h-64 overflow-auto whitespace-pre-wrap font-sans leading-relaxed text-slate-700">{cur.text}</pre>
        </div>
      )}
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Button onClick={approve} disabled={busy || !sel.length}><CheckCircle2 size={14} />승인·발송 ({sel.length}곳)</Button>
        <Button variant="outline" onClick={reject} disabled={busy}><XCircle size={14} />반려</Button>
        <DelayPicker value={delay} onChange={setDelay} />
        <Link to="/admin/customer-notify" className="text-xs text-violet-700 hover:underline">고객 통지 화면에서 자세히</Link>
      </div>
      {err && <Alert tone="crit">{err}</Alert>}
    </div>
  );
}

function RunCard({ run, onChange }: { run: AutoRun; onChange: () => void }) {
  const [n, setN] = useState<CustNotice | null>(null);
  useEffect(() => { if (run.outcome === 'sent' && run.noticeId) adminCustNotifyGet(run.noticeId).then(setN).catch(() => {}); }, [run.outcome, run.noticeId]);
  const o = run.outcome ? OUT[run.outcome] : ['진행 중', 'bg-violet-100 text-violet-800'];
  return (
    <Card><CardContent className="space-y-2 p-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className={cn('rounded px-2 py-0.5 text-xs font-semibold', o[1])}>{o[0]}</span>
        <b className="font-mono text-sm">{run.vulnId}</b>
        {run.severity && <Badge variant={run.severity === 'CRITICAL' ? 'danger' : 'warn'}>{run.severity}</Badge>}
        {run.kev && <Badge variant="danger">KEV</Badge>}
        <span className="text-sm">{run.repo.split('/').pop()} <b>{run.tag}</b>{run.component && <span className="text-muted-foreground"> · {run.component}</span>}</span>
        <span className="ml-auto text-xs text-muted-foreground">{run.trigger === 'auto' ? '자동' : `직접 실행 · ${run.by}`} · {t(run.started)}</span>
      </div>
      <Steps steps={run.stages.map((s) => ({ label: s.label, state: stState(s.state), ai: s.key === 'ai' }))} />
      <ul className="space-y-0.5 text-xs text-slate-700">
        {run.stages.filter((s) => s.detail).map((s) => <li key={s.key}><b className="mr-1">{s.label}</b>{s.detail}{s.at && <span className="ml-1 text-muted-foreground">({t(s.at)})</span>}</li>)}
      </ul>
      {run.aiSummary && <div className="rounded-md border border-fuchsia-200 bg-fuchsia-50/60 p-2 text-xs"><b className="text-fuchsia-700">✦ AI 분석{run.aiModel ? ` · ${run.aiModel}` : ''}</b> — {run.aiSummary}</div>}
      {run.error && <Alert tone="crit">{run.error}</Alert>}
      {run.state === 'waiting' && <Approval run={run} onDone={onChange} />}
      {n && n.targets.some((x) => x.result?.outbox) && <OutboxPanel ids={n.targets.map((x) => x.result?.outbox || '').filter(Boolean)} />}
    </CardContent></Card>
  );
}

export default function AutoResponse() {
  const [d, setD] = useState<{ settings: AutoSettings; runs: AutoRun[]; ai: boolean } | null>(null);
  const [err, setErr] = useState('');
  const [repo, setRepo] = useState('products/innopouch');
  const [tag, setTag] = useState('11.0');
  const [vuln, setVuln] = useState('CVE-2026-123007');
  const load = useCallback(() => adminAutoResponse().then((x) => { setD(x); setErr(''); }).catch((e) => setErr(String(e))), []);
  useEffect(() => { adminAutoResponse().then(setD).catch((e) => setErr(String(e))); }, []);
  const live = !!d?.runs.some((r) => r.state === 'running');
  useEffect(() => { if (!live) return; const id = setInterval(load, 3000); return () => clearInterval(id); }, [live, load]);
  const run = async () => { setErr(''); try { await adminAutoRun(repo.trim(), tag.trim(), vuln.trim()); load(); } catch (e) { setErr(String(e)); } };
  const setMode = async (mode: 'on' | 'off') => { if (!d) return; try { await adminAutoSettings({ ...d.settings, mode }); load(); } catch (e) { setErr(String(e)); } };
  const waiting = d?.runs.filter((r) => r.state === 'waiting').length || 0;

  return (
    <>
      <PageHeader title="자동 대응" description="새 취약점이 잡히면 AI 분석과 패치 버전 확인까지 자동으로 하고, 패치가 있으면 관리자 승인을 거쳐 고객에게, 없으면 개발자에게 알립니다." />
      {err && <Alert tone="crit">{err}</Alert>}
      <Flow />
      {!d ? <Loading /> : (
        <>
          <div className="mt-4 flex flex-wrap items-center gap-3 rounded-lg border bg-card p-3 text-sm">
            <span className="font-semibold">자동 실행</span>
            <select className={selectCls} value={d.settings.mode} onChange={(e) => setMode(e.target.value as 'on' | 'off')}>
              <option value="on">켜짐 — 새 취약점(KEV·치명) 통보 때마다</option><option value="off">꺼짐 — 직접 실행만</option>
            </select>
            <span className="text-xs text-muted-foreground">버전당 최대 {d.settings.maxPerVersion}건 · AI {d.ai ? '연결됨' : '꺼짐(규칙으로 진행)'}</span>
            {waiting > 0 && <span className="ml-auto rounded bg-amber-100 px-2 py-0.5 text-xs font-semibold text-amber-800">승인 대기 {waiting}건</span>}
          </div>
          <div className="mt-3 flex flex-wrap items-center gap-2 rounded-lg border bg-card p-3">
            <span className="text-sm font-semibold">직접 실행</span>
            <Input className="w-48" value={repo} onChange={(e) => setRepo(e.target.value)} placeholder="제품(예: products/innopouch)" />
            <Input className="w-24" value={tag} onChange={(e) => setTag(e.target.value)} placeholder="버전" />
            <Input className="w-44" value={vuln} onChange={(e) => setVuln(e.target.value)} placeholder="CVE-…" />
            <Button onClick={run} disabled={live}><Play size={14} />실행</Button>
            <span className="text-xs text-muted-foreground">로컬 AI 분석이 1~2분 걸립니다.</span>
          </div>
          <div className="mt-4 space-y-3">
            {d.runs.length === 0 ? <p className="text-sm text-muted-foreground">아직 실행 기록이 없습니다.</p> : d.runs.map((r) => <RunCard key={r.id} run={r} onChange={load} />)}
          </div>
        </>
      )}
    </>
  );
}
