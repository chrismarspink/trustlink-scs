import { useEffect, useState } from 'react';
import { cn } from '@/lib/utils';
import { Steps, type StepState } from './SourceBadge';

// 오래 걸리는 작업의 진행 표시 — 화면 전체에서 같은 모양을 쓴다.
//   JobProgress: 서버 작업(단계·완료/전체를 아는 경우) — 단계 칩 + 막대 + 경과·남은 시간
//   Busy: 요청 하나가 끝나기를 기다리는 경우(수를 모름) — 움직이는 막대 + 경과 시간

// useElapsed: 1초마다 경과 초를 돌려준다(from: 시작 시각, 없으면 이 화면 조각이 나타난 때부터).
function useElapsed(from?: string | number) {
  const [t0] = useState(() => Date.now());
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  const start = from ? new Date(from).getTime() : t0;
  return Math.max(0, Math.round((now - start) / 1000));
}

function Elapsed({ from }: { from?: string }) {
  return <>{fmtSec(useElapsed(from))}</>;
}

function fmtSec(s: number) {
  if (s < 60) return `${s}초`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}분 ${s % 60}초`;
  return `${Math.floor(m / 60)}시간 ${m % 60}분`;
}

function Bar({ pct, className }: { pct?: number; className?: string }) {
  return (
    <div className={cn('relative h-2 w-full overflow-hidden rounded-full bg-slate-200', className)}>
      {pct === undefined ? (
        <div className="absolute inset-y-0 w-1/3 animate-[tl-indet_1.4s_ease-in-out_infinite] rounded-full bg-violet-500" />
      ) : (
        <div className="h-full rounded-full bg-violet-600 transition-all duration-500" style={{ width: `${Math.min(100, Math.max(2, pct))}%` }} />
      )}
      <style>{'@keyframes tl-indet{0%{left:-33%}100%{left:100%}}'}</style>
    </div>
  );
}

export function JobProgress({ steps, stage, done = 0, total = 0, started, text, aiSteps = [], className }: {
  steps: string[]; stage: number; done?: number; total?: number; started?: string; text?: string; aiSteps?: string[]; className?: string;
}) {
  const sec = useElapsed(started);
  // 막대: 단계마다 같은 몫, 지금 단계 안에서는 완료/전체 비율(모르면 반 칸)
  const n = Math.max(steps.length, 1);
  const inner = total > 0 ? done / total : 0.5;
  const pct = ((stage + inner) / n) * 100;
  // 남은 시간: 지금 단계의 처리 속도로만 어림(첫 단계 이후, 완료가 있을 때)
  const [stageStart, setStageStart] = useState({ stage, sec });
  if (stage !== stageStart.stage) setStageStart({ stage, sec }); // 단계가 바뀐 시점 기억(이전 렌더 값에서 파생)
  const spent = sec - stageStart.sec;
  const eta = total > 0 && done > 0 && done < total && spent > 3 ? Math.round((spent / done) * (total - done)) : 0;
  const st = (i: number): StepState => (i < stage ? 'done' : i === stage ? 'active' : 'todo');
  return (
    <div className={cn('space-y-2 rounded-md border border-violet-200 bg-violet-50/60 p-3', className)}>
      <Steps steps={steps.map((label, i) => ({ label, state: st(i), ai: aiSteps.includes(label) }))} />
      <Bar pct={pct} />
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-700">
        <span className="font-medium">{text || steps[stage]}</span>
        {total > 0 && <span className="tabular-nums">{done} / {total} ({Math.round((done / total) * 100)}%)</span>}
        <span className="tabular-nums text-muted-foreground">경과 {fmtSec(sec)}</span>
        {eta > 0 && <span className="tabular-nums text-muted-foreground">이 단계 남은 시간 약 {fmtSec(eta)}</span>}
      </div>
    </div>
  );
}

// Busy: 요청 하나를 기다리는 동안(active) 움직이는 막대와 경과 시간. hint 는 보통 걸리는 시간 안내.
// since: 서버가 알려 준 시작 시각(있으면 그때부터 잰다).
export function Busy({ active, label, hint, since, className }: { active: boolean; label: string; hint?: string; since?: string; className?: string }) {
  if (!active) return null;
  return (
    <div className={cn('space-y-1 rounded-md border border-violet-200 bg-violet-50/60 p-2', className)} role="status" aria-live="polite">
      <Bar />
      <div className="flex flex-wrap gap-x-3 text-xs text-slate-700">
        <span className="font-medium">{label}</span>
        <span className="tabular-nums text-muted-foreground">경과 <Elapsed from={since} /></span>
        {hint && <span className="text-muted-foreground">{hint}</span>}
      </div>
    </div>
  );
}

// DownloadLink: 서버가 만들어 주는 파일(PDF 등)을 받는 링크. 받는 동안 경과 시간을 보여 준다.
export function DownloadLink({ href, children, className, title }: { href: string; children: React.ReactNode; className?: string; title?: string }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  async function go(e: React.MouseEvent) {
    e.preventDefault();
    e.stopPropagation();
    if (busy) return;
    setBusy(true); setErr('');
    try {
      const r = await fetch(href, { credentials: 'include' });
      if (!r.ok) throw new Error(`${r.status} ${(await r.text()).slice(0, 120)}`);
      const cd = r.headers.get('Content-Disposition') || '';
      const m = /filename\*=UTF-8''([^;]+)/i.exec(cd) || /filename="?([^";]+)"?/i.exec(cd);
      const name = m ? decodeURIComponent(m[1]) : href.split('/').slice(-2).join('-');
      const url = URL.createObjectURL(await r.blob());
      const a = document.createElement('a');
      a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10000);
    } catch (x) { setErr(String(x)); }
    setBusy(false);
  }
  return (
    <a href={href} onClick={go} className={className} title={err || title} aria-busy={busy}>
      {busy ? <span className="tabular-nums text-violet-700">PDF 만드는 중 <Elapsed /></span> : err ? <span className="text-red-600">실패</span> : children}
    </a>
  );
}

// PartsProgress: 여러 요청을 동시에 기다릴 때 — 받은 항목마다 ✓, 막대는 받은 개수 비율, 경과 시간.
// since: 기다리기 시작한 시각(화면 조각이 바뀌어도 경과 시간이 이어지도록 바깥에서 준다).
export function PartsProgress({ parts, since, hint, className }: {
  parts: { label: string; done: boolean; failed?: boolean }[]; since?: string; hint?: string; className?: string;
}) {
  const done = parts.filter((p) => p.done).length;
  const waiting = parts.filter((p) => !p.done).map((p) => p.label);
  return (
    <div className={cn('space-y-2 rounded-md border border-violet-200 bg-violet-50/60 p-3', className)} role="status" aria-live="polite">
      <div className="flex flex-wrap gap-1.5">
        {parts.map((p) => (
          <span key={p.label} className={cn('inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs',
            p.failed ? 'bg-red-100 text-red-700' : p.done ? 'bg-emerald-100 text-emerald-800' : 'bg-white text-slate-600 ring-1 ring-violet-200')}>
            {p.failed ? '✕' : p.done ? '✓' : <span className="h-2 w-2 animate-pulse rounded-full bg-violet-500" />}{p.label}
          </span>
        ))}
      </div>
      <Bar pct={(done / Math.max(parts.length, 1)) * 100} />
      <div className="flex flex-wrap gap-x-3 text-xs text-slate-700">
        <span className="font-medium">{waiting.length ? `${waiting.join(', ')} 불러오는 중` : '거의 다 됐습니다'}</span>
        <span className="tabular-nums">{done} / {parts.length}</span>
        <span className="tabular-nums text-muted-foreground">경과 <Elapsed from={since} /></span>
        {hint && <span className="text-muted-foreground">{hint}</span>}
      </div>
    </div>
  );
}
