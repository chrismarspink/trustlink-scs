import { Flame, Database, Gauge, Bug, GitBranch, Globe2, Server, ShieldAlert, type LucideIcon } from 'lucide-react';
import { cn } from '@/lib/utils';
import { AIBadge } from './AIBadge';

// 출처·근거 표시 — 어떤 데이터(미러 DB·KEV·EPSS)나 AI 를 근거로 했는지 한눈에 보이게 화면 전체에서 같은 모양을 쓴다.
// AI 는 AIBadge(보라→자홍), 실제 악용(KEV)은 빨강 불꽃, 취약점 DB 는 출처별 색 + 아이콘.
type Src = { label: string; icon: LucideIcon; cls: string; title: string };
const SRC: Record<string, Src> = {
  kev: { label: 'KEV', icon: Flame, cls: 'bg-red-600 text-white', title: 'CISA KEV — 실제 악용이 확인된 취약점' },
  epss: { label: 'EPSS', icon: Gauge, cls: 'bg-orange-100 text-orange-800 ring-1 ring-orange-300', title: 'FIRST EPSS — 30일 안 악용 가능성' },
  exploit: { label: '익스플로잇', icon: ShieldAlert, cls: 'bg-rose-100 text-rose-800 ring-1 ring-rose-300', title: '공개 익스플로잇(Exploit-DB·Metasploit·Nuclei)' },
  osv: { label: 'OSV', icon: Database, cls: 'bg-sky-100 text-sky-800 ring-1 ring-sky-300', title: 'OSV — 생태계별 영향·수정 버전' },
  nvd: { label: 'NVD', icon: Bug, cls: 'bg-slate-100 text-slate-800 ring-1 ring-slate-300', title: 'NVD — CVE·CVSS' },
  ghsa: { label: 'GHSA', icon: GitBranch, cls: 'bg-zinc-100 text-zinc-800 ring-1 ring-zinc-300', title: 'GitHub Advisory Database' },
  euvd: { label: 'EUVD', icon: Globe2, cls: 'bg-indigo-100 text-indigo-800 ring-1 ring-indigo-300', title: 'ENISA EU 취약점 DB' },
  mirror: { label: '내부 미러', icon: Server, cls: 'bg-teal-100 text-teal-800 ring-1 ring-teal-300', title: '서버 내부 취약점 DB 사본(외부 접속 없음)' }
};

export function SourceBadge({ src, label, title, className }: { src: string; label?: string; title?: string; className?: string }) {
  const k = src.toLowerCase();
  if (k === 'ai') return <AIBadge label={label || 'AI'} className={className} />;
  const s = SRC[k] || { label: src, icon: Database, cls: 'bg-slate-100 text-slate-700', title: src };
  const Icon = s.icon;
  return (
    <span title={title || s.title} className={cn('inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-semibold', s.cls, className)}>
      <Icon size={11} /> {label || s.label}
    </span>
  );
}

// 진행 단계 표시 — 기능마다 "지금 어디까지 왔는지"를 같은 모양으로 보여 준다.
// state: done(완료) · active(진행 중) · todo(대기) · error(실패) · skip(해당 없음)
export type StepState = 'done' | 'active' | 'todo' | 'error' | 'skip';
export function Steps({ steps, className }: { steps: { label: string; state: StepState; note?: string; ai?: boolean }[]; className?: string }) {
  const cls: Record<StepState, string> = {
    done: 'bg-emerald-600 text-white', active: 'bg-violet-600 text-white animate-pulse', todo: 'bg-slate-200 text-slate-600',
    error: 'bg-red-600 text-white', skip: 'bg-slate-100 text-slate-400 line-through'
  };
  const mark: Record<StepState, string> = { done: '✓', active: '…', todo: '', error: '!', skip: '–' };
  return (
    <ol className={cn('flex flex-wrap items-center gap-1.5 text-xs', className)}>
      {steps.map((s, i) => (
        <li key={i} className="flex items-center gap-1.5" title={s.note}>
          <span className={cn('inline-flex items-center gap-1 rounded-full px-2.5 py-1 font-medium', cls[s.state], s.ai && s.state === 'active' && 'bg-gradient-to-r from-violet-600 to-fuchsia-500')}>
            <span className="tabular-nums">{i + 1}</span> {s.label} {mark[s.state] && <span>{mark[s.state]}</span>}
          </span>
          {i < steps.length - 1 && <span className="text-slate-300">→</span>}
        </li>
      ))}
    </ol>
  );
}
