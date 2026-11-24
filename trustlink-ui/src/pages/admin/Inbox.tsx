import { AskChip } from '@/components/AskChip';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Workflow, ShieldQuestion, Landmark, CalendarClock, Send, ArrowRight, Inbox as InboxIcon } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { adminInbox, type InboxGroup } from '@/lib/api';
import { PageHeader, Alert, Loading } from './_ui';
import { cn } from '@/lib/utils';

// 관리 › 승인 대기함: 신호 → 영향 → **결정** → 전달 → 기록 중 사람이 하는 "결정"을 한 곳에.
// 흩어진 대기열(자동 대응 승인·VEX 판단·규제 후보·만료·발송 대기)을 모아 보여 주고 원래 화면으로 보낸다.

const META: Record<InboxGroup['key'], { icon: LucideIcon; cls: string; hint: string }> = {
  auto: { icon: Workflow, cls: 'border-amber-300 bg-amber-50/60', hint: '자동 대응이 만든 고객 통지·개발자 수정 요청 — 승인해야 나갑니다' },
  vex: { icon: ShieldQuestion, cls: 'border-red-200 bg-red-50/40', hint: 'KEV·치명 취약점의 영향 판단 — VEX 로 기록' },
  reg: { icon: Landmark, cls: 'border-teal-200 bg-teal-50/40', hint: '규제 탐색이 찾은 새 후보 — 카탈로그에 채택할지' },
  expiry: { icon: CalendarClock, cls: 'border-orange-200 bg-orange-50/40', hint: '30일 안에 끝나는 유지보수·라이선스·EOS' },
  outbox: { icon: Send, cls: 'border-violet-200 bg-violet-50/40', hint: '보내기 전 대기 중 — 지금 취소할 수 있습니다' },
};

export default function Inbox() {
  const [d, setD] = useState<{ groups: InboxGroup[]; decisions: number; generated: string } | null>(null);
  const [err, setErr] = useState('');
  useEffect(() => {
    const load = () => adminInbox().then((x) => { setD(x); setErr(''); }).catch((e) => setErr(String(e)));
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, []);
  return (
    <>
      <PageHeader title="승인 대기함" actions={<AskChip q="오늘 승인할 것?" label="묻고 찾기로 요약" />} description="TrustLink 는 신호를 모으고, 영향을 계산하고, 초안을 쓰고, 보내고, 기록합니다. 사람이 할 일은 여기서 결정하는 것뿐입니다." />
      {err && <Alert tone="crit">{err}</Alert>}
      {!d ? <Loading /> : (
        <>
          <div className="mb-4 flex items-center gap-2 rounded-lg border bg-card px-4 py-3 text-sm">
            <InboxIcon size={16} className="text-violet-600" />
            <b>{d.decisions ? `결정할 일 ${d.decisions}건` : '지금 결정할 일이 없습니다'}</b>
            <span className="text-xs text-muted-foreground">(VEX 판단 대기는 따로 — 건수가 많아 버전별로 묶어 보입니다)</span>
          </div>
          <div className="grid gap-4 lg:grid-cols-2">
            {d.groups.map((g) => {
              const m = META[g.key];
              return (
                <section key={g.key} className={cn('rounded-lg border p-4', g.count ? m.cls : 'bg-card')}>
                  <div className="mb-1 flex items-center gap-2">
                    <m.icon size={16} className="text-slate-600" />
                    <h2 className="text-sm font-semibold">{g.label}</h2>
                    <span className={cn('rounded-full px-2 py-0.5 text-xs font-semibold', g.count ? 'bg-slate-900 text-white' : 'bg-slate-100 text-slate-500')}>{g.count}</span>
                    <Link to={g.link} className="ml-auto inline-flex items-center gap-1 text-xs text-violet-700 hover:underline">열기 <ArrowRight size={12} /></Link>
                  </div>
                  <p className="mb-2 text-xs text-muted-foreground">{m.hint}</p>
                  {g.items.length === 0 ? <p className="text-xs text-muted-foreground">없음</p> : (
                    <ul className="space-y-1.5">
                      {g.items.map((it, i) => (
                        <li key={(it.ref || '') + i}>
                          <Link to={it.link} className="flex flex-wrap items-baseline gap-x-2 rounded-md border bg-white px-3 py-2 text-xs hover:border-violet-300">
                            {it.urgent && <span className="rounded bg-red-600 px-1.5 text-[10px] font-bold text-white">긴급</span>}
                            <b className="text-sm text-slate-800">{it.title}</b>
                            {it.detail && <span className="text-muted-foreground">{it.detail}</span>}
                          </Link>
                        </li>
                      ))}
                      {g.count > g.items.length && <li className="text-xs text-muted-foreground">외 {g.count - g.items.length}건 — <Link to={g.link} className="text-violet-700 hover:underline">전부 보기</Link></li>}
                    </ul>
                  )}
                </section>
              );
            })}
          </div>
        </>
      )}
    </>
  );
}
