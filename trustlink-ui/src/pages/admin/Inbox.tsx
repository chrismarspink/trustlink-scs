import { AskChip } from '@/components/AskChip';
import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Workflow, ShieldQuestion, Landmark, CalendarClock, Send, ArrowRight, Inbox as InboxIcon, MailCheck } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { adminInbox, adminMailHoldApprove, adminMailHoldReject, type InboxGroup } from '@/lib/api';
import { PageHeader, Alert, Loading } from './_ui';
import { cn } from '@/lib/utils';
import { withVT } from '@/lib/vt';

// 관리 › 승인 대기함: 신호 → 영향 → **결정** → 전달 → 기록 중 사람이 하는 "결정"을 한 곳에.
// 흩어진 대기열(자동 대응 승인·VEX 판단·규제 후보·만료·발송 대기)을 모아 보여 주고 원래 화면으로 보낸다.

const META: Record<InboxGroup['key'], { icon: LucideIcon; cls: string; hint: string }> = {
  auto: { icon: Workflow, cls: 'border-amber-300 bg-amber-50/60', hint: '자동 대응이 만든 고객 통지·개발자 수정 요청 — 승인해야 나갑니다' },
  vex: { icon: ShieldQuestion, cls: 'border-red-200 bg-red-50/40', hint: 'KEV·치명 취약점의 영향 판단 — VEX 로 기록' },
  reg: { icon: Landmark, cls: 'border-teal-200 bg-teal-50/40', hint: '규제 탐색이 찾은 새 후보 — 카탈로그에 채택할지' },
  expiry: { icon: CalendarClock, cls: 'border-orange-200 bg-orange-50/40', hint: '30일 안에 끝나는 유지보수·라이선스·EOS' },
  hold: { icon: MailCheck, cls: 'border-amber-300 bg-amber-50/60', hint: '고객에게 갈 자동 메일(VEX 발행 통보·만료 안내) — 승인해야 나갑니다' },
  outbox: { icon: Send, cls: 'border-violet-200 bg-violet-50/40', hint: '보내기 전 대기 중 — 지금 취소할 수 있습니다' },
};

// 한 건씩 보기: 결정할 일을 급한 순으로 하나씩 크게 보여 준다. 고객에게 갈 메일은 여기서 바로 승인·반려하고,
// 받는 사람을 골라야 하는 일(자동 대응 승인 등)은 원래 화면을 열어 결정한다. "나중에"는 건너뛸 뿐 아무것도 바꾸지 않는다.
const ORDER: InboxGroup['key'][] = ['auto', 'hold', 'reg', 'expiry', 'outbox'];
const OPEN_LABEL: Record<InboxGroup['key'], string> = { auto: '받는 사람 확인하고 결정', hold: '', reg: '후보 살펴보기', expiry: '고객 등록부에서 확인', outbox: '발송함에서 취소·확인', vex: '판정하러 가기' };

function Triage({ groups, onDone }: { groups: InboxGroup[]; onDone: () => void }) {
  // 처음 연 때의 목록을 그대로 쓴다(보는 도중 순서가 바뀌지 않게)
  const items = useMemo(() => ORDER.flatMap((k) => (groups.find((g) => g.key === k)?.items || []).map((it) => ({ it, g: groups.find((x) => x.key === k)! })))
    .sort((a, b) => Number(!!b.it.urgent) - Number(!!a.it.urgent)), []); // eslint-disable-line react-hooks/exhaustive-deps
  const [i, setI] = useState(0);
  const [log, setLog] = useState<{ title: string; what: string }[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [show, setShow] = useState(false);
  const cur = items[i];
  const next = (what: string) => withVT(() => { setLog((l) => [{ title: cur.it.title, what }, ...l].slice(0, 6)); setI(i + 1); setShow(false); setErr(''); });
  const act = async (what: string, fn: () => Promise<unknown>) => { setBusy(true); setErr(''); try { await fn(); next(what); onDone(); } catch (e) { setErr(String(e).replace(/^(Api)?Error:\s*(\d{3}\s*)?/, '')); } setBusy(false); };
  const pct = items.length ? Math.round((Math.min(i, items.length) / items.length) * 100) : 100;
  const head = (
    <div className="mb-4 flex items-center gap-3">
      <div className="h-2.5 flex-1 rounded-full bg-secondary" role="img" aria-label={`${items.length}건 가운데 ${Math.min(i, items.length)}건 봄`}><div className="h-2.5 rounded-full bg-violet-600 transition-all" style={{ width: `${pct}%` }} /></div>
      <b className="text-sm tabular-nums">{Math.min(i, items.length)} / {items.length}</b>
    </div>
  );
  if (!cur) {
    return (
      <>
        {head}
        <div className="rounded-xl border bg-card p-10 text-center">
          <p className="text-xl font-bold">{items.length ? '한 번씩 모두 봤습니다' : '지금 결정할 일이 없습니다'}</p>
          <p className="mt-2 text-sm text-muted-foreground">{log.length ? log.map((l) => l.what).join(' · ') : 'VEX 판단 대기는 건수가 많아 "VEX 판단" 화면에서 따로 봅니다.'}</p>
          {items.length > 0 && <button type="button" onClick={() => { setI(0); setLog([]); }} className="mt-4 h-11 rounded-md border px-4 text-sm hover:bg-secondary">처음부터 다시 보기</button>}
        </div>
      </>
    );
  }
  const m = META[cur.g.key];
  const hold = cur.g.key === 'hold' && !!cur.it.ref;
  return (
    <>
      {head}
      <div className="grid gap-4 lg:grid-cols-[3fr_2fr]">
        <div className="vt-card flex flex-col gap-4 rounded-xl border bg-card p-5 lg:p-7">
          <div className="flex flex-wrap gap-2 text-xs">
            {cur.it.urgent && <span className="rounded bg-red-600 px-2 py-1 font-bold text-white">긴급</span>}
            <span className="inline-flex items-center gap-1 rounded bg-secondary px-2 py-1"><m.icon size={13} /> {cur.g.label}</span>
          </div>
          <h2 className="text-xl font-bold leading-snug lg:text-2xl">{cur.it.title}</h2>
          {cur.it.detail && <p className="text-sm leading-relaxed text-muted-foreground lg:text-base">{cur.it.detail}</p>}
          <p className="text-xs text-muted-foreground">{m.hint}</p>
          {hold && show && <iframe src={`/api/mail/hold/${cur.it.ref}/preview`} title="보낼 메일 내용" sandbox="" className="block h-[360px] w-full rounded-md border bg-white" />}
          {err && <p className="text-sm text-red-700" role="alert">{err}</p>}
          <div className="mt-auto flex flex-wrap gap-2">
            {hold ? (
              <>
                <button type="button" disabled={busy} onClick={() => act('승인', () => adminMailHoldApprove(cur.it.ref!, 30))} className="h-12 flex-[2] rounded-lg bg-primary px-4 text-base font-bold text-primary-foreground disabled:opacity-60">승인 — 발송함으로</button>
                <button type="button" disabled={busy} onClick={() => { const r = window.prompt('보내지 않는 이유(기록에 남습니다)', ''); if (r !== null) act('반려', () => adminMailHoldReject(cur.it.ref!, r)); }} className="h-12 flex-1 rounded-lg border-2 border-red-600 px-4 text-base font-bold text-red-700 disabled:opacity-60">반려</button>
                <button type="button" onClick={() => setShow(!show)} aria-expanded={show} className="h-12 rounded-lg border px-4 text-sm hover:bg-secondary">{show ? '내용 닫기' : '내용 보기'}</button>
              </>
            ) : (
              <Link to={cur.it.link} className="inline-flex h-12 flex-[2] items-center justify-center gap-1.5 rounded-lg bg-primary px-4 text-base font-bold text-primary-foreground">{OPEN_LABEL[cur.g.key]} <ArrowRight size={16} /></Link>
            )}
            <button type="button" onClick={() => next('나중에')} className="h-12 flex-1 rounded-lg border px-4 text-base hover:bg-secondary">나중에</button>
          </div>
          {hold && <p className="text-xs text-muted-foreground">승인하면 발송함에서 30초 기다렸다 나가며, 그 사이 취소할 수 있습니다.</p>}
        </div>
        <div className="rounded-xl border bg-card p-5">
          <div className="mb-2 text-xs font-semibold text-muted-foreground">방금 본 것</div>
          {log.length === 0 ? <p className="text-sm text-muted-foreground">아직 없습니다.</p> : (
            <ul className="space-y-2 text-sm">{log.map((l, k) => <li key={k} className="flex justify-between gap-3 border-t pt-2 first:border-0 first:pt-0"><span className="min-w-0 truncate">{l.title}</span><b className="whitespace-nowrap">{l.what}</b></li>)}</ul>
          )}
        </div>
      </div>
    </>
  );
}

export default function Inbox() {
  const [d, setD] = useState<{ groups: InboxGroup[]; decisions: number; generated: string } | null>(null);
  const [err, setErr] = useState('');
  const [one, setOne] = useState(false); // 한 건씩 보기
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
      {d && (
        <div className="mb-4 inline-flex rounded-lg border p-0.5 text-sm" role="group" aria-label="보는 방식">
          <button type="button" aria-pressed={!one} onClick={() => setOne(false)} className={cn('h-9 rounded-md px-3', !one && 'bg-primary font-semibold text-primary-foreground')}>묶음으로 보기</button>
          <button type="button" aria-pressed={one} onClick={() => setOne(true)} className={cn('h-9 rounded-md px-3', one && 'bg-primary font-semibold text-primary-foreground')}>한 건씩 보기</button>
        </div>
      )}
      {!d ? <Loading /> : one ? <Triage groups={d.groups} onDone={() => adminInbox().then(setD).catch(() => {})} /> : (
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
