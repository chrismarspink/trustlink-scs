import { useEffect, useState } from 'react';
import { DELAYS } from '@/lib/sendDelay';
import { Undo2, Clock3, RotateCw } from 'lucide-react';
import { adminOutbox, adminOutboxCancel, adminOutboxResend, adminMailHold, adminMailHoldApprove, adminMailHoldReject, type OutboxItem, type MailHold } from '@/lib/api';
import { cn } from '@/lib/utils';
import { selectCls } from '@/pages/admin/_ui';

export function DelayPicker({ value, onChange }: { value: number; onChange: (n: number) => void }) {
  return (
    <label className="flex items-center gap-1.5 text-xs text-muted-foreground" title="보내기를 누른 뒤 이 시간 동안 발송함에서 기다리며, 그 사이 '보내기 취소'를 누르면 나가지 않습니다">
      <Clock3 size={13} />보내기 전 대기
      <select className={cn(selectCls, 'h-8 text-xs')} value={value} onChange={(e) => onChange(Number(e.target.value))}>
        {DELAYS.map(([s, l]) => <option key={s} value={s}>{l}</option>)}
      </select>
    </label>
  );
}

const ST: Record<OutboxItem['status'], [string, string]> = {
  pending: ['보내기 대기', 'bg-amber-100 text-amber-800'], sent: ['보냄', 'bg-emerald-100 text-emerald-800'], blocked: ['허용 목록 밖', 'bg-slate-100 text-slate-700'],
  failed: ['실패', 'bg-red-100 text-red-700'], cancelled: ['취소됨', 'bg-slate-200 text-slate-700'], lost: ['재시작으로 못 보냄', 'bg-red-100 text-red-700'],
};
const KIND_KO: Record<string, string> = { custnotify: '고객 통지', devreq: '개발자 요청', digest: '현황 메일', notify: '통보', expiry: '만료 안내' };
const left = (it: OutboxItem, now: number) => Math.max(0, Math.ceil((new Date(it.sendAt).getTime() - now) / 1000));

// 발송함: 기다리는 메일은 남은 시간과 "보내기 취소", 끝난 메일은 결과. ids 를 주면 그것만(방금 보낸 것).
export function OutboxPanel({ ids, kind, refreshKey = 0, onChange, compact }: { ids?: string[]; kind?: OutboxItem['kind']; refreshKey?: number; onChange?: () => void; compact?: boolean }) {
  const [items, setItems] = useState<OutboxItem[]>([]);
  const [now, setNow] = useState(() => Date.now());
  const [err, setErr] = useState('');
  const pending = items.some((x) => x.status === 'pending');
  useEffect(() => {
    let alive = true;
    const load = () => adminOutbox().then((r) => {
      if (!alive) return;
      setItems(r.items.filter((x) => (!ids || ids.includes(x.id)) && (!kind || x.kind === kind)));
    }).catch((e) => alive && setErr(String(e)));
    load();
    const t = setInterval(() => { setNow(Date.now()); load(); }, 2000);
    return () => { alive = false; clearInterval(t); };
  }, [ids?.join(','), kind, refreshKey]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { if (!pending) onChange?.(); }, [pending]); // eslint-disable-line react-hooks/exhaustive-deps
  const cancel = async (id: string) => { setErr(''); try { await adminOutboxCancel(id); setItems((xs) => xs.map((x) => (x.id === id ? { ...x, status: 'cancelled' } : x))); onChange?.(); } catch (e) { setErr(String(e)); } };
  const resend = async (it: OutboxItem) => {
    const why = it.status === 'sent' ? '이미 보낸 메일입니다. 같은 내용이 한 번 더 갑니다.\n\n' : '';
    if (!window.confirm(`${why}다시 보낼까요?\n\n${it.subject}\n→ ${it.recipients.join(', ')}\n\n30초 동안 발송함에서 기다리며, 그 사이 취소할 수 있습니다.`)) return;
    setErr('');
    try { const n = await adminOutboxResend(it.id); setItems((xs) => [n, ...xs.map((x) => (x.id === it.id ? { ...x, canResend: false, resentAs: n.id } : x))]); onChange?.(); } catch (e) { setErr(String(e)); }
  };
  if (!items.length) return err ? <p className="text-xs text-red-600">{err}</p> : null;
  const shown = compact ? items.slice(0, 8) : items;
  return (
    <div className="space-y-1.5">
      {shown.map((it) => (
        <div key={it.id} className={cn('flex flex-wrap items-center gap-2 rounded-md border px-3 py-2 text-xs', it.status === 'pending' && 'border-amber-300 bg-amber-50')}>
          <span className={cn('rounded px-1.5 py-0.5 font-medium', ST[it.status][1])}>{ST[it.status][0]}{it.status === 'pending' && ` · ${left(it, now)}초 뒤`}</span>
          {!kind && <span className="rounded bg-slate-100 px-1.5 py-0.5 text-slate-600">{KIND_KO[it.kind] || it.kind}</span>}
          <span className="min-w-0 flex-1 truncate"><b>{it.label || it.subject}</b> <span className="text-muted-foreground">→ {(it.sent?.length ? it.sent : it.recipients).join(', ')}</span></span>
          <span className="text-muted-foreground">{new Date(it.doneAt || it.createdAt).toLocaleTimeString('ko-KR')}{it.doneBy ? ` · ${it.doneBy}` : ''}</span>
          {it.status === 'pending' && (
            <button onClick={() => cancel(it.id)} className="inline-flex items-center gap-1 rounded-md border border-amber-400 bg-white px-2 py-1 font-semibold text-amber-900 hover:bg-amber-100">
              <Undo2 size={12} />보내기 취소
            </button>
          )}
          {it.canResend && (
            <button onClick={() => resend(it)} title="보관해 둔 내용 그대로 같은 받는 사람에게 다시 보냅니다(최근 메일만 가능)" className={cn('inline-flex items-center gap-1 rounded-md border bg-white px-2 py-1 font-semibold hover:bg-slate-50', it.status !== 'sent' && 'border-red-300 text-red-700')}>
              <RotateCw size={12} />다시 보내기
            </button>
          )}
          {it.resendOf && <span className="rounded bg-sky-100 px-1.5 py-0.5 text-sky-800">다시 보냄</span>}
          {it.resentAs && <span className="text-muted-foreground">다시 보냄 →</span>}
          {it.error && <span className="w-full text-red-600">{it.error}</span>}
        </div>
      ))}
      {err && <p className="text-xs text-red-600">{err}</p>}
    </div>
  );
}

const HOLD_KO: Record<MailHold['kind'], string> = { vex: 'VEX 발행 통보', expiry: '만료 안내' };

// 승인 대기: 고객에게 갈 자동 메일은 여기서 내용을 보고 승인해야 발송함으로 간다. 반려하면 나가지 않는다.
export function HoldPanel({ onChange }: { onChange?: () => void }) {
  const [items, setItems] = useState<MailHold[]>([]);
  const [open, setOpen] = useState('');
  const [delay, setDelay] = useState(30);
  const [err, setErr] = useState('');
  const load = () => adminMailHold().then((r) => setItems(r.items)).catch((e) => setErr(String(e)));
  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t); }, []);
  const approve = async (h: MailHold) => {
    if (!window.confirm(`고객에게 보낼까요?\n\n${h.subject}\n→ ${h.recipients.join(', ')}\n\n발송함에서 ${delay}초 기다리며, 그 사이 취소할 수 있습니다.`)) return;
    setErr(''); try { await adminMailHoldApprove(h.id, delay); await load(); onChange?.(); } catch (e) { setErr(String(e)); }
  };
  const reject = async (h: MailHold) => {
    const reason = window.prompt('보내지 않는 이유(기록에 남습니다)', '');
    if (reason === null) return;
    setErr(''); try { await adminMailHoldReject(h.id, reason); await load(); onChange?.(); } catch (e) { setErr(String(e)); }
  };
  const waiting = items.filter((x) => x.status === 'waiting');
  const done = items.filter((x) => x.status !== 'waiting').slice(0, 5);
  if (!items.length && !err) return null;
  return (
    <div className="mb-5 rounded-lg border border-amber-300 bg-amber-50/60 p-3">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <span className="text-sm font-semibold">고객에게 보낼 메일 — 승인 대기 {waiting.length}건</span>
        <span className="ml-auto"><DelayPicker value={delay} onChange={setDelay} /></span>
      </div>
      {err && <p className="mb-2 text-xs text-red-600">{err}</p>}
      {waiting.length === 0 && <p className="text-xs text-muted-foreground">기다리는 메일이 없습니다.</p>}
      <div className="space-y-1.5">
        {waiting.map((h) => (
          <div key={h.id} className="rounded-md border bg-white px-3 py-2 text-xs">
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded bg-amber-100 px-1.5 py-0.5 font-medium text-amber-800">{HOLD_KO[h.kind]}</span>
              <span className="min-w-0 flex-1"><b>{h.label}</b> <span className="text-muted-foreground">→ {h.recipients.join(', ')}</span></span>
              <span className="text-muted-foreground">{new Date(h.createdAt).toLocaleString('ko-KR')}</span>
              <button type="button" onClick={() => setOpen(open === h.id ? '' : h.id)} aria-expanded={open === h.id} className="h-8 rounded-md border px-2.5 hover:bg-secondary">{open === h.id ? '내용 닫기' : '내용 보기'}</button>
              <button type="button" onClick={() => approve(h)} className="h-8 rounded-md bg-primary px-3 font-semibold text-primary-foreground">승인·발송함으로</button>
              <button type="button" onClick={() => reject(h)} className="h-8 rounded-md border border-red-300 px-2.5 text-red-700 hover:bg-red-50">반려</button>
            </div>
            <div className="mt-1 text-muted-foreground">{h.subject}</div>
            {open === h.id && <iframe src={`/api/mail/hold/${h.id}/preview`} title={`${h.label} 메일 내용`} sandbox="" className="mt-2 block h-[420px] w-full rounded-md border bg-white" />}
          </div>
        ))}
      </div>
      {done.length > 0 && (
        <div className="mt-2 space-y-0.5 text-[11px] text-muted-foreground">
          {done.map((h) => <div key={h.id}>{h.status === 'approved' ? '승인' : '반려'} · {h.label} · {h.doneBy} · {h.doneAt ? new Date(h.doneAt).toLocaleString('ko-KR') : ''}{h.reason ? ` · ${h.reason}` : ''}</div>)}
        </div>
      )}
    </div>
  );
}
