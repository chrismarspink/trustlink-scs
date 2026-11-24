import { useEffect, useState } from 'react';
import { DELAYS } from '@/lib/sendDelay';
import { Undo2, Clock3 } from 'lucide-react';
import { adminOutbox, adminOutboxCancel, type OutboxItem } from '@/lib/api';
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
const KIND_KO: Record<string, string> = { custnotify: '고객 통지', devreq: '개발자 요청', digest: '현황 메일', notify: '내부 통보', expiry: '만료 안내' };
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
          {it.error && <span className="w-full text-red-600">{it.error}</span>}
        </div>
      ))}
      {err && <p className="text-xs text-red-600">{err}</p>}
    </div>
  );
}
