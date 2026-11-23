import { Fragment, useCallback, useEffect, useState } from 'react';
import { Search, ChevronRight, ChevronDown, RotateCcw } from 'lucide-react';
import { adminLogs, type LogsResult, type LogsQuery, type LogEntry } from '@/lib/api';
import { Button, Input } from '@/components/ui/primitives';
import { Busy } from '@/components/Progress';
import { cn } from '@/lib/utils';
import { PageTitle, Alert } from './_ui';

// 관리 › 로그: 날짜별로 묶어 보여 주고, 검색어(기본) 또는 이벤트·레벨(자세히)로 찾는다.
// 서버는 파일 끝에서부터 필요한 만큼만 읽는다 — "더 오래된 로그"는 이어 읽기(cursor).

const LEVELS = [
  { key: 'error', label: '오류', cls: 'bg-red-100 text-red-700' },
  { key: 'warn', label: '경고', cls: 'bg-amber-100 text-amber-800' },
  { key: 'info', label: '정보', cls: 'bg-slate-100 text-slate-600' },
  { key: 'debug', label: '디버그', cls: 'bg-slate-50 text-slate-500' },
];
const levelCls = (l: string) => LEVELS.find((x) => x.key === l)?.cls || 'bg-slate-100 text-slate-600';
const levelLabel = (l: string) => LEVELS.find((x) => x.key === l)?.label || l || '—';
const EVENT_CLS: Record<string, string> = {
  upload: 'text-violet-700', download: 'text-sky-700', delete: 'text-orange-700', authfail: 'text-red-700',
  error: 'text-red-700', request: 'text-slate-600', system: 'text-slate-500', other: 'text-slate-500',
};

const kstDate = (t: string) => (t ? new Date(t).toLocaleDateString('sv-SE', { timeZone: 'Asia/Seoul' }) : '');
const dayTitle = (d: string) => {
  if (!d) return '시각 없음';
  const dt = new Date(d + 'T00:00:00+09:00');
  const today = kstDate(new Date().toISOString());
  const yest = kstDate(new Date(Date.now() - 864e5).toISOString());
  const w = dt.toLocaleDateString('ko-KR', { timeZone: 'Asia/Seoul', year: 'numeric', month: 'long', day: 'numeric', weekday: 'short' });
  return d === today ? `오늘 · ${w}` : d === yest ? `어제 · ${w}` : w;
};
const hms = (t: string) => (t ? new Date(t).toLocaleTimeString('en-GB', { timeZone: 'Asia/Seoul', hour12: false }) : '');

function summary(e: LogEntry) {
  if (e.method) return `${e.method} ${e.path} → ${e.status}${e.latency && e.latency !== '0s' ? ` (${e.latency})` : ''}`;
  return e.msg + (e.err ? ` — ${e.err}` : '');
}

function Row({ e, evLabel }: { e: LogEntry; evLabel: string }) {
  const [open, setOpen] = useState(false);
  let pretty = e.raw;
  if (open) { try { pretty = JSON.stringify(JSON.parse(e.raw), null, 2); } catch { /* JSON 아님 */ } }
  return (
    <div className="border-b last:border-0">
      <button onClick={() => setOpen(!open)} className="flex w-full items-start gap-2 px-3 py-1.5 text-left text-xs hover:bg-slate-50">
        {open ? <ChevronDown size={14} className="mt-px shrink-0 text-slate-400" /> : <ChevronRight size={14} className="mt-px shrink-0 text-slate-400" />}
        <span className="w-16 shrink-0 font-mono tabular-nums text-slate-500">{hms(e.time)}</span>
        <span className={cn('w-12 shrink-0 rounded px-1 text-center text-[11px] font-medium', levelCls(e.level))}>{levelLabel(e.level)}</span>
        <span className={cn('w-24 shrink-0 truncate font-medium', EVENT_CLS[e.event])}>{evLabel}</span>
        <span className="w-20 shrink-0 truncate text-slate-700" title={e.user}>{e.user || '—'}</span>
        <span className="min-w-0 flex-1 break-all font-mono text-slate-800">{summary(e)}</span>
      </button>
      {open && <pre className="mx-3 mb-2 overflow-x-auto rounded bg-slate-900 p-3 text-[11px] leading-relaxed text-slate-100">{pretty}</pre>}
    </div>
  );
}

function Chip({ on, onClick, children }: { on: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button onClick={onClick} className={cn('rounded-full border px-2.5 py-1 text-xs transition',
      on ? 'border-violet-500 bg-violet-600 text-white' : 'bg-white text-slate-700 hover:border-violet-300')}>
      {children}
    </button>
  );
}

export default function Logs() {
  const [mode, setMode] = useState<'basic' | 'event'>('basic');
  const [q, setQ] = useState('');
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [levels, setLevels] = useState<string[]>([]);
  const [event, setEvent] = useState('');
  const [user, setUser] = useState('');
  const [all, setAll] = useState(false);
  const [applied, setApplied] = useState<LogsQuery>({});
  const [cursors, setCursors] = useState<number[]>([]); // 지나온 쪽의 시작 위치(더 최근으로 돌아가기)
  const [res, setRes] = useState<LogsResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  const run = useCallback(async (query: LogsQuery, cursor?: number) => {
    setBusy(true); setErr('');
    try { setRes(await adminLogs({ ...query, cursor })); } catch (e) { setErr(String(e)); }
    setBusy(false);
  }, []);
  useEffect(() => { adminLogs({}).then(setRes).catch((e) => setErr(String(e))); }, []);

  const search = () => {
    const query: LogsQuery = mode === 'basic'
      ? { q, from, to: to || from, all }
      : { q, from, to: to || from, all, levels, event, user };
    setApplied(query); setCursors([]); run(query);
  };
  const reset = () => {
    setQ(''); setFrom(''); setTo(''); setLevels([]); setEvent(''); setUser(''); setAll(false);
    setApplied({}); setCursors([]); run({});
  };
  const older = () => { if (!res) return; setCursors([...cursors, res.next]); run(applied, res.next); };
  const newer = () => {
    const c = cursors.slice(0, -1);
    setCursors(c);
    run(applied, c.length ? c[c.length - 1] : undefined);
  };

  const evLabel = (k: string) => res?.events.find((x) => x.Key === k)?.Label || k;
  // 날짜별로 묶기(최신순 유지)
  const groups: { day: string; rows: LogEntry[] }[] = [];
  for (const e of res?.entries || []) {
    const d = kstDate(e.time);
    if (!groups.length || groups[groups.length - 1].day !== d) groups.push({ day: d, rows: [] });
    groups[groups.length - 1].rows.push(e);
  }
  const minDay = kstDate(res?.firstTime || ''), maxDay = kstDate(res?.lastTime || '');
  const countNote = res ? (res.countsComplete ? '선택한 날짜 전체' : `최근 ${res.scope.toLocaleString()}줄 기준`) : '';
  const toggleLevel = (k: string) => setLevels(levels.includes(k) ? levels.filter((x) => x !== k) : [...levels, k]);

  return (
    <>
      <PageTitle>로그</PageTitle>
      <div className="mb-3 flex gap-1 border-b">
        {([['basic', '최근 로그 · 검색'], ['event', '이벤트·레벨로 찾기']] as const).map(([k, l]) => (
          <button key={k} onClick={() => setMode(k)}
            className={cn('-mb-px border-b-2 px-4 py-2 text-sm', mode === k ? 'border-foreground font-medium' : 'border-transparent text-muted-foreground hover:text-foreground')}>
            {l}
          </button>
        ))}
      </div>

      <div className="mb-3 space-y-3 rounded-lg border bg-card p-3">
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search size={15} className="absolute left-2.5 top-2.5 text-muted-foreground" />
            <Input className="w-56 pl-8" placeholder="검색어(경로·메시지·IP 등)" value={q}
              onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && search()} />
          </div>
          <label className="flex items-center gap-1 text-xs text-slate-600">날짜
            <Input type="date" className="w-36" value={from} min={minDay} max={maxDay} onChange={(e) => setFrom(e.target.value)} />
          </label>
          {mode === 'event' && (
            <label className="flex items-center gap-1 text-xs text-slate-600">~
              <Input type="date" className="w-36" value={to} min={from || minDay} max={maxDay} onChange={(e) => setTo(e.target.value)} />
            </label>
          )}
          {mode === 'event' && <Input className="w-32" placeholder="사용자" value={user} onChange={(e) => setUser(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && search()} />}
          <label className="flex items-center gap-1.5 text-xs text-slate-600" title="BFF 가 주기적으로 zot 를 조회하는 기록(svc-bff)과 반복 메시지 — 전체의 대부분">
            <input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} /> 내부 호출도 보기
          </label>
          <Button size="sm" onClick={() => search()} disabled={busy}>찾기</Button>
          <Button size="sm" variant="ghost" onClick={reset} disabled={busy}><RotateCcw size={13} /> 처음으로</Button>
        </div>

        {mode === 'event' && (
          <>
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="w-10 text-xs text-muted-foreground">이벤트</span>
              <Chip on={event === ''} onClick={() => setEvent('')}>전체</Chip>
              {(res?.events || []).map((x) => (
                <Chip key={x.Key} on={event === x.Key} onClick={() => setEvent(x.Key)}>
                  {x.Label}{res?.byEvent[x.Key] ? <span className="ml-1 opacity-70">{res.byEvent[x.Key].toLocaleString()}</span> : null}
                </Chip>
              ))}
            </div>
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="w-10 text-xs text-muted-foreground">레벨</span>
              {LEVELS.map((x) => (
                <Chip key={x.key} on={levels.includes(x.key)} onClick={() => toggleLevel(x.key)}>
                  {x.label}{res?.byLevel[x.key] ? <span className="ml-1 opacity-70">{res.byLevel[x.key].toLocaleString()}</span> : null}
                </Chip>
              ))}
              <span className="text-xs text-muted-foreground">· 숫자는 {countNote}(필터 전) · 고른 뒤 찾기</span>
            </div>
          </>
        )}
      </div>

      {res && (
        <div className="mb-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
          <span>기록 범위 {minDay} ~ {maxDay}</span>
          <span>이 쪽 {res.entries.length}건</span>
          {mode === 'basic' && Object.keys(res.byLevel).length > 0 && (
            <span>{countNote}: {LEVELS.filter((l) => res.byLevel[l.key]).map((l) => `${l.label} ${res.byLevel[l.key].toLocaleString()}`).join(' · ')}</span>
          )}
          <span>응답 {res.ms < 1000 ? `${res.ms}ms` : `${(res.ms / 1000).toFixed(1)}초`}</span>
        </div>
      )}
      <Busy active={busy} label="로그를 찾는 중" className="mb-2" />
      {err && <Alert tone="crit">오류: {err}</Alert>}
      {res?.error && <Alert tone="warn">{res.error}</Alert>}
      {res?.partial && <Alert tone="warn">조건에 맞는 로그가 드물어 일부만 찾았습니다 — "더 오래된 로그"로 이어서 찾을 수 있습니다.</Alert>}

      <div className="overflow-hidden rounded-lg border bg-card">
        {!res ? <p className="p-4 text-sm text-muted-foreground">불러오는 중…</p>
          : groups.length === 0 ? <p className="p-4 text-sm text-muted-foreground">조건에 맞는 로그가 없습니다.</p>
            : groups.map((g) => (
              <Fragment key={g.day}>
                <div className="sticky top-0 z-10 flex items-baseline gap-2 border-b bg-slate-100/95 px-3 py-1.5 text-sm font-semibold backdrop-blur">
                  {dayTitle(g.day)} <span className="text-xs font-normal text-muted-foreground">{g.rows.length}건</span>
                </div>
                {g.rows.map((e) => <Row key={e.off} e={e} evLabel={evLabel(e.event)} />)}
              </Fragment>
            ))}
      </div>

      <div className="mt-3 flex gap-2">
        <Button size="sm" variant="outline" disabled={busy || cursors.length === 0} onClick={newer}>← 더 최근 로그</Button>
        <Button size="sm" variant="outline" disabled={busy || !res?.more} onClick={older}>더 오래된 로그 →</Button>
      </div>
    </>
  );
}
