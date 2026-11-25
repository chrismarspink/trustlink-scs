import { useCallback, useEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import { Link } from 'react-router-dom';
import { X, Zap } from 'lucide-react';
import { adminMailHoldApprove, agentGet, agentPrefs, agentRun, agentScheduleAdd, agentScheduleDelete, agentScheduleSet, agentUndo, type AgentData, type AgentTask } from '@/lib/api';
import { cn } from '@/lib/utils';

// 에이전트: 로그인한 사람의 권한에 맞는 할 일을 모아 제안하고, 고르면 대신 실행한다.
//   바로 실행(되돌릴 수 있음) · 승인 필요(고객에게 나감 — 내용을 보여 주고 기존 승인을 부른다) · 직접 처리(화면으로 안내)
// 새 처리 경로는 없다. 기존 화면은 그대로이고, 여기서 건너뛴 일은 원래 화면에 남는다.

const GRADE: Record<AgentTask['grade'], string> = { run: '바로 실행 · 되돌릴 수 있음', approve: '승인 필요 · 고객에게 나감', go: '직접 처리 · 화면으로 이동' };
const ROLE: Record<string, string> = { admin: '관리자 — 모든 작업이 보입니다.', vex: 'VEX 담당 — 취약점 판단 작업이 보입니다.', customer: '고객 — 내 제품에서 조치할 것이 보입니다.', user: '볼 수 있는 것만 보입니다.' };
const DAYS = ['일', '월', '화', '수', '목', '금', '토'];
const HOLD_DELAY = 30; // 승인 뒤 발송함에서 기다리는 시간(초) — 승인 대기함과 같다
const when = (iso?: string) => (iso ? new Date(iso).toLocaleString('ko-KR', { timeZone: 'Asia/Seoul', month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false }) : '');
const skipped = (): string[] => { try { return JSON.parse(sessionStorage.getItem('tl-agent-skip') || '[]'); } catch { return []; } };

export function useAgent() {
  const [d, setD] = useState<AgentData | null>(null);
  const load = useCallback(() => agentGet().then(setD).catch(() => setD(null)), []);
  useEffect(() => { load(); }, [load]);
  return { d, load };
}

export function AgentView({ d, load, onNavigate }: { d: AgentData; load: () => void; onNavigate?: () => void }) {
  const [tab, setTab] = useState<'todo' | 'sched' | 'log'>('todo');
  const [skip, setSkip] = useState<string[]>(skipped);
  const [sel, setSel] = useState<Record<string, boolean>>({});
  const [openHold, setOpenHold] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');
  const [err, setErr] = useState('');
  const [form, setForm] = useState({ recipe: '', repeat: 'daily', time: '08:30', weekday: 1 });

  const tasks = d.tasks.filter((t) => !skip.includes(t.id));
  const picked = tasks.filter((t) => t.grade === 'run' && sel[t.id]);
  const act = async (fn: () => Promise<string>) => {
    setBusy(true); setErr(''); setMsg('');
    try { setMsg(await fn()); } catch (e) { setErr(String(e)); }
    setBusy(false); load();
  };
  const run = (ids: string[]) => act(async () => {
    const r = await agentRun(ids);
    setSel({});
    const bad = r.results.filter((x) => !x.ok);
    return r.results.length === 1 ? r.results[0].result : `${r.results.length - bad.length}건을 실행했습니다.` + (bad.length ? ` ${bad.length}건은 실행하지 못했습니다 — 실행 기록에서 이유를 볼 수 있습니다.` : ' 실행 기록에서 확인하고 되돌릴 수 있습니다.');
  });
  const doSkip = (id: string) => {
    const next = [...skip, id]; setSkip(next); setMsg('건너뛰었습니다. 원래 화면에는 그대로 남아 있습니다.');
    try { sessionStorage.setItem('tl-agent-skip', JSON.stringify(next)); } catch { /* 저장 못 해도 이번 화면에서는 숨긴다 */ }
  };
  const canSched = d.recipes.length > 0 || d.schedules.length > 0;
  const btn = 'h-9 rounded-md border px-3 text-sm hover:bg-secondary disabled:opacity-50';

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <p className="px-4 pb-2 text-[13px] text-muted-foreground">{d.user} · {ROLE[d.role] || ROLE.user}</p>
      <div className="flex gap-5 border-b px-4" role="tablist">
        {([['todo', `할 일 제안${tasks.length ? ' ' + tasks.length : ''}`], ...(canSched ? [['sched', '예약']] : []), ['log', '실행 기록']] as [typeof tab, string][]).map(([k, l]) => (
          <button key={k} type="button" role="tab" aria-selected={tab === k} onClick={() => { setTab(k); setMsg(''); setErr(''); }} className={cn('py-2 text-sm', tab === k ? 'font-bold text-foreground' : 'text-muted-foreground')}>{l}</button>
        ))}
      </div>
      <div className="min-h-0 flex-1 overflow-auto px-4 py-3">
        {msg && <div className="mb-3 rounded-lg bg-primary/10 px-3 py-2 text-[13px]" role="status">{msg}</div>}
        {err && <div className="mb-3 rounded-lg bg-red-50 px-3 py-2 text-[13px] text-red-700" role="alert">{err}</div>}

        {tab === 'todo' && (
          <>
            {tasks.length === 0 && <div className="rounded-lg border bg-card p-4 text-sm text-muted-foreground">지금 제안할 일이 없습니다. 새 자료나 알림이 생기면 여기에 표시됩니다.</div>}
            {(['run', 'approve', 'go'] as const).map((g) => {
              const xs = tasks.filter((t) => t.grade === g);
              if (!xs.length) return null;
              return (
                <section key={g}>
                  <h3 className="mb-1.5 mt-3 text-xs font-bold text-muted-foreground first:mt-0">{GRADE[g]}</h3>
                  {xs.map((t) => (
                    <div key={t.id} className="mb-2.5 rounded-lg border bg-card p-3">
                      <div className="flex items-start gap-2.5">
                        {g === 'run' && <input type="checkbox" checked={!!sel[t.id]} onChange={(e) => setSel({ ...sel, [t.id]: e.target.checked })} aria-label={t.title} className="mt-1 h-4 w-4 accent-[hsl(var(--primary))]" />}
                        <div className="min-w-0 flex-1">
                          <div className="font-semibold">{t.urgent && <span className="mr-1.5 rounded bg-red-100 px-1.5 py-0.5 text-[11px] font-bold text-red-700">급함</span>}{t.title}</div>
                          {t.why && <div className="mt-0.5 text-[13px] text-muted-foreground">{t.why}</div>}
                          {t.steps.length > 0 && <ol className="mt-2 list-decimal pl-5 text-[13px]">{t.steps.map((s, i) => <li key={i}>{s}</li>)}</ol>}
                          {g === 'approve' && openHold === t.id && (
                            <>
                              <iframe src={`/api/mail/hold/${t.ref}/preview`} title={`${t.title} 메일 내용`} sandbox="" className="mt-2 block h-[360px] w-full rounded-md border bg-white" />
                              <button type="button" disabled={busy} onClick={() => act(async () => { await adminMailHoldApprove(t.ref!, HOLD_DELAY); setOpenHold(''); return `승인했습니다. ${HOLD_DELAY}초 뒤 발송되며, 그 사이 발송함에서 취소할 수 있습니다.`; })}
                                className="mt-2 h-10 w-full rounded-md bg-primary px-3 text-sm font-bold text-primary-foreground disabled:opacity-60">승인 — 발송함으로({HOLD_DELAY}초 뒤 발송)</button>
                            </>
                          )}
                          <div className="mt-2.5 flex flex-wrap gap-1.5">
                            {g === 'run' && <button type="button" disabled={busy} onClick={() => run([t.id])} className={btn}>지금 실행</button>}
                            {g === 'approve' && <button type="button" onClick={() => setOpenHold(openHold === t.id ? '' : t.id)} className={btn}>{openHold === t.id ? '내용 접기' : '내용 보고 승인'}</button>}
                            {t.link && <Link to={t.link} onClick={onNavigate} className={cn(btn, 'inline-flex items-center')}>화면으로 이동</Link>}
                            <button type="button" onClick={() => doSkip(t.id)} className={cn(btn, 'text-muted-foreground')}>건너뛰기</button>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </section>
              );
            })}
            {!d.ai && (d.role === 'admin' || d.role === 'vex') && <p className="mt-2 text-xs text-muted-foreground">AI 연결이 꺼져 있어 판단 초안 준비는 제안하지 않습니다.</p>}
          </>
        )}

        {tab === 'sched' && (
          <>
            {d.schedules.length === 0 && <div className="mb-3 rounded-lg border bg-card p-4 text-sm text-muted-foreground">예약한 작업이 없습니다.</div>}
            {d.schedules.map((x) => {
              const rc = d.recipes.find((r) => r.key === x.recipe);
              return (
                <div key={x.id} className="mb-2.5 rounded-lg border bg-card p-3">
                  <div className="flex items-start gap-2">
                    <div className="min-w-0 flex-1 font-semibold">{rc?.title || x.recipe}</div>
                    <button type="button" disabled={busy} aria-pressed={x.on} onClick={() => act(async () => { await agentScheduleSet(x.id, !x.on); return x.on ? '예약을 껐습니다.' : '예약을 켰습니다.'; })}
                      className={cn('h-7 shrink-0 rounded-full border px-3 text-xs', x.on && 'border-transparent bg-emerald-100 font-semibold text-emerald-800')}>{x.on ? '켜짐' : '꺼짐'}</button>
                  </div>
                  <dl className="mt-1.5 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-[13px]">
                    <dt className="text-muted-foreground">언제</dt><dd>{x.repeat === 'daily' ? '매일' : x.repeat === 'weekly' ? `매주 ${DAYS[x.weekday || 0]}요일` : '한 번'} {x.time} (한국 시간)</dd>
                    <dt className="text-muted-foreground">다음 실행</dt><dd>{x.on ? when(x.next) : '꺼져 있음'}</dd>
                    {rc && <><dt className="text-muted-foreground">결과</dt><dd>{rc.out}</dd></>}
                    <dt className="text-muted-foreground">예약한 사람</dt><dd>{x.owner} — 실행할 때 이 사람의 권한을 다시 확인합니다</dd>
                    {x.last && <><dt className="text-muted-foreground">지난 실행</dt><dd>{when(x.last)} · {x.lastMsg}</dd></>}
                  </dl>
                  <button type="button" disabled={busy} onClick={() => act(async () => { await agentScheduleDelete(x.id); return '예약을 지웠습니다.'; })} className={cn(btn, 'mt-2 text-muted-foreground')}>예약 지우기</button>
                </div>
              );
            })}
            {d.recipes.length > 0 && (
              <form className="rounded-lg border border-dashed p-3 text-sm" onSubmit={(e) => { e.preventDefault(); act(async () => { await agentScheduleAdd({ ...form, recipe: form.recipe || d.recipes[0].key }); return '예약했습니다.'; }); }}>
                <div className="mb-2 font-semibold">예약 추가</div>
                <label className="block text-[13px] text-muted-foreground" htmlFor="ag-recipe">작업</label>
                <select id="ag-recipe" value={form.recipe || d.recipes[0].key} onChange={(e) => setForm({ ...form, recipe: e.target.value })} className="mb-2 h-9 w-full rounded-md border bg-background px-2">
                  {d.recipes.map((r) => <option key={r.key} value={r.key}>{r.title}</option>)}
                </select>
                <div className="flex flex-wrap items-end gap-2">
                  <div><label className="block text-[13px] text-muted-foreground" htmlFor="ag-repeat">반복</label>
                    <select id="ag-repeat" value={form.repeat} onChange={(e) => setForm({ ...form, repeat: e.target.value })} className="h-9 rounded-md border bg-background px-2"><option value="daily">매일</option><option value="weekly">매주</option><option value="once">한 번</option></select></div>
                  {form.repeat === 'weekly' && <div><label className="block text-[13px] text-muted-foreground" htmlFor="ag-day">요일</label>
                    <select id="ag-day" value={form.weekday} onChange={(e) => setForm({ ...form, weekday: Number(e.target.value) })} className="h-9 rounded-md border bg-background px-2">{DAYS.map((x, i) => <option key={x} value={i}>{x}요일</option>)}</select></div>}
                  <div><label className="block text-[13px] text-muted-foreground" htmlFor="ag-time">시각(한국 시간)</label>
                    <input id="ag-time" type="time" required value={form.time} onChange={(e) => setForm({ ...form, time: e.target.value })} className="h-9 rounded-md border bg-background px-2" /></div>
                  <button type="submit" disabled={busy} className="h-9 rounded-md bg-primary px-4 font-semibold text-primary-foreground disabled:opacity-60">예약</button>
                </div>
                <p className="mt-2 text-xs text-muted-foreground">{d.recipes.find((r) => r.key === (form.recipe || d.recipes[0].key))?.out} 고객에게 나가는 것은 예약으로 돌아도 승인 대기에서 멈춥니다.</p>
              </form>
            )}
          </>
        )}

        {tab === 'log' && (
          <>
            {d.log.length === 0 && <div className="rounded-lg border bg-card p-4 text-sm text-muted-foreground">에이전트로 실행한 기록이 없습니다.</div>}
            {d.log.map((x) => (
              <div key={x.id} className="mb-2.5 rounded-lg border bg-card p-3">
                <div className="font-semibold">{!x.ok && <span className="mr-1.5 rounded bg-red-100 px-1.5 py-0.5 text-[11px] font-bold text-red-700">실패</span>}{x.title}</div>
                <div className="mt-0.5 text-[13px] text-muted-foreground">{when(x.at)} · {x.by === 'schedule' ? `예약(${x.actor})` : x.actor}</div>
                <div className="mt-1 text-[13px]">{x.result}</div>
                {x.undone ? <div className="mt-2 text-xs text-muted-foreground">{when(x.undone)}에 되돌렸습니다.</div>
                  : !!x.undo && x.ok && <button type="button" disabled={busy} onClick={() => act(async () => (await agentUndo(x.id)).result)} className={cn(btn, 'mt-2')}>되돌리기</button>}
              </div>
            ))}
            <p className="text-xs text-muted-foreground">메일 승인과 발송은 발송함에, 모든 실행은 로그에도 남습니다. 이미 발송된 메일과 발행한 VEX는 되돌릴 수 없습니다.</p>
          </>
        )}
      </div>
      <div className="border-t bg-card px-4 py-2.5">
        {tab === 'todo' && tasks.some((t) => t.grade === 'run') && (
          <div className="mb-2 flex items-center gap-3">
            <span className="min-w-0 flex-1 text-[13px] text-muted-foreground">{picked.length ? `바로 실행 ${picked.length}건` : '실행할 것을 고르세요'}</span>
            <button type="button" disabled={busy || !picked.length} onClick={() => run(picked.map((t) => t.id))} className="h-9 rounded-md bg-primary px-4 text-sm font-semibold text-primary-foreground disabled:opacity-50">선택한 것 실행</button>
          </div>
        )}
        <label className="flex items-center gap-2 text-[13px] text-muted-foreground">
          <input type="checkbox" checked={d.prefs.autoOpen} onChange={(e) => { agentPrefs(e.target.checked).then(load).catch(() => {}); }} className="h-4 w-4 accent-[hsl(var(--primary))]" />
          접속하면 이 화면을 자동으로 엽니다
        </label>
      </div>
    </div>
  );
}

// 상단 버튼 + 오른쪽 패널. 로그인하지 않았으면 보이지 않는다.
export function AgentButton() {
  const { d, load } = useAgent();
  const [open, setOpen] = useState(false);
  useEffect(() => { // 설정을 켠 사람은 접속했을 때 한 번 자동으로 연다(같은 창에서 다시 열지는 않는다)
    if (!d?.prefs.autoOpen) return;
    try { if (sessionStorage.getItem('tl-agent-auto')) return; sessionStorage.setItem('tl-agent-auto', '1'); } catch { return; }
    setOpen(true);
  }, [d?.prefs.autoOpen]);
  useEffect(() => { if (open) load(); }, [open, load]);
  if (!d) return null;
  const n = d.tasks.filter((t) => !skipped().includes(t.id)).length;
  return (
    <>
      <button type="button" onClick={() => setOpen(true)} title="에이전트 — 할 일 제안과 실행" className="inline-flex h-9 items-center gap-1.5 rounded-md border border-primary/40 px-2.5 text-sm font-semibold text-primary hover:bg-primary/10">
        <Zap size={16} /><span className="hidden sm:inline">에이전트</span>
        {n > 0 && <span className="flex h-[18px] min-w-[18px] items-center justify-center rounded-full bg-primary px-1 text-[11px] font-bold text-primary-foreground">{n > 99 ? '99+' : n}</span>}
      </button>
      {open && createPortal( // 상단 바는 휴대폰에서 겹침 기준이 따로라, 패널은 문서 맨 위에 그린다
        <>
          <div className="fixed inset-0 z-50 bg-black/35" onClick={() => setOpen(false)} />
          <aside aria-label="에이전트" className="fixed inset-y-0 right-0 z-50 flex w-full max-w-[560px] flex-col border-l bg-background text-foreground shadow-xl">
            <div className="flex items-center gap-2 px-4 pb-1 pt-3">
              <h2 className="flex-1 text-lg font-bold">에이전트</h2>
              <button type="button" onClick={() => setOpen(false)} aria-label="닫기" className="rounded-md p-2 hover:bg-secondary"><X size={18} /></button>
            </div>
            <AgentView d={d} load={load} onNavigate={() => setOpen(false)} />
          </aside>
        </>, document.body)}
    </>
  );
}
