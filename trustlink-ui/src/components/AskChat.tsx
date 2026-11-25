import { useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { Link } from 'react-router-dom';
import { Send, Sparkles, ArrowRight, Clapperboard } from 'lucide-react';
import { agentRun, ask, askAction, askScene, askSummary, type AskAnswer } from '@/lib/api';
import { SceneDialog } from '@/components/SceneDialog';
import { answerStory, type StorySpec } from '@/lib/scenes';
import { A2UISurface, applyA2UI, type A2Action, type A2Surface } from '@/components/A2UISurface';
import { AIBadge } from '@/components/AIBadge';
import { cn } from '@/lib/utils';

// 대화 한 벌: 에이전트 패널의 "묻기"와 오른쪽 아래 묻고 찾기 창이 같은 대화를 함께 쓴다(어느 쪽에서 물어도 이어진다).
// 답은 규칙으로 바로 나오고, 정해진 유형에 맞지 않는 질문은 AI 가 조회를 스스로 골라 답한다. 보내거나 저장하는 일은 양식으로 확인받는다.
type Turn = {
  q: string; a?: AskAnswer; err?: string; ai?: { answer: string; model: string; ms: number; steps?: { tool: string; arg?: string; lead: string }[] }; aiBusy?: boolean; aiErr?: string;
  ui?: A2Surface; acting?: boolean; actErr?: string; // 행동 양식(A2UI)과 그 처리 상태
  ran?: Record<string, string>; // 답에 붙은 할 일을 실행한 결과
};

const TONE: Record<string, string> = { crit: 'border-l-red-400', warn: 'border-l-amber-400', ok: 'border-l-emerald-400' };
const DEFAULTS = ['내 할 일은?', 'CVE-2026-123634 가 어디에 걸리나?', 'nginx 를 쓰는 제품은?'];
const clean = (e: unknown) => String(e).replace(/^(Api)?Error:\s*(\d{3}\s*)?/, '');

// ---- 대화 저장소(화면 두 곳이 같이 본다) ----
let state: { turns: Turn[]; busy: boolean; formAt: number } = { turns: [], busy: false, formAt: 0 };
const subs = new Set<() => void>();
const set = (f: (s: typeof state) => typeof state) => { state = f(state); subs.forEach((x) => x()); };
const setTurns = (f: (xs: Turn[]) => Turn[]) => set((s) => ({ ...s, turns: f(s.turns) }));
const at = (k: number, f: (x: Turn) => Turn) => setTurns((xs) => xs.map((x, i) => (i === k ? f(x) : x)));
const byId = (id: string, f: (x: Turn) => Turn) => setTurns((xs) => xs.map((x) => (x.a?.id === id ? f(x) : x)));
export const useAskState = () => useSyncExternalStore((cb) => { subs.add(cb); return () => subs.delete(cb); }, () => state);

async function summarize(id: string) {
  byId(id, (x) => ({ ...x, aiBusy: true, aiErr: '' }));
  try {
    const r = await askSummary(id);
    byId(id, (x) => ({ ...x, aiBusy: false, ai: { answer: r.answer, model: r.model, ms: r.elapsedMs, steps: r.steps } }));
  } catch (e) {
    byId(id, (x) => ({ ...x, aiBusy: false, aiErr: clean(e) }));
  }
}

export async function askSend(text: string) {
  const t = text.trim();
  if (!t || state.busy) return;
  set((s) => ({ ...s, busy: true, turns: [...s.turns, { q: t }] }));
  const k = state.turns.length - 1;
  try {
    const a = await ask(t);
    at(k, (x) => ({ ...x, a, ui: a.ui ? applyA2UI(undefined, a.ui) : undefined }));
    if (a.ui) set((s) => ({ ...s, formAt: s.formAt + 1 }));
    if (a.intent === 'free' && a.canAI) await summarize(a.id); // 바로 찾지 못한 질문은 AI 가 조회를 골라 이어서 답한다
  } catch (e) {
    at(k, (x) => ({ ...x, err: clean(e) }));
  }
  set((s) => ({ ...s, busy: false }));
}

const setData = (k: number, path: string, value: unknown) =>
  at(k, (x) => (x.ui ? { ...x, ui: applyA2UI(x.ui, [{ updateDataModel: { surfaceId: x.ui.id, path, value } }]) } : x));
async function act(k: number, action: A2Action) {
  at(k, (x) => ({ ...x, acting: true, actErr: '' }));
  try {
    const r = await askAction(action);
    at(k, (x) => ({ ...x, acting: false, ui: applyA2UI(x.ui, r.ui), a: x.a && r.lead ? { ...x.a, lead: r.lead } : x.a }));
  } catch (e) {
    at(k, (x) => ({ ...x, acting: false, actErr: clean(e) }));
  }
}
async function runTask(k: number, id: string) {
  at(k, (x) => ({ ...x, ran: { ...x.ran, [id]: '실행하는 중…' } }));
  try {
    const r = await agentRun([id]);
    at(k, (x) => ({ ...x, ran: { ...x.ran, [id]: r.results[0]?.result || '실행했습니다.' } }));
  } catch (e) {
    at(k, (x) => ({ ...x, ran: { ...x.ran, [id]: clean(e) } }));
  }
}

function Form({ k, t }: { k: number; t: Turn }) {
  return (
    <>
      <A2UISurface surface={t.ui!} busy={t.acting} onData={(path, value) => setData(k, path, value)} onAction={(a) => act(k, a)} />
      {t.acting && <div className="mt-2 text-xs text-muted-foreground">처리하는 중…</div>}
      {t.actErr && <div className="mt-2 text-xs text-red-600">{t.actErr}</div>}
    </>
  );
}

// wide: 대화는 왼쪽, 확인할 양식은 오른쪽(넓은 창에서만). onNavigate: 답의 링크를 눌렀을 때(패널 닫기 등).
export function AskChat({ wide = false, onNavigate, autoFocus = false }: { wide?: boolean; onNavigate?: () => void; autoFocus?: boolean }) {
  const { turns, busy } = useAskState();
  const [q, setQ] = useState('');
  const end = useRef<HTMLDivElement>(null);
  // 답을 막대 인형 장면으로: 규칙으로 바로 만들고, 원하면 AI 가 풀어 쓴 장면으로 바꾼다
  const [scene, setScene] = useState<{ id: string; stories: StorySpec[]; busy?: boolean; err?: string; ai?: string } | null>(null);
  const aiScene = async () => {
    if (!scene) return;
    setScene({ ...scene, busy: true, err: '' });
    try { const r = await askScene(scene.id); setScene((s) => (s ? { ...s, busy: false, ai: `${r.model} · ${(r.elapsedMs / 1000).toFixed(0)}초`, stories: [{ name: 'AI 가 풀어 쓴 설명', scenes: r.scenes }, ...s.stories.filter((x) => x.name !== 'AI 가 풀어 쓴 설명')] } : s)); }
    catch (e) { setScene((s) => (s ? { ...s, busy: false, err: clean(e) } : s)); }
  };
  useEffect(() => { end.current?.scrollIntoView({ block: 'end' }); }, [turns.length]);
  const lastUi = turns.reduce((n, t, k) => (t.ui ? k : n), -1);
  const suggest = turns.length ? turns[turns.length - 1].a?.suggest || DEFAULTS : DEFAULTS;
  const chip = 'inline-flex w-fit items-center gap-1 rounded-md border border-primary/40 px-2.5 py-1 text-xs font-semibold text-primary hover:bg-primary/5';

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <SceneDialog open={!!scene} onOpenChange={(v) => { if (!v) setScene(null); }} title="질문의 답 — 장면으로 보기" stories={scene?.stories}
        footer={<>
          <span className="min-w-0 flex-1 text-xs text-muted-foreground">{scene?.err ? <span className="text-red-600">{scene.err}</span> : scene?.ai ? `AI 가 풀어 쓴 장면입니다(${scene.ai}). 그림은 정해진 틀이고 AI 는 글자만 채웁니다.` : '답의 내용으로 바로 만든 장면입니다. AI 가 2~3장면으로 풀어 설명하게 할 수도 있습니다(내부 모델은 1~2분).'}</span>
          <button type="button" disabled={scene?.busy} onClick={aiScene} className="inline-flex h-9 items-center gap-1 rounded-md border border-violet-300 px-3 font-medium text-violet-800 hover:bg-violet-50 disabled:opacity-60"><Sparkles size={13} /> {scene?.busy ? 'AI 가 장면을 쓰는 중…' : 'AI 가 풀어서 설명'}</button>
        </>} />
      <div className="flex min-h-0 flex-1">
        <div className="min-w-0 flex-1 space-y-3 overflow-y-auto px-4 py-3 text-sm">
          {turns.length === 0 && (
            <p className="text-xs leading-relaxed text-muted-foreground">
              취약점 번호(CVE-…), 구성요소 이름, 할 일, 내 제품에 대해 물어보세요. "CVE-… 고객 통지 초안 만들어 줘", "CVE-… VEX 판정 초안", "CVE-… 자료 조사해 줘", "미국 수출 규제 보고서 만들어 줘"처럼 일을 시킬 수도 있습니다. 보내거나 저장하는 일은 양식에서 확인하고 단추를 눌러야 실행됩니다.
            </p>
          )}
          {turns.map((t, k) => (
            <div key={k} className="space-y-2">
              <div className="ml-auto w-fit max-w-[85%] rounded-2xl rounded-br-sm bg-primary px-3 py-1.5 text-primary-foreground">{t.q}</div>
              {!t.a && !t.err && <div className="text-xs text-muted-foreground">찾는 중…</div>}
              {t.err && <div className="rounded-md border border-red-200 bg-red-50 p-2 text-xs text-red-700">{t.err}</div>}
              {t.a && (
                <div className="space-y-2 rounded-xl border bg-card p-3">
                  <div className="text-xs font-semibold text-muted-foreground">{t.a.title}</div>
                  <div className="leading-relaxed">{t.a.lead}</div>
                  {t.a.rows.length > 0 && (
                    <ul className="space-y-1">
                      {t.a.rows.map((r, i) => {
                        const body = (
                          <>
                            <span className="block truncate font-medium">{r.title}</span>
                            {r.detail && <span className="block truncate text-xs text-muted-foreground">{r.detail}</span>}
                          </>
                        );
                        const cls = cn('block rounded-md border border-l-4 px-2.5 py-1.5', TONE[r.tone || ''] || 'border-l-slate-200', r.link && 'hover:bg-secondary/60');
                        const ext = !!r.link && /^https?:/.test(r.link);
                        return <li key={i}>{!r.link ? <div className={cls}>{body}</div> : ext ? <a href={r.link} target="_blank" rel="noreferrer" className={cls}>{body}</a> : <Link to={r.link} onClick={onNavigate} className={cls}>{body}</Link>}</li>;
                      })}
                    </ul>
                  )}
                  {!!t.a.more && <div className="text-xs text-muted-foreground">외 {t.a.more}건 — 해당 화면에서 전체를 볼 수 있습니다.</div>}
                  {!!t.a.tasks?.length && (
                    <div className="rounded-lg border border-primary/30 bg-primary/[0.03] p-2.5">
                      <div className="mb-1.5 text-xs font-semibold text-primary">에이전트가 대신 할 수 있는 일</div>
                      <ul className="space-y-1.5">
                        {t.a.tasks.map((x) => (
                          <li key={x.id} className="flex flex-wrap items-center gap-x-2 gap-y-1">
                            <span className="min-w-0 flex-1 basis-40"><span className="block truncate font-medium">{x.title}</span>{x.why && <span className="block truncate text-xs text-muted-foreground">{x.why}</span>}</span>
                            {t.ran?.[x.id] ? <span className="basis-full text-xs text-muted-foreground">{t.ran[x.id]}</span>
                              : x.grade === 'run' ? <button type="button" onClick={() => runTask(k, x.id)} className="h-8 shrink-0 rounded-md bg-primary px-3 text-xs font-semibold text-primary-foreground">지금 실행</button>
                              : x.grade === 'approve' ? <button type="button" onClick={() => window.dispatchEvent(new CustomEvent('tl-agent', { detail: { tab: 'todo' } }))} className="h-8 shrink-0 rounded-md border px-3 text-xs">내용 보고 승인</button>
                              : x.link && <Link to={x.link} onClick={onNavigate} className="inline-flex h-8 shrink-0 items-center rounded-md border px-3 text-xs">화면으로 이동</Link>}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {t.a.map && <Link to={t.a.map} onClick={onNavigate} className={chip}>영향 지도 보기 <ArrowRight size={12} /></Link>}
                  {t.ui && wide && k === lastUi && <div className="rounded-md bg-primary/5 px-2.5 py-1.5 text-xs text-primary">오른쪽 양식에서 확인해 주세요.</div>}
                  {t.ui && !(wide && k === lastUi) && <div className="rounded-lg border border-primary/30 bg-primary/[0.03] p-3"><Form k={k} t={t} /></div>}
                  {t.ai && (
                    <div className="rounded-md border border-violet-200 bg-violet-50/60 p-2 text-[13px] leading-relaxed">
                      <div className="mb-1 flex items-center gap-1.5"><AIBadge label="AI 생성" /><span className="text-[11px] text-muted-foreground">{t.ai.model} · {(t.ai.ms / 1000).toFixed(0)}초</span></div>
                      {t.ai.answer}
                      {!!t.ai.steps?.length && <div className="mt-1.5 border-t border-violet-200 pt-1.5 text-[11px] text-muted-foreground">AI 가 고른 조회: {t.ai.steps.map((s) => [s.tool, s.arg].filter(Boolean).join(' ')).join(' → ')}</div>}
                    </div>
                  )}
                  {t.aiErr && <div className="text-xs text-red-600">{t.aiErr}</div>}
                  <div className="flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
                    {t.a.sources.length > 0 && <span>출처: {t.a.sources.join(' · ')}</span>}
                    <button type="button" onClick={() => setScene({ id: t.a!.id, stories: [answerStory(t.q, t.a!, t.ai?.answer)] })} className="inline-flex items-center gap-1 rounded-full border border-violet-300 px-2 py-0.5 font-medium text-violet-800 hover:bg-violet-50"><Clapperboard size={11} /> 장면으로 보기</button>
                    {t.a.canAI && !t.ai && (
                      <button onClick={() => summarize(t.a!.id)} disabled={t.aiBusy} className="ml-auto inline-flex items-center gap-1 rounded-full border border-violet-300 px-2 py-0.5 font-medium text-violet-800 hover:bg-violet-50 disabled:opacity-60">
                        <Sparkles size={11} /> {t.aiBusy ? (t.a.intent === 'free' ? 'AI 가 조회를 골라 답하는 중(1~2분)…' : 'AI 가 정리하는 중(20~30초)…') : 'AI 로 한 줄 정리'}
                      </button>
                    )}
                  </div>
                </div>
              )}
            </div>
          ))}
          <div ref={end} />
        </div>
        {wide && (
          <aside className="hidden w-[46%] shrink-0 overflow-y-auto border-l bg-secondary/30 p-4 text-sm lg:block" aria-label="확인이 필요한 일">
            <div className="mb-2 text-xs font-semibold text-muted-foreground">확인이 필요한 일{lastUi >= 0 ? ' · 1건' : ''}</div>
            {lastUi < 0 ? <p className="text-xs leading-relaxed text-muted-foreground">일을 시키면(고객 통지 초안, VEX 판정, 규제 보고서) 확인할 양식이 여기에 뜹니다. 단추를 누르기 전에는 아무것도 나가거나 저장되지 않습니다.</p>
              : <div className="rounded-lg border border-primary/30 bg-background p-3"><Form k={lastUi} t={turns[lastUi]} /></div>}
          </aside>
        )}
      </div>

      <div className="border-t px-3 py-2.5">
        <div className="mb-2 flex flex-wrap gap-1.5">
          {suggest.map((s) => (
            <button key={s} onClick={() => askSend(s)} disabled={busy} className="inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] text-muted-foreground hover:bg-secondary">
              {s} <ArrowRight size={10} />
            </button>
          ))}
        </div>
        <form onSubmit={(e) => { e.preventDefault(); askSend(q); setQ(''); }} className="flex items-center gap-2">
          <input value={q} onChange={(e) => setQ(e.target.value)} maxLength={300} placeholder="예: CVE-2026-1234 가 어디에 걸리나?" autoFocus={autoFocus} aria-label="묻거나 시키기"
            className="h-9 min-w-0 flex-1 rounded-md border bg-background px-3 text-sm outline-none focus:border-primary" />
          <button type="submit" disabled={busy || !q.trim()} aria-label="보내기" className="inline-flex h-9 w-9 items-center justify-center rounded-md bg-primary text-primary-foreground disabled:opacity-50"><Send size={15} /></button>
        </form>
      </div>
    </div>
  );
}
