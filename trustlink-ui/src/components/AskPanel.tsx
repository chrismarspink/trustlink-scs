import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { MessageCircleQuestion, X, Send, Sparkles, ArrowRight } from 'lucide-react';
import { ask, askAction, askSummary, getSession, type AskAnswer } from '@/lib/api';
import { A2UISurface, applyA2UI, type A2Action, type A2Surface } from '@/components/A2UISurface';
import { HelpScene } from '@/components/HelpScene';
import { AIBadge } from '@/components/AIBadge';
import { cn } from '@/lib/utils';

// 묻고 찾기: 로그인한 누구나 문장으로 묻고, 자기 권한 안의 기록에서 답을 받는다.
// 답은 규칙으로 바로 나오고(조회 + 틀), AI 정리는 원할 때만 누른다(로컬 AI 는 20~30초).
type Turn = {
  q: string; a?: AskAnswer; err?: string; ai?: { answer: string; model: string; ms: number }; aiBusy?: boolean; aiErr?: string;
  ui?: A2Surface; acting?: boolean; actErr?: string; // 행동 양식(A2UI)과 그 처리 상태
};

const TONE: Record<string, string> = { crit: 'border-l-red-400', warn: 'border-l-amber-400', ok: 'border-l-emerald-400' };
const DEFAULTS = ['내 할 일은?', 'CVE-2026-123634 가 어디에 걸리나?', 'nginx 를 쓰는 제품은?'];
const last = <T,>(xs: T[], f: (x: T) => T) => xs.map((x, i) => (i === xs.length - 1 ? f(x) : x));
const clean = (e: unknown) => String(e).replace(/^(Api)?Error:\s*(\d{3}\s*)?/, '');

export function AskPanel() {
  const [on, setOn] = useState(false);
  const [open, setOpen] = useState(false);
  const [turns, setTurns] = useState<Turn[]>([]);
  const [q, setQ] = useState('');
  const [busy, setBusy] = useState(false);
  const end = useRef<HTMLDivElement>(null);
  useEffect(() => { getSession().then((s) => setOn(!!s?.username)).catch(() => setOn(false)); }, []);
  useEffect(() => { end.current?.scrollIntoView({ block: 'end' }); }, [turns.length, open]);

  const send = async (text: string) => {
    const t = text.trim();
    if (!t || busy) return;
    setQ(''); setBusy(true);
    setTurns((xs) => [...xs, { q: t }]);
    try {
      const a = await ask(t);
      setTurns((xs) => last(xs, (x) => ({ ...x, a, ui: a.ui ? applyA2UI(undefined, a.ui) : undefined })));
      if (a.intent === 'free' && a.canAI) { // 바로 찾지 못한 질문은 AI 답을 이어서 받는다
        setTurns((xs) => last(xs, (x) => ({ ...x, aiBusy: true })));
        try {
          const r = await askSummary(a.id);
          setTurns((xs) => xs.map((x) => (x.a?.id === a.id ? { ...x, aiBusy: false, ai: { answer: r.answer, model: r.model, ms: r.elapsedMs } } : x)));
        } catch (e) {
          setTurns((xs) => xs.map((x) => (x.a?.id === a.id ? { ...x, aiBusy: false, aiErr: clean(e) } : x)));
        }
      }
    } catch (e) {
      setTurns((xs) => last(xs, (x) => ({ ...x, err: clean(e) })));
    }
    setBusy(false);
  };
  const sendRef = useRef(send);
  sendRef.current = send;
  useEffect(() => { // 다른 화면의 단추(askOpen)로 열기
    const h = (e: Event) => { setOpen(true); const q0 = (e as CustomEvent<{ q?: string }>).detail?.q; if (q0) sendRef.current(q0); };
    window.addEventListener('tl-ask', h);
    return () => window.removeEventListener('tl-ask', h);
  }, []);
  if (!on) return null;
  const setData = (k: number, path: string, value: unknown) =>
    setTurns((xs) => xs.map((x, i) => (i === k && x.ui ? { ...x, ui: applyA2UI(x.ui, [{ updateDataModel: { surfaceId: x.ui.id, path, value } }]) } : x)));
  const act = async (k: number, action: A2Action) => {
    setTurns((xs) => xs.map((x, i) => (i === k ? { ...x, acting: true, actErr: '' } : x)));
    try {
      const r = await askAction(action);
      setTurns((xs) => xs.map((x, i) => (i === k ? { ...x, acting: false, ui: applyA2UI(x.ui, r.ui), a: x.a && r.lead ? { ...x.a, lead: r.lead } : x.a } : x)));
    } catch (e) {
      setTurns((xs) => xs.map((x, i) => (i === k ? { ...x, acting: false, actErr: clean(e) } : x)));
    }
  };
  const summarize = async (k: number) => {
    const id = turns[k]?.a?.id;
    if (!id) return;
    setTurns((xs) => xs.map((x, i) => (i === k ? { ...x, aiBusy: true, aiErr: '' } : x)));
    try {
      const r = await askSummary(id);
      setTurns((xs) => xs.map((x, i) => (i === k ? { ...x, aiBusy: false, ai: { answer: r.answer, model: r.model, ms: r.elapsedMs } } : x)));
    } catch (e) {
      setTurns((xs) => xs.map((x, i) => (i === k ? { ...x, aiBusy: false, aiErr: clean(e) } : x)));
    }
  };
  const suggest = turns.length ? turns[turns.length - 1].a?.suggest || DEFAULTS : DEFAULTS;

  return (
    <>
      {!open && (
        <button onClick={() => setOpen(true)} title="묻고 찾기 — 취약점 번호, 구성요소 이름, 할 일을 물어보세요"
          className="fixed bottom-5 right-5 z-40 inline-flex items-center gap-2 rounded-full bg-primary px-3.5 py-3.5 text-sm font-semibold text-primary-foreground shadow-lg hover:opacity-90 sm:px-4 sm:py-2.5" aria-label="묻고 찾기">
          <MessageCircleQuestion size={18} /> <span className="hidden sm:inline">묻고 찾기</span>
        </button>
      )}
      {open && (
        <div className="fixed bottom-5 right-5 z-40 flex h-[min(620px,80vh)] w-[min(420px,calc(100vw-2.5rem))] flex-col overflow-hidden rounded-xl border bg-background shadow-2xl" role="dialog" aria-label="묻고 찾기">
          <div className="flex items-center gap-2 border-b px-4 py-2.5">
            <MessageCircleQuestion size={17} className="text-primary" />
            <div className="flex-1 leading-tight">
              <div className="text-sm font-semibold">묻고 찾기</div>
              <div className="text-[11px] text-muted-foreground">내 권한 안의 기록에서 찾고, 시킨 일은 양식으로 확인받습니다</div>
            </div>
            <HelpScene topic="ask" title="묻고 찾기는 이렇게 동작합니다" />
            <button onClick={() => setOpen(false)} aria-label="닫기" className="rounded p-1 text-muted-foreground hover:bg-secondary"><X size={16} /></button>
          </div>

          <div className="flex-1 space-y-3 overflow-y-auto px-4 py-3 text-sm">
            {turns.length === 0 && (
              <p className="text-xs leading-relaxed text-muted-foreground">
                취약점 번호(CVE-…), 구성요소 이름, 할 일, 내 제품에 대해 물어보세요. "CVE-… 고객 통지 초안 만들어 줘", "CVE-… VEX 판정 초안", "미국 수출 규제 보고서 만들어 줘"처럼 일을 시킬 수도 있습니다. 보내거나 저장하는 일은 양식에서 확인하고 단추를 눌러야 실행됩니다.
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
                          return <li key={i}>{r.link ? <Link to={r.link} className={cls}>{body}</Link> : <div className={cls}>{body}</div>}</li>;
                        })}
                      </ul>
                    )}
                    {!!t.a.more && <div className="text-xs text-muted-foreground">외 {t.a.more}건 — 해당 화면에서 전체를 볼 수 있습니다.</div>}
                    {t.a.map && <Link to={t.a.map} className="inline-flex w-fit items-center gap-1 rounded-md border border-primary/40 px-2.5 py-1 text-xs font-semibold text-primary hover:bg-primary/5">영향 지도 보기 <ArrowRight size={12} /></Link>}
                    {t.ui && (
                      <div className="rounded-lg border border-primary/30 bg-primary/[0.03] p-3">
                        <A2UISurface surface={t.ui} busy={t.acting} onData={(path, value) => setData(k, path, value)} onAction={(a) => act(k, a)} />
                        {t.acting && <div className="mt-2 text-xs text-muted-foreground">처리하는 중…</div>}
                        {t.actErr && <div className="mt-2 text-xs text-red-600">{t.actErr}</div>}
                      </div>
                    )}
                    {t.ai && (
                      <div className="rounded-md border border-violet-200 bg-violet-50/60 p-2 text-[13px] leading-relaxed">
                        <div className="mb-1 flex items-center gap-1.5"><AIBadge label="AI 생성" /><span className="text-[11px] text-muted-foreground">{t.ai.model} · {(t.ai.ms / 1000).toFixed(0)}초</span></div>
                        {t.ai.answer}
                      </div>
                    )}
                    {t.aiErr && <div className="text-xs text-red-600">{t.aiErr}</div>}
                    <div className="flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
                      {t.a.sources.length > 0 && <span>출처: {t.a.sources.join(' · ')}</span>}
                      {t.a.canAI && !t.ai && (
                        <button onClick={() => summarize(k)} disabled={t.aiBusy} className="ml-auto inline-flex items-center gap-1 rounded-full border border-violet-300 px-2 py-0.5 font-medium text-violet-800 hover:bg-violet-50 disabled:opacity-60">
                          <Sparkles size={11} /> {t.aiBusy ? (t.a.intent === 'free' ? 'AI 가 답하는 중(30초~1분)…' : 'AI 가 정리하는 중(20~30초)…') : 'AI 로 한 줄 정리'}
                        </button>
                      )}
                    </div>
                  </div>
                )}
              </div>
            ))}
            <div ref={end} />
          </div>

          <div className="border-t px-3 py-2.5">
            <div className="mb-2 flex flex-wrap gap-1.5">
              {suggest.map((s) => (
                <button key={s} onClick={() => send(s)} disabled={busy} className="inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] text-muted-foreground hover:bg-secondary">
                  {s} <ArrowRight size={10} />
                </button>
              ))}
            </div>
            <form onSubmit={(e) => { e.preventDefault(); send(q); }} className="flex items-center gap-2">
              <input value={q} onChange={(e) => setQ(e.target.value)} maxLength={300} placeholder="예: CVE-2026-1234 가 어디에 걸리나?" autoFocus
                className="h-9 min-w-0 flex-1 rounded-md border bg-background px-3 text-sm outline-none focus:border-primary" />
              <button type="submit" disabled={busy || !q.trim()} aria-label="보내기" className="inline-flex h-9 w-9 items-center justify-center rounded-md bg-primary text-primary-foreground disabled:opacity-50"><Send size={15} /></button>
            </form>
          </div>
        </div>
      )}
    </>
  );
}
