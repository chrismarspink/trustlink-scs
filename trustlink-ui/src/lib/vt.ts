import { flushSync } from 'react-dom';

// 화면 전환(View Transitions): 브라우저가 지원하고 사용자가 움직임을 줄이지 않았을 때만 쓴다. 아니면 지금처럼 바로 바꾼다.
type Doc = Document & { startViewTransition?: (cb: () => void) => { finished: Promise<void> } };

export const canVT = () => !!(document as Doc).startViewTransition && !window.matchMedia('(prefers-reduced-motion: reduce)').matches;

// withVT: 화면을 바꾸는 일을 전환으로 감싼다. after 는 전환이 끝난 뒤(또는 전환 없이 바꾼 직후) 부른다.
export function withVT(change: () => void, after?: () => void) {
  const d = document as Doc;
  if (!canVT()) { change(); after?.(); return; }
  // 본문에 전환 이름을 붙이는 것은 전환하는 동안만 — 늘 붙여 두면 본문 안의 창(대화상자 등)이 머리줄 아래로 깔릴 수 있다
  const root = document.documentElement;
  root.classList.add('vt-on');
  const t = d.startViewTransition!(() => flushSync(change));
  t.finished.finally(() => { root.classList.remove('vt-on'); after?.(); });
}
