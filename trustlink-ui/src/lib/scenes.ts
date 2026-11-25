import { RELEASES, type Release } from '@/content/news';
import type { AskAnswer } from '@/lib/api';

// 막대 인형 장면을 자료로 만든다. 그림은 /intro.html 의 장면 재생기가 그리고, 여기서는 틀과 글자만 정한다.
//   새 버전 소식: content/news.ts 에 한 항목을 더하면 장면이 자동으로 생긴다(따로 그릴 것이 없다).
//   질문의 답: 답의 줄과 할 일 제안으로 바로 만든다. AI 가 풀어 쓴 장면은 서버(/api/ask/{id}/scene)가 준다.
export type SceneSpec = {
  layout: 'ask' | 'new' | 'improve' | 'fix' | 'warn' | 'steps'; tab: string; kicker: string; title: string; text: string; list?: string[];
  who?: string; say?: string; cards?: { title: string; lines: string[] }[]; tag?: string; before?: string; after?: string; steps?: string[];
};
export type StorySpec = { name: string; scenes: SceneSpec[] };

// "제목 — 설명" 또는 "제목: 설명" 을 나눈다
const split = (t: string) => { const m = t.match(/^(.{4,}?)(?: — |: )(.+)$/); return m ? [m[1], m[2]] : [t, '']; };
const short = (t: string, n: number) => (t.length > n ? t.slice(0, n - 1) + '…' : t);

export function releaseStory(r: Release): StorySpec {
  const heads = r.items.map((it) => split(it.text)[0]);
  const first: SceneSpec = { layout: 'steps', tab: '한눈에', kicker: `v${r.version} · ${r.date}`, title: r.title, text: `이번 버전에서 바뀐 것 ${r.items.length}가지입니다.`, list: heads.map((h) => short(h, 60)), who: '담당자', steps: heads.slice(0, 4).map((h) => short(h, 34)) };
  const rest = r.items.slice(0, 6).map((it, i): SceneSpec => {
    const [head, body] = split(it.text);
    const base = { tab: short(head, 9), kicker: `v${r.version} · ${it.kind} ${i + 1}`, title: short(head, 46), text: body || head, who: '담당자' };
    if (it.kind === '수정') return { ...base, layout: 'fix', after: head };
    if (it.kind === '개선') return { ...base, layout: 'improve', before: '지금까지', after: head };
    return { ...base, layout: 'new', tag: '새 기능', say: '새로 생겼어요', cards: [{ title: '새로 생긴 것', lines: [head] }] };
  });
  return { name: `v${r.version} 새 소식`, scenes: [first, ...rest] };
}

// 지난번에 본 버전 뒤로 나온 것(최대 3개 버전). 처음이면 가장 최근 것 하나.
export function newsStories(seen: string): StorySpec[] {
  const older = (a: string, b: string) => { const x = a.split('.').map(Number), y = b.split('.').map(Number); for (let i = 0; i < 3; i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) < (y[i] || 0); return false; };
  const fresh = seen ? RELEASES.filter((r) => older(seen, r.version)) : RELEASES.slice(0, 1);
  return (fresh.length ? fresh : RELEASES.slice(0, 1)).slice(0, 3).map(releaseStory);
}

// 질문의 답을 규칙으로 장면으로 만든다(AI 없이 바로).
export function answerStory(q: string, a: AskAnswer, ai?: string): StorySpec {
  const scenes: SceneSpec[] = [{
    layout: a.rows.some((r) => r.tone === 'crit') ? 'warn' : 'ask', tab: '답', kicker: a.title, title: short(a.lead, 46), text: a.lead, who: '담당자', say: q,
    cards: (a.rows.length ? a.rows : [{ title: a.title, detail: a.lead }]).slice(0, 3).map((r) => ({ title: short(r.title, 18), lines: [r.detail || ''] })),
    tag: a.sources[0] ? `출처: ${short(a.sources[0], 14)}` : undefined, list: a.rows.slice(0, 5).map((r) => `${r.title}${r.detail ? ' — ' + r.detail : ''}`),
  }];
  if (ai) scenes.push({ layout: 'new', tab: 'AI 정리', kicker: 'AI 생성', title: 'AI 가 정리한 답', text: ai, who: '담당자', say: '정리하면', tag: 'AI 생성', cards: [{ title: 'AI 정리', lines: [short(ai, 60)] }] });
  if (a.tasks?.length) scenes.push({ layout: 'steps', tab: '다음 할 일', kicker: '에이전트', title: '에이전트가 대신 할 수 있는 일', text: '고르면 대신 실행합니다. 고객에게 나가는 것은 내용을 보고 승인해야 나갑니다.', who: '담당자', steps: a.tasks.slice(0, 4).map((t) => short(t.title, 34)), list: a.tasks.slice(0, 5).map((t) => t.title) });
  return { name: '질문의 답', scenes };
}
