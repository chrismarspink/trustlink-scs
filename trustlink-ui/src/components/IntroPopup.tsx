import { useEffect, useMemo, useState } from 'react';
import { CircleHelp } from 'lucide-react';
import { SceneDialog } from '@/components/SceneDialog';
import { getSession } from '@/lib/api';
import { newsStories } from '@/lib/scenes';

declare const __APP_VERSION__: string;

// 안내 장면 팝업: 접속하면 막대 인형 장면으로 "이번에 바뀐 것"과 제품 소개를 보여 준다.
//   오늘은 그만 보기 — 내일 다시 / 다시 보지 않기 — 다음 새 버전이 나올 때까지 / 상단 도움말 아이콘 — 언제든 다시
// 새 버전 장면은 content/news.ts 의 새 소식에서 자동으로 만들어진다.
const K = { seen: 'tl.home.seenVersion', snooze: 'tl.intro.snooze', never: 'tl.intro.never' };
const get = (k: string) => { try { return localStorage.getItem(k) || ''; } catch { return ''; } };
const set = (k: string, v: string) => { try { localStorage.setItem(k, v); } catch { /* 저장 못 해도 이번에는 닫힌다 */ } };
const today = () => new Date().toLocaleDateString('sv'); // 이 컴퓨터의 날짜(YYYY-MM-DD)

export function IntroPopup() {
  const [open, setOpen] = useState(false);
  const seen = useMemo(() => get(K.seen), [open]); // eslint-disable-line react-hooks/exhaustive-deps
  const stories = useMemo(() => newsStories(seen === __APP_VERSION__ ? '' : seen), [seen]);
  useEffect(() => {
    getSession().then((s) => {
      if (!s?.username) return; // 자동으로 띄우는 것만 로그인 확인 뒤에 — 물음표 단추는 권한 세션이 없어도 항상 보인다
      let once = '';
      try { once = sessionStorage.getItem('tl.intro.shown') || ''; sessionStorage.setItem('tl.intro.shown', '1'); } catch { /* 없어도 된다 */ }
      if (!once && get(K.never) !== __APP_VERSION__ && get(K.snooze) !== today()) setOpen(true); // 접속할 때 한 번
    }).catch(() => {});
  }, []);
  const close = (how?: 'today' | 'never') => {
    if (how === 'today') set(K.snooze, today());
    if (how === 'never') set(K.never, __APP_VERSION__);
    set(K.seen, __APP_VERSION__);
    setOpen(false);
  };
  const b = 'h-9 rounded-md border px-3 hover:bg-secondary';
  return (
    <>
      <button type="button" onClick={() => setOpen(true)} title="안내 장면 — 이번에 바뀐 것과 제품 소개" aria-label="안내 장면 보기" className="rounded-md p-2 text-muted-foreground hover:bg-secondary hover:text-foreground"><CircleHelp size={17} /></button>
      <SceneDialog open={open} onOpenChange={(v) => (v ? setOpen(true) : close())} title={`TrustLink 안내 — v${__APP_VERSION__} 에서 바뀐 것`} stories={stories} mode="prepend"
        footer={<>
          <span className="min-w-0 flex-1 text-xs text-muted-foreground">상단의 물음표 아이콘으로 언제든 다시 볼 수 있습니다. 새 버전이 나오면 바뀐 내용이 자동으로 장면에 들어갑니다.</span>
          <button type="button" onClick={() => close('today')} className={b}>오늘은 그만 보기</button>
          <button type="button" onClick={() => close('never')} className={b}>다시 보지 않기</button>
          <button type="button" onClick={() => close()} className="h-9 rounded-md bg-primary px-4 font-semibold text-primary-foreground">닫기</button>
        </>} />
    </>
  );
}
