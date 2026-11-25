import { useEffect, useState } from 'react';
import { MessageCircleQuestion, X, Maximize2, Minimize2 } from 'lucide-react';
import { AskChat, useAskState } from '@/components/AskChat';
import { HelpScene } from '@/components/HelpScene';
import { useAskOff } from '@/lib/askOpen';
import { getSession } from '@/lib/api';
import { cn } from '@/lib/utils';

// 묻고 찾기(오른쪽 아래 창): 에이전트 패널의 "묻기"와 같은 대화를 쓴다.
// 에이전트 설정에서 이 버튼을 끌 수 있다(꺼도 에이전트 패널에서 똑같이 묻는다).
export function AskPanel() {
  const off = useAskOff(); // null = 아직 모름(설정을 받기 전)
  const [on, setOn] = useState(false); // 로그인한 사람에게만
  useEffect(() => { getSession().then((s) => setOn(!!s?.username)).catch(() => setOn(false)); }, []);
  const [open, setOpen] = useState(false);
  const [wide, setWide] = useState(false); // 넓게 보기: 대화 왼쪽, 확인할 양식 오른쪽
  const { formAt } = useAskState();
  useEffect(() => { if (formAt && window.matchMedia('(min-width: 1024px)').matches) setWide(true); }, [formAt]); // 양식이 오면 넓혀서 대화와 나란히
  useEffect(() => { // 에이전트 패널이 열리면 겹치지 않게 닫는다
    const h = () => setOpen(false);
    window.addEventListener('tl-agent', h);
    window.addEventListener('tl-ask', h);
    return () => { window.removeEventListener('tl-agent', h); window.removeEventListener('tl-ask', h); };
  }, []);
  if (!on || off !== false) return null;

  return (
    <>
      {!open && (
        <button onClick={() => setOpen(true)} title="묻고 찾기 — 취약점 번호, 구성요소 이름, 할 일을 물어보세요"
          className="fixed bottom-5 right-5 z-40 inline-flex items-center gap-2 rounded-full bg-primary px-3.5 py-3.5 text-sm font-semibold text-primary-foreground shadow-lg hover:opacity-90 sm:px-4 sm:py-2.5" aria-label="묻고 찾기">
          <MessageCircleQuestion size={18} /> <span className="hidden sm:inline">묻고 찾기</span>
        </button>
      )}
      {open && (
        <div className={cn('fixed bottom-5 right-5 z-40 flex flex-col overflow-hidden rounded-xl border bg-background shadow-2xl', wide ? 'h-[min(760px,88vh)] w-[min(1080px,calc(100vw-2.5rem))]' : 'h-[min(620px,80vh)] w-[min(420px,calc(100vw-2.5rem))]')} role="dialog" aria-label="묻고 찾기">
          <div className="flex items-center gap-2 border-b px-4 py-2.5">
            <MessageCircleQuestion size={17} className="text-primary" />
            <div className="flex-1 leading-tight">
              <div className="text-sm font-semibold">묻고 찾기</div>
              <div className="text-[11px] text-muted-foreground">내 권한 안의 기록에서 찾고, 시킨 일은 양식으로 확인받습니다</div>
            </div>
            <HelpScene topic="ask" title="묻고 찾기는 이렇게 동작합니다" />
            <button type="button" onClick={() => setWide(!wide)} aria-pressed={wide} aria-label={wide ? '작게 보기' : '넓게 보기'} title={wide ? '작게 보기' : '넓게 보기 — 대화와 양식을 나란히'} className="hidden rounded p-1 text-muted-foreground hover:bg-secondary lg:block">{wide ? <Minimize2 size={15} /> : <Maximize2 size={15} />}</button>
            <button onClick={() => setOpen(false)} aria-label="닫기" className="rounded p-1 text-muted-foreground hover:bg-secondary"><X size={16} /></button>
          </div>
          <AskChat wide={wide} autoFocus />
        </div>
      )}
    </>
  );
}
