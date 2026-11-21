import { useState } from 'react';
import { ChevronDown, ChevronUp, ExternalLink, PlayCircle } from 'lucide-react';

// 초기 화면 상단의 제품 소개(막대 인형 장면). 본문은 public/intro.html — 새 창으로도 열 수 있다.
// 접은 상태는 이 브라우저에만 기억한다(저장소를 못 쓰면 늘 펼친 채로 시작).
const KEY = 'tl.intro.open';

export function IntroCard() {
  const [open, setOpen] = useState(() => {
    try { return localStorage.getItem(KEY) !== '0'; } catch { return true; }
  });
  const toggle = () => {
    setOpen(!open);
    try { localStorage.setItem(KEY, open ? '0' : '1'); } catch { /* 저장 못 해도 동작에는 지장 없음 */ }
  };
  return (
    <div className="mb-6 overflow-hidden rounded-lg border border-violet-200 bg-violet-50/40">
      <div className="flex items-center gap-2 px-4 py-2">
        <PlayCircle size={18} className="text-violet-600" />
        <span className="text-sm font-semibold">TrustLink 소개</span>
        <span className="hidden text-xs text-muted-foreground sm:inline">저장부터 검증·통보·규제 대응까지 한눈에</span>
        <span className="flex-1" />
        <a href="/intro.html" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-violet-700 hover:underline">
          <ExternalLink size={13} /> 크게 보기
        </a>
        <button onClick={toggle} className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-slate-600 hover:bg-violet-100" aria-expanded={open}>
          {open ? <><ChevronUp size={14} /> 접기</> : <><ChevronDown size={14} /> 펼치기</>}
        </button>
      </div>
      {open && <iframe src="/intro.html" title="TrustLink 제품 소개" className="block h-[440px] w-full border-0 border-t border-violet-100 bg-white" loading="lazy" />}
    </div>
  );
}
