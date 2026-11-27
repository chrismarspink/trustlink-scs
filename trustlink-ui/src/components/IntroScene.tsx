import { useState } from 'react';
import { ChevronDown, CircleHelp } from 'lucide-react';

// 안내 장면(막대 인형)을 본문에 바로 보여 준다 — 상단 물음표 팝업과 같은 재생기(/intro.html)의 제품 소개.
// 정적 내용이라 로그인·권한과 무관하게 보인다. foldKey 를 주면 접어 둘 수 있고(브라우저에 기억), 기본은 펼침.
export function IntroScene({ foldKey }: { foldKey?: string }) {
  const [open, setOpen] = useState(() => { try { return !foldKey || localStorage.getItem(foldKey) !== '0'; } catch { return true; } });
  const toggle = () => {
    try { if (open) localStorage.setItem(foldKey!, '0'); else localStorage.removeItem(foldKey!); } catch { /* 기억 못 해도 접고 펴진다 */ }
    setOpen(!open);
  };
  return (
    <section aria-label="안내 장면" className="overflow-hidden rounded-xl border bg-white">
      <div className="flex items-center gap-2 border-b px-4 py-2.5">
        <CircleHelp size={16} className="text-violet-700" />
        <h2 className="min-w-0 flex-1 truncate text-sm font-semibold">TrustLink 안내 장면 — 한 권의 장부, 하나의 흐름</h2>
        {foldKey && (
          <button type="button" onClick={toggle} aria-expanded={open} className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs text-muted-foreground hover:bg-secondary hover:text-foreground">
            {open ? '접기' : '펼치기'} <ChevronDown size={14} className={open ? 'rotate-180' : ''} />
          </button>
        )}
      </div>
      {open && <iframe src="/intro.html" title="TrustLink 안내 장면" loading="lazy" className="block h-[min(500px,70vh)] w-full border-0 bg-white" />}
    </section>
  );
}
