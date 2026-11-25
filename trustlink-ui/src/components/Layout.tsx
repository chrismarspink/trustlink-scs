import { useEffect, useState, type ReactNode } from 'react';
import { Menu } from 'lucide-react';
import { useLocation, useNavigate } from 'react-router-dom';
import { canVT, withVT } from '@/lib/vt';
import { Sidebar, navTrail } from '@/components/Sidebar';
import { NotificationBell } from '@/components/NotificationBell';
import { AskPanel } from '@/components/AskPanel';
import { AgentButton } from '@/components/Agent';

// 통합 셸: 사이드바(브랜드·메뉴·사용자) + 경로 표시줄 + 본문. 제품/관리 모두 이 셸을 쓴다.
export function Layout({ children }: { children: ReactNode }) {
  const { pathname } = useLocation();
  const trail = navTrail(pathname);
  // 좁은 화면(휴대폰)에서는 사이드바를 접어 두고 메뉴 단추로 연다. 화면을 옮기면 닫는다.
  const [nav, setNav] = useState(false);
  useEffect(() => { setNav(false); }, [pathname]);
  // 화면 전환: 앱 안의 링크를 누르면 본문이 살짝 밀리며 바뀐다. 목록의 한 줄을 눌러 상세로 갈 때는 그 줄의 이름이 상세 제목으로 옮겨 간다.
  const navigate = useNavigate();
  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || !canVT()) return;
      const a = (e.target as Element | null)?.closest?.('a[href]') as HTMLAnchorElement | null;
      if (!a || a.target || a.hasAttribute('download') || a.origin !== window.location.origin) return;
      const to = a.pathname + a.search + a.hash;
      if (/^\/(api|v2|auth|zot)\//.test(a.pathname) || /\.[a-z0-9]{2,5}$/i.test(a.pathname) || to === window.location.pathname + window.location.search + window.location.hash) return;
      e.preventDefault();
      e.stopPropagation();
      const hero = a.closest('[data-vt-row], tr')?.querySelector<HTMLElement>('[data-vt-hero]') || null;
      if (hero) hero.style.viewTransitionName = 'hero';
      withVT(() => navigate(to), () => { if (hero) hero.style.viewTransitionName = ''; });
    };
    document.addEventListener('click', onClick, true);
    return () => document.removeEventListener('click', onClick, true);
  }, [navigate]);
  return (
    <div className="flex min-h-screen">
      <Sidebar open={nav} onClose={() => setNav(false)} />
      <div className="min-w-0 flex-1">
        <header className="sticky top-0 z-20 flex h-14 items-center border-b bg-background px-3 text-sm text-muted-foreground lg:static lg:px-8">
          <button type="button" onClick={() => setNav(true)} aria-label="메뉴 열기" className="mr-1 rounded-md p-2.5 text-foreground hover:bg-secondary lg:hidden"><Menu size={20} /></button>
          {trail && (
            <span className="flex min-w-0 items-center">
              {trail.slice(0, -1).map((t) => <span key={t} className="hidden whitespace-nowrap sm:inline">{t}<span className="mx-2 text-zinc-300">/</span></span>)}
              <span className="truncate text-foreground">{trail[trail.length - 1]}</span>
            </span>
          )}
          <div className="ml-auto flex shrink-0 items-center gap-1 pl-2"><AgentButton /><NotificationBell /></div>
        </header>
        <main className="vt-view max-w-[1280px] px-4 py-5 lg:px-8 lg:py-6">{children}</main>
      </div>
      <AskPanel />
    </div>
  );
}
