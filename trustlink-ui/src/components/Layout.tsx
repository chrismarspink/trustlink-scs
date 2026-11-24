import { useEffect, useState, type ReactNode } from 'react';
import { Menu } from 'lucide-react';
import { useLocation } from 'react-router-dom';
import { Sidebar, navTrail } from '@/components/Sidebar';
import { NotificationBell } from '@/components/NotificationBell';
import { AskPanel } from '@/components/AskPanel';

// 통합 셸: 사이드바(브랜드·메뉴·사용자) + 경로 표시줄 + 본문. 제품/관리 모두 이 셸을 쓴다.
export function Layout({ children }: { children: ReactNode }) {
  const { pathname } = useLocation();
  const trail = navTrail(pathname);
  // 좁은 화면(휴대폰)에서는 사이드바를 접어 두고 메뉴 단추로 연다. 화면을 옮기면 닫는다.
  const [nav, setNav] = useState(false);
  useEffect(() => { setNav(false); }, [pathname]);
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
          <NotificationBell />
        </header>
        <main className="max-w-[1280px] px-4 py-5 lg:px-8 lg:py-6">{children}</main>
      </div>
      <AskPanel />
    </div>
  );
}
