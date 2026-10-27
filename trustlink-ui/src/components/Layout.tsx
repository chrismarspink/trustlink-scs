import type { ReactNode } from 'react';
import { useLocation } from 'react-router-dom';
import { Sidebar, navTrail } from '@/components/Sidebar';

// 통합 셸: 사이드바(브랜드·메뉴·사용자) + 경로 표시줄 + 본문. 제품/관리 모두 이 셸을 쓴다.
export function Layout({ children }: { children: ReactNode }) {
  const trail = navTrail(useLocation().pathname);
  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="min-w-0 flex-1">
        <header className="flex h-14 items-center border-b px-8 text-sm text-muted-foreground">
          {trail && (
            <>
              {trail[0]}<span className="mx-2 text-zinc-300">/</span><span className="text-foreground">{trail[1]}</span>
            </>
          )}
        </header>
        <main className="max-w-[1280px] px-8 py-6">{children}</main>
      </div>
    </div>
  );
}
