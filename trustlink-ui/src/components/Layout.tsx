import type { ReactNode } from 'react';
import { AppHeader } from '@/components/AppHeader';
import { Sidebar } from '@/components/Sidebar';

// 통합 셸: 상단바 + 공용 사이드바(제품 + 관리) + 본문. 제품/관리 모두 이 셸을 쓴다.
export function Layout({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen">
      <AppHeader />
      <div className="flex">
        <Sidebar />
        <main className="min-w-0 flex-1 px-7 py-6">{children}</main>
      </div>
    </div>
  );
}
