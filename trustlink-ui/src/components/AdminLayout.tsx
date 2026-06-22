import { useEffect, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { ShieldCheck, ArrowLeft } from 'lucide-react';
import { Button } from '@/components/ui/primitives';
import { Layout } from '@/components/Layout';
import { adminMe, bffLogin, ApiError, type Me } from '@/lib/api';

// 관리 영역 게이트. 통과 시 통합 셸(Layout)로 감싼다 — 사이드바에 제품+관리가 함께 보인다.
export function AdminLayout({ children }: { children: ReactNode }) {
  // me=undefined 로딩중, null 권한없음(403), Me 정상.
  const [me, setMe] = useState<Me | null | undefined>(undefined);

  useEffect(() => {
    document.title = 'TrustLink SCS 관리 콘솔';
    adminMe()
      .then(setMe)
      .catch((e: unknown) => {
        // 미인증/세션만료(401) → BFF OIDC 로그인(현재 경로 복귀), 권한없음(403) → 안내.
        if (e instanceof ApiError && e.status === 401) {
          bffLogin(window.location.pathname + window.location.search);
          return;
        }
        setMe(null);
      });
  }, []);

  if (me === undefined) {
    return <div className="flex h-screen items-center justify-center text-muted-foreground">권한 확인 중…</div>;
  }

  if (me === null) {
    return (
      <div className="flex h-screen flex-col items-center justify-center gap-3 text-center">
        <ShieldCheck className="text-accent" size={40} />
        <p className="text-lg font-semibold">관리자 권한이 필요합니다</p>
        <p className="text-sm text-muted-foreground">이 페이지는 admins 그룹만 접근할 수 있습니다.</p>
        <div className="mt-2 flex gap-2">
          <Button variant="default" size="sm" onClick={() => bffLogin('/admin')}>
            다른 계정으로 다시 로그인
          </Button>
          <Link to="/">
            <Button variant="outline" size="sm">
              <ArrowLeft size={16} /> 제품 페이지로
            </Button>
          </Link>
        </div>
      </div>
    );
  }

  return <Layout>{children}</Layout>;
}
