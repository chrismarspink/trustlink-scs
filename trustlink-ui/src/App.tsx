import { lazy, Suspense, useEffect, useState } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { isAuthed, oidcLogin } from '@/lib/api';
import { Layout } from '@/components/Layout';
import Artifacts from '@/pages/Artifacts';
import ArtifactDetail from '@/pages/ArtifactDetail';
import GettingStarted from '@/pages/docs/GettingStarted';
import ShareGuide from '@/pages/docs/ShareGuide';
import Trust from '@/pages/docs/Trust';
import Vuln from '@/pages/docs/Vuln';
import Rbac from '@/pages/docs/Rbac';

// 관리 콘솔은 별도 청크로 분리(코드 스플릿) — /admin 진입 시에만 로드.
const AdminApp = lazy(() => import('@/AdminApp'));

const Centered = ({ children }: { children: string }) => (
  <div className="flex h-screen items-center justify-center text-muted-foreground">{children}</div>
);

// 제품(레지스트리) 영역: zot 세션 게이트. 미인증 → zot OIDC 로그인.
function ProductApp() {
  const [authed, setAuthed] = useState<boolean | null>(null);

  useEffect(() => {
    isAuthed()
      .then((ok) => {
        if (!ok) {
          oidcLogin();
          return;
        }
        setAuthed(true);
      })
      .catch(() => oidcLogin());
  }, []);

  if (authed === null) return <Centered>로그인 확인 중…</Centered>;

  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Artifacts />} />
        <Route path="/docs" element={<GettingStarted />} />
        <Route path="/docs/share" element={<ShareGuide />} />
        <Route path="/docs/trust" element={<Trust />} />
        <Route path="/docs/vuln" element={<Vuln />} />
        <Route path="/docs/rbac" element={<Rbac />} />
        <Route path="/artifact/:name/:tag" element={<ArtifactDetail />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  );
}

function App() {
  return (
    <Routes>
      <Route
        path="/admin/*"
        element={
          <Suspense fallback={<Centered>관리 콘솔 로딩…</Centered>}>
            <AdminApp />
          </Suspense>
        }
      />
      <Route path="/*" element={<ProductApp />} />
    </Routes>
  );
}

export default App;
