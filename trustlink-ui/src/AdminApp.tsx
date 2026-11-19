import { Routes, Route, Navigate } from 'react-router-dom';
import { AdminLayout } from '@/components/AdminLayout';
import Dashboard from '@/pages/admin/Dashboard';
import AdminUsers from '@/pages/admin/Users';
import Capacity from '@/pages/admin/Capacity';
import Logs from '@/pages/admin/Logs';
import Registry from '@/pages/admin/Registry';
import System from '@/pages/admin/System';
import Acl from '@/pages/admin/Acl';
import Storage from '@/pages/admin/Storage';
import Orgs from '@/pages/admin/Orgs';
import Access from '@/pages/admin/Access';
import Robots from '@/pages/admin/Robots';
import Notify from '@/pages/admin/Notify';
import Mirror from '@/pages/admin/Mirror';
import AIConfigPage from '@/pages/admin/AIConfig';
import Regulations from '@/pages/admin/Regulations';
import RegReportPrint from '@/pages/admin/RegReportPrint';
import Compliance from '@/pages/admin/Compliance';
import Reports from '@/pages/admin/Reports';
import Upstream from '@/pages/admin/Upstream';
import UpstreamPrint from '@/pages/admin/UpstreamPrint';

// 관리 콘솔 영역: BFF 세션 + admins 그룹 게이트(AdminLayout 내부).
// 별도 모듈로 분리되어 lazy 로드된다(코드 스플릿) → 비-admin 사용자는 이 번들을 받지 않는다.
export default function AdminApp() {
  return (
    <Routes>
      {/* 보고서 인쇄(PDF) 페이지는 사이드바 없이 — API 는 BFF 가 admins 로 막는다 */}
      <Route path="regs/print/:id" element={<RegReportPrint />} />
      <Route path="upstream/print/:id" element={<UpstreamPrint />} />
      <Route path="*" element={<AdminPages />} />
    </Routes>
  );
}

function AdminPages() {
  return (
    <AdminLayout>
      <Routes>
        <Route path="" element={<Dashboard />} />
        <Route path="users" element={<AdminUsers />} />
        <Route path="orgs" element={<Orgs />} />
        <Route path="access" element={<Access />} />
        <Route path="robots" element={<Robots />} />
        <Route path="notify" element={<Notify />} />
        <Route path="capacity" element={<Capacity />} />
        <Route path="logs" element={<Logs />} />
        <Route path="registry" element={<Registry />} />
        <Route path="system" element={<System />} />
        <Route path="acl" element={<Acl />} />
        <Route path="storage" element={<Storage />} />
        <Route path="mirror" element={<Mirror />} />
        <Route path="compliance" element={<Compliance />} />
        <Route path="ai" element={<AIConfigPage />} />
        <Route path="regs" element={<Regulations />} />
        <Route path="reports" element={<Reports />} />
        <Route path="upstream" element={<Upstream />} />
        <Route path="*" element={<Navigate to="/admin" replace />} />
      </Routes>
    </AdminLayout>
  );
}
