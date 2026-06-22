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
import CaOverview from '@/pages/admin/ca/Overview';
import CaIssue from '@/pages/admin/ca/Issue';
import CaCertificates from '@/pages/admin/ca/Certificates';
import CaRecipients from '@/pages/admin/ca/Recipients';
import CaAudit from '@/pages/admin/ca/Audit';

// 관리 콘솔 영역: BFF 세션 + admins 그룹 게이트(AdminLayout 내부).
// 별도 모듈로 분리되어 lazy 로드된다(코드 스플릿) → 비-admin 사용자는 이 번들을 받지 않는다.
export default function AdminApp() {
  return (
    <AdminLayout>
      <Routes>
        <Route path="" element={<Dashboard />} />
        <Route path="users" element={<AdminUsers />} />
        <Route path="capacity" element={<Capacity />} />
        <Route path="logs" element={<Logs />} />
        <Route path="registry" element={<Registry />} />
        <Route path="system" element={<System />} />
        <Route path="acl" element={<Acl />} />
        <Route path="ca" element={<CaOverview />} />
        <Route path="ca/issue" element={<CaIssue />} />
        <Route path="ca/certs" element={<CaCertificates />} />
        <Route path="ca/recipients" element={<CaRecipients />} />
        <Route path="ca/audit" element={<CaAudit />} />
        <Route path="storage" element={<Storage />} />
        <Route path="*" element={<Navigate to="/admin" replace />} />
      </Routes>
    </AdminLayout>
  );
}
