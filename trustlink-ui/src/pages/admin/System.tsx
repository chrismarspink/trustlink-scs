import { useEffect, useState } from 'react';
import { adminHealth, type Health } from '@/lib/api';
import { PageTitle, Loading, Alert, Table, Th, Td } from './_ui';

function StatusDot({ ok }: { ok: boolean }) {
  return (
    <span className="inline-flex items-center gap-2">
      <span className={`inline-block h-2.5 w-2.5 rounded-full ${ok ? 'bg-emerald-500' : 'bg-red-500'}`} />
      {ok ? '정상' : '중단'}
    </span>
  );
}

export default function System() {
  const [h, setH] = useState<Health | null>(null);
  const [err, setErr] = useState('');

  useEffect(() => {
    adminHealth().then(setH).catch((e) => setErr(String(e)));
  }, []);

  if (err) return (<><PageTitle>시스템 상태</PageTitle><Alert tone="crit">오류: {err}</Alert></>);
  if (!h) return (<><PageTitle>시스템 상태</PageTitle><Loading /></>);

  return (
    <>
      <PageTitle>시스템 상태</PageTitle>
      <Table>
        <thead>
          <tr><Th>구성요소</Th><Th>상태</Th></tr>
        </thead>
        <tbody>
          <tr><Td>zot (레지스트리)</Td><Td><StatusDot ok={h.zot} /></Td></tr>
          <tr><Td>Keycloak (인증)</Td><Td><StatusDot ok={h.keycloak} /></Td></tr>
        </tbody>
      </Table>
    </>
  );
}
