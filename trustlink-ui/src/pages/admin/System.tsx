import { useEffect, useState } from 'react';
import { adminHealth, adminMailStatus, adminMailTest, type Health, type MailStatus } from '@/lib/api';
import { Button, Input } from '@/components/ui/primitives';
import { PageTitle, SectionTitle, Loading, Alert, Table, Th, Td } from './_ui';

function StatusDot({ ok }: { ok: boolean }) {
  return (
    <span className="inline-flex items-center gap-2">
      <span className={`inline-block h-2.5 w-2.5 rounded-full ${ok ? 'bg-emerald-500' : 'bg-red-500'}`} />
      {ok ? '정상' : '중단'}
    </span>
  );
}

// 통보 메일: 설정 상태와 시험 발송. 허용 목록이 있으면 그 주소로만 발송된다.
function MailCard() {
  const [m, setM] = useState<MailStatus | null>(null);
  const [to, setTo] = useState('');
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<{ tone: 'ok' | 'crit'; text: string } | null>(null);
  useEffect(() => { adminMailStatus().then((x) => { setM(x); setTo(x.allowlist[0] || ''); }).catch(() => setM(null)); }, []);
  if (!m) return null;
  const send = async () => {
    setBusy(true); setRes(null);
    try {
      await adminMailTest(to);
      setRes({ tone: 'ok', text: `${to} 로 시험 메일을 보냈습니다. 받은편지함(스팸함 포함)을 확인하세요.` });
    } catch (e) {
      setRes({ tone: 'crit', text: `발송 실패: ${String(e).replace(/^Error: /, '')}` });
    }
    setBusy(false);
  };
  return (
    <>
      <SectionTitle>통보 메일</SectionTitle>
      <Table>
        <tbody>
          <tr><Td className="w-48">메일 서버</Td><Td>{m.configured ? `${m.host}:${m.port}` : '미설정 (SMTP_HOST)'}</Td></tr>
          <tr><Td>보내는 주소</Td><Td>{m.from || '—'}</Td></tr>
          <tr><Td>발송 허용 목록</Td><Td>{m.allowlist.length ? `${m.allowlist.join(', ')} (이 주소로만 발송)` : '제한 없음'}</Td></tr>
        </tbody>
      </Table>
      {m.configured && (
        <div className="mt-3 flex max-w-xl items-center gap-2">
          <Input type="email" placeholder="받는 주소" value={to} onChange={(e) => setTo(e.target.value)} />
          <Button onClick={send} disabled={busy || !to}>{busy ? '보내는 중…' : '시험 메일 보내기'}</Button>
        </div>
      )}
      {res && <div className="mt-3"><Alert tone={res.tone}>{res.text}</Alert></div>}
    </>
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
          {h.dtrack !== undefined && <tr><Td>Dependency-Track (취약점 분석)</Td><Td><StatusDot ok={h.dtrack} /></Td></tr>}
        </tbody>
      </Table>
      <MailCard />
    </>
  );
}
