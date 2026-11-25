import { useEffect, useState } from 'react';
import { adminHealth, adminMailStatus, type Health, type MailStatus } from '@/lib/api';
import MailCompose from './MailCompose';
import { PageTitle, SectionTitle, Loading, Alert, Table, Th, Td } from './_ui';

function StatusDot({ ok }: { ok: boolean }) {
  return (
    <span className="inline-flex items-center gap-2">
      <span className={`inline-block h-2.5 w-2.5 rounded-full ${ok ? 'bg-emerald-500' : 'bg-red-500'}`} />
      {ok ? '정상' : '중단'}
    </span>
  );
}

// 메일 로고: 자동 메일 맨 위에 들어가는 회사 로고를 올리고, 메일 모양을 미리 본다.
function MailLogo() {
  const [msg, setMsg] = useState('');
  const [err, setErr] = useState('');
  const [ver, setVer] = useState(0); // 미리보기 다시 불러오기
  const [show, setShow] = useState(false);
  const put = async (f: File | undefined) => {
    setMsg(''); setErr('');
    if (!f) return;
    if (f.size > 200 * 1024) { setErr('로고는 200KB 이하여야 합니다(메일마다 함께 나갑니다).'); return; }
    try {
      const r = await fetch('/api/mail/logo', { method: 'PUT', body: f, credentials: 'same-origin' });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.error || `올리지 못했습니다(${r.status})`);
      setMsg('로고를 바꿨습니다. 다음 메일부터 적용됩니다.'); setVer((v) => v + 1); setShow(true);
    } catch (e) { setErr(String(e).replace(/^Error:\s*/, '')); }
  };
  const del = async () => {
    if (!confirm('메일 로고를 지울까요? 로고 없이 회사 이름만 나갑니다.')) return;
    setMsg(''); setErr('');
    const r = await fetch('/api/mail/logo', { method: 'DELETE', credentials: 'same-origin' });
    if (r.ok) { setMsg('로고를 지웠습니다.'); setVer((v) => v + 1); } else setErr(`지우지 못했습니다(${r.status})`);
  };
  return (
    <>
      <SectionTitle>메일 로고와 모양</SectionTitle>
      <div className="rounded-lg border bg-card p-4 text-sm">
        <p className="mb-3 text-muted-foreground">자동으로 나가는 메일(승인 요청, 고객 통지, 취약점 통보) 맨 위에 들어가는 회사 로고입니다. PNG·JPEG·GIF, 200KB 이하.</p>
        <div className="flex flex-wrap items-center gap-2">
          <label htmlFor="mail-logo-file" className="inline-flex h-9 cursor-pointer items-center rounded-md bg-primary px-4 text-sm font-semibold text-primary-foreground">로고 올리기</label>
          <input id="mail-logo-file" type="file" accept="image/png,image/jpeg,image/gif" className="sr-only" onChange={(e) => { put(e.target.files?.[0]); e.target.value = ''; }} />
          <button type="button" onClick={del} className="h-9 rounded-md border px-3 hover:bg-secondary">로고 지우기</button>
          <button type="button" onClick={() => setShow(!show)} aria-expanded={show} className="h-9 rounded-md border px-3 hover:bg-secondary">{show ? '미리보기 닫기' : '메일 모양 미리보기'}</button>
        </div>
        {msg && <p className="mt-2 text-emerald-700" role="status">{msg}</p>}
        {err && <p className="mt-2 text-red-700" role="alert">{err}</p>}
        {show && <iframe key={ver} src={`/api/mail/layout-preview?v=${ver}`} title="메일 모양 미리보기(예시 내용)" sandbox="" className="mt-3 block h-[520px] w-full rounded-md border bg-white" />}
      </div>
    </>
  );
}

// 통보 메일: 설정 상태 + 현황 메일 보내기(항목 체크·보고서 PDF 첨부·추천). 허용 목록이 있으면 그 주소로만 발송된다.
function MailCard() {
  const [m, setM] = useState<MailStatus | null>(null);
  useEffect(() => { adminMailStatus().then(setM).catch(() => setM(null)); }, []);
  if (!m) return null;
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
      <MailLogo />
      {m.configured && (
        <>
          <SectionTitle>현황 메일 보내기</SectionTitle>
          <MailCompose allowlist={m.allowlist} />
        </>
      )}
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
