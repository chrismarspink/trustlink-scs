import { useEffect, useState } from 'react';
import { adminNotifyLog, adminNotifySync, type NoticeLog } from '@/lib/api';
import { Badge, Button } from '@/components/ui/primitives';
import { PageHeader, StatCard, Alert, Loading, Table, Th, Td, selectCls } from './_ui';

const fmt = (t: string) => (t ? new Date(t).toLocaleString('ko-KR') : '—');

// 관리 › 취약점 통보: 감시 대상 동기화 상태와 보낸 통보 기록(받는 사람·메일 결과).
export default function Notify() {
  const [log, setLog] = useState<NoticeLog | null>(null);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');
  // 쪽 나눔: 기간(최근 N일, 0=전체)·쪽 크기·쪽 번호는 서버가 잘라서 준다.
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(20);
  const [days, setDays] = useState(0);
  const load = () => adminNotifyLog(page, size, days).then(setLog).catch((e) => setErr(String(e)));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { load(); }, [page, size, days]);
  const pages = log ? Math.max(1, Math.ceil(log.total / log.size)) : 1;

  const sync = async () => {
    setBusy(true); setMsg('');
    try { setMsg((await adminNotifySync()).message); load(); } catch (e) { setMsg(String(e)); }
    setBusy(false);
  };

  return (
    <>
      <PageHeader title="취약점 통보" description="새 취약점은 그 제품 업로드 권한자와 관리자에게, VEX 판단 결과는 그 제품을 받는 고객에게 통보합니다."
        actions={<Button variant="outline" onClick={sync} disabled={busy}>{busy ? '동기화 중…' : '지금 동기화'}</Button>} />
      {err && <Alert tone="crit">오류: {err}</Alert>}
      {msg && <div className="mb-4"><Alert tone="ok">동기화: {msg}</Alert></div>}
      {!log ? <Loading /> : (
        <>
          <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-4">
            <StatCard label="감시 중인 버전" value={log.tracked} />
            <StatCard label="마지막 동기화" value={<span className="text-base">{fmt(log.lastSync)}</span>} />
            <StatCard label="동기화 결과" value={<span className="text-base">{log.lastSyncMsg || '—'}</span>} />
            <StatCard label="모으는 중" value={log.pending} />
          </div>
          <div className="mb-2 flex flex-wrap items-center gap-2 text-sm">
            <select className={selectCls} value={days} onChange={(e) => { setDays(+e.target.value); setPage(1); }} aria-label="기간">
              <option value={0}>전체 기간</option>
              <option value={1}>최근 1일</option>
              <option value={7}>최근 7일</option>
              <option value={30}>최근 30일</option>
              <option value={90}>최근 90일</option>
            </select>
            <select className={selectCls} value={size} onChange={(e) => { setSize(+e.target.value); setPage(1); }} aria-label="쪽당 건수">
              {[20, 50, 100].map((n) => <option key={n} value={n}>{n}건씩</option>)}
            </select>
            <span className="text-muted-foreground">총 {log.total}건</span>
          </div>
          <Table>
            <thead>
              <tr><Th>시각</Th><Th>대상</Th><Th>내용</Th><Th>받는 사람</Th><Th>메일</Th></tr>
            </thead>
            <tbody>
              {log.items.length === 0 ? (
                <tr><Td colSpan={5} className="text-center text-muted-foreground">보낸 통보가 없습니다.</Td></tr>
              ) : log.items.map((n) => (
                <tr key={n.id}>
                  <Td className="whitespace-nowrap text-xs">{fmt(n.time)}</Td>
                  <Td><Badge variant={n.audience === 'customer' ? 'warn' : 'muted'}>{n.audience === 'customer' ? '고객' : '내부'}</Badge></Td>
                  <Td className="text-sm">{n.title.replace(/^\[TrustLink\] /, '')}</Td>
                  <Td className="text-xs">{n.to?.join(', ') || '—'}</Td>
                  <Td className="text-xs">
                    {n.mailError ? <span className="text-red-600">실패: {n.mailError}</span>
                      : n.mailed?.length ? `보냄 ${n.mailed.length}` : '—'}
                    {!!n.dropped?.length && <div className="text-muted-foreground">허용 목록 밖 {n.dropped.length}</div>}
                    {!!n.noEmail?.length && <div className="text-amber-700" title={n.noEmail.join(', ')}>이메일 없음 {n.noEmail.length}</div>}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
          {pages > 1 && (
            <div className="mt-3 flex items-center justify-center gap-2 text-sm">
              <Button size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage(1)}>처음</Button>
              <Button size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage(page - 1)}>이전</Button>
              <span className="px-2 tabular-nums">{page} / {pages}</span>
              <Button size="sm" variant="outline" disabled={page >= pages} onClick={() => setPage(page + 1)}>다음</Button>
              <Button size="sm" variant="outline" disabled={page >= pages} onClick={() => setPage(pages)}>마지막</Button>
            </div>
          )}
        </>
      )}
    </>
  );
}
