import { useEffect, useState } from 'react';
import { adminMetrics, type Metrics } from '@/lib/api';
import { fmtBytes } from '@/lib/utils';
import { PageTitle, SectionTitle, StatCard, Loading, Alert, Table, Th, Td } from './_ui';

export default function Capacity() {
  const [mt, setMt] = useState<Metrics | null>(null);
  const [err, setErr] = useState('');

  useEffect(() => {
    adminMetrics().then(setMt).catch((e) => setErr(String(e)));
  }, []);

  if (err) return (<><PageTitle>용량</PageTitle><Alert tone="crit">오류: {err}</Alert></>);
  if (!mt) return (<><PageTitle>용량</PageTitle><Loading /></>);

  const d = mt.disk;
  const pct = d?.usedPct || 0;
  const repos = [...(mt.repos || [])].sort((a, b) => b.bytes - a.bytes);

  return (
    <>
      <PageTitle>용량</PageTitle>
      {pct >= 95 ? (
        <Alert tone="crit">🚨 위험: 디스크 {pct}% — 즉시 정리/확장 필요</Alert>
      ) : pct >= 85 ? (
        <Alert tone="warn">⚠️ 경고: 디스크 {pct}% — 리텐션 강화/확장 검토</Alert>
      ) : (
        <Alert tone="ok">디스크 여유 충분 ({pct}% 사용)</Alert>
      )}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="전체" value={fmtBytes(d?.totalBytes || 0)} />
        <StatCard label="사용" value={fmtBytes(d?.usedBytes || 0)} />
        <StatCard label="여유" value={fmtBytes(d?.freeBytes || 0)} />
        <StatCard label="경로" value={<span className="break-all text-sm font-mono">{d?.path || '-'}</span>} />
      </div>

      <div className="my-5 h-2.5 overflow-hidden rounded-full bg-secondary">
        <div className="h-full bg-accent" style={{ width: `${pct}%` }} />
      </div>

      <SectionTitle>레포지토리별 사용량</SectionTitle>
      {repos.length === 0 ? (
        <p className="text-sm text-muted-foreground">repo 메트릭 없음 (zot metrics 비활성 또는 데이터 없음)</p>
      ) : (
        <Table>
          <thead>
            <tr><Th>레포</Th><Th className="text-right">용량</Th></tr>
          </thead>
          <tbody>
            {repos.map((r) => (
              <tr key={r.repo}><Td className="font-mono">{r.repo}</Td><Td className="text-right">{fmtBytes(r.bytes)}</Td></tr>
            ))}
          </tbody>
        </Table>
      )}
    </>
  );
}
