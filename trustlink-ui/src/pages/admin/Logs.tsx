import { useCallback, useEffect, useState } from 'react';
import { Search } from 'lucide-react';
import { adminLogs, type LogsResult } from '@/lib/api';
import { Button, Input } from '@/components/ui/primitives';
import { PageTitle, Alert, selectCls } from './_ui';

export default function Logs() {
  const [q, setQ] = useState('');
  const [level, setLevel] = useState('');
  const [page, setPage] = useState(1);
  const [res, setRes] = useState<LogsResult | null>(null);
  const [err, setErr] = useState('');

  const load = useCallback(async (p: number) => {
    setErr('');
    try {
      setRes(await adminLogs({ page: p, q, level }));
    } catch (e) {
      setErr(String(e));
    }
  }, [q, level]);

  // 최초 로드 + 페이지 변경 시 조회. 검색/레벨 변경은 검색 버튼으로 page=1 재조회.
  useEffect(() => { load(page); }, [page, load]);

  const search = () => { if (page === 1) load(1); else setPage(1); };

  return (
    <>
      <PageTitle>로그</PageTitle>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="relative">
          <Search size={15} className="absolute left-2.5 top-2.5 text-muted-foreground" />
          <Input className="w-56 pl-8" placeholder="검색어" value={q}
            onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && search()} />
        </div>
        <select className={selectCls} value={level} onChange={(e) => setLevel(e.target.value)}>
          <option value="">전체</option>
          <option value="info">info</option>
          <option value="warn">warn</option>
          <option value="error">error</option>
        </select>
        <Button size="sm" variant="outline" onClick={search}>검색</Button>
        {res && (
          <span className="text-xs text-muted-foreground">
            {res.page}/{res.pages || 1} 페이지 · 총 {res.total}줄
          </span>
        )}
      </div>

      {err && <Alert tone="crit">오류: {err}</Alert>}
      {res?.error && <Alert tone="warn">{res.error}</Alert>}

      <div className="rounded-lg border bg-card">
        {!res ? (
          <p className="p-4 text-sm text-muted-foreground">로딩…</p>
        ) : res.lines.length === 0 ? (
          <p className="p-4 text-sm text-muted-foreground">결과 없음</p>
        ) : (
          res.lines.map((l, i) => (
            <div key={i} className="whitespace-pre-wrap break-all border-b px-3 py-1 font-mono text-xs last:border-0">
              {l}
            </div>
          ))
        )}
      </div>

      <div className="mt-3 flex gap-2">
        <Button size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>이전</Button>
        <Button size="sm" variant="outline" disabled={!!res && page >= (res.pages || 1)} onClick={() => setPage((p) => p + 1)}>다음</Button>
      </div>
    </>
  );
}
