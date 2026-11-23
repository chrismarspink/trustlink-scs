import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Workflow } from 'lucide-react';
import { adminAutoResponse, type AutoRun } from '@/lib/api';

// 대시보드 맨 위: 자동 대응이 만든 메일 중 관리자 선택(승인)을 기다리는 것.
export default function AutoPending() {
  const [runs, setRuns] = useState<AutoRun[] | null>(null);
  useEffect(() => { adminAutoResponse().then((d) => setRuns(d.runs.filter((r) => r.state === 'waiting'))).catch(() => setRuns([])); }, []);
  if (!runs?.length) return null;
  const cust = runs.filter((r) => r.noticeId).length, dev = runs.length - cust;
  return (
    <div className="mb-4 rounded-lg border-2 border-amber-300 bg-amber-50 p-3">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Workflow size={16} className="text-amber-700" />
        <b className="text-amber-900">자동 대응 — 관리자 선택 대기 {runs.length}건</b>
        <span className="text-xs text-amber-800">고객 통지 {cust} · 개발자 수정 요청 {dev}</span>
        <Link to="/admin/auto-response" className="ml-auto rounded-md bg-amber-600 px-3 py-1 text-xs font-semibold text-white hover:bg-amber-700">선택하러 가기</Link>
      </div>
      <ul className="mt-2 space-y-1 text-xs text-slate-700">
        {runs.slice(0, 4).map((r) => (
          <li key={r.id} className="flex flex-wrap gap-x-2">
            <span className="rounded bg-white px-1.5 font-medium">{r.noticeId ? '고객 통지' : '개발자 요청'}</span>
            <b className="font-mono">{r.vulnId}</b>
            <span>{r.repo.split('/').pop()} {r.tag} · {r.component}</span>
            <span className="text-muted-foreground">{r.noticeId ? `패치 ${r.fixTag} → ${(r.customers || []).join(', ')}` : `패치 없음${r.customers?.length ? ` · 사용 고객 ${r.customers.join(', ')}` : ''}`}</span>
          </li>
        ))}
        {runs.length > 4 && <li className="text-muted-foreground">외 {runs.length - 4}건</li>}
      </ul>
    </div>
  );
}
