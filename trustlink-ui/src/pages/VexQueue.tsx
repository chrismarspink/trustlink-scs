import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ShieldQuestion, RefreshCw, ListChecks, Flame } from 'lucide-react';
import { AIBadge, AIIcon } from '@/components/AIBadge';
import { vexQueue, aiVexBatchStart, aiStatus, type VexQueue as Q, type VexQueueRow, type AIStatus } from '@/lib/api';
import { Badge, Button, Card } from '@/components/ui/primitives';

const fmt = (t?: string) => (t ? new Date(t).toLocaleString('ko-KR') : '');

// VEX 판단 대기열: 감시 중인 전 제품·버전의 미판단 취약점을 급한 순(KEV → 치명 → 높음)으로 모은다.
// 판단·저장·발행은 제품 화면의 "취약점 분석 · VEX" 에서. 여기서는 AI 일괄 판정을 바로 걸 수 있다.
export default function VexQueue() {
  const [q, setQ] = useState<Q | null>(null);
  const [ai, setAi] = useState<AIStatus | null>(null);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState('');
  const [msg, setMsg] = useState('');
  const load = (refresh = false) => vexQueue(refresh).then(setQ).catch((e) => setErr(String(e)));
  useEffect(() => {
    load();
    aiStatus().then(setAi).catch(() => setAi(null));
  }, []);
  // 일괄 판정이 돌고 있으면 10초마다 갱신
  useEffect(() => {
    if (!q?.summary?.running) return;
    const t = setTimeout(() => load(true), 10_000);
    return () => clearTimeout(t);
  }, [q]);

  const batch = async (r: VexQueueRow) => {
    setBusy(r.project); setMsg('');
    try {
      const b = await aiVexBatchStart({ project: r.project, repo: r.repo, tag: r.tag, limit: 20 });
      setMsg(b.state === 'done' && !b.total ? `${r.repo}:${r.tag} — 미판단 항목이 없습니다` : `${r.repo}:${r.tag} — AI 일괄 판정 시작(우선순위 순 최대 20건)`);
      load(true);
    } catch (e) { setMsg(String(e)); }
    setBusy('');
  };

  const aiOn = !!(ai?.enabled && ai.reachable);
  const s = q?.summary || {};
  return (
    <div className="mx-auto max-w-6xl">
      <div className="mb-5 flex flex-wrap items-start gap-3">
        <div className="flex-1">
          <h1 className="flex items-center gap-2 text-2xl font-bold"><ShieldQuestion size={22} /> VEX 판단</h1>
          <p className="mt-1 text-sm text-muted-foreground">감시 중인 모든 제품·버전의 판단 안 된 취약점을 급한 순(실제 악용 KEV → 치명 → 높음)으로 모았습니다. 판단과 VEX 발행은 각 제품 화면에서 합니다.</p>
        </div>
        <Button variant="outline" onClick={() => { setQ(null); load(true); }}><RefreshCw size={14} /> 새로 집계</Button>
      </div>

      <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-5">
        {[['판단 대기', s.pending, ''], ['실제 악용(KEV)', s.pendKev, 'text-red-700'], ['치명', s.pendCritical, 'text-red-600'], ['높음', s.pendHigh, 'text-orange-600'], ['영향 있음(조치)', s.affected, 'text-amber-700']].map(([l, v, c]) => (
          <Card key={l as string} className="p-3">
            <div className="text-xs text-muted-foreground">{l}</div>
            <div className={`mt-1 text-2xl font-bold tabular-nums ${c}`}>{q ? (v ?? 0) : '…'}</div>
          </Card>
        ))}
      </div>

      <div className={`mb-4 flex flex-wrap items-center gap-2 rounded-md border p-3 text-sm ${aiOn ? 'border-violet-200 bg-violet-50/50' : 'border-dashed'}`}>
        <AIIcon size={22} />
        {aiOn ? (
          <span>AI 판단 초안 사용 가능 — <b>{ai?.model}</b>{ai?.mode === 'local' ? ' (서버 내부 LLM, 외부 전송 없음 · 건당 1~2분)' : ''}. 초안은 저장되지 않으며 제품 화면에서 확인 후 저장합니다.{s.drafts ? ` 저장 대기 초안 ${s.drafts}건.` : ''}</span>
        ) : (
          <span className="text-muted-foreground">AI 연결(VEX 용도)이 꺼져 있습니다. 켜지면 여기서 제품별 AI 일괄 판정을 걸 수 있습니다.</span>
        )}
      </div>
      {msg && <div className="mb-3 text-sm text-violet-800">{msg}</div>}
      {err && <div className="mb-3 text-sm text-red-600">{err}</div>}
      {q && !q.dt && <div className="text-sm text-muted-foreground">Dependency-Track 미설정 — 분석 기능이 꺼져 있습니다.</div>}

      <Card className="overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-secondary/50 text-left text-xs text-muted-foreground">
            <tr>
              <th className="px-3 py-2">제품 · 버전</th><th className="px-3 py-2">판단 진행</th>
              <th className="px-3 py-2">KEV</th><th className="px-3 py-2">치명</th><th className="px-3 py-2">높음</th><th className="px-3 py-2">대기</th>
              <th className="px-3 py-2">영향 있음</th><th className="px-3 py-2">AI 일괄 판정</th><th />
            </tr>
          </thead>
          <tbody>
            {!q && <tr><td colSpan={9} className="px-3 py-8 text-center text-muted-foreground">집계 중… (제품 수에 따라 수십 초)</td></tr>}
            {q?.rows.map((r) => {
              const pct = r.total ? Math.round((r.analyzed / r.total) * 100) : 100;
              return (
                <tr key={r.project} className="border-t align-middle hover:bg-secondary/30">
                  <td className="px-3 py-2 font-medium">
                    {r.pendKev > 0 && <Flame size={13} className="mr-1 inline text-red-600" />}
                    {r.repo}:<span className="text-muted-foreground">{r.tag}</span>
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex items-center gap-2">
                      <div className="h-1.5 w-24 overflow-hidden rounded bg-secondary"><div className="h-full bg-emerald-500" style={{ width: `${pct}%` }} /></div>
                      <span className="text-xs tabular-nums text-muted-foreground">{r.analyzed}/{r.total}</span>
                    </div>
                  </td>
                  <td className="px-3 py-2 tabular-nums">{r.pendKev ? <Badge variant="danger">{r.pendKev}</Badge> : '—'}</td>
                  <td className="px-3 py-2 tabular-nums text-red-600">{r.pendCritical || '—'}</td>
                  <td className="px-3 py-2 tabular-nums text-orange-600">{r.pendHigh || '—'}</td>
                  <td className="px-3 py-2 tabular-nums">{r.pending || '—'}</td>
                  <td className="px-3 py-2 tabular-nums">{r.affected ? <Badge variant="warn">{r.affected}</Badge> : '—'}</td>
                  <td className="px-3 py-2 text-xs">
                    {r.batchState === 'running' ? <AIBadge pulse label={`진행 ${r.batchDone}/${r.batchTotal}`} />
                      : r.batchState ? <span className="text-muted-foreground" title={fmt(r.batchAt)}>초안 {r.batchDrafts ?? 0}건{r.batchState === 'cancelled' ? ' (중지)' : ''}</span> : '—'}
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 text-right">
                    {aiOn && r.pending > 0 && r.batchState !== 'running' && (
                      <Button size="sm" className="mr-1 h-7 bg-gradient-to-r from-violet-600 to-fuchsia-500 text-white hover:opacity-90" disabled={!!busy} onClick={() => batch(r)}>
                        <ListChecks size={13} /> {busy === r.project ? '시작 중…' : 'AI 일괄'}
                      </Button>
                    )}
                    <Link to={`/artifact/${encodeURIComponent(r.repo)}/${encodeURIComponent(r.tag)}`} className="text-xs text-primary hover:underline">판단하기 →</Link>
                  </td>
                </tr>
              );
            })}
            {q && q.rows.length === 0 && <tr><td colSpan={9} className="px-3 py-8 text-center text-muted-foreground">감시 중인 제품이 없습니다 — SBOM 이 붙은 버전이 생기면 10분 안에 나타납니다.</td></tr>}
          </tbody>
        </table>
      </Card>
      {q?.generated && <p className="mt-2 text-xs text-muted-foreground">집계 {fmt(q.generated)} · 1분 캐시 · 관리자가 아니면 읽기 권한이 있는 제품만 보입니다.</p>}
    </div>
  );
}
