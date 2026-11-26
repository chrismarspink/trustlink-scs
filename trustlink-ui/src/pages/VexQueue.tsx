import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ShieldQuestion, RefreshCw, ListChecks } from 'lucide-react';
import { AIBadge, AIIcon } from '@/components/AIBadge';
import { HelpScene } from '@/components/HelpScene';
import { vexQueue, aiVexBatch, aiVexBatchStart, aiStatus, type VexQueue as Q, type VexQueueRow, type VexQueueRowAuto, type AIStatus } from '@/lib/api';
import { SourceBadge } from '@/components/SourceBadge';
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
  const [scope, setScope] = useState<'real' | 'demo' | 'all'>('real');
  const [fold, setFold] = useState(true);
  const [open, setOpen] = useState<Set<string>>(new Set());
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
      if (b.state === 'done' && !b.total) setMsg(`${r.repo}:${r.tag} — 미판단 항목이 없습니다`);
      else {
        setMsg(`${r.repo}:${r.tag} — 일괄 판정 시작(우선순위 순 최대 20건)`);
        // 판정은 규칙이라 금방 끝난다. 권고문 요약까지 저장돼 있으면 진행 표시가 뜰 새도 없이 끝나므로, 결과를 바로 알려 준다
        await new Promise((ok) => setTimeout(ok, 1500));
        const cur = await aiVexBatch(r.project).catch(() => null);
        if (cur?.state === 'done') {
          const n = Object.keys(cur.results || {}).length;
          const sec = cur.started && cur.finished ? Math.max(1, Math.round((new Date(cur.finished).getTime() - new Date(cur.started).getTime()) / 1000)) : 0;
          setMsg(`${r.repo}:${r.tag} — 일괄 판정 완료: 초안 ${n}건${sec ? `(${sec}초)` : ''}. 권고문 요약은 저장해 둔 것을 다시 써서 바로 끝났습니다. "판단하기"에서 확인·저장하세요.`);
        }
      }
      load(true);
    } catch (e) { setMsg(String(e).replace(/^(Api)?Error:\s*(\d{3}\s*)?/, '')); load(true); }
    setBusy('');
  };

  // 제품마다 최신 버전(SBOM 을 가장 늦게 받은 버전) 한 줄. 이전 버전은 그 줄에서 펼친다 — 숨기지 않고 접어 둘 뿐이다.
  const all: VexQueueRowAuto[] = q?.rows || [];
  const hasDemo = all.some((r) => r.demo) && all.some((r) => !r.demo);
  const inScope = all.filter((r) => !hasDemo || scope === 'all' || (scope === 'demo') === !!r.demo);
  const canFold = all.some((r) => r.imported);
  const latestOf = new Map<string, VexQueueRowAuto>();
  for (const r of inScope) { const c = latestOf.get(r.repo); if (!c || (r.imported || 0) > (c.imported || 0)) latestOf.set(r.repo, r); }
  const older = (repo: string) => inScope.filter((r) => r.repo === repo && r !== latestOf.get(repo));
  const shown: { r: VexQueueRowAuto; old: boolean }[] = !canFold || !fold
    ? inScope.map((r) => ({ r, old: false }))
    : inScope.filter((r) => latestOf.get(r.repo) === r).flatMap((r) => [{ r, old: false }, ...(open.has(r.repo) ? older(r.repo).map((o) => ({ r: o, old: true })) : [])]);
  const toggle = (repo: string) => setOpen((o) => { const n = new Set(o); if (n.has(repo)) n.delete(repo); else n.add(repo); return n; });
  const aiOn = !!(ai?.enabled && ai.reachable);
  const s = q?.summary || {};
  return (
    <div className="mx-auto max-w-6xl">
      <div className="mb-5 flex flex-wrap items-start gap-3">
        <div className="basis-full sm:flex-1 sm:basis-0">
          <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight"><ShieldQuestion size={22} /> VEX 판단</h1>
          <p className="mt-1 text-sm text-muted-foreground">감시 중인 모든 제품·버전의 판단 안 된 취약점을 급한 순(실제 악용 KEV → 치명 → 높음)으로 모았습니다. 판단과 VEX 발행은 각 제품 화면에서 합니다.</p>
        </div>
        <HelpScene topic="vex" title="VEX 판단은 이렇게 동작합니다" />
        <Button variant="outline" onClick={() => { setQ(null); load(true); }}><RefreshCw size={14} /> 새로 집계</Button>
      </div>

      <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-5">
        {[['판단 대기', s.pending, ''], ['실제 악용(KEV)', s.pendKev, 'text-red-700'], ['치명', s.pendCritical, 'text-red-600'], ['높음', s.pendHigh, 'text-orange-600'], ['영향 있음(조치)', s.affected, 'text-amber-700']].map(([l, v, c]) => (
          <Card key={l as string} className="p-3">
            <div className="text-xs text-muted-foreground">{l}</div>
            <div className={`mt-1 text-2xl font-semibold tracking-tight tabular-nums ${c}`}>{q ? (v ?? 0) : '…'}</div>
          </Card>
        ))}
      </div>

      <div className={`mb-4 flex flex-wrap items-center gap-2 rounded-md border p-3 text-sm ${aiOn ? 'border-violet-200 bg-violet-50/50' : 'border-dashed'}`}>
        <AIIcon size={22} />
        {aiOn ? (
          <span>AI 판단 초안 사용 가능 — <b>{ai?.model}</b>{ai?.mode === 'local' ? ' (서버 내부 LLM, 외부 전송 없음). 판정은 규칙으로 바로 나오고, AI 는 권고문 요약을 건당 20~30초에 덧붙입니다' : ''}. 초안은 저장되지 않으며 제품 화면에서 확인 후 저장합니다.{s.drafts ? ` 저장 대기 초안 ${s.drafts}건.` : ''}</span>
        ) : (
          <span className="text-muted-foreground">AI 연결(VEX 용도)이 꺼져 있습니다. 켜지면 여기서 제품별 AI 일괄 판정을 걸 수 있습니다.</span>
        )}
      </div>
      {/* 지금 돌고 있는 일괄 판정 — 어느 제품이, 어느 단계까지 왔는지 */}
      {(q?.rows || []).filter((r) => r.batchState === 'running').map((r) => {
        const enrich = r.batchPhase === 'enrich';
        const d = enrich ? r.enrichDone ?? 0 : r.batchDone ?? 0, t = enrich ? r.enrichTotal ?? 0 : r.batchTotal ?? 0;
        return (
          <div key={r.project} className="mb-3 rounded-md border border-violet-300 bg-white p-3 text-sm">
            <div className="flex flex-wrap items-center gap-2">
              <span className="relative flex h-2.5 w-2.5"><span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-fuchsia-400 opacity-75" /><span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-fuchsia-500" /></span>
              <span className="font-semibold">지금 진행 중 — {r.repo}:{r.tag}</span>
              <span className="text-xs text-muted-foreground">{enrich ? `① 판정 완료 ${r.batchDone}건 → ② 권고문 요약 보강 ${d}/${t}건` : `① 판정 ${d}/${t}건`}</span>
              <Link to={`/artifact/${encodeURIComponent(r.repo)}/${encodeURIComponent(r.tag)}`} className="ml-auto text-xs text-primary hover:underline">진행 화면 열기(중지·확인) →</Link>
            </div>
            <div className="mt-2 h-2 overflow-hidden rounded-full bg-violet-100">
              <div className="h-full rounded-full bg-gradient-to-r from-violet-600 to-fuchsia-500 transition-all duration-700" style={{ width: `${Math.max(t ? Math.round((d / t) * 100) : 0, 3)}%` }} />
            </div>
            {enrich && <p className="mt-1.5 text-[11px] text-muted-foreground">판정 초안은 모두 나와 있어 지금 확인·저장할 수 있습니다. AI 가 영어 권고문의 한국어 요약을 덧붙이는 중입니다(건당 20~30초).</p>}
          </div>
        );
      })}
      {msg && <div className="mb-3 text-sm text-violet-800">{msg}</div>}
      {err && <div className="mb-3 text-sm text-red-600">{err}</div>}
      {q && !q.dt && <div className="text-sm text-muted-foreground">Dependency-Track 미설정 — 분석 기능이 꺼져 있습니다.</div>}

      {q && (hasDemo || canFold) && (
        <div className="mb-3 flex flex-wrap items-center gap-2 text-sm">
          {hasDemo && (
            <div className="inline-flex rounded-lg border p-0.5" role="group" aria-label="제품 범위">
              {([['real', '실제 제품'], ['demo', '시연용'], ['all', '전체']] as const).map(([k, l]) => (
                <button key={k} type="button" aria-pressed={scope === k} onClick={() => setScope(k)} className={`h-8 rounded-md px-3 ${scope === k ? 'bg-primary font-semibold text-primary-foreground' : ''}`}>{l}</button>
              ))}
            </div>
          )}
          {canFold && (
            <label className="inline-flex cursor-pointer items-center gap-1.5 text-xs text-muted-foreground">
              <input type="checkbox" checked={fold} onChange={(e) => setFold(e.target.checked)} /> 제품마다 최신 버전만(이전 버전은 접어 두기)
            </label>
          )}
          <span className="text-xs text-muted-foreground">제품 {latestOf.size}개 · 버전 {inScope.length}개</span>
        </div>
      )}
      <Card className="overflow-x-auto">
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
            {shown.map(({ r, old }) => {
              const prev = canFold && fold && !old ? older(r.repo) : [];
              const prevPend = prev.reduce((n, x) => n + x.pending, 0), prevKev = prev.reduce((n, x) => n + x.pendKev, 0);
              const pct = r.total ? Math.round((r.analyzed / r.total) * 100) : 100;
              return (
                <tr key={r.project} className={`border-t align-middle hover:bg-secondary/30 ${old ? 'bg-secondary/20' : ''}`}>
                  <td className={`px-3 py-2 font-medium ${old ? 'pl-8 font-normal' : ''}`}>
                    {old && <span className="mr-1 text-xs text-muted-foreground">이전</span>}<span data-vt-hero className="inline-block">{r.repo}</span>:<span className="text-muted-foreground">{r.tag}</span>
                    {prev.length > 0 && (
                      <button type="button" onClick={() => toggle(r.repo)} aria-expanded={open.has(r.repo)} className="mt-0.5 block text-left text-xs font-normal text-primary hover:underline">
                        {open.has(r.repo) ? '이전 버전 접기' : `이전 버전 ${prev.length}개 · 판단 대기 ${prevPend}건${prevKev ? ` (실제 악용 ${prevKev}건)` : ''}`}
                      </button>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex items-center gap-2">
                      <div className="h-1.5 w-24 overflow-hidden rounded bg-secondary"><div className="h-full bg-emerald-500" style={{ width: `${pct}%` }} /></div>
                      <span className="text-xs tabular-nums text-muted-foreground">{r.analyzed}/{r.total}</span>
                    </div>
                  </td>
                  <td className="px-3 py-2 tabular-nums">{r.pendKev ? <SourceBadge src="kev" label={`KEV ${r.pendKev}`} title="실제 악용(CISA KEV) 미판단 건수" /> : '—'}</td>
                  <td className="px-3 py-2 tabular-nums text-red-600">{r.pendCritical || '—'}</td>
                  <td className="px-3 py-2 tabular-nums text-orange-600">{r.pendHigh || '—'}</td>
                  <td className="px-3 py-2 tabular-nums">{r.pending || '—'}</td>
                  <td className="px-3 py-2 tabular-nums">{r.affected ? <Badge variant="warn">{r.affected}</Badge> : '—'}</td>
                  <td className="px-3 py-2 text-xs">
                    <div className="flex flex-wrap items-center gap-1">
                      {r.batchState === 'running' ? (r.batchPhase === 'enrich'
                        ? <><span className="whitespace-nowrap rounded-full bg-emerald-100 px-2 py-0.5 text-[11px] font-semibold text-emerald-800" title="판정 초안은 모두 나왔습니다 — 지금 확인·저장할 수 있습니다">판정 완료 {r.batchDone}건</span><AIBadge pulse label={`요약 보강 ${r.enrichDone ?? 0}/${r.enrichTotal ?? 0}`} /></>
                        : <AIBadge pulse label={`판정 중 ${r.batchDone}/${r.batchTotal}`} />)
                        : r.batchState ? <span className="text-muted-foreground" title={fmt(r.batchAt)}>초안 {r.batchDrafts ?? 0}건{r.batchState === 'cancelled' ? ' (중지)' : ''}{r.batchAt ? ` · ${fmt(r.batchAt)}` : ''}</span> : '—'}
                      {!!r.batchAuto && <span title="새 취약점 통보 직후 KEV·치명 항목에 자동으로 만든 초안(확인·저장 대기)"><AIBadge label={`자동 초안 ${r.batchAuto}`} className="from-fuchsia-600 to-rose-500" /></span>}
                    </div>
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
            {q && shown.length === 0 && <tr><td colSpan={9} className="px-3 py-8 text-center text-muted-foreground">{q.rows.length ? '이 범위에 해당하는 제품이 없습니다.' : '감시 중인 제품이 없습니다 — SBOM 이 붙은 버전이 생기면 10분 안에 나타납니다.'}</td></tr>}
          </tbody>
        </table>
      </Card>
      {!!q?.skipped && <div className="mt-2 rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900" role="status">취약점 분석기가 {q.skipped}개 버전에 답하지 않아 <b>일부만 표시 중</b>입니다. 판단할 것이 줄어든 것이 아닙니다. 잠시 뒤 새로 고침해 보세요.</div>}
      {q?.generated && <p className="mt-2 text-xs text-muted-foreground">집계 {fmt(q.generated)} · 1분 캐시 · 관리자가 아니면 읽기 권한이 있는 제품만 보입니다.</p>}
    </div>
  );
}
