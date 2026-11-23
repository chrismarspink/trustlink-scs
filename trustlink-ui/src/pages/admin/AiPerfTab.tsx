import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import ReactECharts from 'echarts-for-react';
import { CheckCircle2, AlertTriangle, XCircle, Gauge as GaugeIcon } from 'lucide-react';
import { aiPerf, aiPerfBench, type AIPerf } from '@/lib/api';
import { fmtBytes, cn } from '@/lib/utils';
import { Card, CardHeader, CardContent, Button } from '@/components/ui/primitives';
import { Busy } from '@/components/Progress';
import { SectionTitle, Alert, Table, Th, Td, Loading } from './_ui';

// 대시보드 › AI 탭: 로컬 AI(Gemma) 가 얼마나 빠른지, 서버에 얼마나 부담을 주는지, 외부 LLM 이 필요한지.

const fmtMs = (ms: number) => {
  if (!ms) return '—';
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}초`;
  if (s < 3600) return `${Math.floor(s / 60)}분 ${s % 60}초`;
  return `${Math.floor(s / 3600)}시간 ${Math.floor((s % 3600) / 60)}분`;
};
const fmtAt = (t: string) => (t ? new Date(t).toLocaleString('ko-KR', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—');
const kindLabel: Record<string, string> = { local: '로컬', external: '외부', off: '꺼짐' };

// 초당 토큰 → 등급(한국어 1글자 ≈ 1토큰 남짓)
function speedGrade(tps: number) {
  if (!tps) return { label: '측정 전', cls: 'text-muted-foreground' };
  if (tps < 3) return { label: '매우 느림', cls: 'text-red-600' };
  if (tps < 12) return { label: '느림', cls: 'text-amber-600' };
  if (tps < 30) return { label: '보통', cls: 'text-emerald-600' };
  return { label: '빠름', cls: 'text-emerald-600' };
}

const LEVEL = {
  local: { cls: 'border-emerald-200 bg-emerald-50', icon: CheckCircle2, ic: 'text-emerald-600' },
  hybrid: { cls: 'border-amber-200 bg-amber-50', icon: AlertTriangle, ic: 'text-amber-600' },
  external: { cls: 'border-red-200 bg-red-50', icon: XCircle, ic: 'text-red-600' },
} as const;
const TONE_ICON = { ok: CheckCircle2, warn: AlertTriangle, crit: XCircle } as const;
const TONE_CLS = { ok: 'text-emerald-600', warn: 'text-amber-600', crit: 'text-red-600' } as const;

function Tile({ label, value, sub, subCls }: { label: string; value: string; sub?: string; subCls?: string }) {
  return (
    <Card className="p-4">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="mt-1.5 text-2xl font-semibold tracking-tight tabular-nums">{value}</div>
      {sub && <div className={cn('mt-0.5 text-xs', subCls || 'text-muted-foreground')}>{sub}</div>}
    </Card>
  );
}

// 가로 막대 하나를 몇 조각으로(메모리: AI / 그 밖 / 여유)
function Stack({ parts }: { parts: { label: string; v: number; cls: string }[] }) {
  const total = parts.reduce((a, p) => a + p.v, 0) || 1;
  return (
    <div>
      <div className="flex h-3 w-full gap-0.5 overflow-hidden rounded-full bg-slate-100">
        {parts.filter((p) => p.v > 0).map((p) => (
          <div key={p.label} className={cn('h-full first:rounded-l-full last:rounded-r-full', p.cls)} style={{ width: `${(p.v / total) * 100}%` }} title={`${p.label} ${fmtBytes(p.v)}`} />
        ))}
      </div>
      <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-600">
        {parts.map((p) => (
          <span key={p.label} className="inline-flex items-center gap-1.5">
            <span className={cn('h-2.5 w-2.5 rounded-sm', p.cls)} />{p.label} <b className="tabular-nums text-slate-800">{fmtBytes(p.v)}</b>
          </span>
        ))}
      </div>
    </div>
  );
}

function CpuChart({ series }: { series: AIPerf['system']['series'] }) {
  if (series.length < 2) return <p className="text-sm text-muted-foreground">표본을 모으는 중입니다(30초마다, 24시간 보관). 잠시 뒤 다시 보세요.</p>;
  const cats = series.map((p) => new Date(p.t * 1000).toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit' }));
  // AI 가 돈 구간을 띠로
  const bands: [{ xAxis: string }, { xAxis: string }][] = [];
  let s = -1;
  series.forEach((p, i) => {
    if (p.ai && s < 0) s = i;
    if ((!p.ai || i === series.length - 1) && s >= 0) {
      bands.push([{ xAxis: cats[s] }, { xAxis: cats[p.ai ? i : Math.max(s, i - 1)] }]);
      s = -1;
    }
  });
  const option = {
    grid: { left: 8, right: 16, top: 12, bottom: 22, containLabel: true },
    tooltip: {
      trigger: 'axis',
      formatter: (ps: { dataIndex: number }[]) => {
        const p = series[ps[0].dataIndex];
        return `${cats[ps[0].dataIndex]}<br/>CPU ${p.cpu}% · 메모리 ${p.mem}%${p.ai ? '<br/><b>AI 작업 중</b>' : ''}`;
      },
    },
    xAxis: { type: 'category', boundaryGap: false, data: cats, axisLine: { lineStyle: { color: '#e2e8f0' } }, axisLabel: { color: '#64748b' } },
    yAxis: { type: 'value', min: 0, max: 100, axisLabel: { color: '#64748b', formatter: '{value}%' }, splitLine: { lineStyle: { color: '#f1f5f9' } } },
    series: [{
      name: '서버 CPU', type: 'line', data: series.map((p) => p.cpu), symbol: 'none', lineStyle: { width: 2, color: '#334155' }, itemStyle: { color: '#334155' },
      markArea: { silent: true, itemStyle: { color: 'rgba(139,92,246,0.15)' }, data: bands },
    }],
  };
  return <ReactECharts option={option as never} style={{ height: 220 }} opts={{ renderer: 'canvas' }} notMerge />;
}

export default function AiPerfTab() {
  const [d, setD] = useState<AIPerf | null>(null);
  const [err, setErr] = useState('');
  const [msg, setMsg] = useState('');
  const load = useCallback(() => aiPerf().then((x) => { setD(x); setErr(''); }).catch((e) => setErr(String(e))), []);
  useEffect(() => { load(); }, [load]);
  // 측정 중이면 3초마다 다시 읽음
  useEffect(() => {
    if (!d?.bench.running) return;
    const t = setTimeout(load, 3000);
    return () => clearTimeout(t);
  }, [d, load]);

  async function bench(target: 'local' | 'external') {
    setMsg('');
    try { await aiPerfBench(target); await load(); } catch (e) { setMsg(String(e)); }
  }

  if (err) return <Alert tone="crit">AI 성능 정보를 불러오지 못했습니다: {err}</Alert>;
  if (!d) return <Loading />;
  const { verdict: v, system: sys, local } = d;
  const L = LEVEL[v.level];
  const g = speedGrade(local.genTps);
  const vex = d.features.find((f) => f.feature === 'VEX 판단');
  const memUsed = sys.memTotal - sys.memAvail;
  const aiMem = Math.min(sys.aiMemEst, memUsed);
  const lastBench = d.benches[d.benches.length - 1];

  return (
    <div className="space-y-6">
      {/* ① 결론 */}
      <div className={cn('rounded-lg border p-4', L.cls)}>
        <div className="flex items-center gap-2">
          <L.icon size={22} className={L.ic} />
          <h3 className="text-lg font-semibold">{v.title}</h3>
        </div>
        <ul className="mt-2 space-y-1">
          {v.reasons.map((r) => {
            const I = TONE_ICON[r.tone];
            return <li key={r.text} className="flex items-start gap-2 text-sm text-slate-700"><I size={15} className={cn('mt-0.5 shrink-0', TONE_CLS[r.tone])} />{r.text}</li>;
          })}
        </ul>
        {v.level !== 'local' && (
          <p className="mt-3 rounded-md bg-white/70 px-3 py-2 text-sm text-slate-700">
            <b>권장:</b> 고객 데이터가 들어가는 <b>VEX 판단·고객 통지</b>는 지금처럼 로컬에 두고,
            공개 정보만 쓰는 <b>규제 보고서·법규 분석·규제 탐색·공개 저장소 분석</b>은 인터넷이 되는 설치 환경에서 외부 LLM(Claude 등)으로 돌리세요.
            설정은 <Link to="/admin/ai" className="text-violet-700 underline">AI 연결</Link> › 보고서·규제 용도에서 바꿉니다.
            폐쇄망 고객사에는 외부를 쓸 수 없으므로 로컬이 계속 필요합니다.
          </p>
        )}
      </div>

      {/* ② 핵심 숫자 */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Tile label="로컬 AI 글 쓰는 속도" value={local.genTps ? `초당 ${local.genTps} 토큰` : '—'}
          sub={`${g.label}${d.external.genTps ? ` · 외부 ${d.external.genTps}` : ' · 외부 LLM 은 보통 수십~100'}`} subCls={g.cls} />
        <Tile label="VEX 판단 1건(보통)" value={fmtMs(vex?.p50Ms || 0)} sub={vex?.count ? `최근 7일 ${vex.count}건 · 느릴 때 ${fmtMs(vex.p90Ms)}` : '최근 7일 기록 없음'} />
        <Tile label="AI 가 차지하는 메모리(상시)" value={sys.aiMemEst ? `약 ${fmtBytes(sys.aiMemEst)}` : '—'}
          sub={`서버 ${fmtBytes(sys.memTotal)} 중 ${sys.memTotal ? Math.round((sys.aiMemEst / sys.memTotal) * 100) : 0}%${sys.aiMemLimit ? ` · 한도 ${fmtBytes(sys.aiMemLimit)}` : ''}`} />
        <Tile label="로컬 AI 실패율(7일)" value={local.calls ? `${local.failRate}%` : '—'}
          sub={local.calls ? `${local.calls}건 중 ${local.fails}건 실패` : '기록 없음'} subCls={local.failRate >= 10 ? 'text-amber-600' : undefined} />
      </div>

      {/* ③ 서버에 주는 영향 */}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="pb-2"><span className="text-sm font-semibold">메모리 · 디스크</span></CardHeader>
          <CardContent className="space-y-4">
            <div>
              <div className="mb-1.5 text-xs text-muted-foreground">서버 메모리 {fmtBytes(sys.memTotal)}</div>
              <Stack parts={[
                { label: `AI(${sys.modelFile ? '모델 상주' : '추정'})`, v: aiMem, cls: 'bg-violet-500' },
                { label: '그 밖의 서비스', v: memUsed - aiMem, cls: 'bg-slate-400' },
                { label: '여유', v: sys.memAvail, cls: 'bg-emerald-200' },
              ]} />
            </div>
            {sys.swapTotal > 0 && (
              <div className="text-xs text-slate-600">
                스왑 {fmtBytes(sys.swapUsed)} / {fmtBytes(sys.swapTotal)}
                {sys.swapUsed / sys.swapTotal >= 0.5 && <span className="text-amber-700"> — 많이 쓰는 중(서버 전체 기준, 같은 서버의 다른 서비스 포함)</span>}
              </div>
            )}
            <div className="space-y-2">
              {sys.disks.map((k) => (
                <div key={k.label} className="text-xs">
                  <div className="mb-1 flex justify-between text-slate-600"><span>{k.label}</span><span className="tabular-nums">여유 {fmtBytes(k.free)} / {fmtBytes(k.total)}</span></div>
                  <div className="h-2 overflow-hidden rounded-full bg-slate-100"><div className="h-full rounded-full bg-slate-500" style={{ width: `${((k.total - k.free) / k.total) * 100}%` }} /></div>
                </div>
              ))}
              {sys.modelFile && <p className="text-xs text-muted-foreground">모델 파일 {sys.modelFile} — {fmtBytes(sys.modelBytes)}</p>}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><span className="text-sm font-semibold">CPU — AI 가 돌 때와 쉴 때</span></CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-2 gap-3 text-center">
              <div className="rounded-md bg-violet-50 p-3"><div className="text-xs text-muted-foreground">AI 작업 중 서버 CPU</div><div className="text-xl font-semibold tabular-nums">{sys.busySamples ? `${sys.cpuBusy}%` : '—'}</div></div>
              <div className="rounded-md bg-slate-50 p-3"><div className="text-xs text-muted-foreground">평소 서버 CPU</div><div className="text-xl font-semibold tabular-nums">{sys.samples - sys.busySamples ? `${sys.cpuIdle}%` : '—'}</div></div>
            </div>
            <p className="text-xs text-muted-foreground">
              AI 는 코어 {sys.aiCpus || '?'}개까지만 쓰도록 묶여 있습니다(서버 전체 {sys.cpus}개).
              {lastBench?.cpuDuring ? ` 마지막 측정 때 서버 CPU ${lastBench.cpuDuring}%.` : ''}
            </p>
            <CpuChart series={sys.series} />
            <p className="text-[11px] text-muted-foreground">선: 서버 전체 CPU(5분 평균) · 보라 띠: 로컬 AI 가 작업한 구간 · BFF 재시작 후부터 24시간</p>
          </CardContent>
        </Card>
      </div>

      {/* ④ 기능별 */}
      <div>
        <SectionTitle>기능별 AI 사용과 권장 연결 (최근 7일)</SectionTitle>
        <Table>
          <thead><tr><Th>기능</Th><Th>지금 연결</Th><Th className="text-right">호출</Th><Th className="text-right">보통 / 느릴 때</Th><Th className="text-right">앞 작업 대기</Th><Th className="text-right">실패</Th><Th>권장</Th></tr></thead>
          <tbody>
            {d.features.map((f) => (
              <tr key={f.feature} className="border-t">
                <Td className="font-medium">{f.feature}</Td>
                <Td>{kindLabel[f.kind || ''] || '—'}</Td>
                <Td className="text-right tabular-nums">{f.count || '—'}</Td>
                <Td className="text-right tabular-nums">{f.count ? `${fmtMs(f.p50Ms)} / ${fmtMs(f.p90Ms)}` : '—'}</Td>
                <Td className="text-right tabular-nums">{f.count ? fmtMs(f.avgWaitMs) : '—'}</Td>
                <Td className={cn('text-right tabular-nums', f.fails && 'text-red-600')}>{f.count ? `${f.fails}${f.timeouts ? ` (시간 초과 ${f.timeouts})` : ''}` : '—'}</Td>
                <Td>
                  <span className={cn('rounded px-1.5 py-0.5 text-xs font-medium',
                    f.recommend === 'local' ? 'bg-slate-100 text-slate-700' : f.recommend === 'external' ? 'bg-violet-100 text-violet-700' : 'bg-emerald-50 text-emerald-700')}>
                    {f.recommend === 'local' ? '로컬 유지' : f.recommend === 'external' ? '외부 권장' : '어느 쪽이든'}
                  </span>
                  <div className="mt-0.5 text-xs text-muted-foreground">{f.why}</div>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </div>

      {/* ⑤ 성능 측정 */}
      <div>
        <SectionTitle>성능 측정</SectionTitle>
        <p className="mb-3 text-sm text-muted-foreground">
          고객 데이터가 없는 고정 문장(공개 CVE 한 건의 VEX 판단)으로 한 번 돌려 속도를 잽니다. 로컬은 30초~1분 걸리고, 그동안 다른 AI 작업은 기다립니다.
        </p>
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <Button size="sm" onClick={() => bench('local')} disabled={d.bench.running || !d.config.localUrl}><GaugeIcon size={14} /> 로컬 AI 측정</Button>
          <Button size="sm" variant="outline" onClick={() => bench('external')} disabled={d.bench.running || !d.config.externalReady}
            title={d.config.externalReady ? `${d.config.external} — 고정 문장만 외부로 보냅니다(요금 발생)` : '외부 LLM 이 설정되지 않음'}>
            <GaugeIcon size={14} /> 외부 LLM 측정{d.config.external ? ` (${d.config.external})` : ''}
          </Button>
          <span className="text-xs text-muted-foreground">
            로컬 AI 서버: {!d.live.configured ? '설정 안 됨' : d.live.reachable ? `연결됨 · 대화 길이 ${d.live.nCtx ?? '?'} 토큰${d.live.busy ? ' · 지금 작업 중' : ''}` : '응답 없음'}
          </span>
        </div>
        {msg && <Alert tone="crit">{msg}</Alert>}
        <Busy active={d.bench.running} label={`${d.bench.target === 'external' ? '외부 LLM' : '로컬 AI'} 측정 중`} since={d.bench.started} hint="로컬은 보통 30초~1분" className="mb-3" />
        {d.benches.length === 0 ? <p className="text-sm text-muted-foreground">아직 측정 기록이 없습니다.</p> : (
          <Table>
            <thead><tr><Th>시각</Th><Th>대상</Th><Th>모델</Th><Th className="text-right">걸린 시간</Th><Th className="text-right">읽기 속도</Th><Th className="text-right">쓰기 속도</Th><Th className="text-right">서버 CPU</Th><Th>결과</Th></tr></thead>
            <tbody>
              {[...d.benches].reverse().map((b) => (
                <tr key={b.at} className="border-t">
                  <Td className="tabular-nums">{fmtAt(b.at)}</Td>
                  <Td>{kindLabel[b.kind] || b.kind}</Td>
                  <Td className="max-w-[16rem] truncate text-xs">{b.model || '—'}</Td>
                  <Td className="text-right tabular-nums">{fmtMs(b.ms)}</Td>
                  <Td className="text-right tabular-nums">{b.promptTps ? `초당 ${b.promptTps}` : '—'}</Td>
                  <Td className="text-right tabular-nums">{b.genTps ? `초당 ${b.genTps}` : '—'}</Td>
                  <Td className="text-right tabular-nums">{b.cpuDuring ? `${b.cpuDuring}%` : '—'}</Td>
                  <Td>{b.ok ? <span className="text-emerald-700">정상</span> : <span className="text-red-600" title={b.err}>실패{b.fail ? `(${b.fail})` : ''}</span>}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
        <p className="mt-2 text-xs text-muted-foreground">읽기 속도는 질문을 읽는 속도, 쓰기 속도는 답을 써 내려가는 속도(초당 토큰, 한국어 1글자 ≈ 1토큰)입니다. 외부 LLM 은 쓰기 속도를 전체 시간으로 어림합니다.</p>
      </div>
    </div>
  );
}
