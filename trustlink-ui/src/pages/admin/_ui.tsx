import type { ReactNode } from 'react';
import ReactECharts from 'echarts-for-react';
import { Card } from '@/components/ui/primitives';
import { cn } from '@/lib/utils';

// 차트 공용 색(밝은 테마 기준). 축/그리드는 muted, 막대 accent.
const CHART_AXIS = '#64748b';
const CHART_GRID = '#e5e7eb';
const CHART_ACCENT = '#F6A623';

// 관리 페이지 공용 프리미티브 (shadcn/Tailwind 스타일, 소유 컴포넌트)

export function PageTitle({ children }: { children: ReactNode }) {
  return <h1 className="mb-5 text-2xl font-bold">{children}</h1>;
}

export function SectionTitle({ children }: { children: ReactNode }) {
  return <h2 className="mb-3 mt-6 text-lg font-semibold">{children}</h2>;
}

export function StatCard({ label, value }: { label: string; value: ReactNode }) {
  return (
    <Card className="p-4">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="mt-1.5 text-2xl font-extrabold tracking-tight">{value}</div>
    </Card>
  );
}

export function Alert({ tone = 'ok', children }: { tone?: 'ok' | 'warn' | 'crit'; children: ReactNode }) {
  const tones = {
    ok: 'bg-emerald-50 text-emerald-700',
    warn: 'bg-amber-50 text-amber-800',
    crit: 'bg-red-50 text-red-700'
  };
  return <div className={cn('mb-4 rounded-md px-4 py-3 text-sm', tones[tone])}>{children}</div>;
}

export function Loading() {
  return <p className="text-muted-foreground">로딩…</p>;
}

export function Table({ children }: { children: ReactNode }) {
  return (
    <div className="overflow-x-auto rounded-lg border">
      <table className="w-full text-sm">{children}</table>
    </div>
  );
}
export function Th({ children, className }: { children?: ReactNode; className?: string }) {
  return (
    <th className={cn('border-b bg-secondary/60 px-3 py-2 text-left font-medium text-muted-foreground', className)}>
      {children}
    </th>
  );
}
export function Td({ children, className }: { children?: ReactNode; className?: string }) {
  return <td className={cn('border-b px-3 py-2 align-middle', className)}>{children}</td>;
}

// 페이지 내 raw <select> 공용 클래스 (primitives 에 select 가 없어 여기서 통일)
export const selectCls = 'h-9 rounded-md border border-input bg-card px-2 text-sm outline-none focus:ring-2 focus:ring-ring';

// 가로 막대 차트 — Apache ECharts(canvas).
export function BarChart({
  data,
  fmt,
  empty = '데이터 없음'
}: {
  data: { label: string; value: number; color?: string }[];
  fmt?: (v: number) => string;
  empty?: string;
}) {
  if (data.length === 0) return <p className="text-sm text-muted-foreground">{empty}</p>;
  const f = (v: number) => (fmt ? fmt(v) : String(v));
  const option = {
    grid: { left: 8, right: 56, top: 8, bottom: 8, containLabel: true },
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, valueFormatter: (v: number) => f(v) },
    xAxis: { type: 'value', axisLabel: { color: CHART_AXIS, formatter: (v: number) => f(v) }, splitLine: { lineStyle: { color: CHART_GRID } } },
    yAxis: { type: 'category', inverse: true, data: data.map((d) => d.label), axisTick: { show: false }, axisLine: { lineStyle: { color: CHART_GRID } }, axisLabel: { color: CHART_AXIS } },
    series: [{
      type: 'bar', barMaxWidth: 22, data: data.map((d) => d.value),
      itemStyle: { color: CHART_ACCENT, borderRadius: [0, 4, 4, 0] },
      label: { show: true, position: 'right', color: CHART_AXIS, formatter: (p: { value: number }) => f(p.value) }
    }]
  };
  return <ReactECharts option={option as never} style={{ height: Math.max(120, data.length * 38) }} opts={{ renderer: 'canvas' }} notMerge />;
}

// 다중 시리즈 라인 차트(버전 추이 등) — Apache ECharts(canvas). 범례 클릭으로 시리즈 토글.
export type LineSeries = { label: string; color: string; values: number[] };
export function LineChart({
  categories,
  series,
  empty = '데이터 없음'
}: {
  categories: string[];
  series: LineSeries[];
  empty?: string;
}) {
  if (categories.length === 0) return <p className="text-sm text-muted-foreground">{empty}</p>;
  const option = {
    color: series.map((s) => s.color),
    grid: { left: 8, right: 16, top: 30, bottom: 22, containLabel: true },
    tooltip: { trigger: 'axis' },
    legend: { top: 0, data: series.map((s) => s.label), textStyle: { color: CHART_AXIS }, icon: 'roundRect', inactiveColor: '#cbd5e1' },
    xAxis: { type: 'category', boundaryGap: false, data: categories, axisLine: { lineStyle: { color: CHART_GRID } }, axisLabel: { color: CHART_AXIS, formatter: (c: string) => (c.length > 12 ? c.slice(0, 11) + '…' : c) } },
    yAxis: { type: 'value', minInterval: 1, splitLine: { lineStyle: { color: CHART_GRID } }, axisLabel: { color: CHART_AXIS } },
    series: series.map((s) => ({ name: s.label, type: 'line', data: s.values, smooth: false, symbol: 'circle', symbolSize: 6, lineStyle: { width: 2, color: s.color }, itemStyle: { color: s.color } }))
  };
  return <ReactECharts option={option as never} style={{ height: 264 }} opts={{ renderer: 'canvas' }} notMerge />;
}

// 단일 게이지(사용률 %) — Apache ECharts gauge. 임계값에 따라 색 변화.
export function Gauge({ label, pct, sub }: { label: string; pct: number; sub?: string }) {
  const color = pct >= 95 ? '#ef4444' : pct >= 85 ? '#f59e0b' : '#10b981';
  const option = {
    series: [{
      type: 'gauge', startAngle: 210, endAngle: -30, min: 0, max: 100, radius: '92%', center: ['50%', '62%'],
      progress: { show: true, width: 16, itemStyle: { color } },
      axisLine: { lineStyle: { width: 16, color: [[1, CHART_GRID]] } },
      axisTick: { show: false }, splitLine: { show: false }, axisLabel: { show: false }, pointer: { show: false }, anchor: { show: false }, title: { show: false },
      detail: { valueAnimation: true, formatter: '{value}%', color, fontSize: 26, offsetCenter: [0, '0%'] },
      data: [{ value: Math.round(pct) }]
    }]
  };
  return (
    <div>
      <div className="mb-1 flex items-baseline justify-between">
        <span className="text-sm font-medium">{label}</span>
        {sub && <span className="text-xs tabular-nums text-muted-foreground">{sub}</span>}
      </div>
      <ReactECharts option={option as never} style={{ height: 180 }} opts={{ renderer: 'canvas' }} notMerge />
    </div>
  );
}

// 도넛(파이) 차트 — 구성비(제품별 사용량 등). Apache ECharts.
export function Donut({
  data,
  fmt,
  empty = '데이터 없음'
}: {
  data: { label: string; value: number }[];
  fmt?: (v: number) => string;
  empty?: string;
}) {
  if (data.length === 0 || data.every((d) => d.value === 0)) return <p className="text-sm text-muted-foreground">{empty}</p>;
  const f = (v: number) => (fmt ? fmt(v) : String(v));
  const option = {
    tooltip: { trigger: 'item', formatter: (p: { name: string; value: number; percent: number }) => `${p.name}<br/>${f(p.value)} (${p.percent}%)` },
    legend: { type: 'scroll', orient: 'vertical', right: 4, top: 'middle', textStyle: { color: CHART_AXIS }, formatter: (n: string) => (n.length > 18 ? n.slice(0, 17) + '…' : n) },
    series: [{
      type: 'pie', radius: ['46%', '72%'], center: ['34%', '50%'], avoidLabelOverlap: true,
      itemStyle: { borderColor: '#fff', borderWidth: 2 }, label: { show: false }, labelLine: { show: false },
      data: data.map((d) => ({ name: d.label, value: d.value }))
    }]
  };
  return <ReactECharts option={option as never} style={{ height: 220 }} opts={{ renderer: 'canvas' }} notMerge />;
}
