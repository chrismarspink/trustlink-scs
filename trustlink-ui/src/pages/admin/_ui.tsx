import type { ReactNode } from 'react';
import { Card } from '@/components/ui/primitives';
import { cn } from '@/lib/utils';

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

// 가로 막대 차트 — 외부 의존성 없이 div/CSS 로 구현(폐쇄망/오프라인 빌드 원칙).
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
  const max = Math.max(1, ...data.map((d) => d.value));
  return (
    <div className="space-y-2">
      {data.map((d) => (
        <div key={d.label} className="flex items-center gap-3">
          <span className="w-40 shrink-0 truncate font-mono text-xs text-muted-foreground" title={d.label}>
            {d.label}
          </span>
          <div className="h-5 flex-1 overflow-hidden rounded bg-secondary">
            <div className={cn('h-full rounded transition-[width]', d.color || 'bg-accent')} style={{ width: `${(d.value / max) * 100}%` }} />
          </div>
          <span className="w-20 shrink-0 text-right text-xs font-medium tabular-nums">
            {fmt ? fmt(d.value) : d.value}
          </span>
        </div>
      ))}
    </div>
  );
}

// 다중 시리즈 라인 차트(버전 추이 등) — 외부 의존성 없이 SVG.
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
  const W = 640, H = 240, padL = 34, padR = 14, padT = 10, padB = 34;
  const n = categories.length;
  const max = Math.max(1, ...series.flatMap((s) => s.values));
  const x = (i: number) => (n === 1 ? (padL + W - padR) / 2 : padL + (i * (W - padL - padR)) / (n - 1));
  const y = (v: number) => padT + (H - padT - padB) * (1 - v / max);
  const ticks = 4;

  return (
    <div>
      <div className="mb-2 flex flex-wrap gap-3 text-xs">
        {series.map((s) => (
          <span key={s.label} className="flex items-center gap-1.5">
            <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: s.color }} /> {s.label}
          </span>
        ))}
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img">
        {/* y 그리드 + 라벨 */}
        {Array.from({ length: ticks + 1 }, (_, t) => {
          const val = (max * t) / ticks;
          const yy = y(val);
          return (
            <g key={t}>
              <line x1={padL} y1={yy} x2={W - padR} y2={yy} stroke="hsl(var(--border))" strokeWidth={1} />
              <text x={padL - 5} y={yy + 3} textAnchor="end" fontSize={10} fill="hsl(var(--muted-foreground))">
                {Math.round(val)}
              </text>
            </g>
          );
        })}
        {/* x 라벨(버전) */}
        {categories.map((c, i) => (
          <text key={c} x={x(i)} y={H - 12} textAnchor="middle" fontSize={10} fill="hsl(var(--muted-foreground))">
            {c.length > 12 ? c.slice(0, 11) + '…' : c}
          </text>
        ))}
        {/* 시리즈 라인 + 점 */}
        {series.map((s) => (
          <g key={s.label}>
            <polyline
              fill="none"
              stroke={s.color}
              strokeWidth={2}
              vectorEffect="non-scaling-stroke"
              points={s.values.map((v, i) => `${x(i)},${y(v)}`).join(' ')}
            />
            {s.values.map((v, i) => (
              <circle key={i} cx={x(i)} cy={y(v)} r={2.8} fill={s.color} />
            ))}
          </g>
        ))}
      </svg>
    </div>
  );
}

// 단일 게이지(사용률 %) — 임계값에 따라 색 변화.
export function Gauge({ label, pct, sub }: { label: string; pct: number; sub?: string }) {
  const color = pct >= 95 ? 'bg-red-500' : pct >= 85 ? 'bg-amber-500' : 'bg-emerald-500';
  return (
    <div>
      <div className="mb-1 flex items-baseline justify-between">
        <span className="text-sm font-medium">{label}</span>
        <span className="text-sm tabular-nums text-muted-foreground">{pct}%{sub ? ` · ${sub}` : ''}</span>
      </div>
      <div className="h-3 overflow-hidden rounded-full bg-secondary">
        <div className={cn('h-full rounded-full', color)} style={{ width: `${Math.min(100, pct)}%` }} />
      </div>
    </div>
  );
}
