import type { ReactNode } from 'react';
import { Card, CardHeader, CardContent } from '@/components/ui/primitives';

// 문서 하위 페이지 공용 — 표제·코드·용어설명·다이어그램.

export const NAVY = '#16243a';
export const SLATE = '#475569';
export const ORANGE = '#ea7317';
export const LIGHT = '#eef2f7';

export function DocTitle({ title, lead }: { title: string; lead?: string }) {
  return (
    <div className="mb-5">
      <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
      {lead && <p className="mt-1 text-sm text-muted-foreground">{lead}</p>}
    </div>
  );
}

export function Code({ children }: { children: ReactNode }) {
  return (
    <pre className="overflow-auto rounded-md bg-primary px-3 py-2 text-xs leading-relaxed text-primary-foreground">
      <code>{children}</code>
    </pre>
  );
}

export function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Card className="mb-5">
      <CardHeader className="text-base font-semibold">{title}</CardHeader>
      <CardContent className="space-y-3 text-sm leading-relaxed">{children}</CardContent>
    </Card>
  );
}

// 페이지마다 추가하는 용어 설명(사용자 요청).
export function Glossary({ items }: { items: [string, ReactNode][] }) {
  return (
    <Card className="mb-5 border-dashed">
      <CardHeader className="text-base font-semibold">용어 설명</CardHeader>
      <CardContent>
        <dl className="space-y-2 text-sm">
          {items.map(([t, d], i) => (
            <div key={i}>
              <dt className="inline font-semibold text-primary">{t}</dt>
              <dd className="ml-1 inline text-muted-foreground">— {d}</dd>
            </div>
          ))}
        </dl>
      </CardContent>
    </Card>
  );
}

// ── 다이어그램 ──
function Box({ x, y, w, h, label, sub, dashed, accent }: {
  x: number; y: number; w: number; h: number; label: string; sub?: string; dashed?: boolean; accent?: boolean;
}) {
  return (
    <g>
      <rect x={x} y={y} width={w} height={h} rx={8}
        fill={accent ? ORANGE : '#fff'} stroke={accent ? ORANGE : NAVY}
        strokeWidth={1.5} strokeDasharray={dashed ? '5 4' : undefined} />
      <text x={x + w / 2} y={y + (sub ? h / 2 - 4 : h / 2 + 4)} textAnchor="middle" fontSize={13} fontWeight={700} fill={accent ? '#fff' : NAVY}>{label}</text>
      {sub && <text x={x + w / 2} y={y + h / 2 + 13} textAnchor="middle" fontSize={10} fill={accent ? '#fff' : SLATE}>{sub}</text>}
    </g>
  );
}
function Arrow({ x1, y1, x2, y2 }: { x1: number; y1: number; x2: number; y2: number }) {
  return <line x1={x1} y1={y1} x2={x2} y2={y2} stroke={SLATE} strokeWidth={1.5} markerEnd="url(#ah)" />;
}
function ArrowDefs() {
  return (
    <defs>
      <marker id="ah" markerWidth={10} markerHeight={10} refX={8} refY={3} orient="auto" markerUnits="strokeWidth">
        <path d="M0,0 L8,3 L0,6 Z" fill={SLATE} />
      </marker>
    </defs>
  );
}

// 문서용 표
export function DocTable({ head, rows }: { head: string[]; rows: ReactNode[][] }) {
  return (
    <div className="overflow-auto rounded-md border">
      <table className="w-full text-sm">
        <thead className="bg-secondary/60 text-left text-xs text-muted-foreground">
          <tr>{head.map((h) => <th key={h} className="px-3 py-2 font-medium">{h}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} className="border-t align-top">{r.map((c, j) => <td key={j} className="px-3 py-2">{c}</td>)}</tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// 알림 상자(팁·주의)
export function Note({ tone = 'tip', children }: { tone?: 'tip' | 'warn'; children: ReactNode }) {
  return (
    <div className={tone === 'warn' ? 'rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-amber-900' : 'rounded-md border border-sky-200 bg-sky-50 px-3 py-2 text-sky-900'}>
      {children}
    </div>
  );
}

// 구성도: 사용자·CI → TrustLink 정문(웹·BFF) → 내부 구성요소. 작게(최대 폭 3xl) 그린다.
export function ArchDiagram() {
  const right = [
    ['Keycloak', '로그인 · 그룹(역할)'],
    ['zot', '레지스트리 · 산출물·SBOM·VEX'],
    ['Dependency-Track', '취약점 분석'],
    ['취약점 DB 미러', 'NVD · OSV · GitHub · KEV 사본'],
    ['Gotenberg', '보고서 PDF 변환(내부망)'],
    ['AI (선택)', '로컬 LLM · Claude — 초안만']
  ];
  const rx = 460, rw = 290, rh = 32, gap = 7, top = 14;
  return (
    <div className="mx-auto max-w-3xl">
      <svg viewBox="0 0 760 250" className="w-full" style={{ background: LIGHT, borderRadius: 8 }}>
        <ArrowDefs />
        <Box x={16} y={40} w={150} h={46} label="사용자" sub="브라우저 · 웹 화면" />
        <Box x={16} y={150} w={150} h={46} label="CI/CD · 개발자" sub="oras · docker (명령줄)" />
        <Box x={240} y={60} w={170} h={120} label="TrustLink" sub="웹 화면 · 관리 API · 중계" accent />
        <text x={325} y={160} textAnchor="middle" fontSize={9.5} fill="#fff">/v2 레지스트리 · /auth 로그인</text>
        {right.map(([t, d], i) => {
          const y = top + i * (rh + gap);
          return (
            <g key={t}>
              <rect x={rx} y={y} width={rw} height={rh} rx={6} fill="#fff" stroke={i === 5 ? SLATE : NAVY} strokeDasharray={i === 5 ? '4 3' : undefined} />
              <text x={rx + 10} y={y + 20} fontSize={11.5} fontWeight={700} fill={NAVY}>{t}</text>
              <text x={rx + 130} y={y + 20} fontSize={9.5} fill={SLATE}>{d}</text>
              <Arrow x1={410} y1={120} x2={rx} y2={y + rh / 2} />
            </g>
          );
        })}
        <Arrow x1={166} y1={63} x2={240} y2={95} />
        <Arrow x1={166} y1={173} x2={240} y2={145} />
      </svg>
    </div>
  );
}

// 처리 흐름: 올리기 → SBOM → 분석 → VEX 판단 → 발행·통보 → 고객 수령
export function FlowDiagram() {
  const steps = [
    { t: '1. 올리기', s: '산출물 + SBOM' },
    { t: '2. SBOM 확보', s: '첨부 또는 자동 생성' },
    { t: '3. 취약점 분석', s: 'Dependency-Track' },
    { t: '4. VEX 판단', s: '사람 결정 · AI 초안' },
    { t: '5. 발행·통보', s: '새 VEX 첨부 · 메일' },
    { t: '6. 고객 수령', s: '다운로드 · 검증' }
  ];
  const w = 112, gap = 15, y = 22, h = 50;
  return (
    <div className="mx-auto max-w-3xl">
      <svg viewBox="0 0 770 96" className="w-full" style={{ background: LIGHT, borderRadius: 8 }}>
        <ArrowDefs />
        {steps.map((st, i) => {
          const x = 8 + i * (w + gap);
          return (
            <g key={i}>
              <Box x={x} y={y} w={w} h={h} label={st.t} sub={st.s} accent={i === 3} />
              {i < steps.length - 1 && <Arrow x1={x + w} y1={y + h / 2} x2={x + w + gap} y2={y + h / 2} />}
            </g>
          );
        })}
        <text x={385} y={88} textAnchor="middle" fontSize={9.5} fill={SLATE}>올린 SBOM·VEX 는 고치지 않고 새 첨부로 쌓입니다 — 누가 언제 무엇을 냈는지 이력이 남습니다</text>
      </svg>
    </div>
  );
}
