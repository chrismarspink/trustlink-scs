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
      <h1 className="text-2xl font-bold">{title}</h1>
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

// 구성도: 웹(28080) + 레지스트리(28081) + CA(28443) 진입점 & 내부 전용.
export function ArchDiagram() {
  return (
    <svg viewBox="0 0 720 320" className="w-full" style={{ background: LIGHT, borderRadius: 8 }}>
      <ArrowDefs />
      <Box x={20} y={30} w={150} h={50} label="사용자" sub="브라우저 (웹 UI)" />
      <Box x={20} y={130} w={150} h={52} label="CI/CD · 개발자" sub="oras / docker (CLI)" />
      <Box x={20} y={240} w={150} h={50} label="검증자 (협력사)" sub="openssl / CRL" />

      <Box x={250} y={28} w={160} h={70} label="TrustLink (BFF)" sub=":28080 웹 · 관리" accent />

      <text x={595} y={18} textAnchor="middle" fontSize={11} fill={SLATE}>── 내부 전용 / 독립 평면 ──</text>
      <Box x={490} y={28} w={210} h={42} label="Keycloak" sub="OIDC 인증" dashed />
      <Box x={490} y={120} w={210} h={52} label="zot — OCI 레지스트리" sub=":28081 직접 pull/push" accent />
      <Box x={490} y={238} w={210} h={52} label="step-ca — CA" sub=":28443 발급·검증·CRL" accent />

      <Arrow x1={170} y1={55} x2={250} y2={55} />
      <Arrow x1={410} y1={50} x2={490} y2={49} />
      <Arrow x1={410} y1={80} x2={490} y2={140} />
      <Arrow x1={170} y1={150} x2={490} y2={145} />
      <Arrow x1={170} y1={262} x2={490} y2={262} />
    </svg>
  );
}

// 프로세스 흐름: push → SBOM/VEX → 분석 → VEX/서명 → 검증·반출.
export function FlowDiagram() {
  const steps = [
    { t: '1. 산출물 Push', s: 'oras/docker → zot' },
    { t: '2. SBOM/VEX 첨부', s: 'referrers' },
    { t: '3. 취약점 분석', s: 'Dependency-Track' },
    { t: '4. VEX·CMS 서명', s: 'TrustLink + step-ca' },
    { t: '5. 검증·반출', s: 'openssl cms · CRL' }
  ];
  const w = 124, gap = 25, y = 60, h = 56;
  return (
    <svg viewBox="0 0 740 150" className="w-full" style={{ background: LIGHT, borderRadius: 8 }}>
      <ArrowDefs />
      {steps.map((st, i) => {
        const x = 10 + i * (w + gap);
        return (
          <g key={i}>
            <Box x={x} y={y} w={w} h={h} label={st.t} sub={st.s} accent={i === 3} />
            {i < steps.length - 1 && <Arrow x1={x + w} y1={y + h / 2} x2={x + w + gap} y2={y + h / 2} />}
          </g>
        );
      })}
      <text x={370} y={30} textAnchor="middle" fontSize={11} fill={SLATE}>
        업로드된 SBOM/VEX/서명은 덮어쓰지 않고 새 referrer 로 누적 → 출처(provenance) 보존
      </text>
    </svg>
  );
}
