import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { AlertTriangle, CircleAlert, Download, RefreshCw } from 'lucide-react';
import {
  adminMetrics, adminUsers, adminHealth, adminStats, adminDashboard,
  type Metrics, type AdminUser, type Health, type Stats, type Dashboard as Dash
} from '@/lib/api';
import { fmtBytes, cn } from '@/lib/utils';
import { Card, CardHeader, CardContent, Badge, Button } from '@/components/ui/primitives';
import { PageTitle, SectionTitle, StatCard, Loading, Alert, BarChart, Gauge, LineChart, Donut, Table, Th, Td, selectCls } from './_ui';

const GROUPS = ['admins', 'developers', 'partners', 'customers'];

// VEX 타입(상태) — 차트 시리즈/선택 드롭다운 공용 정의
const VEX_TYPES = [
  { key: 'affected', label: '영향있음', color: '#ef4444' },
  { key: 'not_affected', label: '영향없음', color: '#10b981' },
  { key: 'fixed', label: '수정됨', color: '#3b82f6' },
  { key: 'under_investigation', label: '조사중', color: '#f59e0b' }
] as const;

const TABS = [
  { key: 'security', label: '보안 현황' },
  { key: 'quality', label: '공급망 품질' },
  { key: 'customers', label: '고객·배포' },
  { key: 'ops', label: '운영' }
] as const;
type TabKey = (typeof TABS)[number]['key'];

const fmtTime = (t: string) => (t ? new Date(t).toLocaleString('ko-KR') : '—');
const pct = (a: number, b: number) => (b ? Math.round((a / b) * 100) : 0);
const artifactLink = (repo: string, tag: string) => `/artifact/${encodeURIComponent(repo)}/${encodeURIComponent(tag)}`;

// 표를 CSV 로 내려받기(엑셀에서 한글이 깨지지 않게 BOM 포함)
function downloadCSV(name: string, header: string[], rows: (string | number)[][]) {
  const esc = (v: string | number) => `"${String(v).replace(/"/g, '""')}"`;
  const body = [header, ...rows].map((r) => r.map(esc).join(',')).join('\n');
  const url = URL.createObjectURL(new Blob(['﻿' + body], { type: 'text/csv;charset=utf-8' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = `${name}-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

function CsvButton({ onClick }: { onClick: () => void }) {
  return (
    <Button variant="outline" size="sm" className="ml-auto h-7 font-normal" onClick={onClick}>
      <Download size={13} /> CSV
    </Button>
  );
}

function Panel({ title, action, className, children }: { title: string; action?: ReactNode; className?: string; children: ReactNode }) {
  return (
    <Card className={className}>
      <CardHeader className="flex flex-row items-center gap-2 font-semibold">{title}{action}</CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

// ---------- ① 할 일 ----------
function TodoPanel({ d }: { d: Dash }) {
  if (d.todo.length === 0) return <Alert tone="ok">처리할 일이 없습니다.</Alert>;
  return (
    <Card>
      <CardHeader className="font-semibold">할 일</CardHeader>
      <CardContent className="space-y-1.5">
        {d.todo.map((t, i) => {
          const body = (
            <>
              {t.tone === 'crit' ? <CircleAlert size={15} className="text-red-600" /> : <AlertTriangle size={15} className="text-amber-600" />}
              <span className="flex-1">{t.text}</span>
              <span className={cn('tabular-nums font-semibold', t.tone === 'crit' ? 'text-red-600' : 'text-amber-700')}>
                {t.kind === 'cert' ? `D-${t.count}` : t.count}
              </span>
            </>
          );
          const cls = 'flex items-center gap-2 rounded-md border px-3 py-2 text-sm';
          return t.link
            ? <Link key={i} to={t.link} className={cls + ' hover:bg-secondary'}>{body}</Link>
            : <div key={i} className={cls}>{body}</div>;
        })}
      </CardContent>
    </Card>
  );
}

// ---------- ② 보안 현황 ----------
function SecurityTab({ d, trend }: { d: Dash; trend: ReactNode }) {
  const s = d.security;
  const pend = s.pending || {};
  const pendTotal = Object.values(pend).reduce((a, b) => a + b, 0);
  const products = s.products || [];
  const tr = s.trend || [];
  return (
    <>
      {!d.dt && <div className="mb-4"><Alert tone="warn">Dependency-Track 이 연결되지 않아 취약점 집계가 없습니다.</Alert></div>}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <StatCard label="판단 대기 CRITICAL" value={<span className={pend.CRITICAL ? 'text-red-600' : ''}>{pend.CRITICAL || 0}</span>} />
        <StatCard label="판단 대기 HIGH" value={<span className={pend.HIGH ? 'text-amber-700' : ''}>{pend.HIGH || 0}</span>} />
        <StatCard label="판단 대기 전체" value={pendTotal} />
        <StatCard label="VEX 처리율" value={`${pct(s.analyzed, s.total)}%`} />
        <StatCard label="평균 대응 시간" value={s.mttrSamples ? `${s.mttrHours}시간` : '—'} />
      </div>
      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Panel title={`취약점 추이 (최근 ${tr.length}일)`} className="lg:col-span-2">
          <LineChart
            categories={tr.map((x) => x.date.slice(5))}
            empty="DT 지표 이력 없음"
            series={[
              { label: 'CRITICAL', color: '#dc2626', values: tr.map((x) => x.critical || 0) },
              { label: 'HIGH', color: '#f97316', values: tr.map((x) => x.high || 0) },
              { label: 'MEDIUM', color: '#eab308', values: tr.map((x) => x.medium || 0) },
              { label: 'LOW', color: '#64748b', values: tr.map((x) => x.low || 0) },
              { label: '미판단', color: '#7c3aed', values: tr.map((x) => x.unaudited || 0) }
            ]}
          />
        </Panel>
        <Panel title="판단 대기 기간">
          <BarChart data={s.aging || []} empty="판단 대기 없음" />
        </Panel>
      </div>
      <Panel title="제품·버전별 취약점" className="mt-4"
        action={products.length > 0 && <CsvButton onClick={() => downloadCSV('제품별-취약점', ['제품', '버전', 'CRITICAL', 'HIGH', '전체', '판단 대기'],
          products.map((p) => [p.repo, p.tag, p.critical, p.high, p.total, p.pending]))} />}>
        {products.length === 0 ? <p className="text-sm text-muted-foreground">취약점이 있는 버전이 없습니다.</p> : (
          <Table>
            <thead><tr><Th>제품</Th><Th>버전</Th><Th>CRITICAL</Th><Th>HIGH</Th><Th>전체</Th><Th>판단 대기</Th></tr></thead>
            <tbody>
              {products.slice(0, 15).map((p) => (
                <tr key={p.repo + p.tag}>
                  <Td><Link to={artifactLink(p.repo, p.tag)} className="underline-offset-4 hover:underline">{p.repo}</Link></Td>
                  <Td className="text-xs">{p.tag}</Td>
                  <Td className={p.critical ? 'font-semibold text-red-600' : ''}>{p.critical}</Td>
                  <Td className={p.high ? 'text-amber-700' : ''}>{p.high}</Td>
                  <Td>{p.total}</Td>
                  <Td>{p.pending}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Panel>
      <Panel title="최근 새 취약점 통보" className="mt-4">
        {(s.recent || []).length === 0 ? <p className="text-sm text-muted-foreground">없음</p> : (
          <ul className="space-y-1 text-sm">
            {(s.recent || []).map((r, i) => (
              <li key={i} className="flex gap-3">
                <span className="w-36 shrink-0 text-xs text-muted-foreground">{fmtTime(r.time)}</span>
                <Link to={artifactLink(r.repo, r.tag)} className="truncate underline-offset-4 hover:underline">{r.title}</Link>
              </li>
            ))}
          </ul>
        )}
      </Panel>
      {trend}
    </>
  );
}

// ---------- ③ 공급망 품질 ----------
function QualityTab({ d }: { d: Dash }) {
  const q = d.quality;
  const top = q.top || [];
  const noSbom = q.versions - q.withSbom;
  return (
    <>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="SBOM 보유율" value={`${pct(q.withSbom, q.versions)}% (${q.withSbom}/${q.versions})`} />
        <StatCard label="VEX 보유율" value={`${pct(q.withVex, q.versions)}% (${q.withVex}/${q.versions})`} />
        <StatCard label="구성요소(감시 중인 버전)" value={q.components} />
        <StatCard label="copyleft 라이선스" value={<span className={q.copyleft ? 'text-amber-700' : ''}>{q.copyleft}</span>} />
      </div>
      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Panel title="SBOM 출처">
          <Donut data={[
            { label: '공급자 제공', value: q.sbomSupplier },
            { label: 'TrustLink 생성(syft)', value: q.sbomSyft },
            { label: 'SBOM 없음', value: noSbom }
          ]} empty="버전 없음" />
        </Panel>
        <Panel title="SBOM 누락 항목 (구성요소 수)">
          <BarChart data={[
            { label: '버전 없음', value: q.noVersion },
            { label: 'purl 없음', value: q.noPurl },
            { label: '라이선스 없음', value: q.noLicense }
          ]} />
          <p className="mt-1 text-xs text-muted-foreground">전체 {q.components}개 중</p>
        </Panel>
        <Panel title="라이선스 상위 10">
          <BarChart data={q.licenses || []} empty="라이선스 정보 없음" />
        </Panel>
      </div>
      <Panel title="많이 쓰는 구성요소와 영향 범위" className="mt-4"
        action={top.length > 0 && <CsvButton onClick={() => downloadCSV('구성요소-영향범위', ['구성요소', '제품 수', '버전 수', '취약점'],
          top.map((c) => [c.name, c.products, c.versions, c.vulns]))} />}>
        {top.length === 0 ? <p className="text-sm text-muted-foreground">감시 중인 버전이 없습니다.</p> : (
          <Table>
            <thead><tr><Th>구성요소</Th><Th>쓰는 제품</Th><Th>쓰는 버전</Th><Th>취약점</Th></tr></thead>
            <tbody>
              {top.map((c) => (
                <tr key={c.name}>
                  <Td className="font-mono text-xs">{c.name}</Td>
                  <Td>{c.products}</Td>
                  <Td>{c.versions}</Td>
                  <Td className={c.vulns ? 'font-semibold text-red-600' : ''}>{c.vulns}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
        <p className="mt-2 text-xs text-muted-foreground">취약점이 많은 구성요소부터 — 하나가 문제되면 표의 제품·버전이 모두 영향을 받습니다.</p>
      </Panel>
    </>
  );
}

// ---------- ④ 고객·배포 ----------
function DownloadTable({ rows, empty }: { rows: NonNullable<Dash['customers']['recent']>; empty: string }) {
  if (rows.length === 0) return <p className="text-sm text-muted-foreground">{empty}</p>;
  return (
    <Table>
      <thead><tr><Th>시각</Th><Th>계정</Th><Th>고객사</Th><Th>제품</Th><Th>받은 버전</Th></tr></thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={i}>
            <Td className="whitespace-nowrap text-xs">{fmtTime(r.time)}</Td>
            <Td>{r.user}</Td>
            <Td>{r.org || <span className="text-muted-foreground">내부</span>}</Td>
            <Td><Link to={artifactLink(r.repo, r.tag)} className="underline-offset-4 hover:underline">{r.repo}</Link></Td>
            <Td className="text-xs">{r.tag}{r.latest && <span className="ml-1 text-amber-700">(최신 {r.latest})</span>}</Td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

function CustomersTab({ d }: { d: Dash }) {
  const c = d.customers;
  const recent = c.recent || [];
  const outdated = c.outdated || [];
  const toRows = (rs: typeof recent) => rs.map((r) => [r.time, r.user, r.org || '내부', r.repo, r.tag, r.latest || '']);
  const hdr = ['시각', '계정', '고객사', '제품', '받은 버전', '최신 버전'];
  return (
    <>
      <div className="grid gap-3 sm:grid-cols-3">
        <StatCard label="다운로드한 고객사" value={(c.orgs || []).length} />
        <StatCard label="고객사 다운로드 (30일)" value={(c.orgs || []).reduce((a, b) => a + b.value, 0)} />
        <StatCard label="고객 통보 (30일)" value={c.notices} />
      </div>
      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Panel title="고객사별 다운로드 (30일)">
          <BarChart data={c.orgs || []} empty="고객 다운로드 없음" />
        </Panel>
        <Panel title="최신이 아닌 버전을 받은 고객" className="lg:col-span-2"
          action={outdated.length > 0 && <CsvButton onClick={() => downloadCSV('구버전-다운로드', hdr, toRows(outdated))} />}>
          <DownloadTable rows={outdated} empty="모든 고객이 최신 버전을 받았습니다." />
        </Panel>
      </div>
      <Panel title="최근 다운로드" className="mt-4"
        action={recent.length > 0 && <CsvButton onClick={() => downloadCSV('최근-다운로드', hdr, toRows(recent))} />}>
        <DownloadTable rows={recent} empty="최근 30일 다운로드가 없습니다." />
      </Panel>
    </>
  );
}

// ---------- ⑤ 운영 ----------
function OpsTab({ d, base }: { d: Dash; base: ReactNode }) {
  const o = d.ops;
  const daily = o.daily || [];
  return (
    <>
      {base}
      <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="메일 발송 (30일)" value={o.mailed} />
        <StatCard label="메일 실패 (30일)" value={<span className={o.mailFailed ? 'text-red-600' : ''}>{o.mailFailed}</span>} />
        <StatCard label="감시 동기화" value={<span className="text-base">{fmtTime(o.lastSync)}<br /><span className="text-xs text-muted-foreground">{o.lastSyncMsg || '—'}</span></span>} />
        <StatCard label="HTTPS 인증서" value={o.certDays >= 0 ? `${o.certDays}일 남음` : 'http / 확인 불가'} />
      </div>
      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Panel title="일별 업로드·다운로드 (30일)" className="lg:col-span-2">
          <LineChart
            categories={daily.map((x) => x.date.slice(5))}
            series={[
              { label: '업로드', color: '#2563eb', values: daily.map((x) => x.uploads || 0) },
              { label: '다운로드', color: '#10b981', values: daily.map((x) => x.downloads || 0) }
            ]}
          />
        </Panel>
        <Panel title="활동 상위 계정 (30일)">
          <BarChart data={o.actors || []} empty="활동 없음" />
        </Panel>
      </div>
    </>
  );
}

function readTab(): TabKey {
  try {
    const t = localStorage.getItem('tl-dash-tab');
    if (TABS.some((x) => x.key === t)) return t as TabKey;
  } catch { /* 저장소 차단 */ }
  return 'security';
}

export default function Dashboard() {
  const [data, setData] = useState<{ mt: Metrics; us: AdminUser[]; h: Health } | null>(null);
  const [err, setErr] = useState('');
  const [stats, setStats] = useState<Stats | null>(null);
  const [statsErr, setStatsErr] = useState('');
  const [dash, setDash] = useState<Dash | null>(null);
  const [dashErr, setDashErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [tab, setTab] = useState<TabKey>(readTab);
  const [repo, setRepo] = useState('');
  const [vexType, setVexType] = useState<'all' | (typeof VEX_TYPES)[number]['key']>('all');

  const loadDash = (refresh = false) => {
    setBusy(true);
    adminDashboard(refresh).then((x) => { setDash(x); setDashErr(''); }).catch((e) => setDashErr(String(e))).finally(() => setBusy(false));
  };
  useEffect(() => {
    Promise.all([adminMetrics(), adminUsers(), adminHealth()])
      .then(([mt, us, h]) => setData({ mt, us, h }))
      .catch((e) => setErr(String(e)));
    adminStats().then(setStats).catch((e) => setStatsErr(String(e)));
    loadDash();
  }, []);
  const pick = (t: TabKey) => {
    setTab(t);
    try { localStorage.setItem('tl-dash-tab', t); } catch { /* 저장소 차단 */ }
  };

  // 기본 선택: 버전이 가장 많은 제품(추이가 잘 보이는 것)
  const products = stats?.products || [];
  const defaultRepo = useMemo(
    () => products.slice().sort((a, b) => b.versions.length - a.versions.length)[0]?.repo || '',
    [products]
  );
  const selected = products.find((p) => p.repo === (repo || defaultRepo));

  if (err) return (<><PageTitle>대시보드</PageTitle><Alert tone="crit">오류: {err}</Alert></>);
  if (!data) return (<><PageTitle>대시보드</PageTitle><Loading /></>);

  const { mt, us, h } = data;
  const disk = mt.disk;
  const byGroup: Record<string, number> = {};
  us.forEach((u) => (u.groups || []).forEach((g) => (byGroup[g] = (byGroup[g] || 0) + 1)));
  const groupData = GROUPS.map((g) => ({ label: g, value: byGroup[g] || 0 }));
  const repoSorted = [...(mt.repos || [])].sort((a, b) => b.bytes - a.bytes);
  const repoData = repoSorted.slice(0, 8).map((r) => ({ label: r.repo, value: r.bytes }));
  // 제품별 디스크 사용량(도넛): 상위 8 + 나머지는 '기타'로 합산
  const TOPN = 8;
  const productSizes = repoSorted.slice(0, TOPN).map((r) => ({ label: r.repo.split('/').pop() || r.repo, value: r.bytes }));
  const restBytes = repoSorted.slice(TOPN).reduce((s, r) => s + r.bytes, 0);
  if (restBytes > 0) productSizes.push({ label: `기타 ${repoSorted.length - TOPN}개`, value: restBytes });

  const versions = selected?.versions || [];
  const cats = versions.map((v) => v.tag);
  const isSynthetic = versions.some((v) => v.synthetic);

  // 운영 탭 상단: 기존 지표(레지스트리·디스크·사용자·서비스 상태)
  const opsBase = (
    <>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <StatCard label="레포지토리" value={mt.repoCount ?? '-'} />
        <StatCard label="총 이미지 용량" value={fmtBytes(mt.repoTotalBytes || 0)} />
        <StatCard label="디스크 사용률" value={`${disk?.usedPct ?? '-'}%`} />
        <StatCard label="디스크 여유" value={fmtBytes(disk?.freeBytes || 0)} />
        <StatCard label="사용자" value={us.length} />
        <StatCard label="zot / Keycloak" value={`${h.zot ? '정상' : '중단'} / ${h.keycloak ? '정상' : '중단'}`} />
      </div>

      {disk && (
        <Card className="mt-4">
          <CardHeader className="font-semibold">디스크 사용량</CardHeader>
          <CardContent className="grid gap-4 md:grid-cols-2">
            <div>
              <Gauge label={disk.path || '저장소'} pct={disk.usedPct ?? 0} sub={`${fmtBytes(disk.freeBytes || 0)} 여유 / ${fmtBytes(disk.totalBytes || 0)}`} />
              <p className="mt-2 text-xs text-muted-foreground">레지스트리 총 {fmtBytes(mt.repoTotalBytes || 0)} · 제품 {mt.repoCount ?? 0}개</p>
            </div>
            <div>
              <div className="mb-1 text-sm font-medium">제품별 사용량 (레지스트리)</div>
              <Donut data={productSizes} fmt={fmtBytes} empty="제품 사용량 데이터 없음" />
            </div>
          </CardContent>
        </Card>
      )}

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="font-semibold">그룹별 사용자</CardHeader>
          <CardContent><BarChart data={groupData} /></CardContent>
        </Card>
        <Card>
          <CardHeader className="font-semibold">레포지토리 사용량 (상위 8)</CardHeader>
          <CardContent><BarChart data={repoData} fmt={fmtBytes} empty="repo 메트릭 없음" /></CardContent>
        </Card>
      </div>
    </>
  );

  // 보안 현황 탭 하단: 제품 버전 추이(SBOM / 취약점 / VEX) — 실데이터가 없으면 시연용 더미
  const versionTrend = (
    <>
      <div className="mt-6 flex flex-wrap items-center gap-3">
        <SectionTitle>제품 버전 추이</SectionTitle>
        {products.length > 0 && (
          <select className={selectCls} value={selected?.repo || ''} onChange={(e) => setRepo(e.target.value)}>
            {products.map((p) => (
              <option key={p.repo} value={p.repo}>{p.repo} ({p.versions.length}개 버전)</option>
            ))}
          </select>
        )}
        {isSynthetic && <Badge variant="warn">일부 데모(더미) 데이터</Badge>}
      </div>

      {statsErr ? (
        <Alert tone="warn">통계 집계 실패: {statsErr}</Alert>
      ) : !stats ? (
        <p className="text-sm text-muted-foreground">버전 추이 집계 중…</p>
      ) : !selected || versions.length === 0 ? (
        <p className="text-sm text-muted-foreground">표시할 제품/버전이 없습니다.</p>
      ) : (
        <div className="mt-2 grid gap-4 lg:grid-cols-2">
          <Card>
            <CardHeader className="font-semibold">SBOM 컴포넌트 수 추이</CardHeader>
            <CardContent>
              <LineChart
                categories={cats}
                series={[{ label: '컴포넌트 수', color: '#F6A623', values: versions.map((v) => v.components) }]}
              />
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="font-semibold">취약점 추이 (취약점 수 · 영향있음 · 수정됨)</CardHeader>
            <CardContent>
              <LineChart
                categories={cats}
                series={[
                  { label: '취약점 수', color: '#64748b', values: versions.map((v) => v.vulnerabilities) },
                  { label: '영향있음', color: '#ef4444', values: versions.map((v) => v.affected) },
                  { label: '수정됨', color: '#3b82f6', values: versions.map((v) => v.fixed) }
                ]}
              />
            </CardContent>
          </Card>
          <Card className="lg:col-span-2">
            <CardHeader className="flex flex-wrap items-center gap-3 font-semibold">
              <span>VEX 타입별 추이</span>
              <select className={selectCls + ' ml-auto font-normal'} value={vexType} onChange={(e) => setVexType(e.target.value as typeof vexType)}>
                <option value="all">전체 타입</option>
                {VEX_TYPES.map((t) => <option key={t.key} value={t.key}>{t.label}</option>)}
              </select>
            </CardHeader>
            <CardContent>
              <LineChart
                categories={cats}
                series={VEX_TYPES
                  .filter((t) => vexType === 'all' || t.key === vexType)
                  .map((t) => ({ label: t.label, color: t.color, values: versions.map((v) => v.vex?.[t.key] ?? 0) }))}
              />
            </CardContent>
          </Card>
        </div>
      )}
      {isSynthetic && (
        <p className="mt-2 text-xs text-muted-foreground">
          ※ 취약점/VEX 스캔 데이터가 없어 일부 값은 버전 추이 시연용 더미입니다(SBOM 컴포넌트 수는 실데이터). zot CVE 스캐너 구성 시 자동으로 실데이터로 대체됩니다.
        </p>
      )}
    </>
  );

  return (
    <>
      <div className="flex items-center gap-3">
        <PageTitle>대시보드</PageTitle>
        <span className="ml-auto text-xs text-muted-foreground">{dash && `집계 ${fmtTime(dash.generated)}`}</span>
        <Button variant="outline" size="sm" onClick={() => loadDash(true)} disabled={busy}>
          <RefreshCw size={14} className={busy ? 'animate-spin' : ''} /> 새로 집계
        </Button>
      </div>

      {dashErr && <div className="mb-4"><Alert tone="crit">집계 실패: {dashErr}</Alert></div>}
      {!dash ? <Loading /> : <TodoPanel d={dash} />}

      <div className="mt-6 flex gap-1 border-b">
        {TABS.map((t) => (
          <button key={t.key} onClick={() => pick(t.key)}
            className={cn('-mb-px border-b-2 px-4 py-2 text-sm transition-colors',
              tab === t.key ? 'border-foreground font-medium text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground')}>
            {t.label}
          </button>
        ))}
      </div>
      <div className="mt-4">
        {tab === 'ops' ? <OpsTab d={dash ?? EMPTY} base={opsBase} />
          : !dash ? <Loading />
            : tab === 'security' ? <SecurityTab d={dash} trend={versionTrend} />
              : tab === 'quality' ? <QualityTab d={dash} />
                : <CustomersTab d={dash} />}
      </div>
    </>
  );
}

// 집계 전에도 운영 탭(기존 지표)은 바로 보이게 하는 빈 값
const EMPTY: Dash = {
  generated: '', dt: false, todo: [],
  security: { pending: {}, total: 0, analyzed: 0, aging: [], trend: [], products: [], mttrHours: 0, mttrSamples: 0, recent: [] },
  quality: { versions: 0, withSbom: 0, sbomSupplier: 0, sbomSyft: 0, withVex: 0, components: 0, noVersion: 0, noPurl: 0, noLicense: 0, copyleft: 0, licenses: [], top: [] },
  customers: { orgs: [], recent: [], outdated: [], notices: 0 },
  ops: { daily: [], actors: [], mailed: 0, mailFailed: 0, lastSync: '', lastSyncMsg: '', certDays: -1 }
};
