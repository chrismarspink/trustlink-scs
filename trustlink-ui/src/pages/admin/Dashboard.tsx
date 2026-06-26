import { useEffect, useMemo, useState } from 'react';
import {
  adminMetrics, adminUsers, adminHealth, adminStats,
  type Metrics, type AdminUser, type Health, type Stats
} from '@/lib/api';
import { fmtBytes } from '@/lib/utils';
import { Card, CardHeader, CardContent, Badge } from '@/components/ui/primitives';
import { PageTitle, SectionTitle, StatCard, Loading, Alert, BarChart, Gauge, LineChart, Donut, selectCls } from './_ui';

const GROUPS = ['admins', 'developers', 'partners', 'customers'];

// VEX 타입(상태) — 차트 시리즈/선택 드롭다운 공용 정의
const VEX_TYPES = [
  { key: 'affected', label: '영향있음', color: '#ef4444' },
  { key: 'not_affected', label: '영향없음', color: '#10b981' },
  { key: 'fixed', label: '수정됨', color: '#3b82f6' },
  { key: 'under_investigation', label: '조사중', color: '#f59e0b' }
] as const;

export default function Dashboard() {
  const [data, setData] = useState<{ mt: Metrics; us: AdminUser[]; h: Health } | null>(null);
  const [err, setErr] = useState('');
  const [stats, setStats] = useState<Stats | null>(null);
  const [statsErr, setStatsErr] = useState('');
  const [repo, setRepo] = useState('');
  const [vexType, setVexType] = useState<'all' | (typeof VEX_TYPES)[number]['key']>('all');

  useEffect(() => {
    Promise.all([adminMetrics(), adminUsers(), adminHealth()])
      .then(([mt, us, h]) => setData({ mt, us, h }))
      .catch((e) => setErr(String(e)));
    adminStats().then(setStats).catch((e) => setStatsErr(String(e)));
  }, []);

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

  return (
    <>
      <PageTitle>대시보드</PageTitle>
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

      {/* ---------- 제품 버전 추이 (SBOM / 취약점 / VEX) ---------- */}
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
}
