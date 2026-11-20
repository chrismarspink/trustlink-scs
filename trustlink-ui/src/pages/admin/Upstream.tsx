import { useEffect, useState, type ReactNode } from 'react';
import { JobProgress, Busy } from '@/components/Progress';
import { Play, Search, Sparkles, KeyRound, Printer, ExternalLink } from 'lucide-react';
import {
  adminRepos, adminUpstreamConfig, adminUpstreamConfigSave, adminUpstreamRun, adminUpstreamRepo, adminUpstreamReports, adminUpstreamReport,
  type RepoEntry, type UpConfig, type UpRate, type UpReport, type UpReportItem, type UpRepo, type UpComp, type UpRating
} from '@/lib/api';
import { Button, Badge, Card, Input } from '@/components/ui/primitives';
import { PageHeader, SectionTitle, StatCard, Alert, Loading, Table, Th, Td, selectCls } from './_ui';
import { cn } from '@/lib/utils';

// 규제·보고 › 공개 저장소 분석: 제품 SBOM 구성요소의 상류(오픈소스) 저장소 건강도를 점검한다 — CRA 제3자 구성요소 실사 증거.
// 신호는 deps.dev(OpenSSF Scorecard)·GitHub 공개 API, 판정은 규칙(위험·주의·양호·미확인), AI 는 요약만.

const UP_RATING: Record<UpRating, { label: string; cls: string }> = {
  risk: { label: '위험', cls: 'bg-red-50 text-red-700' },
  warn: { label: '주의', cls: 'bg-amber-50 text-amber-800' },
  ok: { label: '양호', cls: 'bg-emerald-50 text-emerald-700' },
  unknown: { label: '미확인', cls: 'bg-secondary text-muted-foreground' }
};
const upDate = (t?: string) => (t ? t.slice(0, 10) : '—');
const fmt = (t?: string) => (t ? new Date(t).toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' }) : '—');
// 경과 시간(대략): 3일 전 / 5개월 전 / 2.4년 전
function upAge(t?: string) {
  if (!t) return '';
  const d = (Date.now() - new Date(t).getTime()) / 86400000;
  if (d < 31) return `${Math.max(0, Math.round(d))}일 전`;
  if (d < 365) return `${Math.round(d / 30)}개월 전`;
  return `${(d / 365).toFixed(1)}년 전`;
}
const GH_STATE: Record<string, string> = {
  ok: '', 'not-found': 'GitHub 저장소 없음', 'rate-limited': 'GitHub 한도 — 미조회', skipped: 'GitHub 조회 상한 — 미조회', error: 'GitHub 조회 오류', 'n/a': 'GitHub 아님'
};
const printUrl = (id: string) => `/admin/upstream/print/${id}`;

const Rating = ({ r }: { r: UpRating }) => (
  <span className={cn('inline-block whitespace-nowrap rounded px-1.5 py-0.5 text-xs font-medium', UP_RATING[r]?.cls)}>{UP_RATING[r]?.label || r}</span>
);

function SecPolicy({ r }: { r?: UpRepo }) {
  if (r?.secPolicy === undefined) return <span className="text-muted-foreground">—</span>;
  return r.secPolicy ? <span className="text-emerald-700">있음</span> : <span className="text-amber-700">없음</span>;
}

function RateLine({ rate, err }: { rate?: UpRate; err?: string }) {
  if (err) return <span className="text-amber-700">GitHub 한도 조회 실패: {err}</span>;
  if (!rate) return null;
  return (
    <span>
      GitHub API 남은 요청 <b>{rate.remaining}</b> / {rate.limit} (시간당) · 재설정 {fmt(rate.reset)}
      {!rate.auth && rate.limit <= 60 && <span className="text-muted-foreground"> · 토큰 없음</span>}
    </span>
  );
}

function SettingsCard({ cfg, rate, rateErr, onSaved }: { cfg: UpConfig; rate?: UpRate; rateErr?: string; onSaved: () => void }) {
  const [token, setToken] = useState('');
  const [max, setMax] = useState(String(cfg.maxRepos || ''));
  const [msg, setMsg] = useState('');
  async function save(clearToken = false) {
    setMsg('');
    const n = Number(max || 0);
    if (!Number.isInteger(n) || n < 0 || n > 1000) { setMsg('GitHub 조회 상한은 0~1000'); return; }
    try {
      await adminUpstreamConfigSave({ githubToken: token.trim() || undefined, clearToken, maxRepos: n });
      setToken('');
      setMsg(clearToken ? '토큰을 지웠습니다.' : '저장했습니다.');
      onSaved();
    } catch (e) { setMsg(String(e)); }
  }
  return (
    <Card className="space-y-2 p-4 text-sm">
      <div className="flex items-center gap-1 font-semibold"><KeyRound size={14} /> GitHub 연결(선택)</div>
      <div className="text-xs text-muted-foreground"><RateLine rate={rate} err={rateErr} /></div>
      <div>
        토큰: {cfg.hasToken ? <Badge variant="success">등록됨 {cfg.tokenHint}</Badge> : <Badge variant="muted">없음 — 시간당 60회</Badge>}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <Input type="password" autoComplete="new-password" name="gh-token" data-lpignore="true" placeholder={cfg.hasToken ? '새 토큰(비우면 유지)' : 'GitHub 토큰(공개 저장소 읽기 권한이면 충분)'}
          value={token} onChange={(e) => setToken(e.target.value)} className="h-8 w-72" />
        <label className="inline-flex items-center gap-1.5 text-xs">
          실행당 GitHub 조회 상한
          <Input value={max} onChange={(e) => setMax(e.target.value)} placeholder={String(cfg.effective)} className="h-8 w-20" />
        </label>
        <Button size="sm" onClick={() => save()}>저장</Button>
        {cfg.hasToken && <Button size="sm" variant="outline" onClick={() => save(true)}>토큰 지우기</Button>}
        {msg && <span className="text-xs text-muted-foreground">{msg}</span>}
      </div>
      <p className="text-xs text-muted-foreground">
        토큰은 서버 설정 파일(권한 0600)에만 저장되고 화면에는 끝 4자리만 보입니다. 현재 상한 {cfg.effective}개(비우면 기본: 토큰 없음 12 · 있음 300).
        저장소 결과는 24시간 캐시해 다시 실행할 때 요청을 아낍니다.
      </p>
    </Card>
  );
}

function RepoSignals({ r }: { r: UpRepo }) {
  const rows: [string, ReactNode][] = [
    ['등급', <span key="r" className="flex flex-wrap items-center gap-2">{r.rating && <Rating r={r.rating} />}<span className="text-xs">{r.reasons?.join(' · ')}</span></span>],
    ['OpenSSF Scorecard', r.scorecard != null ? `${r.scorecard.toFixed(1)} / 10 (${upDate(r.scorecardDate)})` : '없음'],
    ['보관·비활성', r.archived || r.disabled ? <span className="text-red-700">{r.archived ? '보관(archived)' : ''} {r.disabled ? '비활성' : ''}</span> : '아니오'],
    ['마지막 커밋(push)', r.pushedAt ? `${upDate(r.pushedAt)} (${upAge(r.pushedAt)})` : '—'],
    ['최근 릴리스', r.release ? `${r.release} · ${upDate(r.releaseAt)} (${upAge(r.releaseAt)})` : '—'],
    ['라이선스', r.license || '—'],
    ['보안 정책(SECURITY.md)', <SecPolicy key="s" r={r} />],
    ['공개 보안 권고', r.advisories != null ? `${r.advisories}건 (치명 ${r.advCritical || 0} · 높음 ${r.advHigh || 0} · 패치 없는 치명 ${r.advOpenCritical || 0})` : '—'],
    ['별 · 포크 · 열린 이슈', `${r.stars ?? '—'} · ${r.forks ?? '—'} · ${r.openIssues ?? '—'}`],
    ['조회', `deps.dev ${r.depsDev} · GitHub ${r.github}${r.cached ? ' · 캐시' : ''} · ${fmt(r.fetchedAt)}`]
  ];
  return (
    <Card className="p-4 text-sm">
      <a href={r.url} target="_blank" rel="noreferrer" className="mb-2 inline-flex items-center gap-1 font-semibold text-primary hover:underline">
        {r.id} <ExternalLink size={13} />
      </a>
      <dl className="grid grid-cols-[180px_1fr] gap-x-3 gap-y-1.5">
        {rows.map(([k, v]) => <div key={k} className="contents"><dt className="text-muted-foreground">{k}</dt><dd>{v}</dd></div>)}
      </dl>
      {r.checks && (
        <div className="mt-3 flex flex-wrap gap-1">
          {Object.entries(r.checks).map(([k, v]) => (
            <Badge key={k} variant={v < 0 ? 'muted' : v >= 7 ? 'success' : v >= 4 ? 'warn' : 'danger'}>{k} {v < 0 ? '–' : v}</Badge>
          ))}
        </div>
      )}
    </Card>
  );
}

function CompTable({ rep }: { rep: UpReport }) {
  const [f, setF] = useState<'all' | UpRating>('all');
  const [q, setQ] = useState('');
  const list = rep.comps.filter((c) => (f === 'all' || c.rating === f) && (!q || (c.name + ' ' + (c.repo || '')).toLowerCase().includes(q.toLowerCase())));
  const order: Record<UpRating, number> = { risk: 0, warn: 1, unknown: 2, ok: 3 };
  list.sort((a, b) => order[a.rating] - order[b.rating] || a.name.localeCompare(b.name));
  const shown = list.slice(0, 500);
  return (
    <>
      <div className="mb-2 flex flex-wrap items-center gap-2 text-sm">
        {(['all', 'risk', 'warn', 'ok', 'unknown'] as const).map((k) => (
          <Button key={k} size="sm" variant={f === k ? 'default' : 'outline'} onClick={() => setF(k)}>
            {k === 'all' ? `전체 ${rep.comps.length}` : `${UP_RATING[k].label} ${rep.counts?.[k] ?? 0}`}
          </Button>
        ))}
        <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="구성요소·저장소 검색" className="h-8 w-56" />
        {list.length > shown.length && <span className="text-xs text-muted-foreground">앞 {shown.length}개만 표시</span>}
      </div>
      <Table>
        <thead>
          <tr><Th>구성요소</Th><Th>버전</Th><Th>상류 저장소</Th><Th>Scorecard</Th><Th>마지막 커밋</Th><Th>최근 릴리스</Th><Th>보안 정책</Th><Th>권고</Th><Th>등급 · 사유</Th></tr>
        </thead>
        <tbody>
          {shown.map((c: UpComp, i) => {
            const r = c.repo ? rep.repos[c.repo] : undefined;
            const gh = r ? GH_STATE[r.github] : '';
            return (
              <tr key={i}>
                <Td className="max-w-[200px] break-all text-xs font-medium">{c.name}{c.deprecated && <Badge variant="warn" className="ml-1">deprecated</Badge>}</Td>
                <Td className="max-w-[110px] break-all font-mono text-xs">{c.version || '—'}</Td>
                <Td className="max-w-[220px] text-xs">
                  {r ? <a href={r.url} target="_blank" rel="noreferrer" className="break-all text-primary hover:underline">{c.repo}</a>
                    : <span className="text-muted-foreground">{c.repoSrc || '—'}</span>}
                  {r && <div className="text-[11px] text-muted-foreground">출처 {c.repoSrc}{gh && ` · ${gh}`}</div>}
                </Td>
                <Td className="text-xs tabular-nums">{r?.scorecard != null ? r.scorecard.toFixed(1) : '—'}</Td>
                <Td className="whitespace-nowrap text-xs">{r?.pushedAt ? <>{upDate(r.pushedAt)}<div className="text-[11px] text-muted-foreground">{upAge(r.pushedAt)}</div></> : '—'}</Td>
                <Td className="whitespace-nowrap text-xs">{r?.release ? <>{r.release}<div className="text-[11px] text-muted-foreground">{upDate(r.releaseAt)}</div></> : '—'}</Td>
                <Td className="text-xs"><SecPolicy r={r} /></Td>
                <Td className="whitespace-nowrap text-xs">
                  {c.vulns?.length ? <span title={c.vulns.join(', ')}>이 버전 {c.vulns.length}건{(c.vulnCritical || c.vulnHigh) ? ` (치명 ${c.vulnCritical || 0}·높음 ${c.vulnHigh || 0})` : ''}</span> : <span className="text-muted-foreground">이 버전 0</span>}
                  {r?.advisories != null && <div className="text-[11px] text-muted-foreground">저장소 공개 {r.advisories}건</div>}
                </Td>
                <Td className="max-w-[320px] text-xs">
                  <Rating r={c.rating} />
                  {c.reasons && c.reasons.length > 0 && <ul className="mt-1 list-disc pl-4 text-[11px] text-muted-foreground">{c.reasons.map((x, k) => <li key={k}>{x}</li>)}</ul>}
                </Td>
              </tr>
            );
          })}
          {shown.length === 0 && <tr><Td colSpan={9} className="text-center text-muted-foreground">해당 구성요소 없음</Td></tr>}
        </tbody>
      </Table>
    </>
  );
}

function FlagList({ items, empty }: { items: UpReport['top']; empty: string }) {
  if (!items || items.length === 0) return <p className="text-sm text-muted-foreground">{empty}</p>;
  return (
    <Table>
      <thead><tr><Th>구성요소</Th><Th>저장소</Th><Th>등급</Th><Th>사유</Th></tr></thead>
      <tbody>
        {items.map((f, i) => (
          <tr key={i}>
            <Td className="text-xs font-medium">{f.name} <span className="font-mono text-muted-foreground">{f.version}</span></Td>
            <Td className="break-all text-xs">{f.repo || '—'}</Td>
            <Td><Rating r={f.rating} /></Td>
            <Td className="text-xs">{f.reasons.join(' · ')}</Td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

function Summary({ rep }: { rep: UpReport }) {
  if (rep.aiError) return <Alert tone="warn">AI 요약을 만들지 못했습니다 — 규칙 판정만 표시합니다. ({rep.aiError})</Alert>;
  if (!rep.summary) return null;
  const s = rep.summary;
  return (
    <Card className="mt-4 space-y-2 p-4 text-sm">
      <div className="flex items-center gap-1 text-xs text-violet-700"><Sparkles size={12} /> AI 요약 초안 · {rep.aiMeta?.model} · 판정은 아래 규칙 결과, 사람 검토 필요</div>
      <p className="font-medium">{s.headline}</p>
      {s.points.length > 0 && <ul className="list-disc pl-5">{s.points.map((p, i) => <li key={i}>{p}</li>)}</ul>}
      {s.actions.length > 0 && (
        <div className="border-t pt-2">
          <div className="mb-1 text-xs font-semibold">먼저 할 일</div>
          <ol className="list-decimal pl-5">{s.actions.map((p, i) => <li key={i}>{p}</li>)}</ol>
        </div>
      )}
    </Card>
  );
}

function ReportView({ rep }: { rep: UpReport }) {
  const c = rep.counts || { risk: 0, warn: 0, ok: 0, unknown: 0 };
  const repo = rep.kind === 'repo' ? Object.values(rep.repos)[0] : undefined;
  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="text-lg font-semibold">{rep.kind === 'repo' ? rep.target : `${rep.repo}:${rep.tag}`}</div>
          <div className="text-xs text-muted-foreground">
            {fmt(rep.created)} · {rep.createdBy}{rep.sbom && <> · SBOM {rep.sbom}</>}
            {rep.kind === 'product' && <> · 상류 저장소 {Object.keys(rep.repos).length}개</>}
            {rep.rate && <> · GitHub {rep.rate.auth ? '토큰' : '토큰 없음'}{rep.rate.hit && <span className="text-amber-700"> · 한도 도달</span>}</>}
          </div>
        </div>
        {rep.state === 'done' && (
          <a href={printUrl(rep.id)} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-sm text-primary hover:underline">
            <Printer size={14} /> 인쇄용 보기(PDF)
          </a>
        )}
      </div>
      {rep.error && <Alert tone="crit">{rep.error}</Alert>}
      {rep.notes?.map((n, i) => <Alert key={i} tone="warn">{n}</Alert>)}
      <Summary rep={rep} />

      {rep.kind === 'product' && (
        <>
          <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-5">
            <StatCard label="구성요소" value={rep.comps.length} />
            <StatCard label="위험" value={<span className="text-red-700">{c.risk}</span>} />
            <StatCard label="주의" value={<span className="text-amber-700">{c.warn}</span>} />
            <StatCard label="양호" value={<span className="text-emerald-700">{c.ok}</span>} />
            <StatCard label="미확인" value={c.unknown} />
          </div>
          <SectionTitle>주요 위험</SectionTitle>
          <FlagList items={rep.top} empty="위험 등급 구성요소가 없습니다." />
          <SectionTitle>교체·포크 검토 대상 <span className="ml-1 text-xs font-normal text-muted-foreground">보관·비활성·2년 이상 커밋 없음·사용 중단 표시</span></SectionTitle>
          <FlagList items={rep.replace} empty="유지보수 중단 징후가 있는 구성요소가 없습니다." />
          <SectionTitle>구성요소별 상류 저장소</SectionTitle>
          <CompTable rep={rep} />
        </>
      )}

      {repo && (
        <>
          <SectionTitle>저장소 신호</SectionTitle>
          <RepoSignals r={repo} />
          <SectionTitle>GitHub 의존성 그래프(SBOM 내보내기)</SectionTitle>
          {!rep.depGraph ? <p className="text-sm text-muted-foreground">받지 않았습니다(GitHub 조회 실패).</p>
            : rep.depGraph.error ? <Alert tone="warn">{rep.depGraph.error}</Alert>
              : (
                <Card className="p-4 text-sm">
                  <div>패키지 <b>{rep.depGraph.packages}</b>개 · {Object.entries(rep.depGraph.ecosystems || {}).map(([k, v]) => `${k} ${v}`).join(' · ')}</div>
                  {rep.depGraph.sample && <div className="mt-2 text-xs text-muted-foreground">예: {rep.depGraph.sample.slice(0, 15).join(', ')}{rep.depGraph.packages > 15 && ' …'}</div>}
                  <p className="mt-2 text-xs text-muted-foreground">GitHub 이 저장소 매니페스트에서 추출한 SPDX 목록입니다(버전 범위 포함). 협력사가 제출한 SBOM 과 대조하는 데 쓰세요.</p>
                </Card>
              )}
        </>
      )}
      <p className="mt-4 text-xs text-muted-foreground">{rep.disclaimer}</p>
    </div>
  );
}

export default function Upstream() {
  const [repos, setRepos] = useState<RepoEntry[]>([]);
  const [repo, setRepo] = useState('');
  const [tag, setTag] = useState('');
  const [url, setUrl] = useState('');
  const [useAI, setUseAI] = useState(true);
  const [cfg, setCfg] = useState<{ config: UpConfig; ai: boolean; rate?: UpRate; rateError?: string } | null>(null);
  const [list, setList] = useState<UpReportItem[]>([]);
  const [rep, setRep] = useState<UpReport | null>(null);
  const [msg, setMsg] = useState('');
  const [err, setErr] = useState('');

  const loadList = () => adminUpstreamReports().then(setList).catch(() => {});
  const loadCfg = () => adminUpstreamConfig().then(setCfg).catch((e) => setErr(String(e)));
  useEffect(() => {
    loadCfg();
    adminRepos().then((rs) => {
      setRepos(rs);
      if (rs.length) pick(rs, rs[0].repo);
    }).catch(() => {});
    adminUpstreamReports().then((l) => {
      setList(l);
      const want = new URLSearchParams(window.location.search).get('report');
      const first = want || l.find((x) => x.state === 'running')?.id || l[0]?.id;
      if (first) adminUpstreamReport(first).then(setRep).catch(() => {});
    }).catch(() => {});
  }, []);

  function pick(rs: RepoEntry[], r: string) {
    setRepo(r);
    const tags = rs.find((x) => x.repo === r)?.tags || [];
    setTag(tags[tags.length - 1] || '');
  }

  // 진행 중 보고서 폴링
  useEffect(() => {
    if (!rep || rep.state !== 'running') return;
    const t = setTimeout(() => adminUpstreamReport(rep.id).then((r) => {
      setRep(r);
      if (r.state !== 'running') { loadList(); loadCfg(); }
    }).catch(() => {}), 2000);
    return () => clearTimeout(t);
  }, [rep]);

  async function start(kind: 'product' | 'repo') {
    setMsg('');
    try {
      const { id } = kind === 'product' ? await adminUpstreamRun({ repo, tag, ai: useAI && !!cfg?.ai }) : await adminUpstreamRepo({ url: url.trim(), ai: useAI && !!cfg?.ai });
      setRep(await adminUpstreamReport(id));
      loadList();
    } catch (e) { setMsg(String(e)); }
  }

  if (err) return <Alert tone="crit">{err}</Alert>;
  if (!cfg) return <Loading />;
  const tags = repos.find((p) => p.repo === repo)?.tags || [];
  const running = rep?.state === 'running';

  return (
    <div>
      <PageHeader title="공개 저장소 분석"
        description="제품 SBOM 의 구성요소마다 상류 오픈소스 저장소를 찾아 유지보수·보안 건강도를 점검합니다(CRA 제3자 구성요소 실사). 협력사 공개 GitHub 저장소도 단건으로 점검할 수 있습니다." />

      <div className="grid gap-3 md:grid-cols-2">
        <Card className="space-y-3 p-4 text-sm">
          <div className="font-semibold">제품 구성요소 분석</div>
          <div className="flex flex-wrap items-center gap-2">
            <select value={repo} onChange={(e) => pick(repos, e.target.value)} className={selectCls}>
              {repos.map((p) => <option key={p.repo} value={p.repo}>{p.repo}</option>)}
            </select>
            <select value={tag} onChange={(e) => setTag(e.target.value)} className={selectCls}>
              {tags.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
            <Button size="sm" onClick={() => start('product')} disabled={!repo || !tag || running}><Play size={14} /> 분석 시작</Button>
          </div>
          <p className="text-xs text-muted-foreground">이 버전에 첨부된 최신 SBOM(CycloneDX·SPDX)의 purl 로 저장소를 찾습니다. 구성요소가 많으면 수 분 걸립니다.</p>
          <div className="border-t pt-3 font-semibold">공개 GitHub 저장소 단건 점검</div>
          <div className="flex flex-wrap items-center gap-2">
            <Input value={url} onChange={(e) => setUrl(e.target.value)} autoComplete="off" name="gh-repo-url" inputMode="url" placeholder="https://github.com/owner/repo" className="h-8 w-72"
              onKeyDown={(e) => { if (e.key === 'Enter' && url.trim() && !running) start('repo'); }} />
            <Button size="sm" variant="outline" onClick={() => start('repo')} disabled={!url.trim() || running}><Search size={14} /> 저장소 점검</Button>
          </div>
          <label className="inline-flex items-center gap-1.5 text-xs">
            <input type="checkbox" checked={useAI && cfg.ai} disabled={!cfg.ai} onChange={(e) => setUseAI(e.target.checked)} />
            AI 요약 작성 {cfg.ai ? '(보고서 용도 AI 연결 사용)' : '— AI 연결(보고서 용도)이 꺼져 있습니다'}
          </label>
          {running && rep && (rep.steps?.length
            ? <JobProgress steps={rep.steps} stage={rep.stage || 0} done={rep.done} total={rep.total} started={rep.created} text={rep.progress} aiSteps={['AI 요약']} />
            : <Busy active label={`진행 중: ${rep.progress || ''}`} />)}
          {msg && <div className="text-xs text-red-700">{msg}</div>}
        </Card>
        <SettingsCard cfg={cfg.config} rate={cfg.rate} rateErr={cfg.rateError} onSaved={loadCfg} />
      </div>

      {rep && !running && (
        <>
          <SectionTitle>분석 결과</SectionTitle>
          <ReportView rep={rep} />
        </>
      )}

      <SectionTitle>최근 분석</SectionTitle>
      <Table>
        <thead><tr><Th>시각</Th><Th>대상</Th><Th>구성요소</Th><Th>위험</Th><Th>주의</Th><Th>상태</Th><Th /></tr></thead>
        <tbody>
          {list.map((r) => (
            <tr key={r.id}>
              <Td className="whitespace-nowrap text-xs">{fmt(r.created)}</Td>
              <Td className="text-xs">{r.kind === 'repo' ? <>{r.target} <Badge variant="muted">단건</Badge></> : `${r.repo}:${r.tag}`}</Td>
              <Td className="text-xs">{r.kind === 'repo' ? '—' : r.comps}</Td>
              <Td className="text-xs">{r.kind === 'repo' ? (r.rating ? <Rating r={r.rating} /> : '—') : (r.counts?.risk ?? '—')}</Td>
              <Td className="text-xs">{r.kind === 'repo' ? '' : (r.counts?.warn ?? '—')}</Td>
              <Td className="text-xs">{r.state === 'running' ? `진행 중 ${r.progress || ''}` : r.state === 'error' ? <span className="text-red-700">오류</span> : '완료'}</Td>
              <Td className="whitespace-nowrap text-xs">
                <button className="text-primary hover:underline" onClick={() => adminUpstreamReport(r.id).then(setRep)}>열기</button>
                {r.state === 'done' && <a className="ml-3 text-primary hover:underline" href={printUrl(r.id)} target="_blank" rel="noreferrer">인쇄</a>}
              </Td>
            </tr>
          ))}
          {list.length === 0 && <tr><Td colSpan={7} className="text-center text-muted-foreground">아직 없음</Td></tr>}
        </tbody>
      </Table>
    </div>
  );
}
