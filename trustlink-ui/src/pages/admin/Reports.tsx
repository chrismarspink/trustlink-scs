import { AskChip } from '@/components/AskChip';
import { useEffect, useMemo, useState } from 'react';
import { Busy, DownloadLink } from '@/components/Progress';
import { Link } from 'react-router-dom';
import {
  Archive, FilePlus2, FileText, ClipboardCheck, BookMarked, Landmark, Scale, Globe2, Sparkles, ChevronDown, ChevronRight, RefreshCw, Search, Download, GitBranch
} from 'lucide-react';
import {
  adminRegs, adminRegReportRun, adminRegReports, adminRepos, adminCompliance, aiStatus, regReportPdfUrl, adminUpstreamReports,
  type RegsInfo, type RegReportItem, type RepoEntry, type CompInfo, type UpReportItem
} from '@/lib/api';
import { Button, Input, Label } from '@/components/ui/primitives';
import { PageHeader, Alert, Loading, selectCls } from './_ui';
import { cn } from '@/lib/utils';

// 규제·보고 › 보고서함 — 발행한 문서(PDF 로 내보내는 보고서)를 한곳에 모은다.
//   발행 문서함: 규제 대응 보고서(한글·영문, 판 번호별)와 체크리스트 점검 보고서.
//   새 보고서: 역할·지역·제품·언어를 골라 규제 대응 보고서를 만든다.
// 대시보드는 실시간 현황만, 규제 카탈로그·규제 대응 검증 화면은 관리·점검 작업만 맡는다.

const REGION_ORDER = ['US', 'EU', 'JP', 'KR', 'UK', 'IN', 'INTL'];
const fmt = (t?: string) => (t ? new Date(t).toLocaleString('ko-KR', { dateStyle: 'medium', timeStyle: 'short' }) : '');
const printUrl = (id: string) => `/admin/regs/print/${id}`;

type Series = {
  key: string; title: string; audienceKo: string; repo?: string; tag?: string;
  latest: RegReportItem; editions: { edition: number; ko?: RegReportItem; en?: RegReportItem }[];
};

// 같은 조건(역할·지역·제품)의 보고서를 묶는다 — 한글·영문은 한 줄, 판 번호는 펼쳐서.
function toSeries(list: RegReportItem[]): Series[] {
  const m = new Map<string, Series>();
  for (const r of list) {
    const key = (r.key || r.id).replace(/\|(ko|en)$/, '');
    let s = m.get(key);
    if (!s) { s = { key, title: r.title, audienceKo: r.audienceKo, repo: r.repo, tag: r.tag, latest: r, editions: [] }; m.set(key, s); }
    if (r.created > s.latest.created) s.latest = r;
    if (r.lang === 'ko' || !r.lang) { s.title = r.title; s.audienceKo = r.audienceKo; } // 묶음 제목·대상은 한글 우선
    const ed = r.edition || 1;
    let e = s.editions.find((x) => x.edition === ed);
    if (!e) { e = { edition: ed }; s.editions.push(e); }
    const lang = r.lang === 'en' ? 'en' : 'ko';
    if (!e[lang] || r.created > e[lang]!.created) e[lang] = r;
  }
  const out = [...m.values()];
  out.forEach((s) => s.editions.sort((a, b) => b.edition - a.edition));
  return out.sort((a, b) => b.latest.created.localeCompare(a.latest.created));
}

function LangLink({ r, lang }: { r?: RegReportItem; lang: 'ko' | 'en' }) {
  if (!r) return <span className="rounded border border-dashed px-1.5 py-0.5 text-[11px] text-muted-foreground">{lang === 'ko' ? '한글 없음' : 'EN 없음'}</span>;
  return (
    <span className="inline-flex items-center">
    <a href={printUrl(r.id)} target="_blank" rel="noreferrer" title={r.docNo || r.id}
      className="inline-flex items-center gap-1 rounded border border-primary/30 bg-primary/5 px-1.5 py-0.5 text-[11px] font-medium text-primary hover:bg-primary/10">
      <FileText size={11} /> {lang === 'ko' ? '한글' : 'English'}{r.state === 'running' && ' …'}
    </a>
    {r.state !== 'running' && (
      <DownloadLink href={regReportPdfUrl(r.id)} title="서버에서 만든 PDF 내려받기(처음엔 수십 초)" className="ml-0.5 inline-flex items-center rounded px-1 py-0.5 text-[11px] text-muted-foreground hover:bg-secondary hover:text-foreground">
        <Download size={11} />
      </DownloadLink>
    )}
    </span>
  );
}

function SeriesRow({ s }: { s: Series }) {
  const [open, setOpen] = useState(false);
  const cur = s.editions[0];
  return (
    <>
      <tr className="border-t align-top hover:bg-secondary/40">
        <td className="px-3 py-2">
          <button onClick={() => setOpen(!open)} className="flex items-start gap-1.5 text-left" disabled={s.editions.length < 2}>
            {s.editions.length > 1 ? (open ? <ChevronDown size={14} className="mt-0.5" /> : <ChevronRight size={14} className="mt-0.5" />) : <span className="w-[14px]" />}
            <span>
              <span className="font-medium">{s.title}</span>
              <span className="block text-xs text-muted-foreground">{(cur.ko || cur.en)?.docNo || ''}</span>
            </span>
          </button>
        </td>
        <td className="px-3 py-2 text-sm">{s.audienceKo}</td>
        <td className="px-3 py-2 text-sm">{s.repo ? `${s.repo}:${s.tag}` : <span className="text-muted-foreground">공통</span>}</td>
        <td className="px-3 py-2"><span className="rounded bg-primary/10 px-1.5 py-0.5 font-mono text-xs font-semibold text-primary">v{cur.edition}</span>
          {s.editions.length > 1 && <span className="ml-1 text-[11px] text-muted-foreground">({s.editions.length}개 판)</span>}</td>
        <td className="px-3 py-2"><div className="flex gap-1"><LangLink r={cur.ko} lang="ko" /><LangLink r={cur.en} lang="en" /></div></td>
        <td className="whitespace-nowrap px-3 py-2 text-xs text-muted-foreground">{fmt(s.latest.created)}<div>{s.latest.createdBy}</div></td>
      </tr>
      {open && s.editions.slice(1).map((e) => (
        <tr key={e.edition} className="bg-secondary/30 text-xs">
          <td className="py-1.5 pl-10 pr-3 text-muted-foreground">{(e.ko || e.en)?.docNo}</td>
          <td colSpan={2} />
          <td className="px-3 py-1.5 font-mono">v{e.edition}</td>
          <td className="px-3 py-1.5"><div className="flex gap-1"><LangLink r={e.ko} lang="ko" /><LangLink r={e.en} lang="en" /></div></td>
          <td className="px-3 py-1.5 text-muted-foreground">{fmt((e.ko || e.en)!.created)}</td>
        </tr>
      ))}
    </>
  );
}

function Library({ reload }: { reload: number }) {
  const [regs, setRegs] = useState<RegReportItem[] | null>(null);
  const [comp, setComp] = useState<CompInfo['reports']>([]);
  const [ups, setUps] = useState<UpReportItem[]>([]);
  const [kind, setKind] = useState<'all' | 'reg' | 'check' | 'up'>('all');
  const [q, setQ] = useState('');
  const [err, setErr] = useState('');
  useEffect(() => {
    adminRegReports().then(setRegs).catch((e) => setErr(String(e)));
    adminCompliance().then((c) => setComp(c.reports || [])).catch(() => {});
    adminUpstreamReports().then(setUps).catch(() => {});
  }, [reload]);
  const series = useMemo(() => toSeries(regs || []).filter((s) => !q || `${s.title} ${s.audienceKo} ${s.repo || ''} ${s.latest.docNo || ''}`.toLowerCase().includes(q.toLowerCase())), [regs, q]);
  const upList = ups.filter((r) => r.state !== 'running' && (!q || `${r.repo || ''}:${r.tag || ''} ${r.target || ''}`.toLowerCase().includes(q.toLowerCase())));
  const checks = comp.filter((r) => !q || `${r.repo}:${r.tag}`.toLowerCase().includes(q.toLowerCase()));
  if (err) return <Alert tone="crit">{err}</Alert>;
  if (!regs) return <Loading />;
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2">
        {([['all', '전체'], ['reg', '규제 대응 보고서'], ['check', '체크리스트 점검'], ['up', '공개 저장소 분석']] as const).map(([v, l]) => (
          <button key={v} onClick={() => setKind(v)} className={cn('rounded-full border px-3 py-1 text-sm', kind === v ? 'border-primary bg-primary/10 font-medium text-primary' : 'hover:bg-secondary')}>{l}</button>
        ))}
        <div className="relative ml-auto w-64">
          <Search size={14} className="absolute left-2.5 top-2.5 text-muted-foreground" />
          <Input className="pl-8" value={q} onChange={(e) => setQ(e.target.value)} placeholder="제목·제품·문서번호 검색" />
        </div>
      </div>

      {(kind === 'all' || kind === 'reg') && (
        <div className="overflow-hidden rounded-lg border bg-card">
          <div className="flex items-center gap-2 border-b bg-secondary/40 px-3 py-2 text-sm font-medium"><Landmark size={15} /> 규제 대응 보고서 <span className="text-xs font-normal text-muted-foreground">같은 조건으로 다시 만들면 판이 올라갑니다 · 한글/영문은 한 줄에</span></div>
          <table className="w-full text-sm">
            <thead><tr className="text-left text-xs text-muted-foreground"><th className="px-3 py-1.5">문서</th><th className="px-3 py-1.5">대상</th><th className="px-3 py-1.5">제품</th><th className="px-3 py-1.5">판</th><th className="px-3 py-1.5">언어</th><th className="px-3 py-1.5">최근 발행</th></tr></thead>
            <tbody>
              {series.map((s) => <SeriesRow key={s.key} s={s} />)}
              {series.length === 0 && <tr><td colSpan={6} className="px-3 py-6 text-center text-muted-foreground">아직 발행한 보고서가 없습니다 — ‘새 보고서’에서 만드세요</td></tr>}
            </tbody>
          </table>
        </div>
      )}

      {(kind === 'all' || kind === 'check') && (
        <div className="overflow-hidden rounded-lg border bg-card">
          <div className="flex items-center gap-2 border-b bg-secondary/40 px-3 py-2 text-sm font-medium"><ClipboardCheck size={15} /> 체크리스트 점검 보고서 <span className="text-xs font-normal text-muted-foreground">업로드한 공급망 체크리스트로 제품 릴리스를 점검한 결과(내부용 — 체크리스트 원본은 서버에만 보관)</span></div>
          <table className="w-full text-sm">
            <thead><tr className="text-left text-xs text-muted-foreground"><th className="px-3 py-1.5">제품</th><th className="px-3 py-1.5">공급자 미충족</th><th className="px-3 py-1.5">일부</th><th className="px-3 py-1.5">AI 요약</th><th className="px-3 py-1.5">시각</th><th /></tr></thead>
            <tbody>
              {checks.map((r) => (
                <tr key={r.id} className="border-t hover:bg-secondary/40">
                  <td className="px-3 py-2">{r.repo}:{r.tag}</td>
                  <td className="px-3 py-2">{r.counts['supplier.unmet'] ?? 0}</td>
                  <td className="px-3 py-2">{r.counts['supplier.partial'] ?? 0}</td>
                  <td className="px-3 py-2">{r.ai ? '사용' : '—'}</td>
                  <td className="px-3 py-2 text-xs text-muted-foreground">{fmt(r.createdAt)}</td>
                  <td className="px-3 py-2"><Link to={`/admin/compliance?report=${encodeURIComponent(r.id)}`} className="text-xs text-primary hover:underline">열기</Link></td>
                </tr>
              ))}
              {checks.length === 0 && <tr><td colSpan={6} className="px-3 py-6 text-center text-muted-foreground">아직 없습니다 — 규제·보고 › 규제 대응 검증에서 점검하면 여기에 쌓입니다</td></tr>}
            </tbody>
          </table>
        </div>
      )}

      {(kind === 'all' || kind === 'up') && (
        <div className="overflow-hidden rounded-lg border bg-card">
          <div className="flex items-center gap-2 border-b bg-secondary/40 px-3 py-2 text-sm font-medium"><GitBranch size={15} /> 공개 저장소 분석 보고서 <span className="text-xs font-normal text-muted-foreground">제품 구성요소의 상류 오픈소스 건강도 · 단건 저장소 점검(분석할 때마다 저장)</span></div>
          <table className="w-full text-sm">
            <thead><tr className="text-left text-xs text-muted-foreground"><th className="px-3 py-1.5">대상</th><th className="px-3 py-1.5">구성요소</th><th className="px-3 py-1.5">위험</th><th className="px-3 py-1.5">주의</th><th className="px-3 py-1.5">AI 요약</th><th className="px-3 py-1.5">시각</th><th /></tr></thead>
            <tbody>
              {upList.map((r) => (
                <tr key={r.id} className="border-t hover:bg-secondary/40">
                  <td className="px-3 py-2">{r.kind === 'repo' ? <>{r.target} <span className="text-xs text-muted-foreground">(단건)</span></> : `${r.repo}:${r.tag}`}{r.state === 'error' && <span className="ml-1 text-xs text-red-600">오류</span>}</td>
                  <td className="px-3 py-2">{r.kind === 'repo' ? '—' : r.comps}</td>
                  <td className="px-3 py-2">{r.counts?.risk ?? 0}</td>
                  <td className="px-3 py-2">{r.counts?.warn ?? 0}</td>
                  <td className="px-3 py-2">{r.summary ? '사용' : '—'}</td>
                  <td className="px-3 py-2 text-xs text-muted-foreground">{fmt(r.created)}</td>
                  <td className="px-3 py-2 whitespace-nowrap">
                    <a href={`/admin/upstream/print/${encodeURIComponent(r.id)}`} target="_blank" rel="noreferrer" className="text-xs text-primary hover:underline">보고서</a>
                    <Link to={`/admin/upstream?report=${encodeURIComponent(r.id)}`} className="ml-2 text-xs text-muted-foreground hover:underline">화면</Link>
                  </td>
                </tr>
              ))}
              {upList.length === 0 && <tr><td colSpan={7} className="px-3 py-6 text-center text-muted-foreground">아직 없습니다 — 규제·보고 › 공개 저장소 분석에서 분석하면 여기에 쌓입니다</td></tr>}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function NewReport({ onCreated }: { onCreated: () => void }) {
  const [info, setInfo] = useState<RegsInfo | null>(null);
  const [aud, setAud] = useState<string>('dev');
  const [regions, setRegions] = useState<string[]>(['US', 'EU', 'JP', 'KR']);
  const [repos, setRepos] = useState<RepoEntry[]>([]);
  const [repo, setRepo] = useState('');
  const [tag, setTag] = useState('');
  const [ai, setAi] = useState(false);
  const [aiOk, setAiOk] = useState(false);
  const [aiLocal, setAiLocal] = useState(true);
  const [langs, setLangs] = useState<('ko' | 'en')[]>(['ko', 'en']);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [done, setDone] = useState('');
  useEffect(() => {
    adminRegs().then(setInfo).catch((e) => setErr(String(e)));
    adminRepos().then(setRepos).catch(() => {});
    aiStatus('report').then((a) => { setAiOk(a.enabled && a.reachable); setAi(a.enabled && a.reachable); setAiLocal(a.mode === 'local'); }).catch(() => {});
  }, []);
  const present = useMemo(() => REGION_ORDER.filter((r) => info?.catalog.regulations.some((x) => x.region === r)), [info]);
  const tags = repos.find((r) => r.repo === repo)?.tags || [];
  async function run() {
    setBusy(true); setErr(''); setDone('');
    try {
      // 한글·영문을 차례로 만든다(판 번호는 언어별). 팝업 차단을 피하려고 창을 먼저 연다.
      const wins = langs.map(() => window.open('about:blank', '_blank'));
      const docs: string[] = [];
      for (let i = 0; i < langs.length; i++) {
        const r = await adminRegReportRun({ audience: aud, regions, repo: repo || undefined, tag: repo ? tag : undefined, ai: ai && aiOk, lang: langs[i] });
        docs.push(r.docNo);
        const url = printUrl(r.id);
        if (wins[i]) wins[i]!.location.href = url; else window.open(url, '_blank');
      }
      setDone(`발행했습니다: ${docs.join(', ')} — 발행 문서함에 보관됩니다.`);
      onCreated();
    } catch (e) { setErr(String(e)); }
    setBusy(false);
  }
  if (!info) return err ? <Alert tone="crit">{err}</Alert> : <Loading />;
  const AUD_CARDS = [
    { v: 'dev', label: '개발자', icon: BookMarked, note: 'SBOM·서명·취약점 조치 등 빌드·코드에서 할 일' },
    { v: 'admin', label: '관리자', icon: Landmark, note: '운영·보안 절차, 보관, 신고 체계, 고객 통보' },
    { v: 'sales', label: '영업', icon: Scale, note: '계약·입찰 조건, 고객 안내, 인증·라벨' },
    { v: 'all', label: '전체', icon: Globe2, note: '모든 요구사항과 세 역할의 할 일' }
  ];
  return (
    <div className="max-w-4xl space-y-4 rounded-lg border bg-card p-4">
      <div>
        <Label>누가 볼 보고서인가요?</Label>
        <div className="mt-1 grid gap-2 sm:grid-cols-4">
          {AUD_CARDS.map((a) => (
            <button key={a.v} onClick={() => setAud(a.v)} className={cn('rounded-lg border p-2.5 text-left', aud === a.v ? 'border-primary bg-primary/5 ring-1 ring-primary' : 'hover:bg-secondary')}>
              <div className="flex items-center gap-1.5 text-sm font-medium"><a.icon size={15} /> {a.label}</div>
              <p className="mt-0.5 text-[11px] text-muted-foreground">{a.note}</p>
            </button>
          ))}
        </div>
      </div>
      <div>
        <Label>대상 지역</Label>
        <div className="mt-1 flex flex-wrap gap-2">
          {present.map((r) => (
            <label key={r} className={cn('flex cursor-pointer items-center gap-1.5 rounded-full border px-3 py-1 text-sm', regions.includes(r) && 'border-primary bg-primary/5')}>
              <input type="checkbox" checked={regions.includes(r)} onChange={(e) => setRegions(e.target.checked ? [...regions, r] : regions.filter((x) => x !== r))} />
              {info.regions[r] || r}
            </label>
          ))}
        </div>
      </div>
      <div className="grid gap-2 sm:grid-cols-2">
        <div>
          <Label>제품(선택 — 고르면 릴리스 증거로 충족 여부 판정)</Label>
          <select className={cn(selectCls, 'w-full')} value={repo} onChange={(e) => { setRepo(e.target.value); const p = repos.find((x) => x.repo === e.target.value); setTag(p?.tags[p.tags.length - 1] || ''); }}>
            <option value="">— 제품 없이(규제 정보만) —</option>
            {repos.map((r) => <option key={r.repo} value={r.repo}>{r.repo}</option>)}
          </select>
        </div>
        <div>
          <Label>버전</Label>
          <select className={cn(selectCls, 'w-full')} value={tag} disabled={!repo} onChange={(e) => setTag(e.target.value)}>
            {tags.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
      </div>
      <div>
        <Label>언어</Label>
        <div className="mt-1 flex flex-wrap gap-2">
          {([['ko', '한글'], ['en', 'English']] as const).map(([v, l]) => (
            <label key={v} className={cn('flex cursor-pointer items-center gap-1.5 rounded-full border px-3 py-1 text-sm', langs.includes(v) && 'border-primary bg-primary/5')}>
              <input type="checkbox" checked={langs.includes(v)} onChange={(e) => setLangs(e.target.checked ? (['ko', 'en'] as const).filter((x) => x === v || langs.includes(x)) : langs.filter((x) => x !== v))} />
              {l}
            </label>
          ))}
          <span className="self-center text-xs text-muted-foreground">둘 다 고르면 같은 판의 한글·영문 두 문서를 만듭니다</span>
        </div>
      </div>
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={ai} disabled={!aiOk} onChange={(e) => setAi(e.target.checked)} />
        <Sparkles size={14} className="text-violet-600" /> 첫 쪽 요약을 AI 로 작성 {aiOk ? (aiLocal ? '(로컬 CPU 면 언어별 2~4분, 보고서는 먼저 열리고 요약이 채워집니다)' : '(외부 LLM — 수십 초)') : '(AI 연결 꺼짐 — 관리 › AI 연결에서 보고서 용도 설정)'}
      </label>
      <p className="text-xs text-muted-foreground">문서번호·작성일·판(v1, v2 …)이 표지와 파일 이름에 들어갑니다. 같은 조건으로 다시 만들면 판이 올라가고 지난 판 이후 바뀐 점이 실립니다.</p>
      {err && <Alert tone="crit">{err}</Alert>}
      {done && <Alert tone="ok">{done}</Alert>}
      <Button onClick={run} disabled={busy || !regions.length || !langs.length}><FilePlus2 size={15} /> {busy ? '만드는 중…' : '보고서 발행 (새 창 · PDF 저장)'}</Button>
      <Busy active={busy} label="보고서 본문 만드는 중(제품 증거 수집 · 언어별 차례로)" hint="AI 요약은 보고서가 열린 뒤 채워집니다" />
    </div>
  );
}

export default function Reports() {
  const [tab, setTab] = useState<'library' | 'new'>(() => (new URLSearchParams(window.location.search).get('tab') === 'new' ? 'new' : 'library'));
  const [n, setN] = useState(0);
  return (
    <>
      <PageHeader title="보고서함"
        description="발행한 문서를 한곳에 모읍니다 — 규제 대응 보고서(한글·영문, 판별)와 체크리스트 점검 보고서. 실시간 현황은 대시보드, 규제 관리는 규제 카탈로그에서 합니다."
        actions={<><AskChip q="미국 수출 규제 보고서 만들어 줘" label="묻고 찾기로 만들기" /><Button size="sm" variant="outline" onClick={() => setN(n + 1)}><RefreshCw size={14} /> 새로고침</Button></>} />
      <div className="mb-4 flex gap-1 border-b">
        {([['library', '발행 문서함', Archive], ['new', '새 보고서', FilePlus2]] as const).map(([k, l, I]) => (
          <button key={k} onClick={() => setTab(k)} className={cn('-mb-px flex items-center gap-1.5 border-b-2 px-3 py-2 text-sm', tab === k ? 'border-primary font-medium' : 'border-transparent text-muted-foreground hover:text-foreground')}>
            <I size={15} /> {l}
          </button>
        ))}
      </div>
      {tab === 'library' ? <Library reload={n} /> : <NewReport onCreated={() => setN(n + 1)} />}
    </>
  );
}
