import { useEffect, useRef, useState } from 'react';
import { Upload, Play, Download, Sparkles } from 'lucide-react';
import {
  adminCompliance, adminComplianceUpload, adminComplianceRun, adminComplianceReport, complianceMdUrl,
  type CompInfo, type CompReport, type CompItem
} from '@/lib/api';
import { Button, Badge, Card } from '@/components/ui/primitives';
import { PageHeader, SectionTitle, StatCard, Alert, Loading, Table, Th, Td, selectCls } from './_ui';
import { cn } from '@/lib/utils';

// 관리 › 규제 대응 검증: 체크리스트(엑셀)를 기준으로 릴리스가 어떤 규제 대상인지, 무엇이 부족하고 무엇을 보완할지 리포트.
// 판정은 규칙(산출물 증거 점검), AI 는 미충족 항목의 문제·보완 설명과 요약만 쓴다.

const fmt = (t?: string) => (t ? new Date(t).toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' }) : '—');
const RES: Record<string, { label: string; cls: string }> = {
  met: { label: '충족', cls: 'bg-emerald-50 text-emerald-700' },
  pass: { label: '충족', cls: 'bg-emerald-50 text-emerald-700' },
  partial: { label: '일부', cls: 'bg-amber-50 text-amber-800' },
  unmet: { label: '미충족', cls: 'bg-red-50 text-red-700' },
  fail: { label: '미충족', cls: 'bg-red-50 text-red-700' },
  doc: { label: '문서 증거 필요', cls: 'bg-secondary text-muted-foreground' },
  na: { label: '확인 불가', cls: 'bg-secondary text-muted-foreground' }
};
const Pill = ({ r }: { r: string }) => (
  <span className={cn('inline-block whitespace-nowrap rounded px-1.5 py-0.5 text-xs font-medium', RES[r]?.cls)}>{RES[r]?.label || r}</span>
);

function Items({ items, side }: { items: CompItem[]; side: 'supplier' | 'buyer' }) {
  const [filter, setFilter] = useState('gap');
  const list = items.filter((i) => i.side === side && (filter === 'all' || (filter === 'gap' ? i.result === 'unmet' || i.result === 'partial' : i.result === filter)));
  return (
    <>
      <div className="mb-2 flex items-center gap-2 text-sm">
        <select value={filter} onChange={(e) => setFilter(e.target.value)} className={selectCls}>
          <option value="gap">미충족·일부</option>
          <option value="met">충족</option>
          <option value="doc">문서 증거 필요</option>
          <option value="all">전체</option>
        </select>
        <span className="text-muted-foreground">{list.length}개</span>
      </div>
      <Table>
        <thead><tr><Th>ID</Th><Th>단계</Th><Th>항목</Th><Th>규제</Th><Th>결과</Th><Th>문제 · 보완</Th></tr></thead>
        <tbody>
          {list.map((i) => (
            <tr key={i.id}>
              <Td className="whitespace-nowrap font-mono text-xs">{i.id}</Td>
              <Td className="text-xs text-muted-foreground">{i.stage}</Td>
              <Td className="max-w-[340px] text-xs">{i.question}</Td>
              <Td className="whitespace-nowrap text-xs">{i.regs.join(', ')}</Td>
              <Td>
                <Pill r={i.result} />
                {i.result === 'doc' && i.selfEval && <div className="mt-1 text-[11px] text-muted-foreground">자체평가 {i.selfEval}</div>}
              </Td>
              <Td className="max-w-[420px] text-xs">
                {i.problem && <div><b>문제</b> {i.problem}</div>}
                {i.remedy && <div className="mt-1"><b>보완</b> {i.remedy}</div>}
                {i.source === 'ai' && (
                  <div className="mt-1 inline-flex items-center gap-1 text-[11px] text-violet-700">
                    <Sparkles size={11} /> AI 초안 · 근거 {i.aiCitations?.join(', ')}
                  </div>
                )}
              </Td>
            </tr>
          ))}
          {list.length === 0 && <tr><Td colSpan={6} className="text-center text-muted-foreground">해당 항목 없음</Td></tr>}
        </tbody>
      </Table>
    </>
  );
}

function ReportView({ r }: { r: CompReport }) {
  const [side, setSide] = useState<'supplier' | 'buyer'>('supplier');
  const c = r.counts || {};
  const n = (s: string) => (c[`${side}.${s}`] ?? 0);
  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="text-lg font-semibold">{r.repo}:{r.tag}</div>
          <div className="text-xs text-muted-foreground">
            {fmt(r.createdAt)} · {r.createdBy} · 기준 {r.checklist}
            {r.info?.dbSnapshot && <> · DB 스냅샷 <span className="font-mono">{r.info.dbSnapshot.slice(0, 12)}</span></>}
            {r.ai && <> · AI {r.ai.model}</>}
          </div>
        </div>
        {r.state === 'done' && (
          <a href={complianceMdUrl(r.id)} className="inline-flex items-center gap-1 text-sm text-primary hover:underline">
            <Download size={14} /> 리포트 내려받기(.md)
          </a>
        )}
      </div>
      {r.aiError && <Alert tone="warn">AI 설명을 만들지 못했습니다 — 규칙 판정만 표시합니다. ({r.aiError})</Alert>}

      <SectionTitle>1. 이 소프트웨어가 대상인 규제</SectionTitle>
      <Table>
        <thead><tr><Th>규제</Th><Th>대상 근거</Th><Th>구분</Th><Th>체크리스트 항목</Th></tr></thead>
        <tbody>
          {r.regs.map((g) => (
            <tr key={g.id}>
              <Td className="font-medium">{g.name}</Td>
              <Td>{g.basis}</Td>
              <Td><Badge variant={g.mandate ? 'danger' : 'muted'}>{g.mandate ? '의무' : '권고'}</Badge></Td>
              <Td>{g.noSource ? <span className="text-amber-700">0 — 체크리스트에 근거 항목 없음(별도 기준 필요)</span> : g.items}</Td>
            </tr>
          ))}
          {r.regs.length === 0 && <tr><Td colSpan={4} className="text-muted-foreground">판매 지역·고객 분야를 고르지 않아 권고 기준만 적용했습니다.</Td></tr>}
        </tbody>
      </Table>

      {r.summary && (
        <>
          <SectionTitle>2. 요약 · 주요 문제 · 보완 우선순위 <span className="ml-1 text-xs font-normal text-violet-700">AI 초안 — 판정은 아래 규칙 결과</span></SectionTitle>
          <Card className="space-y-3 p-4 text-sm">
            <p className="leading-relaxed">{r.summary.summary}</p>
            {r.summary.risks.map((k, i) => (
              <div key={i}><b>{k.title}</b> — {k.detail} <span className="font-mono text-[11px] text-muted-foreground">[{k.citations.join(', ')}]</span></div>
            ))}
            <div className="space-y-1 border-t pt-2">
              {r.summary.actions.map((a, i) => (
                <div key={i} className="flex gap-2">
                  <Badge variant={a.priority === 'P1' ? 'danger' : a.priority === 'P2' ? 'warn' : 'muted'}>{a.priority}</Badge>
                  <span>{a.action} <span className="font-mono text-[11px] text-muted-foreground">[{a.citations.join(', ')}]</span></span>
                </div>
              ))}
            </div>
          </Card>
        </>
      )}

      <SectionTitle>3. 릴리스 산출물 증거 점검 (규칙)</SectionTitle>
      <Table>
        <thead><tr><Th>점검</Th><Th>결과</Th><Th>값</Th><Th>보완 방법</Th></tr></thead>
        <tbody>
          {r.evidence.map((e) => (
            <tr key={e.id}>
              <Td className="whitespace-nowrap">{e.name}</Td>
              <Td><Pill r={e.result} /></Td>
              <Td className="text-xs">{e.value}</Td>
              <Td className="text-xs text-muted-foreground">{e.result !== 'pass' ? e.fix : ''}</Td>
            </tr>
          ))}
        </tbody>
      </Table>

      <SectionTitle>4. 체크리스트 항목 판정</SectionTitle>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        {(['supplier', 'buyer'] as const).map((s) => (
          <Button key={s} size="sm" variant={side === s ? 'default' : 'outline'} onClick={() => setSide(s)}>
            {s === 'supplier' ? '공급자(개발사) 의무' : '원청이 확인하는 항목'}
          </Button>
        ))}
      </div>
      <div className="mb-3 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <StatCard label="충족" value={n('met')} />
        <StatCard label="일부" value={n('partial')} />
        <StatCard label="미충족" value={n('unmet')} />
        <StatCard label="문서 증거 필요" value={n('doc')} />
      </div>
      <Items items={r.items} side={side} />
      <p className="mt-2 text-xs text-muted-foreground">
        '문서 증거 필요'는 조직·교육·프로세스 항목이라 릴리스 산출물로 판정하지 않았습니다. 체크리스트의 자체 평가를 함께 보여 줍니다.
      </p>
    </div>
  );
}

export default function Compliance() {
  const [info, setInfo] = useState<CompInfo | null>(null);
  const [err, setErr] = useState('');
  const [repo, setRepo] = useState('');
  const [tag, setTag] = useState('');
  const [markets, setMarkets] = useState<string[]>([]);
  const [useAI, setUseAI] = useState(true);
  const [rep, setRep] = useState<CompReport | null>(null);
  const [msg, setMsg] = useState('');
  const fileRef = useRef<HTMLInputElement>(null);

  const load = () => adminCompliance().then((i) => {
    setInfo(i);
    if (!repo && i.products.length) pick(i, i.products[0].repo);
    const want = new URLSearchParams(window.location.search).get('report'); // 보고서함에서 열기
    if (want && !rep) adminComplianceReport(want).then(setRep).catch(() => {});
    else if (i.running) adminComplianceReport(i.running.id).then(setRep).catch(() => {});
    else if (!rep && i.reports.length) adminComplianceReport(i.reports[0].id).then(setRep).catch(() => {}); // 최근 리포트 기본 표시
  }).catch((e) => setErr(String(e)));
  useEffect(() => { load(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  function pick(i: CompInfo, r: string) {
    setRepo(r);
    const p = i.products.find((x) => x.repo === r);
    setTag(p?.tags[p.tags.length - 1] || '');
    setMarkets(i.profiles[r]?.markets || []);
  }

  // 진행 중 리포트 폴링
  useEffect(() => {
    if (!rep || rep.state !== 'running') return;
    const t = setTimeout(() => adminComplianceReport(rep.id).then((r) => { setRep(r); if (r.state !== 'running') load(); }).catch(() => {}), 2000);
    return () => clearTimeout(t);
  }, [rep]); // eslint-disable-line react-hooks/exhaustive-deps

  async function upload(f?: File) {
    if (!f) return;
    setMsg('올리는 중…');
    try {
      const c = await adminComplianceUpload(f);
      setMsg(`체크리스트 ${c?.items}개 항목을 읽었습니다.`);
      load();
    } catch (e) { setMsg(String(e)); }
  }

  async function run() {
    setMsg('');
    try {
      const { id } = await adminComplianceRun({ repo, tag, profile: { markets }, ai: useAI });
      setRep(await adminComplianceReport(id));
    } catch (e) { setMsg(String(e)); }
  }

  if (err) return <Alert tone="crit">{err}</Alert>;
  if (!info) return <Loading />;
  const tags = info.products.find((p) => p.repo === repo)?.tags || [];
  const ai = info.ai;

  return (
    <div>
      <PageHeader title="규제 대응 검증"
        description="체크리스트를 기준으로 릴리스가 어떤 공급망 규제 대상인지, 무엇이 부족하고 무엇을 보완해야 하는지 검증합니다. 판정은 규칙, AI 는 설명만 씁니다." />

      <div className="grid gap-3 md:grid-cols-2">
        <Card className="p-4 text-sm">
          <div className="mb-2 font-semibold">기준 체크리스트</div>
          {info.checklist ? (
            <div className="space-y-1">
              <div>{info.checklist.name} · {info.checklist.items}개 항목 · 시트 '{info.checklist.sheet}'</div>
              <div className="text-xs text-muted-foreground">올린 시각 {fmt(info.checklist.importedAt)} · SHA-256 <span className="font-mono">{info.checklist.sha256.slice(0, 16)}…</span></div>
              <div className="flex flex-wrap gap-1 pt-1">
                {Object.entries(info.checklist.regs).map(([k, v]) => <Badge key={k} variant="muted">{k} {v}</Badge>)}
              </div>
            </div>
          ) : <p className="text-muted-foreground">아직 없습니다. 엑셀(.xlsx)을 올리세요 — 머리글에 '넘버링'·'항목'·'참조문서' 열이 있어야 합니다.</p>}
          <div className="mt-3 flex items-center gap-2">
            <input ref={fileRef} type="file" accept=".xlsx" className="hidden" onChange={(e) => upload(e.target.files?.[0])} />
            <Button size="sm" variant="outline" onClick={() => fileRef.current?.click()}><Upload size={14} /> 체크리스트 올리기</Button>
          </div>
          <p className="mt-2 text-xs text-muted-foreground">원본은 이 서버의 데이터 볼륨에만 저장됩니다(저장소·이미지에 포함되지 않음). 대외비 문서는 사용 범위를 확인하세요.</p>
        </Card>
        <Card className="p-4 text-sm">
          <div className="mb-2 flex items-center gap-1 font-semibold"><Sparkles size={14} /> 로컬 AI</div>
          {!ai.enabled ? <p className="text-muted-foreground">꺼져 있습니다 — 규칙 판정만 합니다. (AI_URL 미설정)</p>
            : !ai.reachable ? <p className="text-amber-700">AI 서비스 응답 없음 {ai.error}</p>
              : (
                <div className="space-y-1">
                  <div>{ai.model} · 문맥 {ai.ctx?.toLocaleString()} 토큰</div>
                  <div className="text-xs text-muted-foreground">모델 SHA-256 <span className="font-mono">{ai.sha256 ? ai.sha256.slice(0, 16) + '…' : '계산 중'}</span> · 외부 망 차단 · CPU 전용</div>
                  <div className="text-xs text-muted-foreground">초안마다 모델 해시·입력 사실 해시·DB 스냅샷을 원장에 남깁니다.</div>
                </div>
              )}
        </Card>
      </div>

      <SectionTitle>검증 실행</SectionTitle>
      <Card className="space-y-3 p-4 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          <select value={repo} onChange={(e) => pick(info, e.target.value)} className={selectCls}>
            {info.products.map((p) => <option key={p.repo} value={p.repo}>{p.repo}</option>)}
          </select>
          <select value={tag} onChange={(e) => setTag(e.target.value)} className={selectCls}>
            {tags.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
        <div>
          <div className="mb-1 text-xs text-muted-foreground">판매 지역 · 고객 분야 (규제 대상 판정 근거, 제품별로 기억)</div>
          <div className="flex flex-wrap gap-3">
            {Object.entries(info.markets).map(([k, v]) => (
              <label key={k} className="inline-flex items-center gap-1.5">
                <input type="checkbox" checked={markets.includes(k)}
                  onChange={(e) => setMarkets(e.target.checked ? [...markets, k] : markets.filter((m) => m !== k))} />
                {v}
              </label>
            ))}
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <label className="inline-flex items-center gap-1.5">
            <input type="checkbox" checked={useAI} disabled={!ai.reachable} onChange={(e) => setUseAI(e.target.checked)} />
            AI 로 문제·보완 설명과 요약 작성 (수 분 소요)
          </label>
          <Button size="sm" onClick={run} disabled={!info.checklist || !repo || !tag || rep?.state === 'running'}>
            <Play size={14} /> 검증 실행
          </Button>
          {rep?.state === 'running' && <span className="text-xs text-muted-foreground">진행 중: {rep.progress}</span>}
          {msg && <span className="text-xs text-muted-foreground">{msg}</span>}
        </div>
      </Card>

      {rep && rep.state !== 'running' && (
        <>
          <SectionTitle>검증 결과</SectionTitle>
          <ReportView r={rep} />
        </>
      )}

      <SectionTitle>최근 리포트</SectionTitle>
      <Table>
        <thead><tr><Th>시각</Th><Th>제품</Th><Th>공급자 미충족</Th><Th>일부</Th><Th>AI</Th><Th /></tr></thead>
        <tbody>
          {info.reports.map((r) => (
            <tr key={r.id}>
              <Td className="whitespace-nowrap text-xs">{fmt(r.createdAt)}</Td>
              <Td>{r.repo}:{r.tag}</Td>
              <Td>{r.counts['supplier.unmet'] ?? 0}</Td>
              <Td>{r.counts['supplier.partial'] ?? 0}</Td>
              <Td>{r.ai ? '사용' : '—'}</Td>
              <Td><button className="text-xs text-primary hover:underline" onClick={() => adminComplianceReport(r.id).then(setRep)}>열기</button></Td>
            </tr>
          ))}
          {info.reports.length === 0 && <tr><Td colSpan={6} className="text-center text-muted-foreground">아직 없음</Td></tr>}
        </tbody>
      </Table>
    </div>
  );
}
