import { useEffect, useState } from 'react';
import { Busy } from '@/components/Progress';
import { useNavigate } from 'react-router-dom';
import {
  BookMarked, Search, Plus, Pencil, Trash2, CheckCircle2, CircleDashed, ChevronDown, ChevronRight, Radar, FileText,
  RefreshCw, ExternalLink, Save, X, Scale, Download, Sparkles, RotateCcw
} from 'lucide-react';
import {
  adminRegs, adminRegSave, adminRegDelete, adminRegVerify, adminRegBuiltinApply, adminRegDiscover, adminRegDiscoverRun,
  adminRegDiscoverCfg, adminRegCandidate, adminRegLawFetch, adminRegLawAnalyze, adminRegLawReview,
  type RegsInfo, type Regulation, type RegReq, type RegDiscoverInfo, type RegCandidate, type RegAudience, type RegAnalysis
} from '@/lib/api';
import { Button, Input, Label, Badge, StatusDot } from '@/components/ui/primitives';
import { PageHeader, SectionTitle, StatCard, Alert, Loading, selectCls } from './_ui';
import { cn } from '@/lib/utils';

// 규제·보고 › 규제 카탈로그: 공급망 보안 관련 국내외 법규·지침을 요구사항 단위로 관리하고(추가·수정·확인),
// 빠진 규제를 탐색하며, 역할(개발자·관리자·영업)별 확인 사항 보고서(PDF)를 만든다.

const REGION_ORDER = ['US', 'EU', 'JP', 'KR', 'UK', 'IN', 'INTL'];
const REGION_STYLE: Record<string, string> = {
  US: 'bg-blue-50 text-blue-800 border-blue-200', EU: 'bg-indigo-50 text-indigo-800 border-indigo-200',
  JP: 'bg-rose-50 text-rose-800 border-rose-200', KR: 'bg-teal-50 text-teal-800 border-teal-200',
  UK: 'bg-violet-50 text-violet-800 border-violet-200', IN: 'bg-amber-50 text-amber-800 border-amber-200'
};
const AUD: { v: RegAudience; label: string }[] = [
  { v: 'dev', label: '개발자' }, { v: 'admin', label: '관리자(운영·보안)' }, { v: 'sales', label: '영업' }
];
const SRC_LABEL: Record<string, string> = { 'federal-register': '미국 관보', 'law-kr': '국가법령정보센터', watch: '원문 변경 감지', ai: 'AI 제안' };
const today = new Date().toISOString().slice(0, 10);
const kdate = (t?: string) => (t ? new Date(t).toLocaleString('ko-KR', { dateStyle: 'medium', timeStyle: 'short' }) : '');

function RegionChip({ r, label }: { r: string; label?: string }) {
  return <span className={cn('inline-flex h-5 items-center rounded border px-1.5 font-mono text-[11px] font-semibold', REGION_STYLE[r] || 'bg-zinc-50 text-zinc-700 border-zinc-200')}>{label || r}</span>;
}

const nextDate = (r: Regulation) => r.dates.filter((d) => d.date >= today).sort((a, b) => a.date.localeCompare(b.date))[0];

// ---------- 편집기 ----------
const emptyReq = (): RegReq => ({ id: '', clause: '', title: '', text: '', evidence: [], actions: {} });
const emptyReg = (): Regulation => ({
  id: '', region: 'KR', name: '', nameKo: '', kind: '', authority: '', binding: '권고', status: '시행', scope: '',
  markets: [], tags: [], dates: [], sources: [], requirements: [emptyReq()], rev: 0, verified: false
});

function Editor({ init, isNew, info, onDone }: { init: Regulation; isNew: boolean; info: RegsInfo; onDone: (saved: boolean) => void }) {
  const [r, setR] = useState<Regulation>(JSON.parse(JSON.stringify(init)));
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const set = (p: Partial<Regulation>) => setR({ ...r, ...p });
  const setReq = (i: number, p: Partial<RegReq>) => set({ requirements: r.requirements.map((q, j) => (j === i ? { ...q, ...p } : q)) });
  async function save() {
    setBusy(true); setErr('');
    try { await adminRegSave(r); onDone(true); } catch (e) { setErr(String(e)); }
    setBusy(false);
  }
  const field = (label: string, el: React.ReactNode, wide = false) => (
    <div className={wide ? 'sm:col-span-2' : ''}><Label>{label}</Label>{el}</div>
  );
  return (
    <div className="space-y-4 rounded-lg border bg-card p-4">
      <div className="flex items-center gap-2">
        <h3 className="font-semibold">{isNew ? '규제 추가' : `규제 편집 — ${init.nameKo}`}</h3>
        {!isNew && init.origin === 'builtin' && <span className="text-xs text-muted-foreground">내장 항목 — 저장하면 '로컬 수정'으로 표시되어 내장 업데이트 때 충돌을 알려 줍니다.</span>}
        <div className="flex-1" />
        <Button size="sm" variant="ghost" onClick={() => onDone(false)}><X size={14} /> 닫기</Button>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        {field('ID (영문 소문자·하이픈)', <Input value={r.id} disabled={!isNew} onChange={(e) => set({ id: e.target.value.toLowerCase() })} placeholder="예: kr-swsc" />)}
        {field('지역', (
          <select className={cn(selectCls, 'w-full')} value={r.region} onChange={(e) => set({ region: e.target.value })}>
            {REGION_ORDER.map((x) => <option key={x} value={x}>{x} {info.regions[x] || ''}</option>)}
          </select>
        ))}
        {field('한국어 이름', <Input value={r.nameKo} onChange={(e) => set({ nameKo: e.target.value })} />)}
        {field('원어 명칭', <Input value={r.name} onChange={(e) => set({ name: e.target.value })} />)}
        {field('종류', <Input value={r.kind} onChange={(e) => set({ kind: e.target.value })} placeholder="법률 / 규정 / 가이드라인 …" />)}
        {field('소관 기관', <Input value={r.authority} onChange={(e) => set({ authority: e.target.value })} />)}
        {field('구속력', <Input value={r.binding} onChange={(e) => set({ binding: e.target.value })} placeholder="의무 / 조달 조건 / 권고 …" />)}
        {field('상태', <Input value={r.status} onChange={(e) => set({ status: e.target.value })} />)}
        {field('적용 대상', <textarea rows={2} className="w-full rounded-md border bg-background p-2 text-sm" value={r.scope} onChange={(e) => set({ scope: e.target.value })} />, true)}
        {field('태그(쉼표)', <Input value={r.tags.join(', ')} onChange={(e) => set({ tags: e.target.value.split(',').map((x) => x.trim()).filter(Boolean) })} />)}
        {field('시장 키(쉼표, 규제 대응 검증 연계)', <Input value={r.markets.join(', ')} onChange={(e) => set({ markets: e.target.value.split(',').map((x) => x.trim()).filter(Boolean) })} placeholder="eu, us_fed, kr_fin …" />)}
      </div>

      <div>
        <Label>일정</Label>
        {r.dates.map((d, i) => (
          <div key={i} className="mt-1 flex gap-2">
            <Input type="date" className="w-44" value={d.date} onChange={(e) => set({ dates: r.dates.map((x, j) => (j === i ? { ...x, date: e.target.value } : x)) })} />
            <Input value={d.label} onChange={(e) => set({ dates: r.dates.map((x, j) => (j === i ? { ...x, label: e.target.value } : x)) })} placeholder="예: 전면 적용" />
            <Button size="sm" variant="ghost" onClick={() => set({ dates: r.dates.filter((_, j) => j !== i) })}><X size={14} /></Button>
          </div>
        ))}
        <Button size="sm" variant="outline" className="mt-1" onClick={() => set({ dates: [...r.dates, { date: today, label: '' }] })}><Plus size={13} /> 일정</Button>
      </div>
      <div>
        <Label>출처(원문)</Label>
        {r.sources.map((s, i) => (
          <div key={i} className="mt-1 flex gap-2">
            <Input className="w-64" value={s.title} onChange={(e) => set({ sources: r.sources.map((x, j) => (j === i ? { ...x, title: e.target.value } : x)) })} placeholder="제목" />
            <Input value={s.url} onChange={(e) => set({ sources: r.sources.map((x, j) => (j === i ? { ...x, url: e.target.value } : x)) })} placeholder="https://" />
            <Button size="sm" variant="ghost" onClick={() => set({ sources: r.sources.filter((_, j) => j !== i) })}><X size={14} /></Button>
          </div>
        ))}
        <Button size="sm" variant="outline" className="mt-1" onClick={() => set({ sources: [...r.sources, { title: '', url: '' }] })}><Plus size={13} /> 출처</Button>
      </div>

      <div>
        <SectionTitle>요구사항 ({r.requirements.length})</SectionTitle>
        <div className="space-y-3">
          {r.requirements.map((q, i) => (
            <div key={i} className="rounded-md border p-3">
              <div className="grid gap-2 sm:grid-cols-[140px_1fr_auto]">
                <Input value={q.clause} onChange={(e) => setReq(i, { clause: e.target.value })} placeholder="조항" />
                <Input value={q.title} onChange={(e) => setReq(i, { title: e.target.value })} placeholder="요구 제목" />
                <Button size="sm" variant="ghost" onClick={() => set({ requirements: r.requirements.filter((_, j) => j !== i) })}><Trash2 size={14} /></Button>
              </div>
              <textarea rows={2} className="mt-2 w-full rounded-md border bg-background p-2 text-sm" value={q.text} onChange={(e) => setReq(i, { text: e.target.value })} placeholder="요구 내용 요약" />
              <div className="mt-2 grid gap-2 sm:grid-cols-3">
                {AUD.map((a) => (
                  <div key={a.v}>
                    <span className="text-xs text-muted-foreground">{a.label} 할 일</span>
                    <textarea rows={2} className="w-full rounded-md border bg-background p-1.5 text-xs" value={q.actions[a.v] || ''}
                      onChange={(e) => setReq(i, { actions: { ...q.actions, [a.v]: e.target.value } })} />
                  </div>
                ))}
              </div>
              <div className="mt-2 flex flex-wrap gap-1.5 text-xs">
                <span className="text-muted-foreground">자동 점검 증거:</span>
                {Object.entries(info.checks).map(([k, v]) => (
                  <label key={k} className={cn('cursor-pointer rounded border px-1.5', q.evidence.includes(k) ? 'border-primary bg-primary/10' : 'opacity-70')}>
                    <input type="checkbox" className="hidden" checked={q.evidence.includes(k)}
                      onChange={(e) => setReq(i, { evidence: e.target.checked ? [...q.evidence, k] : q.evidence.filter((x) => x !== k) })} />{v}
                  </label>
                ))}
              </div>
            </div>
          ))}
        </div>
        <Button size="sm" variant="outline" className="mt-2" onClick={() => set({ requirements: [...r.requirements, emptyReq()] })}><Plus size={13} /> 요구사항</Button>
      </div>
      {err && <Alert tone="crit">{err}</Alert>}
      <div className="flex gap-2">
        <Button onClick={save} disabled={busy}><Save size={15} /> {busy ? '저장 중…' : '저장'}</Button>
        <span className="self-center text-xs text-muted-foreground">저장하면 '확인됨' 표시가 해제됩니다(원문 재확인 후 다시 표시). 변경 이력은 원장에 남습니다.</span>
      </div>
    </div>
  );
}

// ---------- 국내 법규 분석·대응 ----------
const DUTY: Record<string, { label: string; v: 'danger' | 'warn' | 'muted' }> = {
  legal: { label: '법적 의무', v: 'danger' }, conditional: { label: '조달·계약·인증 요건', v: 'warn' }, voluntary: { label: '자율 권고', v: 'muted' }
};
const STAGES = [['now', '즉시'], ['3m', '3개월 내'], ['6m', '6개월 이후']] as const;
const FEATURE: Record<string, string> = { sbom: 'SBOM', vex: 'VEX', sign: '서명', notify: '취약점 통보', report: '규제 보고서', none: '지원 범위 밖' };

function AnalysisBody({ a }: { a: RegAnalysis }) {
  const list = (title: string, xs?: string[]) => !!xs?.length && (
    <div><div className="mb-0.5 font-medium">{title}</div><ul className="list-disc space-y-0.5 pl-4">{xs.map((x, i) => <li key={i}>{x}</li>)}</ul></div>
  );
  return (
    <div className="space-y-3 text-xs">
      {a.dutyNote && <p className="leading-relaxed">{a.dutyNote}</p>}
      <div className="grid gap-3 sm:grid-cols-[1fr_220px]">
        <div>
          <div className="mb-0.5 font-medium">적용 여부 판단 질문</div>
          {a.questions.map((q, i) => (
            <div key={i} className="flex gap-2 border-b border-dashed py-0.5"><span className="flex-1">{q}</span><span className="whitespace-nowrap text-muted-foreground">☐ 예 ☐ 아니오</span></div>
          ))}
        </div>
        {list('의무 주체', a.subjects)}
      </div>
      <div>
        <div className="mb-0.5 font-medium">근거 조문</div>
        {a.articles.length === 0 ? <p className="text-muted-foreground">근거 법령 조문 없음(법령이 아닌 기준)</p> : (
          <table className="w-full">
            <tbody>
              {a.articles.map((x, i) => (
                <tr key={i} className="border-t align-top">
                  <td className="w-[38%] py-1 pr-2">
                    <a href={x.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-primary underline">
                      {x.law} {x.article || ''} <ExternalLink size={10} />
                    </a>
                    {x.title && <span className="text-muted-foreground"> ({x.title})</span>}
                    {(x.check || !x.article) && <Badge variant="warn" className="ml-1">확인 필요</Badge>}
                  </td>
                  <td className="py-1">
                    {x.gist}
                    {x.text && (
                      <details className="mt-1"><summary className="cursor-pointer text-muted-foreground">원문 보기 · {kdate(x.fetchedAt)} 국가법령정보센터</summary>
                        <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap rounded bg-secondary p-2 font-sans">{x.text}</pre>
                      </details>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <div><div className="mb-0.5 font-medium">위반 시 제재·불이익</div><p>{a.sanctions}</p></div>
      <div>
        <div className="mb-0.5 font-medium">역할별 대응 방안</div>
        <table className="w-full">
          <thead><tr className="text-left text-muted-foreground"><th className="w-28 py-1">역할</th>{STAGES.map(([k, l]) => <th key={k}>{l}</th>)}</tr></thead>
          <tbody>
            {AUD.filter((r) => a.plans[r.v]?.length).map((r) => (
              <tr key={r.v} className="border-t align-top">
                <td className="py-1 font-medium">{r.label}</td>
                {STAGES.map(([k]) => (
                  <td key={k} className="py-1 pr-2">{(a.plans[r.v] || []).filter((s) => s.stage === k).map((s, i) => <div key={i}>· {s.do}</div>)}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        {list('필요 증빙', a.evidence)}
        {!!a.trustlink.length && (
          <div><div className="mb-0.5 font-medium">TrustLink 대응</div>
            {a.trustlink.map((m, i) => <div key={i}><span className="mr-1 rounded bg-secondary px-1">{FEATURE[m.feature] || m.feature}</span>{m.how}</div>)}
          </div>
        )}
        {list('영업 설명 포인트', a.talking)}
        {list('확인 필요 사항', a.checks)}
      </div>
      {!!a.sources?.length && (
        <div>{a.sources.map((s, i) => <a key={i} href={s.url} target="_blank" rel="noreferrer" className="mr-3 inline-flex items-center gap-1 text-primary underline">{s.title} <ExternalLink size={10} /></a>)}</div>
      )}
    </div>
  );
}

function LawPanel({ id, a, lawOC, onChanged }: { id: string; a?: RegAnalysis; lawOC: boolean; onChanged: () => void }) {
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => { // AI 초안 작성 중이면 다시 읽는다
    if (!a?.running) return;
    const t = setTimeout(onChanged, 3000);
    return () => clearTimeout(t);
  }, [a, onChanged]);
  async function run(f: () => Promise<unknown>, done?: (r: unknown) => string) {
    setBusy(true); setMsg('');
    try { const r = await f(); if (done) setMsg(done(r)); onChanged(); } catch (e) { setMsg(String(e)); }
    setBusy(false);
  }
  const fetchLaw = () => run(() => adminRegLawFetch(id), (r) => {
    const x = r as Awaited<ReturnType<typeof adminRegLawFetch>>;
    if (x.status === 'no-oc') return x.message || 'OC 미설정';
    const fail = (x.results || []).filter((y) => !y.ok);
    return `조문 ${x.fetched}건을 가져왔습니다${fail.length ? ` · 실패 ${fail.length}건: ${fail.map((y) => `${y.article} ${y.error}`).join(', ')}` : ''}`;
  });
  const review = (act: 'verify' | 'unverify' | 'adopt' | 'discard' | 'reset') => run(() => adminRegLawReview(id, act));
  const d = a ? DUTY[a.duty] : undefined;
  return (
    <div className="rounded-md border border-teal-200 bg-teal-50/40 p-3">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <Scale size={14} className="text-teal-700" /><b className="text-sm">법규 분석·대응</b>
        {a?.nature && <Badge variant="outline">{a.nature}</Badge>}
        {d && <Badge variant={d.v}>{d.label}</Badge>}
        {a && (a.verified
          ? <span title={`${a.verifiedBy} · ${kdate(a.verifiedAt)}`}><StatusDot tone="ok">분석 확인됨</StatusDot></span>
          : <StatusDot tone="warn">분석 확인 필요</StatusDot>)}
        {a?.origin === 'ai' && <Badge variant="warn">AI 초안 채택</Badge>}
        {a?.asOf && <span className="text-[11px] text-muted-foreground">기준일 {a.asOf}</span>}
        <div className="flex-1" />
        <Button size="sm" variant="outline" disabled={busy || !a?.articles.some((x) => x.article)} onClick={fetchLaw}
          title={lawOC ? '국가법령정보센터에서 조문 원문을 가져옵니다' : 'OC 미설정 — 규제 탐색 › 탐색 설정에서 OC 저장'}>
          <Download size={13} /> 조문 가져오기{!lawOC && ' (OC 미설정)'}
        </Button>
        <Button size="sm" variant="outline" disabled={busy || a?.running} onClick={() => run(() => adminRegLawAnalyze(id), () => 'AI 분석 초안을 작성합니다. 끝나면 아래에 초안이 나타납니다.')}>
          <Sparkles size={13} /> {a?.running ? 'AI 작성 중…' : 'AI 분석 초안'}
        </Button>
        {a && a.origin !== undefined && (
          <Button size="sm" variant={a.verified ? 'outline' : 'default'} disabled={busy} onClick={() => review(a.verified ? 'unverify' : 'verify')}>
            {a.verified ? <><CircleDashed size={13} /> 확인 해제</> : <><CheckCircle2 size={13} /> 원문 대조함</>}
          </Button>
        )}
        {a && (a.origin === 'ai' || a.verified || a.builtinNewer) && (
          <Button size="sm" variant="ghost" disabled={busy} onClick={() => { if (confirm('작업본 분석을 지우고 내장 분석으로 되돌릴까요?')) review('reset'); }}><RotateCcw size={13} /> 내장 분석으로</Button>
        )}
      </div>
      <Busy className="mb-2" active={busy} label="처리 중 — 조문은 국가법령정보센터에서 한 조씩 가져옵니다" />
      <Busy className="mb-2" active={!!a?.running} label="AI 가 조문·규제 정보를 읽고 분석 초안 작성 중" hint="로컬 AI 면 2~5분 — 끝나면 아래에 초안이 나타납니다" />
      {msg && <p className="mb-2 text-xs text-amber-800">{msg}</p>}
      {a?.aiError && <p className="mb-2 text-xs text-red-700">AI 초안 실패: {a.aiError}</p>}
      {a?.builtinNewer && <p className="mb-2 text-xs text-amber-800">새 버전 내장 분석이 있습니다 — '내장 분석으로'를 누르면 반영됩니다(확인 표시는 해제).</p>}
      {a?.draft && (
        <div className="mb-3 rounded-md border border-violet-300 bg-violet-50/60 p-3">
          <div className="mb-2 flex flex-wrap items-center gap-2 text-xs">
            <Sparkles size={13} className="text-violet-700" />
            <b>AI 분석 초안</b><span className="text-muted-foreground">{a.draft.aiMeta?.model} · {kdate(a.draft.updatedAt)} · 근거 {a.draft.citations?.join(', ') || '없음'} · 사람 검토 필요</span>
            <div className="flex-1" />
            <Button size="sm" disabled={busy} onClick={() => review('adopt')}><CheckCircle2 size={13} /> 채택(미확인 상태)</Button>
            <Button size="sm" variant="ghost" disabled={busy} onClick={() => review('discard')}><X size={13} /> 버림</Button>
          </div>
          <AnalysisBody a={a.draft} />
        </div>
      )}
      {a && a.origin !== undefined ? <AnalysisBody a={a} />
        : !a?.draft && <p className="text-xs text-muted-foreground">이 규제에는 아직 법규 분석이 없습니다. 'AI 분석 초안'으로 요구사항을 근거로 초안을 만들 수 있습니다.</p>}
      <p className="mt-2 text-[11px] text-muted-foreground">법률 자문이 아닙니다. '확인 필요' 조문은 번호를 확인하지 못한 항목입니다. 원문과 대조한 뒤 '원문 대조함'으로 표시하세요.</p>
    </div>
  );
}

// ---------- 카탈로그 탭 ----------
function RegCard({ r, info, onEdit, onChanged }: { r: Regulation; info: RegsInfo; onEdit: () => void; onChanged: () => void }) {
  const [open, setOpen] = useState(false);
  const nd = nextDate(r);
  async function verify() { await adminRegVerify(r.id, !r.verified); onChanged(); }
  async function del() { if (confirm(`'${r.nameKo}' 를 카탈로그에서 삭제할까요?`)) { await adminRegDelete(r.id); onChanged(); } }
  return (
    <div className="border-t py-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <button onClick={() => setOpen(!open)} className="flex items-center gap-2 text-left">
          {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          <RegionChip r={r.region} />
          <span className="font-medium">{r.nameKo || r.name}</span>
        </button>
        <Badge variant={r.binding.startsWith('의무') ? 'danger' : r.binding.includes('조달') ? 'warn' : 'muted'}>{r.binding}</Badge>
        <span className="text-xs text-muted-foreground">{r.status}</span>
        {nd && <span className="text-xs text-amber-700">· {nd.date} {nd.label}</span>}
        <div className="flex-1" />
        {r.origin === 'discovered' && <Badge variant="warn">탐색 채택</Badge>}
        {r.origin === 'custom' && <Badge variant="muted">직접 추가</Badge>}
        {r.edited && <Badge variant="muted">로컬 수정</Badge>}
        {r.verified
          ? <span title={`${r.verifiedBy} · ${kdate(r.verifiedAt)}`}><StatusDot tone="ok">확인됨</StatusDot></span>
          : <StatusDot tone="warn">확인 필요</StatusDot>}
        <span className="text-xs text-muted-foreground">요구 {r.requirements.length}</span>
      </div>
      {open && (
        <div className="mt-2 space-y-2 pl-6 text-sm">
          <div className="text-xs text-muted-foreground">{r.name} · {r.kind} · {r.authority} · rev {r.rev}{r.updatedAt ? ` · ${kdate(r.updatedAt)} ${r.updatedBy || ''}` : ''}</div>
          <p>{r.scope}</p>
          {r.dates.length > 0 && (
            <div className="flex flex-wrap gap-2 text-xs">
              {r.dates.map((d, i) => <span key={i} className={cn('rounded border px-1.5', d.date >= today ? 'border-amber-300 bg-amber-50' : 'bg-secondary')}>{d.date} {d.label}</span>)}
            </div>
          )}
          {r.sources.map((s, i) => (
            <a key={i} href={s.url} target="_blank" rel="noreferrer" className="mr-3 inline-flex items-center gap-1 text-xs text-primary underline">{s.title} <ExternalLink size={11} /></a>
          ))}
          {r.note && <div className="text-xs text-amber-800">메모: {r.note}</div>}
          <table className="w-full text-xs">
            <thead><tr className="text-left text-muted-foreground"><th className="w-32 py-1">조항</th><th>요구</th><th className="w-[38%]">역할별 할 일</th><th className="w-40">자동 점검</th></tr></thead>
            <tbody>
              {r.requirements.map((q) => (
                <tr key={q.id} className="border-t align-top">
                  <td className="py-1.5 font-mono">{q.clause}</td>
                  <td className="py-1.5"><b>{q.title}</b><div className="text-muted-foreground">{q.text}</div></td>
                  <td className="py-1.5">{AUD.filter((a) => q.actions[a.v]).map((a) => <div key={a.v}><span className="text-muted-foreground">{a.label}:</span> {q.actions[a.v]}</div>)}</td>
                  <td className="py-1.5">{q.evidence.map((e) => <span key={e} className="mb-0.5 mr-1 inline-block rounded bg-secondary px-1">{info.checks[e] || e}</span>)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {r.region === 'KR' && <LawPanel id={r.id} a={info.analyses?.[r.id]} lawOC={!!info.lawOC} onChanged={onChanged} />}
          <div className="flex gap-2">
            <Button size="sm" variant={r.verified ? 'outline' : 'default'} onClick={verify}>
              {r.verified ? <><CircleDashed size={13} /> 확인 해제</> : <><CheckCircle2 size={13} /> 원문 확인함</>}
            </Button>
            <Button size="sm" variant="outline" onClick={onEdit}><Pencil size={13} /> 편집</Button>
            <Button size="sm" variant="ghost" onClick={del}><Trash2 size={13} /> 삭제</Button>
          </div>
        </div>
      )}
    </div>
  );
}

function CatalogTab({ info, reload, editId }: { info: RegsInfo; reload: () => void; editId?: string }) {
  const [region, setRegion] = useState('');
  const [q, setQ] = useState('');
  const [onlyUnverified, setOnlyUnverified] = useState(false);
  const [edit, setEdit] = useState<{ r: Regulation; isNew: boolean } | null>(() => {
    const r = editId ? info.catalog.regulations.find((x) => x.id === editId) : undefined;
    return r ? { r, isNew: false } : null; // 탐색에서 채택한 규제는 바로 편집기로
  });
  const [pick, setPick] = useState<string[]>([]);
  const [overwrite, setOverwrite] = useState(false);
  const [msg, setMsg] = useState('');
  const regs = info.catalog.regulations;
  const list = regs.filter((r) =>
    (!region || (region === '기타' ? !['US', 'EU', 'JP', 'KR'].includes(r.region) : r.region === region)) &&
    (!onlyUnverified || !r.verified) &&
    (!q || JSON.stringify(r).toLowerCase().includes(q.toLowerCase())));
  const diff = info.builtin.diff;

  if (edit) return <Editor init={edit.r} isNew={edit.isNew} info={info} onDone={(saved) => { setEdit(null); if (saved) reload(); }} />;
  async function apply() {
    const r = await adminRegBuiltinApply(pick, overwrite);
    setMsg(`반영 ${r.applied.length}건${r.skipped.length ? `, 로컬 수정으로 건너뜀 ${r.skipped.length}건` : ''}`);
    setPick([]); reload();
  }
  const verified = regs.filter((r) => r.verified).length;
  return (
    <>
      <div className="mb-4 grid gap-3 sm:grid-cols-4">
        <StatCard label="관리 규제" value={regs.length} />
        <StatCard label="요구사항" value={regs.reduce((n, r) => n + r.requirements.length, 0)} />
        <StatCard label="원문 확인됨" value={`${verified} / ${regs.length}`} />
        <StatCard label="카탈로그 버전" value={<span className="text-base">작업본 {info.catalog.version} · 내장 {info.catalog.builtinVersion}</span>} />
      </div>
      {diff.length > 0 && (
        <div className="mb-4 rounded-lg border border-amber-300 bg-amber-50 p-3 text-sm">
          <div className="font-medium">내장 카탈로그 {info.builtin.version} 에 바뀐 규제가 {diff.length}건 있습니다</div>
          <div className="mt-2 space-y-1">
            {diff.map((d) => (
              <label key={d.id} className="flex items-center gap-2">
                <input type="checkbox" checked={pick.includes(d.id)} onChange={(e) => setPick(e.target.checked ? [...pick, d.id] : pick.filter((x) => x !== d.id))} />
                <Badge variant={d.change === 'removed' ? 'danger' : d.change === 'added' ? 'default' : 'warn'}>{{ added: '추가', changed: '변경', removed: '삭제' }[d.change]}</Badge>
                <span>{d.name}</span>{d.localEdit && <span className="text-xs text-red-700">로컬 수정과 충돌</span>}
              </label>
            ))}
          </div>
          <div className="mt-2 flex items-center gap-3">
            <Button size="sm" onClick={apply}>{pick.length ? `선택 ${pick.length}건 반영` : '모두 반영'}</Button>
            <label className="flex items-center gap-1 text-xs"><input type="checkbox" checked={overwrite} onChange={(e) => setOverwrite(e.target.checked)} /> 로컬 수정한 항목도 덮어쓰기</label>
            {msg && <span className="text-xs">{msg}</span>}
          </div>
        </div>
      )}
      <div className="mb-2 flex flex-wrap items-center gap-2">
        {['', 'US', 'EU', 'JP', 'KR', '기타'].map((x) => (
          <button key={x} onClick={() => setRegion(x)} className={cn('rounded-full border px-3 py-1 text-xs', region === x ? 'border-primary bg-primary text-primary-foreground' : 'hover:bg-secondary')}>
            {x ? `${x} ${info.regions[x] || ''}` : '전체'}
          </button>
        ))}
        <div className="relative ml-2">
          <Search size={14} className="absolute left-2 top-2.5 text-muted-foreground" />
          <Input className="h-9 w-56 pl-7" value={q} onChange={(e) => setQ(e.target.value)} placeholder="이름·조항·내용 검색" />
        </div>
        <label className="flex items-center gap-1 text-xs"><input type="checkbox" checked={onlyUnverified} onChange={(e) => setOnlyUnverified(e.target.checked)} /> 확인 필요만</label>
        <div className="flex-1" />
        <Button size="sm" onClick={() => setEdit({ r: emptyReg(), isNew: true })}><Plus size={14} /> 규제 추가</Button>
      </div>
      <div className="rounded-lg border bg-card px-3">
        {list.length === 0 ? <p className="py-6 text-center text-sm text-muted-foreground">해당하는 규제가 없습니다</p>
          : list.map((r) => <RegCard key={r.id} r={r} info={info} onEdit={() => setEdit({ r, isNew: false })} onChanged={reload} />)}
      </div>
      {info.catalog.note && <p className="mt-2 text-xs text-muted-foreground">{info.catalog.note}</p>}
    </>
  );
}

// ---------- 탐색 탭 ----------
function DiscoverTab({ onAdopted }: { onAdopted: (regId: string) => void }) {
  const [d, setD] = useState<RegDiscoverInfo | null>(null);
  const [src, setSrc] = useState<string[]>(['federal-register', 'law-kr', 'watch', 'ai']);
  const [filter, setFilter] = useState<'new' | 'all'>('new');
  const [kwUS, setKwUS] = useState('');
  const [kwKR, setKwKR] = useState('');
  const [oc, setOc] = useState('');
  const [msg, setMsg] = useState('');
  const load = () => adminRegDiscover().then((x) => { setD(x); setKwUS(x.config.keywordsUS.join('\n')); setKwKR(x.config.keywordsKR.join('\n')); });
  useEffect(() => { load(); }, []);
  useEffect(() => {
    if (!d?.state.running) return;
    const t = setTimeout(() => adminRegDiscover().then(setD), 2000);
    return () => clearTimeout(t);
  }, [d]);
  if (!d) return <Loading />;
  async function run() { await adminRegDiscoverRun(src); setTimeout(() => adminRegDiscover().then(setD), 500); }
  async function saveCfg() {
    const r = await adminRegDiscoverCfg({ keywordsUS: kwUS.split('\n'), keywordsKR: kwKR.split('\n'), lawOC: oc || undefined });
    setOc(''); setMsg(`저장했습니다${r.hasLawOC ? ' (OC 설정됨)' : ''}`); load();
  }
  async function act(c: RegCandidate, a: 'adopt' | 'dismiss' | 'restore') {
    const r = await adminRegCandidate(c.id, a);
    await load();
    if (a === 'adopt' && r.candidate.regId && c.source !== 'watch') onAdopted(r.candidate.regId);
  }
  const cands = d.candidates.filter((c) => filter === 'all' || c.state === 'new');
  return (
    <div className="grid gap-4 lg:grid-cols-[1fr_320px]">
      <div>
        <div className="mb-3 flex flex-wrap items-center gap-3 rounded-lg border bg-card p-3 text-sm">
          {Object.entries(SRC_LABEL).map(([k, v]) => (
            <label key={k} className="flex items-center gap-1">
              <input type="checkbox" checked={src.includes(k)} onChange={(e) => setSrc(e.target.checked ? [...src, k] : src.filter((x) => x !== k))} />{v}
            </label>
          ))}
          <div className="flex-1" />
          <Button size="sm" onClick={run} disabled={d.state.running || !src.length}>
            <Radar size={14} /> {d.state.running ? '탐색 중…' : '탐색 실행'}
          </Button>
        </div>
        {d.state.log.length > 0 && (
          <pre className="mb-3 max-h-40 overflow-auto rounded-md bg-zinc-950 p-2 text-[11px] leading-relaxed text-zinc-200">{d.state.log.join('\n')}</pre>
        )}
        <div className="mb-2 flex items-center gap-2 text-sm">
          <SectionTitle>후보 {cands.length}건</SectionTitle>
          <div className="flex-1" />
          <select className={selectCls} value={filter} onChange={(e) => setFilter(e.target.value as 'new' | 'all')}>
            <option value="new">새 후보만</option><option value="all">전체(무시·채택 포함)</option>
          </select>
        </div>
        <div className="space-y-2">
          {cands.length === 0 && <p className="rounded-lg border bg-card p-6 text-center text-sm text-muted-foreground">후보가 없습니다. 탐색을 실행하세요.</p>}
          {cands.map((c) => (
            <div key={c.id} className={cn('rounded-lg border bg-card p-3 text-sm', c.state !== 'new' && 'opacity-60')}>
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant={c.source === 'ai' ? 'warn' : c.source === 'watch' ? 'danger' : 'muted'}>{SRC_LABEL[c.source]}</Badge>
                {c.region && <RegionChip r={c.region} />}
                <span className="font-medium">{c.title}</span>
                {c.date && <span className="text-xs text-muted-foreground">{c.date}</span>}
                <div className="flex-1" />
                {c.state === 'new' ? (
                  <>
                    <Button size="sm" onClick={() => act(c, 'adopt')}>{c.source === 'watch' ? '재확인 필요로 표시' : '카탈로그에 채택'}</Button>
                    <Button size="sm" variant="ghost" onClick={() => act(c, 'dismiss')}>무시</Button>
                  </>
                ) : (
                  <>
                    <span className="text-xs">{c.state === 'adopted' ? '채택됨' : '무시됨'}</span>
                    <Button size="sm" variant="ghost" onClick={() => act(c, 'restore')}>되돌리기</Button>
                  </>
                )}
              </div>
              {c.summary && <p className="mt-1 text-xs text-muted-foreground">{c.summary}</p>}
              <div className="mt-1 flex gap-3 text-xs">
                {c.url && <a href={c.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-primary underline">원문 <ExternalLink size={11} /></a>}
                {c.keyword && <span className="text-muted-foreground">검색어 “{c.keyword}”</span>}
                <span className="text-muted-foreground">발견 {kdate(c.foundAt)}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
      <div className="space-y-3">
        <div className="rounded-lg border bg-card p-3 text-sm">
          <div className="mb-2 font-medium">탐색 설정</div>
          <Label>미국 관보 검색어(줄마다)</Label>
          <textarea rows={3} className="w-full rounded-md border bg-background p-2 text-xs" value={kwUS} onChange={(e) => setKwUS(e.target.value)} />
          <Label>국가법령정보센터 검색어(줄마다)</Label>
          <textarea rows={3} className="w-full rounded-md border bg-background p-2 text-xs" value={kwKR} onChange={(e) => setKwKR(e.target.value)} />
          <Label>국가법령정보센터 OC {d.hasLawOC ? '(설정됨 — 바꿀 때만 입력)' : '(Open API 신청 후 발급)'}</Label>
          <Input type="password" autoComplete="off" value={oc} onChange={(e) => setOc(e.target.value)} placeholder={d.hasLawOC ? '••••' : 'OC 값'} />
          <div className="mt-2 flex items-center gap-2">
            <Button size="sm" variant="outline" onClick={saveCfg}><Save size={13} /> 저장</Button>
            {msg && <span className="text-xs text-muted-foreground">{msg}</span>}
          </div>
        </div>
        <div className="rounded-lg border bg-card p-3 text-xs text-muted-foreground">
          <p className="mb-1 font-medium text-foreground">출처별 동작</p>
          <p><b>미국 관보</b>: Federal Register 공개 API 구문 검색(최신순).</p>
          <p><b>국가법령정보센터</b>: 법령·행정규칙 검색(OC 필요).</p>
          <p><b>원문 변경 감지</b>: 카탈로그 출처 페이지 본문이 바뀌면 후보로 올립니다. 처음 실행은 기준값만 저장합니다.</p>
          <p><b>AI 제안</b>: 연결된 LLM 의 지식으로 빠진 규제를 제안합니다. 출처가 없으므로 반드시 원문을 확인하세요.</p>
          <p className="mt-1">외부 접속은 '탐색 실행'을 누를 때만 합니다.</p>
        </div>
      </div>
    </div>
  );
}

export default function Regulations() {
  const nav = useNavigate();
  const [tab, setTab] = useState<'catalog' | 'discover'>(() => {
    const t = new URLSearchParams(window.location.search).get('tab');
    return t === 'discover' ? t : 'catalog'; // ?tab= 으로 바로 열기(시연·링크용)
  });
  useEffect(() => { // 예전 링크(?tab=report) → 보고서함
    if (new URLSearchParams(window.location.search).get('tab') === 'report') nav('/admin/reports?tab=new', { replace: true });
  }, [nav]);
  const [info, setInfo] = useState<RegsInfo | null>(null);
  const [err, setErr] = useState('');
  const [editId, setEditId] = useState<string>();
  const reload = () => adminRegs().then(setInfo).catch((e) => setErr(String(e)));
  useEffect(() => { reload(); }, []);
  const head = (
    <PageHeader title="규제 카탈로그"
      description="미국·유럽·일본·한국 등 공급망 보안 법규·지침을 요구사항 단위로 관리하고 빠진 규제를 찾습니다. 보고서는 '보고서함'에서 만들고 보관합니다. 법률 자문이 아니며 '원문 확인함' 표시는 사람이 합니다."
      actions={<>
        <Button size="sm" variant="outline" onClick={reload}><RefreshCw size={14} /> 새로고침</Button>
        <Button size="sm" onClick={() => nav('/admin/reports?tab=new')}><FileText size={14} /> 보고서 만들기</Button>
      </>} />
  );
  if (err) return (<>{head}<Alert tone="crit">오류: {err}</Alert></>);
  if (!info) return (<>{head}<Loading /></>);
  const newCount = info.builtin.diff.length;
  return (
    <>
      {head}
      <div className="mb-4 flex gap-1 border-b">
        {([['catalog', '카탈로그', BookMarked], ['discover', '규제 탐색', Radar]] as const).map(([k, l, I]) => (
          <button key={k} onClick={() => setTab(k)} className={cn('-mb-px flex items-center gap-1.5 border-b-2 px-3 py-2 text-sm', tab === k ? 'border-primary font-medium' : 'border-transparent text-muted-foreground hover:text-foreground')}>
            <I size={15} /> {l}{k === 'catalog' && newCount > 0 && <span className="rounded-full bg-amber-500 px-1.5 text-[10px] text-white">{newCount}</span>}
          </button>
        ))}
      </div>
      {tab === 'catalog' && <CatalogTab key={editId || ''} info={info} reload={reload} editId={editId} />}
      {tab === 'discover' && <DiscoverTab onAdopted={(id) => { reload().then(() => { setEditId(id); setTab('catalog'); }); }} />}
    </>
  );
}
