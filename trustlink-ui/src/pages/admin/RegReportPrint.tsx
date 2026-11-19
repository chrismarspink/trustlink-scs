import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { Printer, Sparkles, ShieldCheck } from 'lucide-react';
import { adminRegReport, ApiError, bffLogin, type RegReport, type RegReportReq, type RegLawSection } from '@/lib/api';

// 규제 보고서 인쇄용 페이지(A4) — 브라우저 '인쇄 → PDF 로 저장'으로 PDF 를 만든다.
// 표지(1쪽, 여백 없음) → 요약 → 규제별 확인 사항 → 역할별 체크리스트 → 제품 증거 → 부록(출처·검토 서명).

const REGION_HUE: Record<string, string> = { US: '#1d4ed8', EU: '#4338ca', JP: '#be123c', KR: '#0f766e', UK: '#6d28d9', IN: '#b45309' };
const ST_COLOR: Record<string, { color: string; bg: string }> = {
  met: { color: '#047857', bg: '#ecfdf5' }, partial: { color: '#b45309', bg: '#fffbeb' },
  unmet: { color: '#b91c1c', bg: '#fef2f2' }, manual: { color: '#475569', bg: '#f1f5f9' }
};
const EV_COLOR: Record<string, string> = { pass: '#047857', partial: '#b45309', fail: '#b91c1c', na: '#64748b' };

// 인쇄본 문구(한글·영문). 규제·요구사항 본문은 서버가 보고서 언어로 채워 보낸다.
const TX = {
  ko: {
    st: { met: '충족', partial: '일부', unmet: '미충족', manual: '수동 확인' } as Record<string, string>,
    ev: { pass: '충족', partial: '일부', fail: '미충족', na: '해당 없음' } as Record<string, string>,
    aud: { dev: '개발자', admin: '관리자', sales: '영업' } as Record<string, string>,
    loading: '보고서를 불러오는 중…', allProducts: '전 제품 공통(제품 미지정)', footerFor: (a: string) => `${a}용`,
    barFor: (a: string) => `${a}용`, aiRunning: 'AI 요약 작성 중… 끝나면 자동으로 채워집니다', printHint: '인쇄 대화상자에서 ‘PDF로 저장’, 배경 그래픽 켜기', save: 'PDF 저장',
    coverTitle: <>공급망 보안<br />규제 대응 보고서</>, checkFor: (a: string) => `${a} 확인 사항`,
    product: '대상 제품', date: '작성일', regions: '대상 지역', author: '작성자', catalog: '규제 카탈로그', docNo: '문서번호', edition: '판',
    catalogV: (c: string, b: string) => `작업본 v${c} (내장 ${b})`, editionV: (n: number, prev?: string) => `제${n}판${prev ? ` (이전 판 ${prev})` : ' (초판)'}`,
    kpi: ['적용 규제', '의무 규제', '확인 사항', '원문 확인 필요'], notLegal: '본 보고서는 공개 규제 정보를 요약한 참고 자료이며 법률 자문이 아닙니다.',
    s1: '요약', s1sub: (a: string, n: number, q: number) => `${a}가 확인해야 할 규제 ${n}건 · 확인 사항 ${q}건`,
    aiDraft: (m?: string) => `AI 요약 초안 · ${m || ''} · 사람 검토 필요`, points: '핵심 관찰', priority: '먼저 할 일', aiWriting: 'AI 요약을 작성하고 있습니다…', aiFail: 'AI 요약을 만들지 못했습니다: ',
    changes: (n: number, d: string) => `지난 판(${d}) 이후 바뀐 점 ${n}건`, noChanges: (d: string) => `지난 판(${d}) 이후 바뀐 점 없음`,
    chKind: { added: '새 규제', removed: '빠진 규제', revised: '내용 개정', date: '다음 일정', status: '상태 변화' } as Record<string, string>,
    upcoming: '다가오는 시행·적용 일정', noUpcoming: '예정된 일정이 없습니다', recent: '최근 1년 시행·적용', byRegion: '지역별 적용 규제',
    regCount: (n: number, m: number) => `${n}건 · 의무 ${m}`, prodStatus: '제품 충족 현황',
    s2: '규제별 확인 사항', s2sub: '구속력: 의무(법적 의무) · 조달 조건(공공·고객 계약 요건) · 권고', nRegs: (n: number) => `${n}개 규제`,
    verifyNeeded: '◆ 원문 확인 필요', next: '다음 일정', untranslated: '영문 번역 없음 — 원문(한국어) 표시',
    thClause: '조항', thReq: '요구사항', thActAll: '역할별 할 일', thAct: (a: string) => `${a} 할 일`, thSt: '상태',
    s3: (a: string) => `${a} 체크리스트`, s3sub: '의무 → 조달 조건 → 권고 순, 같은 구속력 안에서는 다가오는 일정 순',
    s4: '제품 증거 점검', s4sub: (p: string) => `${p} 릴리스에 첨부된 SBOM·서명·VEX·문서와 취약점 분석 결과로 자동 판정`,
    thCheck: '점검', thRes: '결과', thVal: '값', thFix: '보완 방법',
    s5: '부록 — 출처와 검토', thRegion: '지역', thReg: '규제', thSrc: '원문', thVerified: '원문 확인', verified: '확인됨', toVerify: '확인 필요',
    sign: ['작성', '검토', '승인'], signLine: '이름 / 서명 / 날짜',
    tail: (c: string, b: string, id: string) => ` 규제 카탈로그 작업본 v${c}(내장 ${b}) 기준. 생성 기록은 TrustLink 원장에 남아 있습니다(보고서 ID ${id}).`,
    locale: 'ko-KR'
  },
  en: {
    st: { met: 'Met', partial: 'Partial', unmet: 'Not met', manual: 'Manual' } as Record<string, string>,
    ev: { pass: 'Pass', partial: 'Partial', fail: 'Fail', na: 'N/A' } as Record<string, string>,
    aud: { dev: 'Developers', admin: 'Administrators', sales: 'Sales' } as Record<string, string>,
    loading: 'Loading report…', allProducts: 'All products (no product selected)', footerFor: (a: string) => `for ${a}`,
    barFor: (a: string) => `for ${a}`, aiRunning: 'Writing AI summary… it will appear automatically', printHint: 'In the print dialog choose “Save as PDF” and enable background graphics', save: 'Save PDF',
    coverTitle: <>Supply-Chain Security<br />Regulatory Compliance Report</>, checkFor: (a: string) => `Checklist for ${a}`,
    product: 'Product', date: 'Date', regions: 'Regions', author: 'Prepared by', catalog: 'Regulation catalog', docNo: 'Document No.', edition: 'Edition',
    catalogV: (c: string, b: string) => `Working copy v${c} (built-in ${b})`, editionV: (n: number, prev?: string) => `Edition ${n}${prev ? ` (previous ${prev})` : ' (first edition)'}`,
    kpi: ['Regulations', 'Mandatory', 'Check items', 'To be verified'], notLegal: 'This report summarizes public regulatory information for reference only and is not legal advice.',
    s1: 'Summary', s1sub: (a: string, n: number, q: number) => `${n} regulations · ${q} items for ${a}`,
    aiDraft: (m?: string) => `AI draft summary · ${m || ''} · requires human review`, points: 'Key observations', priority: 'Do first', aiWriting: 'Writing AI summary…', aiFail: 'Could not create the AI summary: ',
    changes: (n: number, d: string) => `${n} change(s) since the previous edition (${d})`, noChanges: (d: string) => `No changes since the previous edition (${d})`,
    chKind: { added: 'New regulation', removed: 'Removed', revised: 'Revised', date: 'Next date', status: 'Status change' } as Record<string, string>,
    upcoming: 'Upcoming effective dates', noUpcoming: 'No upcoming dates', recent: 'Applied in the last 12 months', byRegion: 'Regulations by region',
    regCount: (n: number, m: number) => `${n} · mandatory ${m}`, prodStatus: 'Product compliance status',
    s2: 'Requirements by regulation', s2sub: 'Binding force: Mandatory (legal obligation) · Procurement condition (public/customer contract) · Recommended', nRegs: (n: number) => `${n} regulation(s)`,
    verifyNeeded: '◆ To be verified', next: 'Next', untranslated: 'No English translation — shown in Korean',
    thClause: 'Clause', thReq: 'Requirement', thActAll: 'Actions by role', thAct: (a: string) => `Actions for ${a}`, thSt: 'Status',
    s3: (a: string) => `Checklist for ${a}`, s3sub: 'Mandatory → procurement → recommended; within each, by upcoming date',
    s4: 'Product evidence check', s4sub: (p: string) => `Assessed automatically from the SBOM, signatures, VEX, documents and vulnerability analysis attached to release ${p}`,
    thCheck: 'Check', thRes: 'Result', thVal: 'Value', thFix: 'How to fix',
    s5: 'Appendix — Sources and review', thRegion: 'Region', thReg: 'Regulation', thSrc: 'Source', thVerified: 'Verified', verified: 'Verified', toVerify: 'To be verified',
    sign: ['Prepared', 'Reviewed', 'Approved'], signLine: 'Name / Signature / Date',
    tail: (c: string, b: string, id: string) => ` Based on regulation catalog working copy v${c} (built-in ${b}). The generation record is kept in the TrustLink ledger (report ID ${id}).`,
    locale: 'en-GB'
  }
};
type Tx = typeof TX.ko;
const isMand = (b: string) => b.startsWith('의무') || b.startsWith('Mandatory');
const isProc = (b: string) => b.includes('조달') || b.startsWith('Procurement');

const dday = (d: string) => Math.round((new Date(d + 'T00:00:00').getTime() - new Date(new Date().toISOString().slice(0, 10) + 'T00:00:00').getTime()) / 86400e3);
// AI 문장의 근거 표시([G3-1], (G1, G3))는 데이터에만 남기고 인쇄본에서는 뺀다
const clean = (t: string) => t.replace(/\s*[[(]\s*G\d+(?:-\d+)?(?:\s*,\s*G\d+(?:-\d+)?)*\s*[\])]/g, '').replace(/\s+([.,])/g, '$1');
const fdate = (t: string, locale: string) => new Date(t).toLocaleDateString(locale, { year: 'numeric', month: 'long', day: 'numeric' });

function Chip({ r }: { r: string }) {
  const c = REGION_HUE[r] || '#334155';
  return <span style={{ color: c, borderColor: c + '55', background: c + '10' }} className="inline-flex items-center rounded border px-1.5 text-[10px] font-bold tracking-wide">{r}</span>;
}

function Pattern() {
  // 표지 장식: 옅은 노드-링크 그물 + 동심원 호
  const nodes = [[60, 40], [180, 90], [320, 50], [470, 110], [610, 60], [720, 150], [120, 200], [280, 230], [430, 260], [580, 230], [700, 300], [40, 320], [220, 360], [380, 390], [540, 370], [680, 420]];
  const links = [[0, 1], [1, 2], [2, 3], [3, 4], [4, 5], [1, 6], [6, 7], [7, 8], [8, 9], [9, 10], [3, 8], [6, 11], [11, 12], [12, 13], [13, 14], [14, 15], [7, 12], [9, 14], [5, 10], [10, 15]];
  return (
    <svg viewBox="0 0 794 460" className="absolute inset-0 h-full w-full" preserveAspectRatio="xMidYMid slice" aria-hidden>
      <defs>
        <radialGradient id="glow" cx="80%" cy="20%" r="60%"><stop offset="0" stopColor="#2dd4bf" stopOpacity=".28" /><stop offset="1" stopColor="#2dd4bf" stopOpacity="0" /></radialGradient>
      </defs>
      <rect width="794" height="460" fill="url(#glow)" />
      {[140, 220, 300, 380].map((r) => <circle key={r} cx="700" cy="70" r={r} fill="none" stroke="#ffffff" strokeOpacity=".06" strokeWidth="1" />)}
      {links.map(([a, b], i) => <line key={i} x1={nodes[a][0]} y1={nodes[a][1]} x2={nodes[b][0]} y2={nodes[b][1]} stroke="#93c5fd" strokeOpacity=".16" strokeWidth="1" />)}
      {nodes.map(([x, y], i) => <circle key={i} cx={x} cy={y} r={i % 4 === 0 ? 3.2 : 2} fill="#bfdbfe" fillOpacity={i % 4 === 0 ? 0.55 : 0.3} />)}
    </svg>
  );
}

function SectionHead({ n, title, sub }: { n: string; title: string; sub?: string }) {
  return (
    <div className="mb-4 mt-2 flex items-end gap-3 border-b-2 pb-2" style={{ borderColor: '#0b1f3a' }}>
      <span className="font-mono text-3xl font-extrabold leading-none" style={{ color: '#14b8a6' }}>{n}</span>
      <div>
        <h2 className="text-xl font-bold leading-tight" style={{ color: '#0b1f3a' }}>{title}</h2>
        {sub && <p className="text-[11px] text-slate-500">{sub}</p>}
      </div>
    </div>
  );
}

function StatusPill({ s, t }: { s: string; t: Tx }) {
  const x = ST_COLOR[s] || ST_COLOR.manual;
  return <span style={{ color: x.color, background: x.bg }} className="whitespace-nowrap rounded-full px-2 py-0.5 text-[10px] font-semibold">{t.st[s] || t.st.manual}</span>;
}

function ActionCell({ q, audience, t }: { q: RegReportReq; audience: string; t: Tx }) {
  if (audience !== 'all') return <>{q.action}</>;
  return <>{(['dev', 'admin', 'sales'] as const).filter((a) => q.actions[a]).map((a) => (
    <div key={a}><b className="text-slate-500">{t.aud[a]}</b> {q.actions[a]}</div>
  ))}</>;
}

// 국내 법규 분석 및 대응 방안(한글 보고서만 — 서버가 역할에 맞춰 계획·설명 포인트를 줄여 보낸다)
const DUTY_KO: Record<string, { label: string; color: string; bg: string }> = {
  legal: { label: '법적 의무', color: '#991b1b', bg: '#fee2e2' },
  conditional: { label: '조달·계약·인증 요건', color: '#92400e', bg: '#fef3c7' },
  voluntary: { label: '자율 권고', color: '#334155', bg: '#e2e8f0' }
};
const STAGE_KO = [['now', '즉시'], ['3m', '3개월 내'], ['6m', '6개월 이후']] as const;
const ROLE_KO: Record<string, string> = { dev: '개발', admin: '운영·관리', sales: '영업' };
const FEATURE_KO: Record<string, string> = { sbom: 'SBOM', vex: 'VEX', sign: '서명', notify: '취약점 통보', report: '규제 보고서', none: '지원 범위 밖' };

function LawSection({ x, audience }: { x: RegLawSection; audience: string }) {
  const a = x.analysis;
  const d = DUTY_KO[a.duty] || DUTY_KO.voluntary;
  const roles = (['dev', 'admin', 'sales'] as const).filter((r) => a.plans[r]?.length);
  const sales = audience === 'sales';
  return (
    <div className="mb-6">
      <div className="avoid" style={{ breakAfter: 'avoid' }}>
        <div className="flex flex-wrap items-baseline gap-2">
          <h3 className="text-[15px] font-bold" style={{ color: '#0b1f3a' }}>{x.name}</h3>
          <span className="rounded px-1.5 text-[10px] font-semibold" style={{ background: '#e0f2fe', color: '#075985' }}>{a.nature}</span>
          <span className="rounded px-1.5 text-[10px] font-semibold" style={{ background: d.bg, color: d.color }}>{d.label}</span>
          {!a.verified && <span className="text-[10px] text-amber-700">◆ 분석 원문 대조 필요</span>}
          {a.origin === 'ai' && <span className="text-[10px] text-violet-700">AI 초안 채택</span>}
        </div>
        {a.dutyNote && <p className="mt-1 text-[11.5px] leading-relaxed text-slate-700">{a.dutyNote}</p>}
      </div>
      <div className="avoid mt-2 grid grid-cols-[1.3fr_1fr] gap-4 text-[11px]">
        <div>
          <div className="mb-1 font-semibold text-slate-600">적용 여부 판단</div>
          {a.questions.map((q, i) => (
            <div key={i} className="flex gap-2 border-b border-dashed border-slate-200 py-0.5"><span className="flex-1">{q}</span><span className="whitespace-nowrap text-slate-400">☐ 예 ☐ 아니오</span></div>
          ))}
        </div>
        <div>
          <div className="mb-1 font-semibold text-slate-600">의무 주체</div>
          <ul className="list-disc pl-4">{a.subjects.map((s, i) => <li key={i}>{s}</li>)}</ul>
          <div className="mb-1 mt-2 font-semibold text-slate-600">위반 시 제재·불이익</div>
          <p className="leading-snug">{a.sanctions}</p>
        </div>
      </div>
      {a.articles.length > 0 && (
        <table className="mt-2 w-full border-collapse text-[10.5px] leading-snug">
          <thead><tr style={{ background: '#f1f5f9' }} className="text-left text-slate-600"><th className="w-[36%] px-1.5 py-1">근거 조문</th><th className="px-1.5 py-1">요지</th></tr></thead>
          <tbody>
            {a.articles.map((r, i) => (
              <tr key={i} className="border-b border-slate-200 align-top">
                <td className="px-1.5 py-1"><b>{r.law}</b> {r.article || ''}{r.title ? ` (${r.title})` : ''}
                  {(r.check || !r.article) && <span className="ml-1 text-[10px] font-semibold text-amber-700">확인 필요</span>}
                  {r.url && <div className="break-all text-[9px] text-sky-700">{r.url}</div>}
                </td>
                <td className="px-1.5 py-1 text-slate-700">{r.gist}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {roles.length > 0 && (
        <table className="mt-2 w-full border-collapse text-[10.5px] leading-snug">
          <thead><tr style={{ background: '#f1f5f9' }} className="text-left text-slate-600"><th className="w-20 px-1.5 py-1">대응 방안</th>{STAGE_KO.map(([k, l]) => <th key={k} className="px-1.5 py-1">{l}</th>)}</tr></thead>
          <tbody>
            {roles.map((r) => (
              <tr key={r} className="border-b border-slate-200 align-top">
                <td className="px-1.5 py-1 font-semibold">{ROLE_KO[r]}</td>
                {STAGE_KO.map(([k]) => <td key={k} className="px-1.5 py-1">{(a.plans[r] || []).filter((s) => s.stage === k).map((s, i) => <div key={i}>☐ {s.do}</div>)}</td>)}
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="avoid mt-2 grid grid-cols-2 gap-4 text-[10.5px]">
        {!sales && a.evidence.length > 0 && <div><div className="mb-0.5 font-semibold text-slate-600">필요 증빙</div><ul className="list-disc pl-4">{a.evidence.map((e, i) => <li key={i}>{e}</li>)}</ul></div>}
        {a.trustlink.length > 0 && <div><div className="mb-0.5 font-semibold text-slate-600">TrustLink 대응</div>{a.trustlink.map((m, i) => <div key={i}><b className="text-slate-500">{FEATURE_KO[m.feature] || m.feature}</b> {m.how}</div>)}</div>}
        {!!a.talking?.length && <div><div className="mb-0.5 font-semibold text-slate-600">영업 설명 포인트</div><ul className="list-disc pl-4">{a.talking.map((e, i) => <li key={i}>{e}</li>)}</ul></div>}
        {!!a.checks?.length && <div><div className="mb-0.5 font-semibold text-slate-600">확인 필요 사항</div><ul className="list-disc pl-4">{a.checks.map((e, i) => <li key={i}>{e}</li>)}</ul></div>}
      </div>
    </div>
  );
}

export default function RegReportPrint() {
  const { id = '' } = useParams();
  const [rep, setRep] = useState<RegReport | null>(null);
  const [err, setErr] = useState('');
  useEffect(() => {
    let t: ReturnType<typeof setTimeout>;
    const load = () => adminRegReport(id).then((r) => {
      setRep(r);
      // 브라우저 'PDF 로 저장' 기본 파일 이름 = 문서 제목(언어·작성일·판 포함)
      document.title = r.fileName || `TrustLink_Report_${r.created.slice(0, 10)}`;
      if (r.state === 'running') t = setTimeout(load, 3000);
    }).catch((e) => {
      if (e instanceof ApiError && e.status === 401) { bffLogin(window.location.pathname); return; }
      setErr(String(e));
    });
    load();
    return () => clearTimeout(t);
  }, [id]);
  // 서버 PDF 변환(Gotenberg)용 준비 신호: 내용·AI 요약이 다 그려지고 글꼴까지 읽힌 뒤
  useEffect(() => {
    if (!rep || rep.state === 'running') return;
    document.fonts.ready.then(() => requestAnimationFrame(() => { (window as unknown as { __tlReady?: boolean }).__tlReady = true; }));
  }, [rep]);
  if (err) return <div className="p-10 text-red-700">{err}</div>;
  if (!rep) return <div className="p-10 text-slate-500">…</div>;

  const t: Tx = rep.lang === 'en' ? TX.en : TX.ko;
  const RN = rep.regionNames || {};
  const rn = (r: string) => RN[r] || r;
  const kdate = (d: string) => fdate(d, t.locale);
  const product = rep.repo ? `${rep.repo} : ${rep.tag}` : t.allProducts;
  const upcoming = rep.timeline.filter((t) => t.future).slice(0, 8);
  const recent = rep.timeline.filter((t) => !t.future && dday(t.date) >= -400).reverse().slice(0, Math.max(3, 8 - upcoming.length));
  const st = ['met', 'partial', 'unmet', 'manual'].map((k) => ({ k, n: rep.totals[k] || 0 }));
  const stTotal = st.reduce((a, b) => a + b.n, 0) || 1;
  const byRegion = Array.from(new Set(rep.regs.map((g) => g.region)));
  const rank = (b: string) => (isMand(b) ? 0 : isProc(b) ? 1 : 2);
  const regsOf = (r: string) => rep.regs.filter((g) => g.region === r)
    .sort((a, b) => rank(a.binding) - rank(b.binding) || (a.next?.date || '9999').localeCompare(b.next?.date || '9999'));
  const checklist = rep.regs.flatMap((g) => g.reqs.map((q) => ({ g, q })))
    .filter((x) => rep.audience === 'all' || x.q.action)
    .sort((a, b) => rank(a.g.binding) - rank(b.g.binding) || (a.g.next?.date || '9999').localeCompare(b.g.next?.date || '9999'));
  const footer = `TrustLink SCS · ${rep.docNo || rep.id} · ${t.footerFor(rep.audienceKo)}`;

  return (
    <div className="report bg-slate-100 text-slate-800 print:bg-white">
      <style>{`
        @page { size: A4; margin: 16mm 15mm 18mm 15mm;
          @bottom-left { content: "${footer.replace(/"/g, '')}"; font-size: 8pt; color: #94a3b8; }
          @bottom-right { content: counter(page) " / " counter(pages); font-size: 8pt; color: #94a3b8; } }
        @page :first { margin: 0; @bottom-left { content: none; } @bottom-right { content: none; } }
        @media print {
          .no-print { display: none !important; }
          .sheet { box-shadow: none !important; margin: 0 !important; width: auto !important; padding: 0 !important; }
          .cover { width: 210mm !important; height: 297mm !important; margin: 0 !important; }
          .pb { break-before: page; }
          .avoid { break-inside: avoid; }
          thead { display: table-header-group; }
          tr { break-inside: avoid; }
          body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
        }
        .report { font-family: Pretendard, -apple-system, "Apple SD Gothic Neo", sans-serif; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      `}</style>

      <div className="no-print sticky top-0 z-10 flex items-center gap-3 border-b bg-white/95 px-6 py-2 text-sm backdrop-blur">
        <ShieldCheck size={18} className="text-teal-600" />
        <b>{rep.title}</b><span className="text-slate-500">{t.barFor(rep.audienceKo)} · {rep.docNo || rep.id}</span>
        {rep.state === 'running' && <span className="flex items-center gap-1 text-violet-700"><Sparkles size={14} /> {t.aiRunning}</span>}
        <div className="flex-1" />
        <span className="text-xs text-slate-500">{t.printHint}</span>
        <button onClick={() => window.print()} className="flex items-center gap-1.5 rounded-md bg-slate-900 px-3 py-1.5 text-white hover:bg-slate-700">
          <Printer size={15} /> {t.save}
        </button>
      </div>

      {/* ── 표지 ── */}
      <section className="cover sheet relative mx-auto my-6 flex flex-col overflow-hidden bg-white shadow-xl" style={{ width: '210mm', height: '297mm' }}>
        <div className="relative flex-[0_0_60%] overflow-hidden px-[18mm] pt-[16mm] text-white" style={{ background: 'linear-gradient(150deg,#081a33 0%,#0b2a52 55%,#0e3b6b 100%)' }}>
          <Pattern />
          <div className="relative flex items-center gap-2">
            <span className="flex h-8 w-8 items-center justify-center rounded-md" style={{ background: 'linear-gradient(135deg,#14b8a6,#0ea5e9)' }}><ShieldCheck size={18} /></span>
            <span className="text-lg font-bold tracking-tight">TrustLink <span className="font-normal text-sky-200">SCS</span></span>
          </div>
          <div className="relative mt-[38mm]">
            <div className="text-[11px] font-semibold tracking-[0.25em] text-teal-300">SOFTWARE SUPPLY CHAIN · REGULATORY BRIEF</div>
            <h1 className={`mt-3 font-extrabold leading-tight ${rep.lang === 'en' ? 'text-[30px]' : 'text-[34px]'}`}>{t.coverTitle}</h1>
            <div className="mt-3 text-[15px] text-sky-100">{rep.regions.map(rn).join(' · ')}</div>
            <div className="mt-6 flex flex-wrap items-center gap-2">
              <span className="inline-flex items-center gap-2 rounded-full border border-white/25 bg-white/10 px-4 py-1.5 text-sm font-semibold">
                <span className="h-2 w-2 rounded-full bg-teal-300" /> {t.checkFor(rep.audienceKo)}
              </span>
              <span className="rounded-full bg-teal-400/90 px-3 py-1.5 font-mono text-xs font-bold text-slate-900">{rep.created.slice(0, 7).replace('-', '.')} · v{rep.edition || 1}</span>
            </div>
          </div>
        </div>
        <div className="h-1.5" style={{ background: 'linear-gradient(90deg,#14b8a6,#0ea5e9 45%,#f59e0b)' }} />
        <div className="flex flex-1 flex-col px-[18mm] py-[12mm]">
          <div className="grid grid-cols-2 gap-x-10 gap-y-5 text-sm">
            {[
              [t.product, product], [t.date, kdate(rep.created)],
              [t.regions, rep.regions.map(rn).join(', ')], [t.author, rep.createdBy || '—'],
              [t.docNo, rep.docNo || rep.id], [t.edition, t.editionV(rep.edition || 1, rep.prevDate ? rep.prevDate.slice(0, 10) : undefined)],
              [t.catalog, t.catalogV(rep.catalogVersion, rep.builtinVersion)]
            ].map(([k, v]) => (
              <div key={k}><div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">{k}</div><div className="mt-0.5 font-medium text-slate-800">{v}</div></div>
            ))}
          </div>
          <div className="mt-6 grid grid-cols-4 gap-3">
            {[
              [t.kpi[0], rep.totals.regs || 0], [t.kpi[1], rep.totals.mandatory || 0],
              [t.kpi[2], rep.totals.reqs || 0], [t.kpi[3], rep.unverified]
            ].map(([k, v]) => (
              <div key={k as string} className="rounded-lg border border-slate-200 px-3 py-2.5">
                <div className="text-2xl font-extrabold" style={{ color: '#0b1f3a' }}>{v}</div>
                <div className="text-[11px] text-slate-500">{k}</div>
              </div>
            ))}
          </div>
          <div className="flex-1" />
          <div className="flex items-end justify-between border-t pt-3 text-[10px] text-slate-400">
            <span>{t.notLegal}</span>
            <span>Generated by TrustLink SCS</span>
          </div>
        </div>
      </section>

      {/* ── 본문 ── */}
      <div className="sheet mx-auto my-6 bg-white px-[15mm] py-[14mm] shadow-xl" style={{ width: '210mm' }}>
        <SectionHead n="01" title={t.s1} sub={t.s1sub(rep.audienceKo, rep.totals.regs || 0, rep.totals.reqs || 0)} />

        {rep.summary ? (
          <div className="avoid mb-5 rounded-lg border-l-4 bg-violet-50/60 p-4" style={{ borderColor: '#7c3aed' }}>
            <div className="mb-1 flex items-center gap-1.5 text-[10px] font-semibold tracking-wider text-violet-700">
              <Sparkles size={12} /> {t.aiDraft(rep.aiMeta?.model)}
            </div>
            <p className="text-[15px] font-bold leading-snug text-slate-900">{clean(rep.summary.headline)}</p>
            <div className="mt-3 grid grid-cols-2 gap-4 text-[12px] leading-relaxed">
              <div><div className="mb-1 font-semibold text-slate-600">{t.points}</div><ul className="list-disc space-y-0.5 pl-4">{rep.summary.points.map((p, i) => <li key={i}>{clean(p)}</li>)}</ul></div>
              <div><div className="mb-1 font-semibold text-slate-600">{t.priority}</div><ol className="list-decimal space-y-0.5 pl-4">{rep.summary.priority.map((p, i) => <li key={i}>{clean(p)}</li>)}</ol></div>
            </div>
          </div>
        ) : rep.state === 'running' ? (
          <div className="no-print mb-5 rounded-lg border border-dashed border-violet-300 p-4 text-sm text-violet-700">{t.aiWriting}</div>
        ) : rep.aiError ? (
          <div className="mb-5 rounded-lg bg-amber-50 p-3 text-xs text-amber-800">{t.aiFail}{rep.aiError}</div>
        ) : null}

        {(rep.edition || 1) > 1 && rep.prevDate && (
          <div className="avoid mb-5 rounded-lg border border-sky-200 bg-sky-50/60 p-3">
            <div className="mb-1.5 text-[12px] font-semibold text-sky-900">
              {rep.changes?.length ? t.changes(rep.changes.length, rep.prevDate.slice(0, 10)) : t.noChanges(rep.prevDate.slice(0, 10))}
            </div>
            {!!rep.changes?.length && (
              <ul className="grid grid-cols-2 gap-x-4 gap-y-0.5 text-[11px] leading-snug">
                {rep.changes.slice(0, 16).map((c, i) => (
                  <li key={i}><span className="mr-1 rounded bg-white px-1 text-[10px] font-semibold text-sky-800">{t.chKind[c.kind]}</span><b>{c.reg}</b>{c.detail ? ` — ${c.detail}` : ''}</li>
                ))}
              </ul>
            )}
          </div>
        )}

        <div className="avoid mb-5 grid grid-cols-[1.1fr_1fr] gap-5">
          <div>
            <div className="mb-2 text-[12px] font-semibold text-slate-600">{t.upcoming}</div>
            {upcoming.length === 0 && <p className="text-xs text-slate-400">{t.noUpcoming}</p>}
            <ol className="relative border-l-2 border-slate-200 pl-4">
              {upcoming.map((u, i) => {
                const d = dday(u.date);
                return (
                  <li key={i} className="relative mb-2.5">
                    <span className="absolute -left-[21px] top-1 h-2.5 w-2.5 rounded-full border-2 border-white" style={{ background: d <= 90 ? '#dc2626' : d <= 365 ? '#f59e0b' : '#14b8a6' }} />
                    <div className="flex items-center gap-2 text-[11px]">
                      <span className="font-mono font-semibold text-slate-700">{u.date}</span>
                      <span className="rounded px-1 font-mono text-[10px] font-bold" style={{ color: d <= 90 ? '#b91c1c' : '#475569', background: d <= 90 ? '#fee2e2' : '#f1f5f9' }}>D-{d}</span>
                      <Chip r={u.region} />
                    </div>
                    <div className="text-[12px] leading-snug"><b>{u.reg}</b> — {u.label}</div>
                  </li>
                );
              })}
            </ol>
            {recent.length > 0 && (
              <>
                <div className="mb-2 mt-3 text-[12px] font-semibold text-slate-600">{t.recent}</div>
                <ol className="relative border-l-2 border-slate-200 pl-4">
                  {recent.map((u, i) => (
                    <li key={i} className="relative mb-2">
                      <span className="absolute -left-[21px] top-1 h-2.5 w-2.5 rounded-full border-2 border-white bg-slate-400" />
                      <div className="flex items-center gap-2 text-[11px]"><span className="font-mono text-slate-500">{u.date}</span><Chip r={u.region} /></div>
                      <div className="text-[11.5px] leading-snug text-slate-600"><b>{u.reg}</b> — {u.label}</div>
                    </li>
                  ))}
                </ol>
              </>
            )}
          </div>
          <div>
            <div className="mb-2 text-[12px] font-semibold text-slate-600">{t.byRegion}</div>
            {byRegion.map((r) => {
              const regs = rep.regs.filter((g) => g.region === r);
              const max = Math.max(...byRegion.map((x) => rep.regs.filter((g) => g.region === x).length));
              return (
                <div key={r} className="mb-1.5 flex items-center gap-2 text-[11px]">
                  <span className="w-24 truncate">{rn(r)}</span>
                  <div className="h-3 flex-1 rounded-sm bg-slate-100">
                    <div className="h-3 rounded-sm" style={{ width: `${(regs.length / max) * 100}%`, background: REGION_HUE[r] || '#334155', opacity: 0.8 }} />
                  </div>
                  <span className="w-24 whitespace-nowrap text-right font-mono">{t.regCount(regs.length, regs.filter((g) => isMand(g.binding)).length)}</span>
                </div>
              );
            })}
            {rep.repo && (
              <>
                <div className="mb-1.5 mt-4 text-[12px] font-semibold text-slate-600">{t.prodStatus} ({rep.repo}:{rep.tag})</div>
                <div className="flex h-4 overflow-hidden rounded">
                  {st.map((x) => x.n > 0 && <div key={x.k} style={{ width: `${(x.n / stTotal) * 100}%`, background: ST_COLOR[x.k].color }} />)}
                </div>
                <div className="mt-1 flex flex-wrap gap-3 text-[10px]">
                  {st.map((x) => <span key={x.k}><span className="mr-1 inline-block h-2 w-2 rounded-sm" style={{ background: ST_COLOR[x.k].color }} />{t.st[x.k]} {x.n}</span>)}
                </div>
              </>
            )}
          </div>
        </div>

        <div className="pb" />
        <SectionHead n="02" title={t.s2} sub={t.s2sub} />
        {byRegion.map((r) => (
          <div key={r} className="mb-6">
            <div className="mb-3 flex items-center gap-2 rounded-md px-3 py-1.5 text-white" style={{ background: REGION_HUE[r] || '#334155', breakAfter: 'avoid' }}>
              <span className="font-mono text-xs font-bold">{r}</span><span className="text-sm font-semibold">{rn(r)}</span>
              <span className="ml-auto text-[11px] opacity-80">{t.nRegs(rep.regs.filter((g) => g.region === r).length)}</span>
            </div>
            {regsOf(r).map((g) => (
              <div key={g.id} className="mb-5">
                <div className="avoid" style={{ breakAfter: 'avoid' }}>
                  <div className="flex flex-wrap items-baseline gap-2">
                    <h3 className="text-[15px] font-bold" style={{ color: '#0b1f3a' }}>{g.nameKo}</h3>
                    <span className="rounded px-1.5 text-[10px] font-semibold" style={{ background: isMand(g.binding) ? '#fee2e2' : isProc(g.binding) ? '#fef3c7' : '#e2e8f0', color: isMand(g.binding) ? '#991b1b' : isProc(g.binding) ? '#92400e' : '#334155' }}>{g.binding}</span>
                    <span className="text-[10px] text-slate-500">{g.status}</span>
                    {!g.verified && <span className="text-[10px] text-amber-700">{t.verifyNeeded}</span>}
                    {g.untranslated && <span className="text-[10px] text-slate-400">({t.untranslated})</span>}
                  </div>
                  <div className="text-[10px] italic text-slate-500">{g.name !== g.nameKo ? `${g.name} — ` : ''}{g.authority}</div>
                  <p className="mt-1 text-[11.5px] leading-relaxed text-slate-700">{g.scope}</p>
                  {g.next && <p className="mt-0.5 text-[11px] font-medium text-amber-700">{t.next} {g.next.date} · {g.next.label} (D-{dday(g.next.date)})</p>}
                </div>
                <table className="mt-2 w-full border-collapse text-[10.5px] leading-snug">
                  <thead>
                    <tr style={{ background: '#f1f5f9' }} className="text-left text-slate-600">
                      <th className="w-6 px-1.5 py-1">☐</th><th className="w-[18%] px-1.5 py-1">{t.thClause}</th><th className="px-1.5 py-1">{t.thReq}</th>
                      <th className="w-[36%] px-1.5 py-1">{rep.audience === 'all' ? t.thActAll : t.thAct(rep.audienceKo)}</th>
                      {rep.repo && <th className="w-14 px-1.5 py-1">{t.thSt}</th>}
                    </tr>
                  </thead>
                  <tbody>
                    {g.reqs.map((q) => (
                      <tr key={q.id} className="border-b border-slate-200 align-top">
                        <td className="px-1.5 py-1.5 text-slate-400">☐</td>
                        <td className="px-1.5 py-1.5 font-mono text-[10px] text-slate-600">{q.clause}</td>
                        <td className="px-1.5 py-1.5"><b>{q.title}</b><div className="text-slate-500">{q.text}</div></td>
                        <td className="px-1.5 py-1.5"><ActionCell q={q} audience={rep.audience} t={t} /></td>
                        {rep.repo && <td className="px-1.5 py-1.5"><StatusPill s={q.status} t={t} /></td>}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ))}
          </div>
        ))}

        <div className="pb" />
        <SectionHead n="03" title={t.s3(rep.audienceKo)} sub={t.s3sub} />
        <div className="columns-1 text-[11.5px]">
          {checklist.map(({ g, q }, i) => (
            <div key={i} className="avoid flex gap-2 border-b border-dashed border-slate-200 py-1.5">
              <span className="mt-0.5 inline-block h-3.5 w-3.5 flex-none rounded-sm border-[1.5px] border-slate-400" />
              <div className="flex-1">
                <div className="leading-snug">{rep.audience === 'all' ? q.title : q.action}</div>
                <div className="mt-0.5 flex flex-wrap items-center gap-1.5 text-[10px] text-slate-500">
                  <Chip r={g.region} /><span>{g.nameKo}</span><span className="font-mono">{q.clause}</span>
                  {g.next && <span className="text-amber-700">· {g.next.date}</span>}
                  {rep.repo && <StatusPill s={q.status} t={t} />}
                </div>
              </div>
            </div>
          ))}
        </div>

        {!!rep.law?.length && (
          <>
            <div className="pb" />
            <SectionHead n="04" title="국내 법규 분석 및 대응 방안"
              sub={rep.audience === 'sales' ? '법적 성격·적용 여부·제재와 영업 설명 포인트 — 법률 자문이 아니며 원문 대조 필요' : '법적 성격·근거 조문·제재와 역할별 단계 대응 — 법률 자문이 아니며 원문 대조 필요'} />
            {rep.law.map((x) => <LawSection key={x.regId} x={x} audience={rep.audience} />)}
          </>
        )}

        {rep.evidence && rep.evidence.length > 0 && (
          <>
            <div className="pb" />
            <SectionHead n={rep.law?.length ? '05' : '04'} title={t.s4} sub={t.s4sub(`${rep.repo}:${rep.tag}`)} />
            <table className="w-full border-collapse text-[11px]">
              <thead><tr style={{ background: '#f1f5f9' }} className="text-left text-slate-600"><th className="px-2 py-1">{t.thCheck}</th><th className="w-16 px-2 py-1">{t.thRes}</th><th className="px-2 py-1">{t.thVal}</th><th className="px-2 py-1">{t.thFix}</th></tr></thead>
              <tbody>
                {rep.evidence.map((e) => (
                  <tr key={e.id} className="border-b border-slate-200 align-top">
                    <td className="px-2 py-1.5 font-medium">{e.name}</td>
                    <td className="px-2 py-1.5 font-semibold" style={{ color: EV_COLOR[e.result] }}>{t.ev[e.result]}</td>
                    <td className="px-2 py-1.5 text-slate-600">{e.value}</td>
                    <td className="px-2 py-1.5 text-slate-600">{e.result !== 'pass' ? e.fix : ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}

        <div className="pb" />
        <SectionHead n={String(4 + (rep.evidence?.length ? 1 : 0) + (rep.law?.length ? 1 : 0)).padStart(2, '0')} title={t.s5} />
        <table className="w-full border-collapse text-[10.5px]">
          <thead><tr style={{ background: '#f1f5f9' }} className="text-left text-slate-600"><th className="w-10 px-2 py-1">{t.thRegion}</th><th className="px-2 py-1">{t.thReg}</th><th className="px-2 py-1">{t.thSrc}</th><th className="w-24 px-2 py-1">{t.thVerified}</th></tr></thead>
          <tbody>
            {rep.regs.map((g) => (
              <tr key={g.id} className="border-b border-slate-200 align-top">
                <td className="px-2 py-1"><Chip r={g.region} /></td>
                <td className="px-2 py-1">{g.nameKo}{g.name !== g.nameKo && <div className="text-slate-400">{g.name}</div>}</td>
                <td className="break-all px-2 py-1 text-sky-700">{g.sources.map((s) => <div key={s.url}>{s.url}</div>)}</td>
                <td className="px-2 py-1">{g.verified ? <span className="text-emerald-700">{t.verified}{g.verifiedAt ? ` ${g.verifiedAt.slice(0, 10)}` : ''}</span> : <span className="text-amber-700">{t.toVerify}</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="avoid mt-6 grid grid-cols-3 gap-4 text-[11px]">
          {t.sign.map((k) => (
            <div key={k} className="rounded-md border border-slate-300 p-3">
              <div className="font-semibold text-slate-600">{k}</div>
              <div className="mt-6 border-t border-slate-300 pt-1 text-[10px] text-slate-400">{t.signLine}</div>
            </div>
          ))}
        </div>
        <p className="mt-5 text-[10px] leading-relaxed text-slate-400">
          {rep.disclaimer}{t.tail(rep.catalogVersion, rep.builtinVersion, rep.id)}
        </p>
      </div>
    </div>
  );
}
