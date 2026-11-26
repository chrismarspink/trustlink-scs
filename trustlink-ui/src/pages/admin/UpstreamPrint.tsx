import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { Printer, ShieldCheck } from 'lucide-react';
import { adminUpstreamReport, ApiError, bffLogin, type UpReport, type UpRating, type UpFlag } from '@/lib/api';

// 공개 저장소(상류) 분석 인쇄용 페이지(A4) — 브라우저 '인쇄 → PDF 로 저장'. CRA 제3자 구성요소 실사 기록으로 보관한다.

const UP_RATING: Record<UpRating, { label: string; color: string }> = {
  risk: { label: '위험', color: '#b91c1c' }, warn: { label: '주의', color: '#b45309' },
  ok: { label: '양호', color: '#047857' }, unknown: { label: '미확인', color: '#64748b' }
};
const GH_STATE: Record<string, string> = { 'not-found': 'GitHub 저장소 없음', 'rate-limited': 'GitHub 한도 — 미조회', skipped: 'GitHub 조회 상한 — 미조회', error: 'GitHub 조회 오류' };
const upDate = (t?: string) => (t ? t.slice(0, 10) : '—');
function upAge(t?: string) {
  if (!t) return '';
  const d = (Date.now() - new Date(t).getTime()) / 86400000;
  return d < 31 ? `${Math.max(0, Math.round(d))}일 전` : d < 365 ? `${Math.round(d / 30)}개월 전` : `${(d / 365).toFixed(1)}년 전`;
}

const Pill = ({ r }: { r: UpRating }) => (
  <span style={{ color: UP_RATING[r].color, borderColor: UP_RATING[r].color }} className="inline-block whitespace-nowrap rounded border px-1.5 text-[10px] font-semibold">
    {UP_RATING[r].label}
  </span>
);

function Flags({ items }: { items?: UpFlag[] }) {
  if (!items?.length) return <p className="text-[11px] text-slate-500">해당 없음</p>;
  return (
    <table className="w-full border-collapse text-[10px]">
      <thead><tr className="border-b-2 border-slate-300 text-left text-slate-600"><th className="py-1 pr-2">구성요소</th><th className="pr-2">저장소</th><th className="pr-2">등급</th><th>사유</th></tr></thead>
      <tbody>
        {items.map((f, i) => (
          <tr key={i} className="border-b border-slate-200 align-top">
            <td className="py-1 pr-2 font-medium">{f.name} <span className="font-mono text-slate-500">{f.version}</span></td>
            <td className="break-all pr-2">{f.repo || '—'}</td>
            <td className="pr-2"><Pill r={f.rating} /></td>
            <td>{f.reasons.join(' · ')}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function UpstreamPrint() {
  const { id = '' } = useParams();
  const [rep, setRep] = useState<UpReport | null>(null);
  const [err, setErr] = useState('');
  useEffect(() => {
    let t: ReturnType<typeof setTimeout>;
    const load = () => adminUpstreamReport(id).then((r) => {
      setRep(r);
      const target = r.kind === 'repo' ? (r.target || '').replace(/^https:\/\/github\.com\//, '') : `${r.repo}_${r.tag}`;
      // 브라우저 'PDF 로 저장' 기본 파일 이름
      document.title = `TrustLink_상류점검_${target.replace(/[/:\s]+/g, '_')}_${(r.finished || r.created).slice(0, 10)}`;
      if (r.state === 'running') t = setTimeout(load, 3000);
    }).catch((e) => {
      if (e instanceof ApiError && e.status === 401) { bffLogin(window.location.pathname); return; }
      setErr(String(e));
    });
    load();
    return () => clearTimeout(t);
  }, [id]);
  if (err) return <div className="p-10 text-red-700">{err}</div>;
  if (!rep) return <div className="p-10 text-slate-500">…</div>;

  const c = rep.counts || { risk: 0, warn: 0, ok: 0, unknown: 0 };
  const title = rep.kind === 'repo' ? rep.target : `${rep.repo} : ${rep.tag}`;
  const order: Record<UpRating, number> = { risk: 0, warn: 1, unknown: 2, ok: 3 };
  const comps = [...rep.comps].sort((a, b) => order[a.rating] - order[b.rating] || a.name.localeCompare(b.name));
  const repo = rep.kind === 'repo' ? Object.values(rep.repos)[0] : undefined;

  return (
    <div className="report min-h-screen bg-slate-100 text-slate-800 print:bg-white">
      <style>{`
        @page { size: A4; margin: 15mm 13mm 16mm 13mm;
          @bottom-left { content: "TrustLink SCS · 공개 저장소 분석 · ${rep.id}"; font-size: 8pt; color: #94a3b8; }
          @bottom-right { content: counter(page) " / " counter(pages); font-size: 8pt; color: #94a3b8; } }
        @media print {
          .no-print { display: none !important; }
          .sheet { box-shadow: none !important; margin: 0 !important; width: auto !important; padding: 0 !important; }
          thead { display: table-header-group; }
          tr, .avoid { break-inside: avoid; }
        }
        .report { font-family: Pretendard, -apple-system, "Apple SD Gothic Neo", sans-serif; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      `}</style>

      <div className="no-print sticky top-0 z-10 flex items-center gap-3 border-b bg-white/95 px-6 py-2 text-sm backdrop-blur">
        <ShieldCheck size={18} className="text-teal-600" />
        <b>공개 저장소(상류) 분석</b><span className="text-slate-500">{title}</span>
        {rep.state === 'running' && <span className="text-violet-700">분석 중… {rep.progress}</span>}
        <div className="flex-1" />
        <span className="text-xs text-slate-500">인쇄 대화상자에서 ‘PDF로 저장’, 배경 그래픽 켜기</span>
        <button onClick={() => window.print()} className="flex items-center gap-1.5 rounded-md bg-slate-900 px-3 py-1.5 text-white hover:bg-slate-700">
          <Printer size={15} /> PDF 저장
        </button>
      </div>

      <div className="sheet mx-auto my-6 w-[210mm] bg-white p-[13mm] shadow">
        <div className="border-b-2 border-slate-800 pb-3">
          <div className="text-[11px] font-semibold tracking-wide text-teal-700">제3자 구성요소 실사(Due Diligence) 기록</div>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight">공개 저장소(상류) 건강도 점검</h1>
          <div className="mt-2 grid grid-cols-2 gap-x-6 gap-y-0.5 text-[11px] text-slate-600">
            <div>대상: <b className="text-slate-800">{title}</b></div>
            <div>보고서 ID: {rep.id}</div>
            <div>작성: {rep.createdBy} · {upDate(rep.finished || rep.created)}</div>
            <div>{rep.sbom ? `SBOM: ${rep.sbom}` : '단건 저장소 점검'}</div>
            <div>자료: deps.dev(OpenSSF Scorecard) · GitHub 공개 API</div>
            <div>GitHub: {rep.rate?.auth ? '토큰 사용' : '토큰 없음'}{rep.rate?.hit ? ' · 한도 도달(일부 미조회)' : ''}</div>
          </div>
        </div>

        {rep.error && <p className="mt-3 rounded bg-red-50 p-2 text-[11px] text-red-700">{rep.error}</p>}
        {rep.notes?.map((n, i) => <p key={i} className="mt-2 rounded bg-amber-50 p-2 text-[11px] text-amber-800">{n}</p>)}

        {rep.summary && (
          <section className="avoid mt-4 rounded border border-violet-200 bg-violet-50/40 p-3 text-[11.5px]">
            <div className="mb-1 text-[10px] text-violet-700">AI 요약 초안 · {rep.aiMeta?.model} · 판정은 규칙 결과, 사람 검토 필요</div>
            <p className="font-semibold">{rep.summary.headline}</p>
            <ul className="mt-1 list-disc pl-5">{rep.summary.points.map((p, i) => <li key={i}>{p}</li>)}</ul>
            {rep.summary.actions.length > 0 && <><div className="mt-2 font-semibold">먼저 할 일</div><ol className="list-decimal pl-5">{rep.summary.actions.map((p, i) => <li key={i}>{p}</li>)}</ol></>}
          </section>
        )}

        {rep.kind === 'product' && (
          <>
            <div className="mt-4 grid grid-cols-5 gap-2 text-center">
              {([['구성요소', rep.comps.length, '#0f172a'], ['위험', c.risk, UP_RATING.risk.color], ['주의', c.warn, UP_RATING.warn.color],
                ['양호', c.ok, UP_RATING.ok.color], ['미확인', c.unknown, UP_RATING.unknown.color]] as const).map(([k, v, col]) => (
                <div key={k} className="rounded border border-slate-200 py-2">
                  <div className="text-[10px] text-slate-500">{k}</div>
                  <div className="text-xl font-bold" style={{ color: col }}>{v}</div>
                </div>
              ))}
            </div>
            <h2 className="mt-5 mb-1 text-sm font-bold">1. 주요 위험</h2>
            <Flags items={rep.top} />
            <h2 className="mt-5 mb-1 text-sm font-bold">2. 교체·포크 검토 대상 <span className="text-[10px] font-normal text-slate-500">보관·비활성·2년 이상 커밋 없음·사용 중단 표시</span></h2>
            <Flags items={rep.replace} />
            <h2 className="mt-5 mb-1 text-sm font-bold">3. 구성요소별 상류 저장소 ({comps.length}개)</h2>
            <table className="w-full border-collapse text-[9px]">
              <thead>
                <tr className="border-b-2 border-slate-300 text-left text-slate-600">
                  <th className="py-1 pr-1">구성요소 · 버전</th><th className="pr-1">상류 저장소</th><th className="pr-1">Scorecard</th><th className="pr-1">마지막 커밋</th>
                  <th className="pr-1">최근 릴리스</th><th className="pr-1">보안 정책</th><th className="pr-1">권고(이 버전)</th><th>등급 · 사유</th>
                </tr>
              </thead>
              <tbody>
                {comps.map((x, i) => {
                  const r = x.repo ? rep.repos[x.repo] : undefined;
                  return (
                    <tr key={i} className="border-b border-slate-200 align-top">
                      <td className="max-w-[34mm] break-all py-0.5 pr-1"><b>{x.name}</b> <span className="font-mono text-slate-500">{x.version}</span></td>
                      <td className="max-w-[36mm] break-all pr-1">{x.repo || <span className="text-slate-400">{x.repoSrc}</span>}{r && GH_STATE[r.github] && <div className="text-slate-400">{GH_STATE[r.github]}</div>}</td>
                      <td className="pr-1">{r?.scorecard != null ? r.scorecard.toFixed(1) : '—'}</td>
                      <td className="whitespace-nowrap pr-1">{r?.pushedAt ? `${upDate(r.pushedAt)}` : '—'}</td>
                      <td className="whitespace-nowrap pr-1">{r?.release ? `${r.release} ${upDate(r.releaseAt)}` : '—'}</td>
                      <td className="pr-1">{r?.secPolicy === undefined ? '—' : r.secPolicy ? '있음' : '없음'}</td>
                      <td className="pr-1">{x.vulns?.length || 0}{x.vulnCritical ? ` (치명 ${x.vulnCritical})` : ''}</td>
                      <td><Pill r={x.rating} /> <span className="text-slate-600">{x.reasons?.join(' · ')}</span></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </>
        )}

        {repo && (
          <section className="avoid mt-4 text-[11.5px]">
            <h2 className="mb-1 text-sm font-bold">저장소 신호 — {repo.id} {repo.rating && <Pill r={repo.rating} />}</h2>
            {repo.reasons && repo.reasons.length > 0 && <ul className="mb-2 list-disc pl-5">{repo.reasons.map((x, i) => <li key={i}>{x}</li>)}</ul>}
            <table className="w-full border-collapse text-[10.5px]">
              <tbody>
                {([
                  ['OpenSSF Scorecard', repo.scorecard != null ? `${repo.scorecard.toFixed(1)} / 10 (${upDate(repo.scorecardDate)})` : '없음'],
                  ['보관·비활성', repo.archived || repo.disabled ? `${repo.archived ? '보관 ' : ''}${repo.disabled ? '비활성' : ''}` : '아니오'],
                  ['마지막 커밋(push)', repo.pushedAt ? `${upDate(repo.pushedAt)} (${upAge(repo.pushedAt)})` : '—'],
                  ['최근 릴리스', repo.release ? `${repo.release} · ${upDate(repo.releaseAt)}` : '—'],
                  ['라이선스', repo.license || '—'],
                  ['보안 정책(SECURITY.md)', repo.secPolicy === undefined ? '확인 못함' : repo.secPolicy ? '있음' : '없음'],
                  ['공개 보안 권고', repo.advisories != null ? `${repo.advisories}건 (치명 ${repo.advCritical || 0} · 높음 ${repo.advHigh || 0} · 패치 없는 치명 ${repo.advOpenCritical || 0})` : '—'],
                  ['Scorecard 주요 점검', Object.entries(repo.checks || {}).map(([k, v]) => `${k} ${v < 0 ? '–' : v}`).join(' · ') || '—'],
                  ['의존성 그래프(GitHub SBOM)', rep.depGraph ? (rep.depGraph.error || `패키지 ${rep.depGraph.packages}개 · ${Object.entries(rep.depGraph.ecosystems || {}).map(([k, v]) => `${k} ${v}`).join(' · ')}`) : '—']
                ] as const).map(([k, v]) => (
                  <tr key={k} className="border-b border-slate-200"><td className="w-48 py-1 text-slate-500">{k}</td><td>{v}</td></tr>
                ))}
              </tbody>
            </table>
          </section>
        )}

        <section className="avoid mt-6 border-t pt-3 text-[10px] text-slate-500">
          <p>판정 기준 — 위험: 보관·비활성, 2년 이상 커밋 없음, Scorecard 3 미만, 패치 없는 치명 권고, 이 버전에 치명(CVSS 9+) 권고 ·
            주의: 1년 이상 커밋 없음, Scorecard 5 미만, 보안 정책 없음, 위험한 워크플로, 사용 중단 표시, 이 버전에 높음(CVSS 7+) 권고 ·
            미확인: 상류 저장소를 찾지 못함.</p>
          <p className="mt-1">{rep.disclaimer}</p>
          <div className="mt-6 grid grid-cols-2 gap-8 text-slate-700">
            <div className="border-t border-slate-400 pt-1">검토자 / 일자</div>
            <div className="border-t border-slate-400 pt-1">승인자 / 일자</div>
          </div>
        </section>
      </div>
    </div>
  );
}
