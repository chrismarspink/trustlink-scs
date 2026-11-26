import { CompanyLogo } from '@/components/CompanyLogo';
import { useEffect, useState } from 'react';
import { Package, ShieldCheck, ShieldAlert, CalendarClock, Mail, ArrowUpCircle, ChevronDown, ChevronRight } from 'lucide-react';
import { myProducts, type MyInstall, type MyNotice, type MyUsage } from '@/lib/api';
import { Card, CardContent, Badge } from '@/components/ui/primitives';
import { SourceBadge } from '@/components/SourceBadge';
import { cn } from '@/lib/utils';

// 고객 전용 › 내 제품: 우리 고객사(로그인 계정의 고객사 그룹)에 등록된 제품·설치 버전과
// 그 버전의 취약점(VEX 판정)·권장 패치 버전·최근 보안 통지. 다른 고객사 정보는 서버가 주지 않는다.

const STATE: Record<string, { l: string; cls: string }> = {
  NOT_SET: { l: '분석 전', cls: 'bg-slate-100 text-slate-700' },
  IN_TRIAGE: { l: '조사 중', cls: 'bg-sky-100 text-sky-800' },
  EXPLOITABLE: { l: '영향 있음', cls: 'bg-red-100 text-red-800' },
  NOT_AFFECTED: { l: '영향 없음', cls: 'bg-emerald-100 text-emerald-800' },
  FALSE_POSITIVE: { l: '오탐', cls: 'bg-emerald-50 text-emerald-700' },
  RESOLVED: { l: '해결됨', cls: 'bg-emerald-50 text-emerald-700' }
};
const LIC: Record<string, string> = { perpetual: '영구', subscription: '구독', term: '기간제' };
const fmt = (t?: string) => (t ? new Date(t).toLocaleString('ko-KR') : '—');
const sevCls = (s: string) => (s === 'CRITICAL' ? 'bg-red-600 text-white' : s === 'HIGH' ? 'bg-orange-500 text-white' : s === 'MEDIUM' ? 'bg-amber-100 text-amber-800' : 'bg-slate-100 text-slate-700');
const daysLeft = (d?: string) => (d ? Math.ceil((new Date(d + 'T00:00:00+09:00').getTime() - Date.now()) / 86400000) : null);

function DDay({ days, label }: { days: number; label: string }) {
  const cls = days < 0 ? 'bg-red-600 text-white' : days <= 30 ? 'bg-amber-100 text-amber-800' : 'bg-slate-100 text-slate-600';
  return <span className={cn('inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-semibold', cls)}><CalendarClock size={11} />{label} {days < 0 ? `만료 D+${-days}` : `D-${days}`}</span>;
}

function Install({ i }: { i: MyInstall }) {
  const open = i.vulns.filter((v) => !['NOT_AFFECTED', 'FALSE_POSITIVE', 'RESOLVED'].includes(v.state));
  const [all, setAll] = useState(false);
  const [show, setShow] = useState(false);
  const shown = all ? i.vulns : open;
  const kev = open.filter((v) => v.kev).length;
  const crit = open.filter((v) => v.severity === 'CRITICAL').length;
  const high = open.filter((v) => v.severity === 'HIGH').length;
  const canOpen = i.vulns.length > 0;
  return (
    <div className="rounded-md border p-3">
      <div className={cn('flex flex-wrap items-center gap-2', canOpen && 'cursor-pointer select-none')} onClick={() => canOpen && setShow(!show)}
        role={canOpen ? 'button' : undefined} aria-expanded={canOpen ? show : undefined}>
        {canOpen && (show ? <ChevronDown size={16} className="text-muted-foreground" /> : <ChevronRight size={16} className="text-muted-foreground" />)}
        <b>버전 {i.tag}</b><Badge variant="muted">{i.env}{i.qty ? ` ×${i.qty}` : ''}</Badge>
        {i.eosDays != null && <DDay days={i.eosDays} label="지원 종료" />}
        {i.upgrade && <span className="inline-flex items-center gap-1 text-xs text-sky-700"><ArrowUpCircle size={12} />권장 업그레이드 {i.upgrade}</span>}
        <span className="ml-auto text-xs">
          {!i.analyzed ? <span className="text-muted-foreground">분석 결과 없음</span>
            : open.length === 0 ? <span className="inline-flex items-center gap-1 text-emerald-700"><ShieldCheck size={13} />조치가 필요한 취약점 없음</span>
              : <span className="inline-flex items-center gap-2">
                {kev > 0 && <span className="rounded bg-red-100 px-1.5 font-semibold text-red-700">KEV {kev}</span>}
                {crit > 0 && <span className="rounded bg-red-600 px-1.5 font-semibold text-white">치명 {crit}</span>}
                {high > 0 && <span className="rounded bg-orange-500 px-1.5 font-semibold text-white">높음 {high}</span>}
                <span className="inline-flex items-center gap-1 text-red-700"><ShieldAlert size={13} />확인 필요 {open.length}</span>
              </span>}
        </span>
      </div>
      {show && shown.length > 0 && (
        <table className="mt-2 w-full text-xs max-lg:block max-lg:overflow-x-auto">
          <thead><tr className="text-left text-muted-foreground"><th className="py-1">취약점</th><th>구성요소</th><th>판정(VEX)</th><th>권장 패치 버전</th></tr></thead>
          <tbody>
            {shown.map((v) => (
              <tr key={v.vulnId + v.component} className="border-t">
                <td className="py-1"><span className="inline-flex flex-wrap items-center gap-1"><b>{v.vulnId}</b><span className={cn('rounded px-1 text-[10px] font-semibold', sevCls(v.severity))}>{v.severity || '미상'}</span>{v.kev && <SourceBadge src="kev" />}</span></td>
                <td>{v.component}</td>
                <td><span className={cn('rounded px-1.5 py-0.5', (STATE[v.state] || STATE.NOT_SET).cls)}>{(STATE[v.state] || { l: v.state }).l}</span></td>
                <td>{v.recommend ? <Badge variant="success">{v.recommend}</Badge> : ['NOT_AFFECTED', 'FALSE_POSITIVE', 'RESOLVED'].includes(v.state) ? '—' : <span className="text-amber-700">준비 중</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {show && i.vulns.length > open.length && (
        <button className="mt-1 text-xs text-muted-foreground underline" onClick={() => setAll(!all)}>{all ? '조치 필요만 보기' : `영향 없음·해결 ${i.vulns.length - open.length}건도 보기`}</button>
      )}
    </div>
  );
}

function Usage({ u }: { u: MyUsage }) {
  const lic = daysLeft(u.licenseExpiry);
  const mnt = daysLeft(u.maintExpiry);
  const [show, setShow] = useState(true);
  return (
    <Card><CardContent className="space-y-3 p-5">
      <div className="flex cursor-pointer select-none flex-wrap items-center gap-2" onClick={() => setShow(!show)} role="button" aria-expanded={show}>
        {show ? <ChevronDown size={18} className="text-muted-foreground" /> : <ChevronRight size={18} className="text-muted-foreground" />}
        <Package size={18} className="text-primary" /><span className="text-lg font-semibold">{u.repo}</span>
        {u.licenseType && <Badge variant="outline">{LIC[u.licenseType] || u.licenseType}</Badge>}
        {u.supportTier && <Badge variant="muted">지원 {u.supportTier}</Badge>}
        {lic != null && u.licenseType !== 'perpetual' && <DDay days={lic} label="라이선스" />}
        {mnt != null && <DDay days={mnt} label="유지보수" />}
        <span className="ml-auto text-xs text-muted-foreground">설치 버전 {u.installs.length}개 · {show ? '접기' : '펼치기'}</span>
      </div>
      {!show ? null : u.installs.length === 0 ? <p className="text-sm text-muted-foreground">등록된 설치 버전이 없습니다.</p> : u.installs.map((i) => <Install key={i.tag + i.env} i={i} />)}
    </CardContent></Card>
  );
}

function Notice({ n }: { n: MyNotice }) {
  return (
    <details className="rounded-md border p-3 text-sm">
      <summary className="flex cursor-pointer flex-wrap items-center gap-2">
        <Mail size={13} className="text-muted-foreground" />
        <Badge variant={n.kind === 'patch' ? 'danger' : 'success'}>{n.kind === 'patch' ? '패치 권고' : '영향 없음 확인'}</Badge>
        <span className="font-medium">{n.subject}</span>
        <span className="ml-auto text-xs text-muted-foreground">{fmt(n.sentAt)}</span>
      </summary>
      <pre className="mt-2 whitespace-pre-wrap font-sans text-sm">{n.text}</pre>
    </details>
  );
}

export default function MyProducts() {
  const [d, setD] = useState<Awaited<ReturnType<typeof myProducts>> | null>(null);
  const [err, setErr] = useState('');
  useEffect(() => { myProducts().then(setD).catch((e) => setErr(String(e))); }, []);

  return (
    <div>
      <h1 className="mb-1 text-2xl font-semibold tracking-tight">내 제품</h1>
      <p className="mb-5 text-sm text-muted-foreground">귀사에 등록된 제품·설치 버전과 그 버전의 취약점 판정, 권장 패치 버전, 최근 보안 통지입니다.</p>
      {err && <div className="rounded-md bg-red-100 p-3 text-sm text-red-700">{err}</div>}
      {!d ? !err && <p className="text-muted-foreground">불러오는 중…</p> : d.customers.length === 0 ? (
        <p className="text-muted-foreground">이 계정에 연결된 고객 정보가 없습니다. 담당 영업·지원 담당에게 문의해 주십시오.</p>
      ) : d.customers.map((c) => (
        <section key={c.name} className="mb-8 space-y-3">
          <h2 className="flex items-center gap-2.5 text-lg font-semibold"><CompanyLogo logo={c.logo} size={36} />{c.name}</h2>
          {c.usages.map((u) => <Usage key={u.repo} u={u} />)}
          <h3 className="pt-2 text-sm font-semibold">최근 보안 통지</h3>
          {c.notices.length === 0 ? <p className="text-sm text-muted-foreground">받은 통지가 없습니다.</p> : <div className="space-y-2">{c.notices.map((n) => <Notice key={n.id} n={n} />)}</div>}
        </section>
      ))}
    </div>
  );
}
