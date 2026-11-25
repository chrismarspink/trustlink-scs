import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import type { LucideIcon } from 'lucide-react';
import {
  Package, PackageCheck, ShieldQuestion, Rocket, Download, Bug, KeyRound, ExternalLink,
  LayoutDashboard, Bell, Archive, ClipboardCheck, Megaphone, Sparkles, X, ArrowRight, MessageCircleQuestion,
} from 'lucide-react';
import { adminInbox, getSession, vexQueue, type InboxGroup, type Session } from '@/lib/api';
import { askOpen } from '@/lib/askOpen';
import { EXT_LINKS, NOTICES, RELEASES } from '@/content/news';
import { cn } from '@/lib/utils';

declare const __APP_VERSION__: string;

// 첫 화면(홈): 소개 자료 · 공지 · 버전별 새 소식 · 바로 가기.
// "새 버전" 띠는 이 브라우저에서 마지막으로 본 버전보다 새 버전일 때만 보인다.
const SEEN = 'tl.home.seenVersion';

type L = { to: string; label: string; desc: string; icon: LucideIcon; ext?: boolean };
const LINKS: L[] = [
  { to: '/artifacts', label: '아티팩트', desc: '제품·버전별 산출물', icon: Package },
  { to: '/my', label: '내 제품', desc: '권한 받은 제품', icon: PackageCheck },
  { to: '/vex', label: 'VEX 판단', desc: '미판단 취약점 대기열', icon: ShieldQuestion },
  { to: '/docs', label: '시작하기', desc: '처음 쓰는 분을 위한 안내', icon: Rocket },
  { to: '/docs/share', label: '업로드·다운로드', desc: 'oras·API 사용법', icon: Download },
  { to: '/docs/vuln', label: '취약점·VEX 안내', desc: '판단 기준과 절차', icon: Bug },
  { to: '/apikeys', label: '내 API 키', desc: '자동화용 키 발급', icon: KeyRound },
  { to: '/intro.html', label: '소개 자료 크게 보기', desc: '새 창으로 열기', icon: ExternalLink, ext: true },
];
const ADMIN_LINKS: L[] = [
  { to: '/admin', label: '대시보드', desc: '운영·보안 현황', icon: LayoutDashboard },
  { to: '/admin/notify', label: '취약점 통보', desc: '개발자 알림 기록', icon: Bell },
  { to: '/admin/customer-notify', label: '고객 통지', desc: '보안 권고 메일', icon: Megaphone },
  { to: '/admin/compliance', label: '규제 대응 검증', desc: '규제 항목별 증거 점검', icon: ClipboardCheck },
  { to: '/admin/reports', label: '보고서함', desc: '발행한 보고서 PDF', icon: Archive },
];

const kindCls = { 신규: 'bg-violet-100 text-violet-700', 개선: 'bg-sky-100 text-sky-700', 수정: 'bg-amber-100 text-amber-800' } as const;
const isRecent = (d: string) => Date.now() - new Date(d).getTime() < 7 * 864e5;
// "2.13.0" < "2.14.0" 비교(숫자 단위)
const older = (a: string, b: string) => {
  const x = a.split('.').map(Number), y = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) < (y[i] || 0);
  return false;
};

function LinkTile({ l }: { l: L }) {
  const inner = (
    <>
      <l.icon size={18} className="mt-0.5 shrink-0 text-violet-600" />
      <span className="min-w-0">
        <span className="block text-sm font-medium">{l.label}</span>
        <span className="block truncate text-xs text-muted-foreground">{l.desc}</span>
      </span>
    </>
  );
  const cls = 'flex items-start gap-2.5 rounded-md border bg-white px-3 py-2.5 transition hover:border-violet-300 hover:shadow-sm';
  return l.ext
    ? <a href={l.to} target="_blank" rel="noreferrer" className={cls}>{inner}</a>
    : <Link to={l.to} className={cls}>{inner}</Link>;
}

// 오늘 결정할 일: 로그인하면 가장 먼저 보이는 것. 관리자는 승인 대기함의 묶음, 개발·보안은 판단 대기 취약점.
const ASKS = ['오늘 승인할 것?', '급한 것부터', '취약점 몇 건이야?'];
function Today({ sess }: { sess: Session }) {
  const admin = !!sess.groups?.includes('admins');
  const [groups, setGroups] = useState<InboxGroup[] | null>(null);
  const [total, setTotal] = useState(0);
  const [vex, setVex] = useState<{ pending: number; kev: number } | null>(null);
  const [q, setQ] = useState('');
  useEffect(() => {
    if (admin) adminInbox().then((r) => { setGroups(r.groups); setTotal(r.decisions); }).catch(() => setGroups([]));
    else if (sess.canEditVex) vexQueue().then((r) => setVex({ pending: r.summary?.pending || 0, kev: r.summary?.pendKev || 0 })).catch(() => {});
  }, [admin, sess.canEditVex]);
  if (!admin && !sess.canEditVex) return null;
  const cards = admin
    ? (groups || []).filter((g) => g.count > 0).slice(0, 3).map((g) => ({ key: g.key, n: g.count, title: g.label, hint: g.items[0]?.title || '', to: g.key === 'vex' ? '/vex' : '/admin/inbox', go: g.key === 'vex' ? '급한 순으로 판정' : '한 건씩 보기' }))
    : vex && vex.pending > 0 ? [{ key: 'vex', n: vex.pending, title: '취약점 영향 판정하기', hint: vex.kev ? `실제 악용 ${vex.kev}건 포함` : '규칙 초안을 확인하고 저장합니다', to: '/vex', go: '급한 순으로 판정' }] : [];
  const loaded = admin ? groups !== null : vex !== null;
  return (
    <section className="rounded-xl border border-violet-200 bg-violet-50/40 p-4 lg:p-5" aria-label="오늘 결정할 일">
      <h2 className="text-xl font-bold">{!loaded ? '할 일을 세는 중…' : cards.length ? (admin ? `오늘 결정할 일이 ${total}건 있습니다` : `판단을 기다리는 취약점이 ${vex?.pending}건 있습니다`) : '지금 결정할 일이 없습니다'}</h2>
      <p className="mt-1 text-sm text-muted-foreground">TrustLink 가 찾고 계산해 둔 것입니다. 사람은 고르기만 하면 됩니다.</p>
      {cards.length > 0 && (
        <div className="mt-3 grid gap-3 md:grid-cols-3">
          {cards.map((c) => (
            <Link key={c.key} to={c.to} className="flex flex-col rounded-lg border bg-white p-3.5 transition hover:border-violet-400 hover:shadow-sm">
              <span className="text-xs text-muted-foreground">{c.title}</span>
              <span className="mt-0.5 text-3xl font-bold tabular-nums">{c.n}</span>
              <span className="mt-1 min-h-[2.2em] text-xs leading-snug text-slate-600 line-clamp-2">{c.hint}</span>
              <span className="mt-2 inline-flex items-center gap-1 text-sm font-semibold text-violet-700">{c.go} <ArrowRight size={14} /></span>
            </Link>
          ))}
        </div>
      )}
      <form className="mt-3 flex flex-wrap items-center gap-2" onSubmit={(e) => { e.preventDefault(); if (q.trim()) { askOpen(q.trim()); setQ(''); } }}>
        <label htmlFor="home-ask" className="inline-flex items-center gap-1.5 text-sm font-semibold"><MessageCircleQuestion size={16} /> 묻고 찾기</label>
        <input id="home-ask" value={q} onChange={(e) => setQ(e.target.value)} maxLength={300} placeholder="예: CVE-2026-1234 가 어디에 걸리나?" className="h-10 min-w-0 flex-1 rounded-md border bg-white px-3 text-sm outline-none focus:border-violet-500" />
        <button type="submit" className="h-10 rounded-md bg-primary px-4 text-sm font-semibold text-primary-foreground">묻기</button>
        <span className="flex w-full flex-wrap gap-1.5">
          {ASKS.map((a) => <button key={a} type="button" onClick={() => askOpen(a)} className="rounded-full border bg-white px-2.5 py-1 text-xs hover:border-violet-400">{a}</button>)}
        </span>
      </form>
    </section>
  );
}

export default function Home() {
  const [sess, setSess] = useState<Session | null>(null);
  const [all, setAll] = useState(false);
  const [seen, setSeen] = useState(() => { try { return localStorage.getItem(SEEN) || ''; } catch { return ''; } });
  useEffect(() => { getSession().then(setSess).catch(() => {}); }, []);
  const admin = !!sess?.groups?.includes('admins');
  const latest = RELEASES[0];
  const showNew = !!latest && (!seen || older(seen, latest.version));
  const dismiss = () => {
    setSeen(__APP_VERSION__);
    try { localStorage.setItem(SEEN, __APP_VERSION__); } catch { /* 저장 못 해도 이번 화면에서만 닫힘 */ }
  };
  const releases = all ? RELEASES : RELEASES.slice(0, 4);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="mb-1 text-2xl font-bold">TrustLink</h1>
        <p className="text-sm text-muted-foreground">
          납품하는 소프트웨어의 신뢰를 잇습니다 — 저장 · 검증 · 판단 · 통보 · 규제 대응
          {sess?.username && <> · <b className="text-foreground">{sess.username}</b> 님 환영합니다</>}
        </p>
      </div>

      {sess && <Today sess={sess} />}

      {showNew && (
        <div className="flex items-start gap-3 rounded-lg border border-violet-200 bg-violet-50 px-4 py-3" role="status">
          <Sparkles size={18} className="mt-0.5 shrink-0 text-violet-600" />
          <div className="min-w-0 flex-1 text-sm">
            <b>v{latest.version} 로 업데이트되었습니다 — {latest.title}</b>
            <ul className="mt-1 list-disc pl-5 text-slate-700">{latest.items.map((it) => <li key={it.text}>{it.text}</li>)}</ul>
          </div>
          <button onClick={dismiss} className="rounded p-1 text-slate-500 hover:bg-violet-100" aria-label="새 버전 알림 닫기"><X size={16} /></button>
        </div>
      )}

      <section className="overflow-hidden rounded-lg border border-violet-200">
        <div className="flex items-center gap-2 border-b border-violet-100 bg-violet-50/50 px-4 py-2">
          <span className="text-sm font-semibold">제품 소개</span>
          <span className="flex-1" />
          <a href="/intro.html" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-violet-700 hover:underline">
            <ExternalLink size={13} /> 크게 보기
          </a>
        </div>
        <iframe src="/intro.html" title="TrustLink 제품 소개" className="block h-[440px] w-full border-0 bg-white" />
      </section>

      <section className="rounded-lg border bg-white p-4">
        <div className="mb-2 flex flex-wrap items-baseline gap-2">
          <h2 className="text-base font-semibold">TrustLink 한눈에 — 납품 소프트웨어의 신뢰 장부</h2>
          <span className="text-xs text-muted-foreground">제품을 모으고, 분석하고, 고객에게 전달합니다. 그 뒤의 변화도 같은 다섯 단계 — 사람은 결정만 합니다.</span>
        </div>
        <img src="/concept-flow.svg" alt="신호 → 영향 → 결정 → 전달 → 기록 다섯 단계. 맨 윗줄은 릴리스(제품 등록 · SBOM 분석 · VEX 판단 · 고객 내려받기 · 신뢰 장부), 아래는 취약점·규제·만료 세 갈래" className="mx-auto w-full max-w-[720px]" loading="lazy" />
      </section>

      <div className="grid gap-6 lg:grid-cols-2">
        <section>
          <h2 className="mb-2 text-base font-semibold">공지</h2>
          <ul className="space-y-2">
            {NOTICES.map((n) => (
              <li key={n.date + n.title} className={cn('rounded-md border bg-white px-3 py-2.5', n.level === 'warn' && 'border-amber-200 bg-amber-50/50')}>
                <div className="flex items-center gap-2 text-sm font-medium">
                  {isRecent(n.date) && <span className="rounded bg-red-500 px-1.5 text-[10px] font-bold text-white">NEW</span>}
                  <span className="min-w-0 flex-1">{n.title}</span>
                  <span className="shrink-0 text-xs tabular-nums text-muted-foreground">{n.date}</span>
                </div>
                <p className="mt-1 text-xs leading-relaxed text-slate-600">{n.body}</p>
              </li>
            ))}
          </ul>
        </section>

        <section>
          <h2 className="mb-2 text-base font-semibold">버전별 새 소식 <span className="text-xs font-normal text-muted-foreground">현재 v{__APP_VERSION__}</span></h2>
          <ol className="space-y-2">
            {releases.map((r) => (
              <li key={r.version} className="rounded-md border bg-white px-3 py-2.5">
                <div className="flex items-center gap-2 text-sm">
                  <span className="rounded bg-slate-800 px-1.5 font-mono text-[11px] text-white">v{r.version}</span>
                  <b className="min-w-0 flex-1">{r.title}</b>
                  <span className="shrink-0 text-xs tabular-nums text-muted-foreground">{r.date}</span>
                </div>
                <ul className="mt-1.5 space-y-1">
                  {r.items.map((it) => (
                    <li key={it.text} className="flex items-start gap-2 text-xs text-slate-700">
                      <span className={cn('shrink-0 rounded px-1.5 py-px text-[10px] font-semibold', kindCls[it.kind])}>{it.kind}</span>
                      <span>{it.text}</span>
                    </li>
                  ))}
                </ul>
              </li>
            ))}
          </ol>
          {RELEASES.length > 4 && (
            <button onClick={() => setAll(!all)} className="mt-2 text-xs text-violet-700 hover:underline">
              {all ? '최근 것만 보기' : `지난 버전 ${RELEASES.length - 4}개 더 보기`}
            </button>
          )}
        </section>
      </div>

      <section>
        <h2 className="mb-2 text-base font-semibold">바로 가기</h2>
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">{LINKS.map((l) => <LinkTile key={l.to} l={l} />)}</div>
        {admin && (
          <>
            <h3 className="mb-2 mt-4 text-sm font-semibold text-muted-foreground">관리</h3>
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">{ADMIN_LINKS.map((l) => <LinkTile key={l.to} l={l} />)}</div>
          </>
        )}
      </section>

      <section>
        <h2 className="mb-1 text-base font-semibold">공급망 참고 링크</h2>
        <p className="mb-3 text-xs text-muted-foreground">TrustLink 가 쓰는 오픈소스와 따르는 표준·취약점 정보·규제 원문입니다. 새 창으로 열립니다.</p>
        <div className="space-y-4">
          {EXT_LINKS.map((g) => (
            <div key={g.group}>
              <h3 className="mb-2 text-sm font-semibold text-muted-foreground">{g.group}</h3>
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
                {g.links.map((l) => (
                  <a key={l.label} href={l.url} target="_blank" rel="noreferrer"
                    className="group flex items-center gap-3 rounded-md border bg-white px-3 py-2.5 transition hover:border-violet-300 hover:shadow-sm">
                    <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-slate-100 bg-white p-1">
                      <img src={`/logos/${l.logo}`} alt="" className="max-h-full max-w-full object-contain" loading="lazy" />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="flex items-center gap-1 text-sm font-medium">{l.label}<ExternalLink size={11} className="text-slate-300 group-hover:text-violet-500" /></span>
                      <span className="block truncate text-xs text-muted-foreground" title={l.desc}>{l.desc}</span>
                    </span>
                  </a>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
