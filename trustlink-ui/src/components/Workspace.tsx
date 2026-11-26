import { useEffect, useState } from 'react';
import { Link, NavLink, useLocation } from 'react-router-dom';
import type { LucideIcon } from 'lucide-react';
import { ListChecks, Package, Contact, Bug, Send, Settings, BookOpen, PackageCheck, Plug, Home } from 'lucide-react';
import { getSession, type Session } from '@/lib/api';
import { cn } from '@/lib/utils';

// 역할별 작업공간(시험 운영) — 로그인한 사람의 권한에 따라 메뉴 한 벌만 보인다.
//   고객(users)           → 고객 포털
//   개발자(developers)    → 내부 콘솔(고객·보낸 것·설정 제외)
//   운영자(admins)        → 내부 콘솔 전체 + 자사(내부 고객)
// 주소(경로)와 각 화면은 그대로 두고 메뉴 묶음과 탭만 바꾼다. 스위치를 끄면 기존 사이드바로 돌아간다.
// 스위치는 브라우저마다 따로 저장한다(localStorage). 실제 접근 권한은 지금처럼 서버가 막는다.

const KEY = 'tl-ws';

// 주소에 ?ws=1 / ?ws=0 을 붙여 켜고 끌 수 있다(관리자가 아닌 시험 계정용).
try {
  const q = new URLSearchParams(window.location.search).get('ws');
  if (q === '1') localStorage.setItem(KEY, '1');
  else if (q === '0') localStorage.removeItem(KEY);
} catch {
  /* 저장소를 못 쓰면 기존 화면 그대로 */
}

export function wsOn(): boolean {
  try {
    return localStorage.getItem(KEY) === '1';
  } catch {
    return false;
  }
}

export function setWs(on: boolean) {
  try {
    if (on) localStorage.setItem(KEY, '1');
    else localStorage.removeItem(KEY);
  } catch {
    return;
  }
  window.location.reload();
}

type Who = 'all' | 'login' | 'vex' | 'admin';
type Tab = { to: string; label: string; end?: boolean; who?: Who };
type Menu = { id: string; label: string; icon: LucideIcon; tabs: Tab[]; section?: string };

const DOCS: Tab[] = [
  { to: '/docs', label: '시작하기', end: true },
  { to: '/docs/share', label: '업로드·다운로드' },
  { to: '/docs/vuln', label: '취약점·VEX' },
  { to: '/docs/rbac', label: '권한·참고' },
  { to: '/docs/collector', label: '진단 수집기' },
  { to: '/tools', label: '진단 도구', who: 'login' },
];

const PORTAL: Menu[] = [
  { id: 'products', label: '내 제품', icon: PackageCheck, tabs: [
    { to: '/my', label: '내 제품', who: 'login' },
    { to: '/artifacts', label: '전체 아티팩트' },
  ] },
  { id: 'connect', label: '연결', icon: Plug, tabs: [
    { to: '/apikeys', label: '내 API 키' },
    { to: '/mcp', label: 'AI 도구 연결', who: 'login' },
  ] },
  { id: 'help', label: '도움말·도구', icon: BookOpen, tabs: DOCS },
];

const CONSOLE: Menu[] = [
  { id: 'todo', label: '할 일', icon: ListChecks, tabs: [
    { to: '/admin/inbox', label: '승인 대기', who: 'admin' },
    { to: '/vex', label: 'VEX 판단', who: 'vex' },
    { to: '/agent', label: '에이전트', who: 'login' },
    { to: '/admin', label: '대시보드', end: true, who: 'admin' },
  ] },
  { id: 'release', label: '제품·릴리스', icon: Package, tabs: [
    { to: '/artifacts', label: '아티팩트' },
    { to: '/admin/registry', label: '레지스트리', who: 'admin' },
    { to: '/admin/upstream', label: '공개 저장소 분석', who: 'admin' },
    { to: '/apikeys', label: '내 API 키' },
    { to: '/mcp', label: 'AI 도구 연결', who: 'login' },
  ] },
  { id: 'customer', label: '고객', icon: Contact, tabs: [
    { to: '/admin/customers', label: '고객 등록부', who: 'admin' },
    { to: '/admin/users', label: '계정', who: 'admin' },
    { to: '/admin/orgs', label: '고객사', who: 'admin' },
    { to: '/admin/access', label: '제품 권한', who: 'admin' },
    { to: '/admin/robots', label: '자동화 계정', who: 'admin' },
    { to: '/admin/acl', label: '전체 권한', who: 'admin' },
  ] },
  { id: 'signal', label: '취약점·규제', icon: Bug, tabs: [
    { to: '/impact', label: '영향 지도', who: 'vex' },
    { to: '/admin/auto-response', label: '자동 대응', who: 'admin' },
    { to: '/admin/regs', label: '규제 카탈로그', who: 'admin' },
    { to: '/admin/compliance', label: '규제 대응 검증', who: 'admin' },
  ] },
  { id: 'sent', label: '보낸 것', icon: Send, tabs: [
    { to: '/admin/outbox', label: '발송함', who: 'admin' },
    { to: '/admin/customer-notify', label: '고객 통지', who: 'admin' },
    { to: '/admin/notify', label: '취약점 통보', who: 'admin' },
    { to: '/admin/reports', label: '보고서', who: 'admin' },
  ] },
  { id: 'settings', label: '설정', icon: Settings, tabs: [
    { to: '/admin/system', label: '시스템', who: 'admin' },
    { to: '/admin/capacity', label: '용량', who: 'admin' },
    { to: '/admin/ai', label: 'AI', who: 'admin' },
    { to: '/admin/storage', label: '저장소', who: 'admin' },
    { to: '/admin/mirror', label: '취약점 DB', who: 'admin' },
    { to: '/admin/logs', label: '로그', who: 'admin' },
  ] },
  { id: 'help', label: '도움말·도구', icon: BookOpen, tabs: DOCS },
  // 운영자·개발자는 자사를 내부 고객으로 보고, 고객과 같은 화면으로 먼저 확인한다.
  { id: 'mine', label: '내 제품', icon: PackageCheck, section: '자사 (내부 고객)', tabs: [
    { to: '/my', label: '내 제품', who: 'login' },
  ] },
];

type Sess = Session | null | undefined;

const isAdmin = (s: Sess) => !!s?.groups?.includes('admins');
const isInternal = (s: Sess) => isAdmin(s) || !!s?.groups?.includes('developers') || !!s?.canEditVex;
const can = (s: Sess, w: Who = 'all') =>
  w === 'all' || (w === 'login' && !!s) || (w === 'vex' && !!s?.canEditVex) || (w === 'admin' && isAdmin(s));

export const wsName = (s: Sess) => (isInternal(s) ? '내부 콘솔' : '고객 포털');

function wsMenus(s: Sess): Menu[] {
  return (isInternal(s) ? CONSOLE : PORTAL)
    .map((m) => ({ ...m, tabs: m.tabs.filter((t) => can(s, t.who)) }))
    .filter((m) => m.tabs.length > 0);
}

const hit = (pathname: string, t: Tab) => (t.end ? pathname === t.to : pathname === t.to || pathname.startsWith(t.to + '/'));

// 현재 경로가 속한 메뉴와 탭(가장 길게 맞는 것)
function wsFind(pathname: string, menus: Menu[]): { menu: Menu; tab: Tab } | null {
  const p = pathname.startsWith('/artifact/') ? '/artifacts' : pathname;
  let best: { menu: Menu; tab: Tab } | null = null;
  for (const menu of menus) {
    for (const tab of menu.tabs) {
      if (hit(p, tab) && (!best || tab.to.length > best.tab.to.length)) best = { menu, tab };
    }
  }
  return best;
}

// 상단 경로 표시용
export function wsTrail(pathname: string, s: Sess): string[] | null {
  if (pathname === '/') return ['홈'];
  const f = wsFind(pathname, wsMenus(s));
  if (!f) return null;
  return f.menu.tabs.length > 1 ? [f.menu.label, f.tab.label] : [f.menu.label];
}

// 세션은 한 번만 물어 여러 곳에서 같이 쓴다.
let sessOnce: Promise<Session | null> | null = null;
export function useWsSession(): Sess {
  const [s, setS] = useState<Sess>(undefined);
  useEffect(() => {
    if (!wsOn()) return;
    sessOnce ??= getSession().catch(() => null);
    sessOnce.then(setS);
  }, []);
  return s;
}

const itemCls = (active: boolean) =>
  cn('mx-2 flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm text-foreground/75 transition-colors hover:bg-secondary hover:text-foreground',
    active && 'bg-zinc-200/60 font-medium text-foreground');

// 사이드바 메뉴(한 줄에 한 메뉴). 메뉴 안의 화면들은 본문 위 탭(WsTabs)으로 고른다.
export function WsNav({ sess, todo }: { sess: Sess; todo: number }) {
  const { pathname } = useLocation();
  const menus = wsMenus(sess);
  const cur = wsFind(pathname, menus);
  return (
    <>
      <div className="pt-2">
        <Link to="/" className={itemCls(pathname === '/')}><Home size={16} className="text-muted-foreground" /> 홈</Link>
      </div>
      {menus.map((m) => (
        <div key={m.id}>
          {m.section && <div className="px-[18px] pb-1 pt-4 text-[11px] text-muted-foreground">{m.section}</div>}
          <Link to={m.tabs[0].to} className={itemCls(cur?.menu.id === m.id)}>
            <m.icon size={16} className="text-muted-foreground" /> {m.label}
            {m.id === 'todo' && todo > 0 && (
              <span className="ml-auto rounded-full bg-violet-600 px-1.5 text-[11px] font-semibold leading-5 text-white">{todo > 99 ? '99+' : todo}</span>
            )}
          </Link>
        </div>
      ))}
    </>
  );
}

// 본문 위 탭 — 같은 메뉴에 속한 화면들. 화면이 하나뿐이면 표시하지 않는다.
export function WsTabs({ sess }: { sess: Sess }) {
  const { pathname } = useLocation();
  const cur = wsFind(pathname, wsMenus(sess));
  if (!cur || cur.menu.tabs.length < 2) return null;
  return (
    <div className="mb-5 flex gap-1 overflow-x-auto border-b" role="tablist" aria-label={cur.menu.label}>
      {cur.menu.tabs.map((t) => (
        <NavLink
          key={t.to} to={t.to} end={t.end} role="tab" aria-selected={t.to === cur.tab.to}
          className={cn('-mb-px whitespace-nowrap border-b-2 border-transparent px-3 py-2 text-sm text-muted-foreground hover:text-foreground',
            t.to === cur.tab.to && 'border-foreground font-medium text-foreground')}
        >
          {t.label}
        </NavLink>
      ))}
    </div>
  );
}
