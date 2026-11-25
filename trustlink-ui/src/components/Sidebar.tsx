import { useEffect, useState } from 'react';
import { Link, NavLink, useLocation } from 'react-router-dom';
import type { LucideIcon } from 'lucide-react';
import {
  Package, BookOpen, LayoutDashboard, Users, HardDrive,
  ScrollText, Boxes, Activity, KeyRound, Database,
  ChevronRight, Home, Rocket, Download, Bug, Building2, ShieldCheck, Bot, LogOut, Bell, DatabaseZap, ClipboardCheck, Sparkles, Landmark, Archive, GitBranch, ShieldQuestion, Contact, Megaphone, PackageCheck, Workflow, Inbox, Send, Plug, Share2, ListChecks, Settings } from 'lucide-react';
import { adminInbox, bffLogin, getSession, logout, type Session } from '@/lib/api';
import { cn } from '@/lib/utils';

declare const __APP_VERSION__: string;

type Who = 'all' | 'login' | 'vex' | 'admin'; // 누구에게 보이나: 모두 / 로그인한 사람 / VEX 편집 권한 / 관리자
type Sub = { to: string; label: string; icon: LucideIcon; end?: boolean; who?: Who };
// open: 처음부터 펼쳐 둔다(자주 쓰는 묶음). 아니면 그 안의 화면에 있을 때만 펼침.
type Item = { to: string; label: string; icon: LucideIcon; end?: boolean; open?: boolean; children?: Sub[] };

// 메뉴는 사람이 하는 일 기준으로 여섯 묶음(+ 홈, 문서). 주소는 그대로 두고 위치와 이름만 바꾼다(기존 링크가 깨지지 않게).
//   할 일 · 제품·릴리스(무엇을 줬나) · 고객(누가 쓰나) · 취약점·규제(무엇이 바뀌었나) · 보낸 것·기록(누구에게 알렸나) · 설정
// 관리 항목은 admins 로 확인된 경우에만 보인다(외부 고객 화면에 관리 메뉴가 보이지 않게). 실제 접근은 서버가 막는다.
const HOME: Item = { to: '/', label: '홈', icon: Home, end: true };
const MENUS: Item[] = [
  {
    to: '#todo', label: '할 일', icon: ListChecks, open: true, children: [
      { to: '/admin/inbox', label: '승인 대기함', icon: Inbox, who: 'admin' },
      { to: '/vex', label: 'VEX 판단', icon: ShieldQuestion, who: 'vex' },
      { to: '/admin', label: '대시보드', icon: LayoutDashboard, end: true, who: 'admin' },
    ]
  },
  {
    to: '#release', label: '제품·릴리스', icon: Package, open: true, children: [
      { to: '/artifacts', label: '아티팩트', icon: Package },
      { to: '/my', label: '내 제품', icon: PackageCheck, who: 'login' },
      { to: '/admin/registry', label: '레지스트리', icon: Boxes, who: 'admin' },
      { to: '/admin/upstream', label: '공개 저장소 분석', icon: GitBranch, who: 'admin' },
      { to: '/apikeys', label: '내 API 키', icon: KeyRound },
      { to: '/mcp', label: 'AI 도구 연결', icon: Plug, who: 'login' },
    ]
  },
  {
    to: '#customer', label: '고객', icon: Contact, children: [
      { to: '/admin/customers', label: '고객 등록부', icon: Contact, who: 'admin' },
      { to: '/admin/users', label: '사용자', icon: Users, who: 'admin' },
      { to: '/admin/orgs', label: '고객사', icon: Building2, who: 'admin' },
      { to: '/admin/access', label: '제품 권한', icon: ShieldCheck, who: 'admin' },
      { to: '/admin/robots', label: '자동화 계정', icon: Bot, who: 'admin' },
      { to: '/admin/acl', label: '권한 매트릭스', icon: KeyRound, who: 'admin' },
    ]
  },
  {
    to: '#signal', label: '취약점·규제', icon: Bug, children: [
      { to: '/impact', label: '영향 지도', icon: Share2, who: 'vex' },
      { to: '/admin/auto-response', label: '자동 대응', icon: Workflow, who: 'admin' },
      { to: '/admin/mirror', label: '취약점 DB 미러', icon: DatabaseZap, who: 'admin' },
      { to: '/admin/regs', label: '규제 카탈로그·탐색', icon: Landmark, who: 'admin' },
      { to: '/admin/compliance', label: '규제 대응 검증', icon: ClipboardCheck, who: 'admin' },
    ]
  },
  {
    to: '#sent', label: '보낸 것·기록', icon: Send, children: [
      { to: '/admin/outbox', label: '발송함', icon: Send, who: 'admin' },
      { to: '/admin/customer-notify', label: '고객 통지', icon: Megaphone, who: 'admin' },
      { to: '/admin/notify', label: '취약점 통보', icon: Bell, who: 'admin' },
      { to: '/admin/reports', label: '보고서함', icon: Archive, who: 'admin' },
      { to: '/admin/logs', label: '로그', icon: ScrollText, who: 'admin' },
    ]
  },
  {
    to: '#settings', label: '설정', icon: Settings, children: [
      { to: '/admin/system', label: '시스템 상태', icon: Activity, who: 'admin' },
      { to: '/admin/capacity', label: '용량', icon: HardDrive, who: 'admin' },
      { to: '/admin/ai', label: 'AI 연결', icon: Sparkles, who: 'admin' },
      { to: '/admin/storage', label: '설정·스토리지', icon: Database, who: 'admin' },
    ]
  },
  {
    to: '#docs', label: '문서', icon: BookOpen, children: [
      { to: '/docs', label: '시작하기', icon: Rocket, end: true },
      { to: '/docs/share', label: '업로드·다운로드', icon: Download },
      { to: '/docs/vuln', label: '취약점·VEX', icon: Bug },
      { to: '/docs/rbac', label: '권한·참고', icon: KeyRound },
    ]
  },
];

const matches = (pathname: string, it: Sub) => (it.end ? pathname === it.to : pathname === it.to || pathname.startsWith(it.to + '/'));

// 현재 경로의 [묶음, 메뉴명] — 상단 경로 표시용
export function navTrail(pathname: string): string[] | null {
  if (pathname === '/') return ['홈'];
  if (pathname.startsWith('/artifact/')) return ['제품·릴리스', '아티팩트'];
  let best: string[] | null = null, len = 0;
  for (const m of MENUS) {
    for (const c of m.children || []) {
      if (matches(pathname, c) && c.to.length > len) { best = [m.label, c.label]; len = c.to.length; }
    }
  }
  return best;
}


const linkCls = (extra = '') => ({ isActive }: { isActive: boolean }) =>
  cn('mx-2 flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm text-foreground/75 transition-colors hover:bg-secondary hover:text-foreground', extra,
    isActive && 'bg-zinc-200/60 font-medium text-foreground');

function NavItem({ item }: { item: Item }) {
  return (
    <NavLink to={item.to} end={item.end} className={linkCls()}>
      <item.icon size={16} className="text-muted-foreground" /> {item.label}
    </NavLink>
  );
}

// 하위 트리 그룹 — 부모는 토글, 활성 경로면 자동 펼침.
function NavGroup({ item, badge }: { item: Item; badge?: number }) {
  const loc = useLocation();
  const within = matches(loc.pathname, item) || item.children!.some((c) => matches(loc.pathname, c));
  const [open, setOpen] = useState(within || !!item.open);
  useEffect(() => { if (within) setOpen(true); }, [within]);
  return (
    <div>
      <button
        type="button" aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        className={cn('mx-2 flex w-[calc(100%-1rem)] items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm text-foreground/75 transition-colors hover:bg-secondary hover:text-foreground',
          within && 'text-foreground')}
      >
        <item.icon size={16} className="text-muted-foreground" /> {item.label}
        {!!badge && <span className="rounded-full bg-violet-600 px-1.5 text-[11px] font-semibold leading-5 text-white">{badge > 99 ? '99+' : badge}</span>}
        <ChevronRight size={14} className={cn('ml-auto text-muted-foreground transition-transform', open && 'rotate-90')} />
      </button>
      {open && (
        <div className="ml-[22px] border-l pl-1">
          {item.children!.map((c) => (
            <NavLink key={c.to} to={c.to} end={c.end} className={linkCls('text-[13px]')}>
              {c.label}
            </NavLink>
          ))}
        </div>
      )}
    </div>
  );
}

function roleLabel(groups: string[] = []) {
  if (groups.includes('admins')) return '관리자';
  if (groups.includes('developers')) return '내부 개발자';
  return '외부 사용자';
}

// 제품·관리 공용 사이드바 — 아티팩트와 관리 콘솔 항목을 한 곳에 함께 노출(트리 구조).
// 관리 섹션은 admins 로 확인된 경우에만 노출(외부 고객 화면에 관리 메뉴가 보이지 않게).
// 제품 화면으로만 로그인해 관리 콘솔 세션이 없으면 숨김 → 관리자는 /admin 으로 진입(SSO), 이후 노출. 실제 접근은 /admin 게이트가 강제.
export function Sidebar({ open = false, onClose }: { open?: boolean; onClose?: () => void }) {
  const [sess, setSess] = useState<Session | null | undefined>(undefined);

  useEffect(() => {
    getSession()
      .then((s) => {
        setSess(s);
        // 제품 화면 로그인만 있고 BFF 세션이 없으면(BFF 재시작 등) Keycloak SSO 로 한 번 조용히 재발급.
        // 반복 리다이렉트 방지: 탭당 1분에 한 번만 시도.
        if (s) return;
        try {
          const last = Number(sessionStorage.getItem('tl-bff-sso') || 0);
          if (Date.now() - last < 60_000) return;
          sessionStorage.setItem('tl-bff-sso', String(Date.now()));
        } catch {
          return;
        }
        bffLogin(window.location.pathname + window.location.search);
      })
      .catch(() => setSess(null));
  }, []);

  const admin = !!sess?.groups?.includes('admins');
  const can = (w: Who = 'all') => w === 'all' || (w === 'login' && !!sess) || (w === 'vex' && !!sess?.canEditVex) || (w === 'admin' && admin);
  const menus = MENUS.map((m) => ({ ...m, children: (m.children || []).filter((c) => can(c.who)) })).filter((m) => m.children.length > 0);
  // 할 일 옆 숫자: 관리자가 결정할 일(승인 대기함의 합계)
  const [todo, setTodo] = useState(0);
  useEffect(() => {
    if (!admin) return;
    const load = () => adminInbox().then((r) => setTodo(r.decisions)).catch(() => {});
    load();
    const t = setInterval(load, 60000);
    return () => clearInterval(t);
  }, [admin]);

  return (
    <>
    {open && <div className="fixed inset-0 z-40 bg-black/40 lg:hidden" onClick={onClose} aria-hidden="true" />}
    <aside className={cn('fixed inset-y-0 left-0 z-50 flex h-dvh w-64 max-w-[85vw] shrink-0 flex-col border-r bg-sidebar transition-transform lg:sticky lg:top-0 lg:z-auto lg:h-screen lg:w-60 lg:translate-x-0',
      open ? 'translate-x-0 shadow-xl' : 'invisible -translate-x-full lg:visible')}>
      <Link to="/" className="flex h-14 select-none items-center gap-2.5 border-b px-4">
        <span className="flex h-7 w-7 items-center justify-center rounded-md bg-primary text-primary-foreground">
          <ShieldCheck size={15} />
        </span>
        <span className="leading-tight">
          <span className="block text-sm font-semibold">TrustLink</span>
          <span className="block text-[11px] text-muted-foreground">Software Supply Chain · v{__APP_VERSION__}</span>
        </span>
      </Link>
      <nav className="flex-1 space-y-0.5 overflow-y-auto pb-3" aria-label="주 메뉴">
        <div className="pt-2"><NavItem item={HOME} /></div>
        {menus.map((m) => <NavGroup key={m.to} item={m} badge={m.to === '#todo' ? todo : 0} />)}
      </nav>
      {sess?.username && (
        <div className="flex items-center gap-2.5 border-t p-3">
          <span className="flex h-8 w-8 items-center justify-center rounded-full bg-zinc-200 text-xs font-semibold uppercase">
            {sess.username.slice(0, 2)}
          </span>
          <div className="min-w-0 flex-1 leading-tight">
            <div className="truncate text-sm font-medium">{sess.username}</div>
            <div className="truncate text-xs text-muted-foreground">{roleLabel(sess.groups)}</div>
          </div>
          <button onClick={() => logout()} title="로그아웃" className="rounded-md p-1.5 text-muted-foreground hover:bg-secondary hover:text-foreground">
            <LogOut size={15} />
          </button>
        </div>
      )}
    </aside>
    </>
  );
}
