import { useEffect, useState } from 'react';
import { Link, NavLink, useLocation } from 'react-router-dom';
import type { LucideIcon } from 'lucide-react';
import {
  Package, BookOpen, LayoutDashboard, Users, HardDrive,
  ScrollText, Boxes, Activity, KeyRound, Database,
  ChevronRight, Rocket, Download, Bug, Building2, ShieldCheck, Bot, LogOut
} from 'lucide-react';
import { bffLogin, getSession, logout, type Session } from '@/lib/api';
import { cn } from '@/lib/utils';

type Sub = { to: string; label: string; icon: LucideIcon; end?: boolean };
type Item = { to: string; label: string; icon: LucideIcon; end?: boolean; children?: Sub[] };

// 제품(레지스트리) 섹션 — 항상 노출. "문서"는 하위 트리.
const PRODUCT: Item[] = [
  { to: '/', label: '아티팩트', icon: Package, end: true },
  { to: '/apikeys', label: '내 API 키', icon: KeyRound },
  {
    to: '/docs', label: '문서', icon: BookOpen, children: [
      { to: '/docs', label: '시작하기', icon: Rocket, end: true },
      { to: '/docs/share', label: '업로드·다운로드', icon: Download },
      { to: '/docs/vuln', label: '취약점·VEX', icon: Bug },
      { to: '/docs/rbac', label: '권한·참고', icon: KeyRound }
    ]
  }
];
// 관리 콘솔 섹션 — admins 일 때 노출.
const ADMIN: Item[] = [
  { to: '/admin', label: '대시보드', icon: LayoutDashboard, end: true },
  { to: '/admin/users', label: '사용자', icon: Users },
  { to: '/admin/orgs', label: '고객사', icon: Building2 },
  { to: '/admin/access', label: '제품 권한', icon: ShieldCheck },
  { to: '/admin/robots', label: '기계 계정', icon: Bot },
  { to: '/admin/capacity', label: '용량', icon: HardDrive },
  { to: '/admin/logs', label: '로그', icon: ScrollText },
  { to: '/admin/registry', label: '레지스트리', icon: Boxes },
  { to: '/admin/system', label: '시스템 상태', icon: Activity },
  { to: '/admin/acl', label: '권한 매트릭스', icon: KeyRound },
  { to: '/admin/storage', label: '설정·스토리지', icon: Database }
];

// 현재 경로의 [섹션, 메뉴명] — 상단 경로 표시용
export function navTrail(pathname: string): [string, string] | null {
  const hit = (items: Item[]) => {
    let best: Sub | null = null;
    for (const it of items.flatMap((i) => [i, ...(i.children || [])])) {
      const ok = it.end ? pathname === it.to : pathname === it.to || pathname.startsWith(it.to + '/');
      if (ok && (!best || it.to.length > best.to.length)) best = it;
    }
    return best;
  };
  const a = hit(ADMIN);
  if (a) return ['관리', a.label];
  if (pathname.startsWith('/artifact/')) return ['제품', '아티팩트'];
  const p = hit(PRODUCT);
  return p ? ['제품', p.label] : null;
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
function NavGroup({ item }: { item: Item }) {
  const loc = useLocation();
  const within = loc.pathname === item.to || loc.pathname.startsWith(item.to + '/');
  const [open, setOpen] = useState(within);
  useEffect(() => { if (within) setOpen(true); }, [within]);
  return (
    <div>
      <button
        onClick={() => setOpen((o) => !o)}
        className={cn('mx-2 flex w-[calc(100%-1rem)] items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm text-foreground/75 transition-colors hover:bg-secondary hover:text-foreground',
          within && 'text-foreground')}
      >
        <item.icon size={16} className="text-muted-foreground" /> {item.label}
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

function render(items: Item[]) {
  return items.map((i) => (i.children ? <NavGroup key={i.to} item={i} /> : <NavItem key={i.to} item={i} />));
}

function roleLabel(groups: string[] = []) {
  if (groups.includes('admins')) return '관리자';
  if (groups.includes('developers')) return '내부 개발자';
  return '외부 사용자';
}

function SectionLabel({ children }: { children: string }) {
  return (
    <div className="px-4 pb-1 pt-5 text-xs font-medium text-muted-foreground">
      {children}
    </div>
  );
}

// 제품·관리 공용 사이드바 — 아티팩트와 관리 콘솔 항목을 한 곳에 함께 노출(트리 구조).
// 관리 섹션은 admins 로 확인된 경우에만 노출(외부 고객 화면에 관리 메뉴가 보이지 않게).
// 제품 화면으로만 로그인해 관리 콘솔 세션이 없으면 숨김 → 관리자는 /admin 으로 진입(SSO), 이후 노출. 실제 접근은 /admin 게이트가 강제.
export function Sidebar() {
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

  const showAdmin = !!sess?.groups?.includes('admins');

  return (
    <aside className="sticky top-0 flex h-screen w-60 shrink-0 flex-col border-r bg-sidebar">
      <Link to="/" className="flex h-14 select-none items-center gap-2.5 border-b px-4">
        <span className="flex h-7 w-7 items-center justify-center rounded-md bg-primary text-primary-foreground">
          <ShieldCheck size={15} />
        </span>
        <span className="leading-tight">
          <span className="block text-sm font-semibold">TrustLink</span>
          <span className="block text-[11px] text-muted-foreground">Software Supply Chain</span>
        </span>
      </Link>
      <nav className="flex-1 space-y-0.5 overflow-y-auto pb-3">
        <SectionLabel>제품</SectionLabel>
        {render(PRODUCT)}
        {showAdmin && (
          <>
            <SectionLabel>관리</SectionLabel>
            {render(ADMIN)}
          </>
        )}
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
  );
}
