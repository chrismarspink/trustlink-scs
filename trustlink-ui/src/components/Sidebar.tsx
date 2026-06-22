import { useEffect, useState } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import type { LucideIcon } from 'lucide-react';
import {
  Package, BookOpen, LayoutDashboard, Users, HardDrive,
  ScrollText, Boxes, Activity, KeyRound, Database, ShieldCheck,
  ChevronRight, Rocket, Download, Bug, FilePlus2, FileBadge, Inbox, History
} from 'lucide-react';
import { getSession, type Session } from '@/lib/api';
import { cn } from '@/lib/utils';

type Sub = { to: string; label: string; icon: LucideIcon; end?: boolean };
type Item = { to: string; label: string; icon: LucideIcon; end?: boolean; children?: Sub[] };

// 제품(레지스트리) 섹션 — 항상 노출. "문서"는 하위 트리.
const PRODUCT: Item[] = [
  { to: '/', label: '아티팩트', icon: Package, end: true },
  {
    to: '/docs', label: '문서', icon: BookOpen, children: [
      { to: '/docs', label: '시작하기', icon: Rocket, end: true },
      { to: '/docs/share', label: '업로드·다운로드', icon: Download },
      { to: '/docs/trust', label: '신뢰·검증(CA)', icon: ShieldCheck },
      { to: '/docs/vuln', label: '취약점·VEX', icon: Bug },
      { to: '/docs/rbac', label: '권한·참고', icon: KeyRound }
    ]
  }
];
// 관리 콘솔 섹션 — admins 일 때 노출. "인증서·신뢰(CA)"는 하위 트리.
const ADMIN: Item[] = [
  { to: '/admin', label: '대시보드', icon: LayoutDashboard, end: true },
  { to: '/admin/users', label: '사용자', icon: Users },
  { to: '/admin/capacity', label: '용량', icon: HardDrive },
  { to: '/admin/logs', label: '로그', icon: ScrollText },
  { to: '/admin/registry', label: '레지스트리', icon: Boxes },
  { to: '/admin/system', label: '시스템 상태', icon: Activity },
  { to: '/admin/acl', label: '권한 매트릭스', icon: KeyRound },
  {
    to: '/admin/ca', label: '인증서·신뢰(CA)', icon: ShieldCheck, children: [
      { to: '/admin/ca', label: '개요', icon: ShieldCheck, end: true },
      { to: '/admin/ca/issue', label: '발급·서명', icon: FilePlus2 },
      { to: '/admin/ca/certs', label: '인증서', icon: FileBadge },
      { to: '/admin/ca/recipients', label: '수신자', icon: Inbox },
      { to: '/admin/ca/audit', label: '감사', icon: History }
    ]
  },
  { to: '/admin/storage', label: '설정·스토리지', icon: Database }
];

const linkCls = (extra = '') => ({ isActive }: { isActive: boolean }) =>
  cn('flex items-center gap-2.5 px-5 py-2.5 text-sm text-foreground/80 transition-colors hover:bg-secondary', extra,
    isActive && 'border-l-[3px] border-accent bg-secondary pl-[17px] font-semibold text-primary');

function NavItem({ item }: { item: Item }) {
  return (
    <NavLink to={item.to} end={item.end} className={linkCls()}>
      <item.icon size={17} /> {item.label}
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
        className={cn('flex w-full items-center gap-2.5 px-5 py-2.5 text-sm text-foreground/80 transition-colors hover:bg-secondary',
          within && 'font-semibold text-primary')}
      >
        <item.icon size={17} /> {item.label}
        <ChevronRight size={15} className={cn('ml-auto transition-transform', open && 'rotate-90')} />
      </button>
      {open && item.children!.map((c) => (
        <NavLink key={c.to} to={c.to} end={c.end}
          className={linkCls('py-2 pl-12 text-[13px] text-foreground/70')}>
          <c.icon size={14} /> {c.label}
        </NavLink>
      ))}
    </div>
  );
}

function render(items: Item[]) {
  return items.map((i) => (i.children ? <NavGroup key={i.to} item={i} /> : <NavItem key={i.to} item={i} />));
}

function SectionLabel({ children }: { children: string }) {
  return (
    <div className="px-5 pb-1 pt-4 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
      {children}
    </div>
  );
}

// 제품·관리 공용 사이드바 — 아티팩트와 관리 콘솔 항목을 한 곳에 함께 노출(트리 구조).
// 관리 섹션은 확정 비-admin(BFF 세션 있고 admins 아님)일 때만 숨김(판별 불가면 노출, 실제 접근은 /admin 게이트가 강제).
export function Sidebar() {
  const [sess, setSess] = useState<Session | null | undefined>(undefined);

  useEffect(() => {
    getSession().then(setSess).catch(() => setSess(null));
  }, []);

  const showAdmin = !(sess && !sess.groups?.includes('admins'));

  return (
    <nav className="w-52 shrink-0 border-r bg-card pb-3">
      <SectionLabel>제품</SectionLabel>
      {render(PRODUCT)}
      {showAdmin && (
        <>
          <SectionLabel>관리 콘솔</SectionLabel>
          {render(ADMIN)}
        </>
      )}
    </nav>
  );
}
