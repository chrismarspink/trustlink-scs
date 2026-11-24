import { useEffect, useState } from 'react';
import { Link, NavLink, useLocation } from 'react-router-dom';
import type { LucideIcon } from 'lucide-react';
import {
  Package, BookOpen, LayoutDashboard, Users, HardDrive,
  ScrollText, Boxes, Activity, KeyRound, Database,
  ChevronRight, Home, Rocket, Download, Bug, Building2, ShieldCheck, Bot, LogOut, Bell, UserCog, DatabaseZap, ClipboardCheck, Sparkles, Landmark, Archive, GitBranch, ShieldQuestion, Contact, Megaphone, PackageCheck, Workflow, Inbox, Send } from 'lucide-react';
import { bffLogin, getSession, logout, type Session } from '@/lib/api';
import { cn } from '@/lib/utils';

declare const __APP_VERSION__: string;

type Sub = { to: string; label: string; icon: LucideIcon; end?: boolean };
// open: 하위 트리를 처음부터 펼쳐 둔다(자주 쓰는 묶음). 아니면 그 안의 화면에 있을 때만 펼침.
type Item = { to: string; label: string; icon: LucideIcon; end?: boolean; open?: boolean; children?: Sub[] };

// 제품(레지스트리) 섹션 — 항상 노출. "문서"는 하위 트리.
// 맨 위(구역 이름 없음): 홈 · 문서
const TOP: Item[] = [
  { to: '/', label: '홈', icon: Home, end: true },
  {
    to: '/docs', label: '문서', icon: BookOpen, children: [
      { to: '/docs', label: '시작하기', icon: Rocket, end: true },
      { to: '/docs/share', label: '업로드·다운로드', icon: Download },
      { to: '/docs/vuln', label: '취약점·VEX', icon: Bug },
      { to: '/docs/rbac', label: '권한·참고', icon: KeyRound }
    ]
  }
];
// 제품: 아티팩트 · 내 제품 · VEX 판단 · 내 API 키 (내 제품·VEX 판단은 권한에 따라)
const ARTIFACTS_ITEM: Item = { to: '/artifacts', label: '아티팩트', icon: Package };
const APIKEY_ITEM: Item = { to: '/apikeys', label: '내 API 키', icon: KeyRound };
const VEX_ITEM: Item = { to: '/vex', label: 'VEX 판단', icon: ShieldQuestion };
const MY_ITEM: Item = { to: '/my', label: '내 제품', icon: PackageCheck };
// 관리 콘솔 — admins 일 때. 제품 개념 "납품 소프트웨어의 신뢰 장부"의 칸대로 묶는다:
//   결정(사람이 할 일) · 릴리스(무엇을 줬나) · 고객(누가 쓰나) · 신호(무엇이 바뀌었나) · 전달·기록(누구에게 알렸나) · 설정.
// 주소는 그대로 두고 위치와 이름만 바꾼다(기존 링크가 깨지지 않게).
const DECIDE: Item[] = [
  { to: '/admin/inbox', label: '승인 대기함', icon: Inbox },
  { to: '/admin', label: '대시보드', icon: LayoutDashboard, end: true },
];
const RELEASE: Item[] = [
  { to: '/admin/registry', label: '레지스트리', icon: Boxes },
  { to: '/admin/upstream', label: '공개 저장소 분석', icon: GitBranch },
];
const CUSTOMER: Item[] = [
  { to: '/admin/customers', label: '고객 등록부', icon: Contact },
  {
    to: '/admin/accounts', label: '계정 및 권한', icon: UserCog, children: [
      { to: '/admin/users', label: '사용자', icon: Users },
      { to: '/admin/orgs', label: '고객사', icon: Building2 },
      { to: '/admin/access', label: '제품 권한', icon: ShieldCheck },
      { to: '/admin/robots', label: '자동화 계정', icon: Bot },
      { to: '/admin/acl', label: '권한 매트릭스', icon: KeyRound }
    ]
  },
];
const SIGNAL: Item[] = [
  { to: '/admin/auto-response', label: '자동 대응', icon: Workflow },
  { to: '/admin/mirror', label: '취약점 DB 미러', icon: DatabaseZap },
  { to: '/admin/regs', label: '규제 카탈로그·탐색', icon: Landmark },
  { to: '/admin/compliance', label: '규제 대응 검증', icon: ClipboardCheck },
];
const DELIVER: Item[] = [
  { to: '/admin/outbox', label: '발송함', icon: Send },
  { to: '/admin/customer-notify', label: '고객 통지', icon: Megaphone },
  { to: '/admin/notify', label: '취약점 통보', icon: Bell },
  { to: '/admin/reports', label: '보고서함', icon: Archive },
  { to: '/admin/logs', label: '로그', icon: ScrollText }
];
const SETTINGS: Item[] = [
  { to: '/admin/system', label: '시스템 상태', icon: Activity },
  { to: '/admin/capacity', label: '용량', icon: HardDrive },
  { to: '/admin/ai', label: 'AI 연결', icon: Sparkles },
  { to: '/admin/storage', label: '설정·스토리지', icon: Database }
];
const ADMIN_SECTIONS: [string, Item[]][] = [['승인·판단', DECIDE], ['릴리스', RELEASE], ['고객', CUSTOMER], ['취약점·규제 대응', SIGNAL], ['전달·기록', DELIVER], ['설정', SETTINGS]];

const matches = (pathname: string, it: Sub) => (it.end ? pathname === it.to : pathname === it.to || pathname.startsWith(it.to + '/'));

// 현재 경로의 [섹션, (묶음,) 메뉴명] — 상단 경로 표시용
export function navTrail(pathname: string): string[] | null {
  const hit = (items: Item[]) => {
    let best: string[] | null = null, len = 0;
    for (const i of items) {
      for (const [it, trail] of [[i, [i.label]] as const, ...(i.children || []).map((c) => [c, [i.label, c.label]] as const)]) {
        if (matches(pathname, it) && it.to.length > len) { best = [...trail]; len = it.to.length; }
      }
    }
    return best;
  };
  for (const [name, items] of ADMIN_SECTIONS) {
    const a = hit(items);
    if (a) return [name, ...a];
  }
  if (pathname.startsWith('/artifact/')) return ['제품', '아티팩트'];
  const p = hit([ARTIFACTS_ITEM, MY_ITEM, VEX_ITEM, APIKEY_ITEM]);
  if (p) return ['제품', ...p];
  return hit(TOP);
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
  const within = matches(loc.pathname, item) || item.children!.some((c) => matches(loc.pathname, c));
  const [open, setOpen] = useState(within || !!item.open);
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

  const showAdmin = !!sess?.groups?.includes('admins');
  // VEX 판단 대기열: 보안·개발·관리자(VEX 편집 권한)에게만
  // 내 제품: 고객사 사용자용(로그인 사용자 모두에게 보이되 서버가 본인 고객사로 제한)
  const product = [ARTIFACTS_ITEM, ...(sess ? [MY_ITEM] : []), ...(sess?.canEditVex ? [VEX_ITEM] : []), APIKEY_ITEM];

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
      <nav className="flex-1 space-y-0.5 overflow-y-auto pb-3">
        <div className="pt-2">{render(TOP)}</div>
        <SectionLabel>제품</SectionLabel>
        {render(product)}
        {showAdmin && (
          <>
            {ADMIN_SECTIONS.map(([name, items]) => (
              <div key={name}>
                <SectionLabel>{name}</SectionLabel>
                {render(items)}
              </div>
            ))}
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
    </>
  );
}
