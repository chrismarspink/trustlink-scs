import { useEffect, useMemo, useState } from 'react';
import { UserPlus, Search, ChevronLeft, ChevronRight, ShieldCheck, Code, Handshake, Building2, User as UserIcon } from 'lucide-react';
import {
  adminUsers, adminGroups, adminCreateUser, adminSetUserGroup, type AdminUser
} from '@/lib/api';
import { Button, Input, Badge } from '@/components/ui/primitives';
import { PageTitle, SectionTitle, Loading, Alert, Table, Th, Td, selectCls } from './_ui';

const PER_PAGE = 8;

// 그룹(역할)별 아이콘·색상 — 사용자 아바타에 사용
const ROLE_META: Record<string, { icon: typeof UserIcon; cls: string }> = {
  admins: { icon: ShieldCheck, cls: 'bg-red-100 text-red-700' },
  developers: { icon: Code, cls: 'bg-blue-100 text-blue-700' },
  partners: { icon: Handshake, cls: 'bg-amber-100 text-amber-700' },
  customers: { icon: Building2, cls: 'bg-emerald-100 text-emerald-700' }
};

function Avatar({ user }: { user: AdminUser }) {
  const g = (user.groups || [])[0] || '';
  const meta = ROLE_META[g] || { icon: UserIcon, cls: 'bg-slate-100 text-slate-600' };
  const Icon = meta.icon;
  return (
    <span className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full ${meta.cls}`} title={g || '그룹 없음'}>
      <Icon size={16} />
    </span>
  );
}

export default function Users() {
  const [users, setUsers] = useState<AdminUser[] | null>(null);
  const [groups, setGroups] = useState<string[]>([]);
  const [err, setErr] = useState('');

  // 검색 + 페이지네이션
  const [q, setQ] = useState('');
  const [page, setPage] = useState(0);

  // 신규 생성 폼
  const [nu, setNu] = useState('');
  const [ne, setNe] = useState('');
  const [ng, setNg] = useState('');
  const [np, setNp] = useState('');
  const [busy, setBusy] = useState(false);

  async function load() {
    setErr('');
    try {
      const [us, gs] = await Promise.all([adminUsers(), adminGroups()]);
      setUsers(us);
      setGroups(gs);
      if (!ng && gs.length) setNg(gs[0]);
    } catch (e) {
      setErr(String(e));
    }
  }
  useEffect(() => { load(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const filtered = useMemo(() => {
    const k = q.trim().toLowerCase();
    const list = users || [];
    if (!k) return list;
    return list.filter((u) => u.username.toLowerCase().includes(k) || (u.email || '').toLowerCase().includes(k) || (u.groups || []).some((g) => g.toLowerCase().includes(k)));
  }, [users, q]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PER_PAGE));
  const cur = Math.min(page, totalPages - 1);
  const paged = filtered.slice(cur * PER_PAGE, cur * PER_PAGE + PER_PAGE);

  async function create() {
    if (!nu.trim()) { alert('username 을 입력하세요'); return; }
    setBusy(true);
    try {
      await adminCreateUser({ username: nu.trim(), email: ne.trim(), group: ng, password: np });
      setNu(''); setNe(''); setNp('');
      await load();
    } catch (e) {
      alert('생성 실패: ' + e);
    }
    setBusy(false);
  }

  async function changeGroup(id: string, group: string) {
    try {
      await adminSetUserGroup(id, group);
      await load();
    } catch (e) {
      alert('변경 실패: ' + e);
    }
  }

  if (err) return (<><PageTitle>사용자 관리</PageTitle><Alert tone="crit">오류: {err}</Alert></>);
  if (!users) return (<><PageTitle>사용자 관리</PageTitle><Loading /></>);

  return (
    <>
      <PageTitle>사용자 관리</PageTitle>

      <SectionTitle>신규 생성</SectionTitle>
      <div className="mb-5 flex flex-wrap items-center gap-2">
        <Input className="w-40" placeholder="username" value={nu} onChange={(e) => setNu(e.target.value)} />
        <Input className="w-56" placeholder="email (선택)" value={ne} onChange={(e) => setNe(e.target.value)} />
        <select className={selectCls} value={ng} onChange={(e) => setNg(e.target.value)}>
          {groups.map((g) => <option key={g} value={g}>{g}</option>)}
        </select>
        <Input className="w-52" placeholder="임시PW (기본 Passw0rd!)" value={np} onChange={(e) => setNp(e.target.value)} />
        <Button variant="accent" size="sm" onClick={create} disabled={busy}>
          <UserPlus size={15} /> {busy ? '생성중…' : '생성'}
        </Button>
      </div>

      <div className="mb-2 flex flex-wrap items-center gap-2">
        <div className="relative">
          <Search size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <Input className="w-64 pl-8" placeholder="사용자·이메일·그룹 검색" value={q} onChange={(e) => { setQ(e.target.value); setPage(0); }} />
        </div>
        <span className="ml-auto text-sm text-muted-foreground">총 {filtered.length}명{q && ` (필터)`}</span>
      </div>

      <Table>
        <thead>
          <tr><Th>사용자</Th><Th>이메일</Th><Th>그룹</Th><Th>그룹 변경</Th></tr>
        </thead>
        <tbody>
          {paged.map((u) => (
            <UserRow key={u.id} u={u} groups={groups} onChange={changeGroup} />
          ))}
          {paged.length === 0 && (
            <tr><Td className="text-muted-foreground" >검색 결과 없음</Td><Td> </Td><Td> </Td><Td> </Td></tr>
          )}
        </tbody>
      </Table>

      <div className="mt-3 flex items-center justify-end gap-2 text-sm">
        <span className="text-muted-foreground">{cur + 1} / {totalPages} 페이지</span>
        <Button size="sm" variant="outline" disabled={cur <= 0} onClick={() => setPage(cur - 1)}><ChevronLeft size={14} /> 이전</Button>
        <Button size="sm" variant="outline" disabled={cur >= totalPages - 1} onClick={() => setPage(cur + 1)}>다음 <ChevronRight size={14} /></Button>
      </div>
    </>
  );
}

function UserRow({ u, groups, onChange }: { u: AdminUser; groups: string[]; onChange: (id: string, g: string) => void }) {
  const current = u.groups?.[0] || groups[0] || '';
  const [sel, setSel] = useState(current);
  return (
    <tr className={u.enabled ? '' : 'opacity-60'}>
      <Td>
        <div className="flex items-center gap-2.5">
          <Avatar user={u} />
          <span className="font-medium">{u.username}</span>
          {!u.enabled && <Badge variant="muted">비활성</Badge>}
        </div>
      </Td>
      <Td className="text-muted-foreground">{u.email || ''}</Td>
      <Td>
        <div className="flex flex-wrap gap-1">
          {(u.groups || []).map((g) => <Badge key={g} variant="muted">{g}</Badge>)}
        </div>
      </Td>
      <Td>
        <div className="flex items-center gap-2">
          <select className={selectCls} value={sel} onChange={(e) => setSel(e.target.value)}>
            {groups.map((g) => <option key={g} value={g}>{g}</option>)}
          </select>
          <Button size="sm" variant="outline" onClick={() => onChange(u.id, sel)}>적용</Button>
        </div>
      </Td>
    </tr>
  );
}
