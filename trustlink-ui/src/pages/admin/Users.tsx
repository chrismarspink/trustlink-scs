import { useEffect, useMemo, useState } from 'react';
import {
  UserPlus, Search, ChevronLeft, ChevronRight, ShieldCheck, Code, Building2, User as UserIcon, KeyRound,
  Pencil, Trash2, Check, X
} from 'lucide-react';
import {
  adminUsers, adminOrgs, adminCreateUser, adminUpdateUser, adminDeleteUser, adminResetPassword, adminCICredential,
  ROLES, ORG_PREFIX, type AdminUser
} from '@/lib/api';
import { Button, Input, Badge } from '@/components/ui/primitives';
import { PageTitle, SectionTitle, Loading, Alert, Table, Th, Td, selectCls } from './_ui';
import CredentialDialog, { type CredentialInfo } from './CredentialDialog';

const PER_PAGE = 8;

// 역할(그룹) — 사용자당 1개. 고객사(org-*)는 여러 개 가능.
const ROLE_META: Record<string, { label: string; desc: string; icon: typeof UserIcon; cls: string }> = {
  admins: { label: '관리자', desc: '전체 관리', icon: ShieldCheck, cls: 'bg-red-100 text-red-700' },
  developers: { label: '내부 개발자', desc: '업로드·다운로드', icon: Code, cls: 'bg-blue-100 text-blue-700' },
  users: { label: '외부 사용자', desc: '허용된 제품 다운로드', icon: Building2, cls: 'bg-emerald-100 text-emerald-700' }
};

const roleOf = (u: AdminUser) => (u.groups || []).find((g) => (ROLES as readonly string[]).includes(g)) || '';
const orgsOf = (u: AdminUser) => (u.groups || []).filter((g) => g.startsWith(ORG_PREFIX)).map((g) => g.slice(ORG_PREFIX.length));
const otherGroupsOf = (u: AdminUser) => (u.groups || []).filter((g) => !(ROLES as readonly string[]).includes(g) && !g.startsWith(ORG_PREFIX));

function Avatar({ role }: { role: string }) {
  const meta = ROLE_META[role] || { icon: UserIcon, cls: 'bg-slate-100 text-slate-600' };
  const Icon = meta.icon;
  return (
    <span className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full ${meta.cls}`}>
      <Icon size={16} />
    </span>
  );
}

// 고객사 다중 선택(체크 칩)
function OrgPicker({ all, value, onChange }: { all: string[]; value: string[]; onChange: (v: string[]) => void }) {
  if (all.length === 0) return <span className="text-xs text-muted-foreground">고객사 없음(고객사 메뉴에서 추가)</span>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {all.map((o) => {
        const on = value.includes(o);
        return (
          <button key={o} type="button"
            onClick={() => onChange(on ? value.filter((x) => x !== o) : [...value, o])}
            className={`rounded-full border px-2.5 py-0.5 text-xs ${on ? 'border-emerald-600 bg-emerald-50 text-emerald-700' : 'text-muted-foreground hover:bg-secondary'}`}>
            {on && <Check size={11} className="mr-0.5 inline" />}{o}
          </button>
        );
      })}
    </div>
  );
}

function RoleSelect({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <select className={selectCls} value={value} onChange={(e) => onChange(e.target.value)}>
      {ROLES.map((r) => <option key={r} value={r}>{ROLE_META[r].label} — {ROLE_META[r].desc}</option>)}
    </select>
  );
}

export default function Users() {
  const [users, setUsers] = useState<AdminUser[] | null>(null);
  const [orgs, setOrgs] = useState<string[]>([]);
  const [err, setErr] = useState('');
  const [q, setQ] = useState('');
  const [page, setPage] = useState(0);

  // 신규 생성 폼
  const [nu, setNu] = useState('');
  const [ne, setNe] = useState('');
  const [nr, setNr] = useState<string>('users');
  const [no, setNo] = useState<string[]>([]);
  const [np, setNp] = useState('');
  const [busy, setBusy] = useState(false);

  // 자격 전달 창(발급 직후 1회 표시)
  const [cred, setCred] = useState<CredentialInfo | null>(null);

  async function load() {
    setErr('');
    try {
      const [us, os] = await Promise.all([adminUsers(), adminOrgs()]);
      setUsers(us);
      setOrgs(os.map((o) => o.name).sort());
    } catch (e) {
      setErr(String(e));
    }
  }
  useEffect(() => { load(); }, []);

  const filtered = useMemo(() => {
    const k = q.trim().toLowerCase();
    const list = (users || []).slice().sort((a, b) => a.username.localeCompare(b.username));
    if (!k) return list;
    return list.filter((u) => u.username.toLowerCase().includes(k) || (u.email || '').toLowerCase().includes(k) || (u.groups || []).some((g) => g.toLowerCase().includes(k)));
  }, [users, q]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PER_PAGE));
  const cur = Math.min(page, totalPages - 1);
  const paged = filtered.slice(cur * PER_PAGE, cur * PER_PAGE + PER_PAGE);

  async function create() {
    if (!nu.trim()) { alert('username 을 입력하세요'); return; }
    if (nr === 'users' && no.length === 0 && !confirm('고객사를 지정하지 않으면 이 외부 사용자는 아무 제품도 볼 수 없습니다. 계속할까요?')) return;
    setBusy(true);
    try {
      const r = await adminCreateUser({ username: nu.trim(), email: ne.trim(), role: nr, orgs: no, password: np });
      setCred({ kind: 'user', username: r.username, password: r.password, group: nr });
      setNu(''); setNe(''); setNp(''); setNo([]);
      await load();
    } catch (e) {
      alert('생성 실패: ' + e);
    }
    setBusy(false);
  }

  async function resetPassword(u: AdminUser) {
    if (!confirm(`${u.username} 의 비밀번호를 새 임시 비밀번호로 재설정할까요?\n기존 비밀번호는 즉시 사용할 수 없게 됩니다.`)) return;
    try {
      const r = await adminResetPassword(u.id, u.username);
      setCred({ kind: 'user', username: r.username, password: r.password, group: roleOf(u) });
    } catch (e) {
      alert('재설정 실패: ' + e);
    }
  }

  async function showCI() {
    try {
      const r = await adminCICredential();
      setCred({ kind: 'ci', username: r.username, password: r.password });
    } catch (e) {
      alert('조회 실패: ' + e);
    }
  }

  async function save(u: AdminUser, role: string, os: string[]) {
    try {
      await adminUpdateUser(u.id, { username: u.username, role, orgs: os });
      await load();
    } catch (e) {
      alert('변경 실패: ' + e);
    }
  }

  async function toggleEnabled(u: AdminUser) {
    const next = !u.enabled;
    if (!confirm(`${u.username} 를 ${next ? '활성화' : '비활성화(로그인 차단)'}할까요?`)) return;
    try {
      await adminUpdateUser(u.id, { username: u.username, enabled: next });
      await load();
    } catch (e) {
      alert('변경 실패: ' + e);
    }
  }

  async function remove(u: AdminUser) {
    if (!confirm(`${u.username} 계정을 삭제할까요? 되돌릴 수 없습니다.\n(일시 차단은 '비활성'을 사용하세요)`)) return;
    try {
      await adminDeleteUser(u.id, u.username);
      await load();
    } catch (e) {
      alert('삭제 실패: ' + e);
    }
  }

  if (err) return (<><PageTitle>사용자 관리</PageTitle><Alert tone="crit">오류: {err}</Alert></>);
  if (!users) return (<><PageTitle>사용자 관리</PageTitle><Loading /></>);

  return (
    <>
      <PageTitle>사용자 관리</PageTitle>
      {cred && <CredentialDialog cred={cred} onClose={() => setCred(null)} />}

      <SectionTitle>신규 생성</SectionTitle>
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <Input className="w-40" placeholder="username" value={nu} onChange={(e) => setNu(e.target.value)} />
        <Input className="w-56" placeholder="email (선택)" value={ne} onChange={(e) => setNe(e.target.value)} />
        <RoleSelect value={nr} onChange={setNr} />
        <Input className="w-52" placeholder="임시PW (비우면 자동 생성)" value={np} onChange={(e) => setNp(e.target.value)} />
        <Button variant="accent" size="sm" onClick={create} disabled={busy}>
          <UserPlus size={15} /> {busy ? '생성중…' : '생성'}
        </Button>
      </div>
      <div className="mb-5 flex items-center gap-3">
        <span className="text-sm text-muted-foreground">고객사</span>
        <OrgPicker all={orgs} value={no} onChange={setNo} />
      </div>

      <SectionTitle>업로드(CI) 계정</SectionTitle>
      <div className="mb-5 flex flex-wrap items-center gap-3">
        <span className="text-sm text-muted-foreground">기본 공용 업로드 계정 ci(.env). 제품별 계정은 '기계 계정' 메뉴에서 발급합니다.</span>
        <Button size="sm" variant="outline" onClick={showCI}><KeyRound size={14} /> 계정 정보 전달</Button>
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
          <tr><Th>사용자</Th><Th>역할</Th><Th>고객사</Th><Th>상태</Th><Th>관리</Th></tr>
        </thead>
        <tbody>
          {paged.map((u) => (
            <UserRow key={u.id} u={u} orgs={orgs} onSave={save} onReset={resetPassword} onToggle={toggleEnabled} onDelete={remove} />
          ))}
          {paged.length === 0 && (
            <tr><Td className="text-muted-foreground">검색 결과 없음</Td><Td> </Td><Td> </Td><Td> </Td><Td> </Td></tr>
          )}
        </tbody>
      </Table>

      <div className="mt-3 flex items-center justify-end gap-2 text-sm">
        <span className="text-muted-foreground">{cur + 1} / {totalPages} 페이지</span>
        <Button size="sm" variant="outline" disabled={cur <= 0} onClick={() => setPage(cur - 1)}><ChevronLeft size={14} /> 이전</Button>
        <Button size="sm" variant="outline" disabled={cur >= totalPages - 1} onClick={() => setPage(cur + 1)}>다음 <ChevronRight size={14} /></Button>
      </div>
      <p className="mt-3 text-xs text-muted-foreground">역할·고객사 변경은 해당 사용자가 다음에 로그인할 때 적용됩니다.</p>
    </>
  );
}

function UserRow({ u, orgs, onSave, onReset, onToggle, onDelete }: {
  u: AdminUser; orgs: string[];
  onSave: (u: AdminUser, role: string, orgs: string[]) => void;
  onReset: (u: AdminUser) => void; onToggle: (u: AdminUser) => void; onDelete: (u: AdminUser) => void;
}) {
  const role = roleOf(u);
  const [editing, setEditing] = useState(false);
  const [r, setR] = useState(role || 'users');
  const [os, setOs] = useState<string[]>(orgsOf(u));
  const others = otherGroupsOf(u);
  return (
    <tr className={u.enabled ? '' : 'opacity-60'}>
      <Td>
        <div className="flex items-center gap-2.5">
          <Avatar role={role} />
          <div>
            <div className="font-medium">{u.username}</div>
            <div className="text-xs text-muted-foreground">{u.email || ''}</div>
          </div>
        </div>
      </Td>
      <Td>
        {editing ? <RoleSelect value={r} onChange={setR} />
          : role ? <Badge variant="muted">{ROLE_META[role].label}</Badge> : <span className="text-xs text-red-600">역할 없음</span>}
        {others.length > 0 && <div className="mt-1 text-xs text-muted-foreground">기타: {others.join(', ')}</div>}
      </Td>
      <Td>
        {editing ? <OrgPicker all={orgs} value={os} onChange={setOs} />
          : (
            <div className="flex flex-wrap gap-1">
              {orgsOf(u).map((o) => <Badge key={o} variant="success">{o}</Badge>)}
              {orgsOf(u).length === 0 && <span className="text-xs text-muted-foreground">-</span>}
            </div>
          )}
      </Td>
      <Td>
        <button onClick={() => onToggle(u)} title="클릭하여 전환">
          <Badge variant={u.enabled ? 'success' : 'danger'}>{u.enabled ? '활성' : '비활성'}</Badge>
        </button>
      </Td>
      <Td>
        <div className="flex flex-wrap items-center gap-1.5">
          {editing ? (
            <>
              <Button size="sm" variant="accent" onClick={() => { onSave(u, r, os); setEditing(false); }}><Check size={14} /> 저장</Button>
              <Button size="sm" variant="outline" onClick={() => { setEditing(false); setR(role || 'users'); setOs(orgsOf(u)); }}><X size={14} /> 취소</Button>
            </>
          ) : (
            <>
              <Button size="sm" variant="outline" onClick={() => setEditing(true)}><Pencil size={14} /> 편집</Button>
              <Button size="sm" variant="outline" onClick={() => onReset(u)}><KeyRound size={14} /> 재설정</Button>
              <Button size="sm" variant="outline" onClick={() => onDelete(u)} title="삭제"><Trash2 size={14} /></Button>
            </>
          )}
        </div>
      </Td>
    </tr>
  );
}
