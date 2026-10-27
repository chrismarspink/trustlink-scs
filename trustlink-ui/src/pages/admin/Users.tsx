import { useEffect, useMemo, useState } from 'react';
import { UserPlus, Search, ChevronLeft, ChevronRight, KeyRound, MoreHorizontal, Pencil, Ban, CircleCheck, Trash2, Check } from 'lucide-react';
import {
  adminUsers, adminOrgs, adminCreateUser, adminUpdateUser, adminDeleteUser, adminResetPassword, adminCICredential,
  ROLES, ORG_PREFIX, type AdminUser
} from '@/lib/api';
import { Button, Input, Badge, Label, StatusDot } from '@/components/ui/primitives';
import { DropdownMenu, DropdownMenuTrigger, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator } from '@/components/ui/dropdown-menu';
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription, SheetBody, SheetFooter } from '@/components/ui/sheet';
import { PageHeader, PageTitle, Loading, Alert, Table, Th, Td, selectCls } from './_ui';
import CredentialDialog, { type CredentialInfo } from './CredentialDialog';

const PER_PAGE = 10;

// 역할(그룹) — 사용자당 1개. 고객사(org-*)는 여러 개 가능.
const ROLE_META: Record<string, { label: string; desc: string }> = {
  admins: { label: '관리자', desc: '전체 관리' },
  developers: { label: '내부 개발자', desc: '업로드·다운로드' },
  users: { label: '외부 사용자', desc: '허용된 제품 다운로드' }
};

const roleOf = (u: AdminUser) => (u.groups || []).find((g) => (ROLES as readonly string[]).includes(g)) || '';
const orgsOf = (u: AdminUser) => (u.groups || []).filter((g) => g.startsWith(ORG_PREFIX)).map((g) => g.slice(ORG_PREFIX.length));
const otherGroupsOf = (u: AdminUser) => (u.groups || []).filter((g) => !(ROLES as readonly string[]).includes(g) && !g.startsWith(ORG_PREFIX));

// 고객사 다중 선택(체크 칩)
function OrgPicker({ all, value, onChange }: { all: string[]; value: string[]; onChange: (v: string[]) => void }) {
  if (all.length === 0) return <p className="text-sm text-muted-foreground">등록된 고객사가 없습니다. 고객사 메뉴에서 먼저 추가하세요.</p>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {all.map((o) => {
        const on = value.includes(o);
        return (
          <button key={o} type="button"
            onClick={() => onChange(on ? value.filter((x) => x !== o) : [...value, o])}
            className={`inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs ${on ? 'border-primary bg-primary text-primary-foreground' : 'hover:bg-secondary'}`}>
            {on && <Check size={12} />}{o}
          </button>
        );
      })}
    </div>
  );
}

// 생성·편집 패널 상태
type Form = { mode: 'create' } | { mode: 'edit'; user: AdminUser };

export default function Users() {
  const [users, setUsers] = useState<AdminUser[] | null>(null);
  const [orgs, setOrgs] = useState<string[]>([]);
  const [err, setErr] = useState('');
  const [q, setQ] = useState('');
  const [roleFilter, setRoleFilter] = useState('');
  const [page, setPage] = useState(0);

  const [form, setForm] = useState<Form | null>(null);
  const [fu, setFu] = useState('');
  const [fe, setFe] = useState('');
  const [fr, setFr] = useState<string>('users');
  const [fo, setFo] = useState<string[]>([]);
  const [fp, setFp] = useState('');
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
    return (users || [])
      .slice()
      .sort((a, b) => a.username.localeCompare(b.username))
      .filter((u) => !roleFilter || roleOf(u) === roleFilter)
      .filter((u) => !k || u.username.toLowerCase().includes(k) || (u.email || '').toLowerCase().includes(k) || (u.groups || []).some((g) => g.toLowerCase().includes(k)));
  }, [users, q, roleFilter]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PER_PAGE));
  const cur = Math.min(page, totalPages - 1);
  const paged = filtered.slice(cur * PER_PAGE, cur * PER_PAGE + PER_PAGE);

  function openCreate() {
    setFu(''); setFe(''); setFr('users'); setFo([]); setFp('');
    setForm({ mode: 'create' });
  }
  function openEdit(u: AdminUser) {
    setFu(u.username); setFe(u.email || ''); setFr(roleOf(u) || 'users'); setFo(orgsOf(u)); setFp('');
    setForm({ mode: 'edit', user: u });
  }

  async function submit() {
    if (!form) return;
    if (form.mode === 'create' && !fu.trim()) { alert('아이디를 입력하세요'); return; }
    if (fr === 'users' && fo.length === 0 && !confirm('고객사를 지정하지 않으면 이 외부 사용자는 아무 제품도 볼 수 없습니다. 계속할까요?')) return;
    setBusy(true);
    try {
      if (form.mode === 'create') {
        const r = await adminCreateUser({ username: fu.trim(), email: fe.trim(), role: fr, orgs: fo, password: fp });
        setCred({ kind: 'user', username: r.username, password: r.password, group: fr });
      } else {
        await adminUpdateUser(form.user.id, { username: form.user.username, role: fr, orgs: fo });
      }
      setForm(null);
      await load();
    } catch (e) {
      alert((form.mode === 'create' ? '생성' : '변경') + ' 실패: ' + e);
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
    if (!confirm(`${u.username} 계정을 삭제할까요? 되돌릴 수 없습니다.\n(일시 차단은 '비활성화'를 사용하세요)`)) return;
    try {
      await adminDeleteUser(u.id, u.username);
      await load();
    } catch (e) {
      alert('삭제 실패: ' + e);
    }
  }

  if (err) return (<><PageTitle>사용자</PageTitle><Alert tone="crit">오류: {err}</Alert></>);
  if (!users) return (<><PageTitle>사용자</PageTitle><Loading /></>);

  return (
    <>
      <PageHeader
        title="사용자"
        description="TrustLink에 로그인하는 사람 계정입니다. 고객은 고객사에 소속시켜야 제품을 받을 수 있습니다."
        actions={
          <>
            <Button variant="outline" onClick={showCI} title="기본 공용 업로드 계정 ci 의 정보를 전달합니다"><KeyRound size={15} /> 공용 CI 계정</Button>
            <Button onClick={openCreate}><UserPlus size={15} /> 사용자 추가</Button>
          </>
        }
      />
      {cred && <CredentialDialog cred={cred} onClose={() => setCred(null)} />}

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="relative">
          <Search size={15} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <Input className="w-72 pl-8" placeholder="이름, 이메일, 고객사 검색" value={q} onChange={(e) => { setQ(e.target.value); setPage(0); }} />
        </div>
        <select className={selectCls} value={roleFilter} onChange={(e) => { setRoleFilter(e.target.value); setPage(0); }}>
          <option value="">모든 역할</option>
          {ROLES.map((r) => <option key={r} value={r}>{ROLE_META[r].label}</option>)}
        </select>
        <span className="ml-auto text-sm text-muted-foreground">{filtered.length}명</span>
      </div>

      <Table>
        <thead>
          <tr><Th>사용자</Th><Th>역할</Th><Th>고객사</Th><Th>상태</Th><Th className="w-12" /></tr>
        </thead>
        <tbody>
          {paged.map((u) => {
            const role = roleOf(u);
            const os = orgsOf(u);
            const others = otherGroupsOf(u);
            return (
              <tr key={u.id} className="hover:bg-secondary/40">
                <Td>
                  <div className="flex items-center gap-3">
                    <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-secondary text-xs font-medium uppercase text-muted-foreground">
                      {u.username.slice(0, 2)}
                    </span>
                    <div>
                      <div className="font-medium">{u.username}</div>
                      <div className="text-xs text-muted-foreground">{u.email || ''}</div>
                    </div>
                  </div>
                </Td>
                <Td>
                  {role ? ROLE_META[role].label : <span className="text-red-600">역할 없음</span>}
                  {others.length > 0 && <div className="text-xs text-muted-foreground">기타 그룹: {others.join(', ')}</div>}
                </Td>
                <Td>
                  {os.length > 0
                    ? <div className="flex flex-wrap gap-1">{os.map((o) => <Badge key={o} variant="outline">{o}</Badge>)}</div>
                    : role === 'users'
                      ? <span className="text-xs text-amber-600" title="고객사가 없으면 아무 제품도 볼 수 없습니다">미지정</span>
                      : <span className="text-zinc-300">—</span>}
                </Td>
                <Td><StatusDot tone={u.enabled ? 'ok' : 'off'}>{u.enabled ? '활성' : '비활성'}</StatusDot></Td>
                <Td className="text-right">
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="ghost" size="icon" aria-label={`${u.username} 작업`}><MoreHorizontal size={16} /></Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" className="w-48">
                      <DropdownMenuItem onSelect={() => openEdit(u)}><Pencil /> 역할·고객사 편집</DropdownMenuItem>
                      <DropdownMenuItem onSelect={() => resetPassword(u)}><KeyRound /> 비밀번호 재설정</DropdownMenuItem>
                      <DropdownMenuItem onSelect={() => toggleEnabled(u)}>
                        {u.enabled ? <><Ban /> 비활성화</> : <><CircleCheck /> 활성화</>}
                      </DropdownMenuItem>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem destructive onSelect={() => remove(u)}><Trash2 /> 삭제</DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </Td>
              </tr>
            );
          })}
          {paged.length === 0 && (
            <tr><Td className="h-24 text-center text-muted-foreground" colSpan={5}>검색 결과가 없습니다.</Td></tr>
          )}
        </tbody>
      </Table>

      <div className="mt-3 flex items-center justify-between text-sm text-muted-foreground">
        <span>역할·고객사 변경은 해당 사용자가 다음에 로그인할 때 웹 화면에 적용됩니다.</span>
        <div className="flex items-center gap-2">
          <span>{cur + 1} / {totalPages}</span>
          <Button size="sm" variant="outline" disabled={cur <= 0} onClick={() => setPage(cur - 1)}><ChevronLeft size={14} /> 이전</Button>
          <Button size="sm" variant="outline" disabled={cur >= totalPages - 1} onClick={() => setPage(cur + 1)}>다음 <ChevronRight size={14} /></Button>
        </div>
      </div>

      <Sheet open={!!form} onOpenChange={(o) => !o && setForm(null)}>
        <SheetContent>
          <SheetHeader>
            <SheetTitle>{form?.mode === 'edit' ? `${form.user.username} 편집` : '사용자 추가'}</SheetTitle>
            <SheetDescription>
              {form?.mode === 'edit' ? '역할과 소속 고객사를 바꿉니다.' : '생성하면 임시 비밀번호가 발급됩니다. 첫 로그인 때 본인이 변경합니다.'}
            </SheetDescription>
          </SheetHeader>
          <SheetBody>
            <div className="space-y-2">
              <Label htmlFor="fu">아이디</Label>
              <Input id="fu" value={fu} onChange={(e) => setFu(e.target.value)} disabled={form?.mode === 'edit'} placeholder="예: kim.minsu" />
            </div>
            {form?.mode === 'create' && (
              <div className="space-y-2">
                <Label htmlFor="fe">이메일 <span className="font-normal text-muted-foreground">(선택)</span></Label>
                <Input id="fe" type="email" value={fe} onChange={(e) => setFe(e.target.value)} />
              </div>
            )}
            <div className="space-y-2">
              <Label>역할</Label>
              <div className="grid gap-2">
                {ROLES.map((r) => (
                  <label key={r} className={`flex cursor-pointer items-center gap-3 rounded-md border px-3 py-2.5 text-sm ${fr === r ? 'border-primary ring-1 ring-primary' : ''}`}>
                    <input type="radio" name="role" className="accent-zinc-900" checked={fr === r} onChange={() => setFr(r)} />
                    <span className="font-medium">{ROLE_META[r].label}</span>
                    <span className="text-muted-foreground">{ROLE_META[r].desc}</span>
                  </label>
                ))}
              </div>
            </div>
            <div className="space-y-2">
              <Label>고객사</Label>
              <OrgPicker all={orgs} value={fo} onChange={setFo} />
              {fr === 'users' && <p className="text-xs text-muted-foreground">외부 사용자는 소속 고객사에 허용된 제품만 받을 수 있습니다.</p>}
            </div>
            {form?.mode === 'create' && (
              <div className="space-y-2">
                <Label htmlFor="fp">임시 비밀번호 <span className="font-normal text-muted-foreground">(비우면 자동 생성)</span></Label>
                <Input id="fp" value={fp} onChange={(e) => setFp(e.target.value)} />
              </div>
            )}
          </SheetBody>
          <SheetFooter>
            <Button variant="outline" onClick={() => setForm(null)}>취소</Button>
            <Button onClick={submit} disabled={busy}>{busy ? '처리 중…' : form?.mode === 'edit' ? '저장' : '추가'}</Button>
          </SheetFooter>
        </SheetContent>
      </Sheet>
    </>
  );
}
