import { useEffect, useState } from 'react';
import { UserPlus } from 'lucide-react';
import {
  adminUsers, adminGroups, adminCreateUser, adminSetUserGroup, type AdminUser
} from '@/lib/api';
import { Button, Input, Badge } from '@/components/ui/primitives';
import { PageTitle, SectionTitle, Loading, Alert, Table, Th, Td, selectCls } from './_ui';

export default function Users() {
  const [users, setUsers] = useState<AdminUser[] | null>(null);
  const [groups, setGroups] = useState<string[]>([]);
  const [err, setErr] = useState('');

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

      <Table>
        <thead>
          <tr><Th>사용자</Th><Th>이메일</Th><Th>그룹</Th><Th>그룹 변경</Th></tr>
        </thead>
        <tbody>
          {users.map((u) => (
            <UserRow key={u.id} u={u} groups={groups} onChange={changeGroup} />
          ))}
        </tbody>
      </Table>
    </>
  );
}

function UserRow({ u, groups, onChange }: { u: AdminUser; groups: string[]; onChange: (id: string, g: string) => void }) {
  const current = u.groups?.[0] || groups[0] || '';
  const [sel, setSel] = useState(current);
  return (
    <tr>
      <Td className="font-medium">{u.username}</Td>
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
