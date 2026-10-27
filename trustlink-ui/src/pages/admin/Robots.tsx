import { useEffect, useState } from 'react';
import { Bot, Plus, RefreshCw, Trash2, Check } from 'lucide-react';
import {
  adminRobots, adminCreateRobot, adminReissueRobot, adminDeleteRobot, adminProductAccess, type RobotAccount
} from '@/lib/api';
import { Button, Input, Badge } from '@/components/ui/primitives';
import { PageTitle, SectionTitle, Loading, Alert, Table, Th, Td, selectCls } from './_ui';
import CredentialDialog, { type CredentialInfo } from './CredentialDialog';

// 기계 계정: 사람이 아닌 시스템이 oras 로 접속할 때 쓰는 ID + 비밀값.
//   업로드용(ci-…)  = 빌드 서버 → 지정 제품에 쓰기
//   다운로드용(robot-…) = 고객사 시스템 → 지정 제품 읽기
const KIND = {
  push: { label: '업로드용 (빌드 서버)', prefix: 'ci-' },
  pull: { label: '다운로드용 (고객 시스템)', prefix: 'robot-' }
} as const;

const fmtDate = (s: string) => (s ? s.slice(0, 10) : '무기한');

export default function Robots() {
  const [list, setList] = useState<RobotAccount[] | null>(null);
  const [repos, setRepos] = useState<string[]>([]);
  const [err, setErr] = useState('');
  const [cred, setCred] = useState<CredentialInfo | null>(null);

  const [kind, setKind] = useState<'push' | 'pull'>('pull');
  const [suffix, setSuffix] = useState('');
  const [prods, setProds] = useState<string[]>([]);
  const [days, setDays] = useState(365);
  const [note, setNote] = useState('');

  async function load() {
    setErr('');
    try {
      const [rs, ps] = await Promise.all([adminRobots(), adminProductAccess()]);
      setList(rs.sort((a, b) => a.name.localeCompare(b.name)));
      setRepos(ps.map((p) => p.repo));
    } catch (e) {
      setErr(String(e));
    }
  }
  useEffect(() => { load(); }, []);

  async function create() {
    const name = KIND[kind].prefix + suffix.trim().toLowerCase();
    if (!suffix.trim()) { alert('이름을 입력하세요'); return; }
    if (prods.length === 0 && !confirm('제품을 지정하지 않으면 이 계정은 아무 제품에도 접근할 수 없습니다(제품 권한에서 나중에 지정 가능). 계속할까요?')) return;
    try {
      const r = await adminCreateRobot({ name, kind, products: prods, days, note });
      setCred({ kind: 'robot', username: r.username, password: r.password, robotKind: r.kind, products: r.products, expires: r.expires });
      setSuffix(''); setProds([]); setNote('');
      await load();
    } catch (e) {
      alert('발급 실패: ' + e);
    }
  }

  async function reissue(r: RobotAccount) {
    if (!confirm(`${r.name} 의 토큰을 재발급할까요?\n기존 토큰은 즉시 사용할 수 없게 됩니다(연결된 시스템 설정을 바꿔야 함).`)) return;
    try {
      const x = await adminReissueRobot(r.name);
      setCred({ kind: 'robot', username: x.username, password: x.password, robotKind: x.kind, products: r.products, expires: x.expires });
      await load();
    } catch (e) {
      alert('토큰 재발급 실패: ' + e);
    }
  }

  async function remove(r: RobotAccount) {
    if (!confirm(`${r.name} 를 폐기할까요? 즉시 로그인할 수 없게 되고 모든 제품 권한에서 제거됩니다.`)) return;
    try {
      await adminDeleteRobot(r.name);
      await load();
    } catch (e) {
      alert('폐기 실패: ' + e);
    }
  }

  if (err) return (<><PageTitle>기계 계정</PageTitle><Alert tone="crit">오류: {err}</Alert></>);
  if (!list) return (<><PageTitle>기계 계정</PageTitle><Loading /></>);

  return (
    <>
      <PageTitle>기계 계정</PageTitle>
      {cred && <CredentialDialog cred={cred} onClose={() => setCred(null)} />}
      <p className="mb-4 text-sm text-muted-foreground">
        사람이 아닌 시스템이 oras 로 접속할 때 쓰는 계정입니다. 인증 토큰은 발급·재발급 때 한 번만 표시되며, 만료일이 지나면 자동으로 로그인이 차단됩니다.
      </p>

      <SectionTitle>발급</SectionTitle>
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <select className={selectCls} value={kind} onChange={(e) => setKind(e.target.value as 'push' | 'pull')}>
          {(Object.keys(KIND) as ('push' | 'pull')[]).map((k) => <option key={k} value={k}>{KIND[k].label}</option>)}
        </select>
        <div className="flex items-center">
          <span className="rounded-l-md border border-r-0 bg-secondary px-2 py-1.5 font-mono text-sm">{KIND[kind].prefix}</span>
          <Input className="w-44 rounded-l-none" placeholder={kind === 'push' ? 'npouch' : 'acme'} value={suffix} onChange={(e) => setSuffix(e.target.value)} />
        </div>
        <select className={selectCls} value={days} onChange={(e) => setDays(Number(e.target.value))}>
          <option value={90}>90일</option><option value={180}>180일</option><option value={365}>1년</option><option value={0}>무기한</option>
        </select>
        <Input className="w-56" placeholder="메모 (예: ACME 배포서버)" value={note} onChange={(e) => setNote(e.target.value)} />
        <Button variant="accent" size="sm" onClick={create}><Plus size={15} /> 발급</Button>
      </div>
      <div className="mb-5 flex items-start gap-3">
        <span className="pt-0.5 text-sm text-muted-foreground">{kind === 'push' ? '업로드할 제품' : '다운로드할 제품'}</span>
        <div className="flex flex-wrap gap-1.5">
          {repos.map((p) => {
            const on = prods.includes(p);
            return (
              <button key={p} type="button" onClick={() => setProds(on ? prods.filter((x) => x !== p) : [...prods, p])}
                className={`rounded-full border px-2.5 py-0.5 text-xs ${on ? 'border-emerald-600 bg-emerald-50 text-emerald-700' : 'text-muted-foreground hover:bg-secondary'}`}>
                {on && <Check size={11} className="mr-0.5 inline" />}{p}
              </button>
            );
          })}
        </div>
      </div>

      <Table>
        <thead>
          <tr><Th>계정</Th><Th>용도</Th><Th>제품</Th><Th>만료</Th><Th>발급</Th><Th>관리</Th></tr>
        </thead>
        <tbody>
          {list.map((r) => (
            <tr key={r.name} className={r.valid ? '' : 'opacity-60'}>
              <Td>
                <div className="flex items-center gap-2.5">
                  <span className="flex h-8 w-8 items-center justify-center rounded-full bg-slate-100 text-slate-600"><Bot size={16} /></span>
                  <div>
                    <div className="font-mono font-medium">{r.name}</div>
                    {r.note && <div className="text-xs text-muted-foreground">{r.note}</div>}
                  </div>
                </div>
              </Td>
              <Td><Badge variant={r.kind === 'push' ? 'muted' : 'success'}>{r.kind === 'push' ? '업로드' : '다운로드'}</Badge></Td>
              <Td>
                <div className="flex flex-wrap gap-1">
                  {r.products.map((p) => <Badge key={p} variant="muted">{p}</Badge>)}
                  {r.products.length === 0 && <span className="text-xs text-muted-foreground">없음</span>}
                </div>
              </Td>
              <Td>{r.valid ? fmtDate(r.expires) : <Badge variant="danger">만료됨</Badge>}</Td>
              <Td className="text-xs text-muted-foreground">{fmtDate(r.created)}<br />{r.createdBy}</Td>
              <Td>
                <div className="flex gap-1.5">
                  <Button size="sm" variant="outline" onClick={() => reissue(r)}><RefreshCw size={14} /> 토큰 재발급</Button>
                  <Button size="sm" variant="outline" onClick={() => remove(r)} title="폐기"><Trash2 size={14} /></Button>
                </div>
              </Td>
            </tr>
          ))}
          {list.length === 0 && <tr><Td className="text-muted-foreground">발급된 기계 계정 없음</Td><Td> </Td><Td> </Td><Td> </Td><Td> </Td><Td> </Td></tr>}
        </tbody>
      </Table>
    </>
  );
}
