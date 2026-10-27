import { useEffect, useState } from 'react';
import { Save, RotateCcw, X, Package } from 'lucide-react';
import {
  adminProductAccess, adminSetProductAccess, adminResetProductAccess, adminPrincipals, ORG_PREFIX,
  type ProductAccess, type Principal
} from '@/lib/api';
import { Button, Badge } from '@/components/ui/primitives';
import { PageTitle, Loading, Alert, Table, Th, Td, selectCls } from './_ui';

// 제품 권한: 제품(레포)마다 업로드(쓰기)·다운로드(읽기) 대상을 지정한다.
// 저장하면 BFF 가 zot 설정(accessControl)으로 렌더 → zot 이 즉시 반영하고 oras·웹 모두 같은 규칙으로 판정.
const key = (p: Principal) => `${p.type}:${p.name}`;

function principalLabel(p: Principal): string {
  if (p.type === 'group') {
    if (p.name === 'developers') return '내부 개발자';
    if (p.name === 'users') return '외부 사용자 전체';
    if (p.name === 'admins') return '관리자';
    if (p.name.startsWith(ORG_PREFIX)) return `고객사 ${p.name.slice(ORG_PREFIX.length)}`;
    return p.name;
  }
  return p.name === 'ci' ? 'ci (공용)' : `기계 ${p.name}`;
}

function Chips({ list, onRemove, tone }: { list: Principal[]; onRemove: (p: Principal) => void; tone: 'muted' | 'success' }) {
  return (
    <div className="flex flex-wrap gap-1">
      {list.map((p) => (
        <Badge key={key(p)} variant={tone} className="gap-1">
          {principalLabel(p)}
          <button onClick={() => onRemove(p)} aria-label="제거"><X size={11} /></button>
        </Badge>
      ))}
      {list.length === 0 && <span className="text-xs text-muted-foreground">없음</span>}
    </div>
  );
}

function AddSelect({ options, exclude, onAdd }: { options: Principal[]; exclude: Principal[]; onAdd: (p: Principal) => void }) {
  const avail = options.filter((o) => !exclude.some((e) => key(e) === key(o)));
  return (
    <select className={`${selectCls} mt-1.5 h-8 text-xs`} value=""
      onChange={(e) => { const o = avail.find((x) => key(x) === e.target.value); if (o) onAdd(o); }}>
      <option value="">+ 추가…</option>
      {avail.map((o) => <option key={key(o)} value={key(o)}>{principalLabel(o)}</option>)}
    </select>
  );
}

export default function Access() {
  const [rows, setRows] = useState<ProductAccess[] | null>(null);
  const [opts, setOpts] = useState<Principal[]>([]);
  const [dirty, setDirty] = useState<Record<string, boolean>>({});
  const [err, setErr] = useState('');

  async function load() {
    setErr('');
    try {
      const [ps, pr] = await Promise.all([adminProductAccess(), adminPrincipals()]);
      setRows(ps);
      setOpts([
        ...pr.groups.filter((g) => g !== 'admins').map((g) => ({ type: 'group' as const, name: g })),
        ...pr.users.map((u) => ({ type: 'user' as const, name: u }))
      ]);
      setDirty({});
    } catch (e) {
      setErr(String(e));
    }
  }
  useEffect(() => { load(); }, []);

  function edit(repo: string, fn: (r: ProductAccess) => ProductAccess) {
    setRows((rs) => (rs || []).map((r) => (r.repo === repo ? fn(r) : r)));
    setDirty((d) => ({ ...d, [repo]: true }));
  }

  async function save(r: ProductAccess) {
    if (r.readers.some((p) => p.type === 'group' && p.name === 'users') &&
      !confirm('"외부 사용자 전체"에 읽기를 주면 모든 고객사가 이 제품을 받을 수 있습니다. 계속할까요?')) return;
    try {
      await adminSetProductAccess({ repo: r.repo, writers: r.writers, readers: r.readers });
      await load();
    } catch (e) {
      alert('저장 실패: ' + e);
    }
  }

  async function reset(r: ProductAccess) {
    if (!confirm(`${r.repo} 의 개별 권한을 지우고 기본 규칙(내부 전용)으로 되돌릴까요?`)) return;
    try {
      await adminResetProductAccess(r.repo);
      await load();
    } catch (e) {
      alert('실패: ' + e);
    }
  }

  if (err) return (<><PageTitle>제품 권한</PageTitle><Alert tone="crit">오류: {err}</Alert></>);
  if (!rows) return (<><PageTitle>제품 권한</PageTitle><Loading /></>);

  return (
    <>
      <PageTitle>제품 권한</PageTitle>
      <p className="mb-4 text-sm text-muted-foreground">
        제품마다 <b>업로드(쓰기)</b>와 <b>다운로드(읽기)</b> 대상을 지정합니다. 저장 즉시 레지스트리(oras)와 웹에 같은 규칙으로 적용됩니다.
        개별 설정이 없는 제품은 기본 규칙(내부 개발자·ci 만)이 적용되어 외부에 보이지 않습니다. 관리자는 항상 전체 권한입니다.
      </p>
      <Table>
        <thead>
          <tr><Th>제품</Th><Th>업로드(쓰기)</Th><Th>다운로드(읽기)</Th><Th>관리</Th></tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.repo}>
              <Td>
                <div className="flex items-center gap-2">
                  <Package size={15} className="text-muted-foreground" />
                  <span className="font-medium">{r.repo}</span>
                </div>
                <div className="mt-1">
                  {r.explicit ? <Badge variant="success">개별 설정</Badge> : <Badge variant="muted">기본(내부 전용)</Badge>}
                  {dirty[r.repo] && <Badge variant="warn" className="ml-1">저장 안 됨</Badge>}
                </div>
              </Td>
              <Td>
                {r.explicit || dirty[r.repo]
                  ? <Chips list={r.writers} tone="muted" onRemove={(p) => edit(r.repo, (x) => ({ ...x, writers: x.writers.filter((w) => key(w) !== key(p)) }))} />
                  : <span className="text-xs text-muted-foreground">내부 개발자, ci (기본)</span>}
                <AddSelect options={opts.filter((o) => o.type === 'user' ? !o.name.startsWith('robot-') : o.name === 'developers')}
                  exclude={r.writers}
                  onAdd={(p) => edit(r.repo, (x) => ({
                    ...x,
                    // 기본 규칙에서 개별 설정으로 처음 전환할 때는 기존 업로드 대상(개발자·ci)을 이어받는다
                    writers: [...(x.explicit || dirty[r.repo] ? x.writers : [{ type: 'group' as const, name: 'developers' }, { type: 'user' as const, name: 'ci' }].filter((d) => key(d) !== key(p))), p]
                  }))} />
              </Td>
              <Td>
                <Chips list={r.readers} tone="success" onRemove={(p) => edit(r.repo, (x) => ({ ...x, readers: x.readers.filter((w) => key(w) !== key(p)) }))} />
                <AddSelect options={opts.filter((o) => o.type === 'group' ? o.name !== 'developers' : !o.name.startsWith('ci'))}
                  exclude={r.readers}
                  onAdd={(p) => edit(r.repo, (x) => ({
                    ...x,
                    writers: x.explicit || dirty[r.repo] ? x.writers : [{ type: 'group', name: 'developers' }, { type: 'user', name: 'ci' }],
                    readers: [...x.readers, p]
                  }))} />
              </Td>
              <Td>
                <div className="flex flex-wrap gap-1.5">
                  <Button size="sm" variant="accent" disabled={!dirty[r.repo]} onClick={() => save(r)}><Save size={14} /> 저장</Button>
                  {r.explicit && <Button size="sm" variant="outline" onClick={() => reset(r)} title="기본 규칙으로"><RotateCcw size={14} /></Button>}
                </div>
              </Td>
            </tr>
          ))}
          {rows.length === 0 && <tr><Td className="text-muted-foreground">레지스트리에 제품이 없습니다</Td><Td> </Td><Td> </Td><Td> </Td></tr>}
        </tbody>
      </Table>
    </>
  );
}
