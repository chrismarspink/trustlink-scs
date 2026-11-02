import { useEffect, useState } from 'react';
import { Building2, Plus, Trash2, X, Mail } from 'lucide-react';
import { adminOrgs, adminCreateOrg, adminDeleteOrg, adminSetOrgContacts, type Org } from '@/lib/api';
import { Button, Input, Badge } from '@/components/ui/primitives';
import { PageTitle, SectionTitle, Loading, Alert, Table, Th, Td } from './_ui';

// 고객사 보안 담당 통보 주소: 계정이 없어도 VEX 발행(보안 판단) 통보 메일을 받는다.
function Contacts({ org, onSaved }: { org: Org; onSaved: () => void }) {
  const [v, setV] = useState('');
  const save = async (emails: string[]) => {
    try { await adminSetOrgContacts(org.name, emails); setV(''); onSaved(); } catch (e) { alert('저장 실패: ' + e); }
  };
  const add = () => {
    const e = v.trim();
    if (!e) return;
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) { alert('이메일 형식 오류'); return; }
    save([...org.contacts, e]);
  };
  return (
    <div className="space-y-1.5">
      <div className="flex flex-wrap gap-1">
        {org.contacts.map((c) => (
          <span key={c} className="inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-xs">
            <Mail size={11} className="text-muted-foreground" />{c}
            <button onClick={() => save(org.contacts.filter((x) => x !== c))} title="삭제" className="text-muted-foreground hover:text-foreground"><X size={11} /></button>
          </span>
        ))}
      </div>
      <Input className="h-7 w-56 text-xs" placeholder="security@고객사.com + Enter" value={v}
        onChange={(e) => setV(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && add()} />
    </div>
  );
}

// 고객사(조직) = Keycloak 그룹 org-<ID>. 소속은 '사용자', 받을 수 있는 제품은 '제품 권한'에서 지정.
export default function Orgs() {
  const [orgs, setOrgs] = useState<Org[] | null>(null);
  const [err, setErr] = useState('');
  const [name, setName] = useState('');

  async function load() {
    setErr('');
    try {
      setOrgs((await adminOrgs()).sort((a, b) => a.name.localeCompare(b.name)));
    } catch (e) {
      setErr(String(e));
    }
  }
  useEffect(() => { load(); }, []);

  // 서버 규칙(reOrgName)과 동일 — 비었거나 형식이 틀리면 버튼 비활성 + 안내.
  const valid = /^[a-z0-9][a-z0-9-]{1,30}$/.test(name.trim().toLowerCase());

  async function create() {
    const n = name.trim().toLowerCase();
    if (!valid) return;
    try {
      await adminCreateOrg(n);
      setName('');
      await load();
    } catch (e) {
      alert('추가 실패: ' + e);
    }
  }

  async function remove(o: Org) {
    if (!confirm(`고객사 ${o.name} 를 삭제할까요?\n소속 ${o.members.length}명의 소속이 해제되고, 이 고객사의 제품 권한(${o.products.length}개)도 함께 제거됩니다.\n(사용자 계정 자체는 삭제되지 않습니다)`)) return;
    try {
      await adminDeleteOrg(o.name);
      await load();
    } catch (e) {
      alert('삭제 실패: ' + e);
    }
  }

  if (err) return (<><PageTitle>고객사</PageTitle><Alert tone="crit">오류: {err}</Alert></>);
  if (!orgs) return (<><PageTitle>고객사</PageTitle><Loading /></>);

  return (
    <>
      <PageTitle>고객사</PageTitle>
      <p className="mb-4 text-sm text-muted-foreground">
        외부 사용자는 고객사 단위로 제품 다운로드 권한을 받습니다. 소속은 <b>사용자</b> 메뉴, 받을 수 있는 제품은 <b>제품 권한</b> 메뉴에서 지정합니다.
        제품의 보안 판단(VEX)이 발행되면 소속 사용자의 이메일과 <b>통보 주소</b>로 메일이 갑니다.
      </p>

      <SectionTitle>추가</SectionTitle>
      <div className="mb-5 flex items-center gap-2">
        <Input className="w-64" placeholder="고객사 ID (예: acme)" value={name}
          onChange={(e) => setName(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && create()} />
        <Button variant="accent" size="sm" onClick={create} disabled={!valid}
          title={valid ? '' : '고객사 ID 를 먼저 입력하세요'}><Plus size={15} /> 추가</Button>
        <span className={name.trim() && !valid ? 'text-xs text-red-600' : 'text-xs text-muted-foreground'}>
          {name.trim() && !valid ? '형식 오류: ' : ''}영소문자·숫자·- (2~31자)
        </span>
      </div>

      <Table>
        <thead>
          <tr><Th>고객사</Th><Th>소속 사용자</Th><Th>보안 통보 주소</Th><Th>다운로드 가능 제품</Th><Th>관리</Th></tr>
        </thead>
        <tbody>
          {orgs.map((o) => (
            <tr key={o.name}>
              <Td>
                <div className="flex items-center gap-2.5">
                  <span className="flex h-8 w-8 items-center justify-center rounded-full bg-emerald-100 text-emerald-700"><Building2 size={16} /></span>
                  <span className="font-medium">{o.name}</span>
                </div>
              </Td>
              <Td>
                <div className="space-y-0.5">
                  {o.members.map((m) => (
                    <div key={m} className="text-xs">
                      <span className="font-medium">{m}</span>{' '}
                      {o.emails?.[m] ? <span className="text-muted-foreground">{o.emails[m]}</span>
                        : <span className="text-amber-700">이메일 없음</span>}
                    </div>
                  ))}
                  {o.members.length === 0 && <span className="text-xs text-muted-foreground">-</span>}
                </div>
              </Td>
              <Td>
                <Contacts org={o} onSaved={load} />
                {(() => {
                  const n = o.members.filter((m) => o.emails?.[m]).length + o.contacts.length;
                  return <div className={n ? 'mt-1 text-xs text-muted-foreground' : 'mt-1 text-xs text-amber-700'}>{n ? `메일 받는 곳 ${n}` : '메일 받는 곳 없음 — 통보를 받지 못함'}</div>;
                })()}
              </Td>
              <Td>
                <div className="flex flex-wrap gap-1">
                  {o.products.map((p) => <Badge key={p} variant="success">{p}</Badge>)}
                  {o.products.length === 0 && <span className="text-xs text-muted-foreground">없음</span>}
                </div>
              </Td>
              <Td><Button size="sm" variant="outline" onClick={() => remove(o)} title="삭제"><Trash2 size={14} /></Button></Td>
            </tr>
          ))}
          {orgs.length === 0 && <tr><Td className="text-muted-foreground">고객사 없음</Td><Td> </Td><Td> </Td><Td> </Td><Td> </Td></tr>}
        </tbody>
      </Table>
    </>
  );
}
