import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { Busy, DownloadLink } from '@/components/Progress';
import { Building2, Plus, Trash2, Pencil, Users, Package, CalendarClock, AlertTriangle, Mail, Phone, RefreshCw, Save, X } from 'lucide-react';
import {
  adminCustomers, adminCustomerSave, adminCustomerDelete, adminCustomerProduct, adminCustomerSettings, adminCustomerExpiring, adminCustomerExpiryCheck,
  adminOrgs, adminUsers, searchRepos, adminCustomerStatus, adminCustomerLogo, adminCustomerLogoDelete, CUST_DISABLE_REASONS, adminCustomerUndelete, adminCustomerPurge, adminCustomersRestore, CUST_INDUSTRIES, INDUSTRY_CLS,
  type CustDisableReason,
  type Customer, type CustomerView, type CustContact, type CustUsage, type CustExpiry, type VerPolicy, type CustSettings, type ExpiryRec, type CustNotifyKind
} from '@/lib/api';
import { Button, Input, Badge, Card, CardContent, Label } from '@/components/ui/primitives';
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription, SheetBody, SheetFooter } from '@/components/ui/sheet';
import { PageHeader, SectionTitle, Loading, Alert, Table, Th, Td, selectCls } from './_ui';
import { cn } from '@/lib/utils';
import { CompanyLogo } from '@/components/CompanyLogo';

// 관리 › 고객 등록부: 고객(CRM 카드) — 담당자 · 제품 사용(설치 버전·계약·유지보수·통지 정책) · 우리 쪽 담당.
// 만료 D-day 와 "다운로드 기록 추정 버전 ≠ 등록 버전(확인 필요)"을 한눈에 보여 준다. 고객사 그룹(Keycloak)은 이름으로만 연결.

const INDUSTRIES = CUST_INDUSTRIES;
const Ind = ({ v }: { v: string }) => <span className={cn('rounded px-1.5 py-px text-[11px] font-medium', INDUSTRY_CLS[v] || INDUSTRY_CLS['일반'])}>{v}</span>;
const ROLES: Record<CustContact['role'], string> = { security: '보안', itops: 'IT 운영', purchase: '구매', other: '기타' };
const KINDS: Record<CustNotifyKind, string> = { vuln: '취약점', vex: 'VEX', incident: '사고', patch: '패치', eos: 'EOS', contract: '계약' };
const ENVS = ['운영', 'DR', '검증', '개발'] as const;
const LIC: Record<string, string> = { '': '—', perpetual: '영구', subscription: '구독', term: '기간제' };
const LEVELS: Record<CustUsage['notifyLevel'], string> = { critical_kev: 'CRITICAL·KEV 만', high: 'HIGH 이상·KEV', all: '전부' };
const EXP_KIND: Record<CustExpiry['kind'], string> = { license: '라이선스', maint: '유지보수', eos: 'EOS' };
const base = (r: string) => r.split('/').pop() || r;
const fmt = (t?: string) => (t ? new Date(t).toLocaleString('ko-KR') : '—');

function DDay({ days, label }: { days: number; label?: string }) {
  const cls = days < 0 ? 'bg-red-600 text-white' : days <= 7 ? 'bg-red-100 text-red-800' : days <= 30 ? 'bg-amber-100 text-amber-800' : days <= 90 ? 'bg-yellow-50 text-yellow-800' : 'bg-slate-100 text-slate-600';
  return (
    <span className={cn('inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-semibold tabular-nums', cls)}>
      <CalendarClock size={11} />{label && <span>{label}</span>}{days < 0 ? `만료 D+${-days}` : days === 0 ? 'D-DAY' : `D-${days}`}
    </span>
  );
}

function NeedCheck({ n }: { n: number }) {
  return <span className="inline-flex items-center gap-1 rounded-full bg-orange-100 px-2 py-0.5 text-[11px] font-semibold text-orange-800"><AlertTriangle size={11} />확인 필요 {n}</span>;
}

const emptyUsage = (): CustUsage => ({ repo: '', installs: [{ tag: '', env: '운영', qty: 1 }], notifyLevel: 'high', licenseType: '', notifyContacts: [] });
const emptyCustomer = (): Customer => ({ id: '', name: '', industry: '일반', lang: 'ko', contacts: [], usages: [] });

export default function Customers() {
  const [data, setData] = useState<{ customers: CustomerView[]; products: Record<string, VerPolicy[]>; settings: CustSettings } | null>(null);
  const [err, setErr] = useState('');
  const [tab, setTab] = useState<'list' | 'expiring' | 'versions' | 'trash'>('list');
  const [sel, setSel] = useState('');
  const [form, setForm] = useState<{ c: Customer; isNew: boolean } | null>(null);
  const [q, setQ] = useState('');
  const [showOff, setShowOff] = useState(false); // 중지된 회사도 보기
  const [ind, setInd] = useState(''); // 업종 거르기
  const load = () => adminCustomers().then((d) => { setData(d); setErr(''); }).catch((e) => setErr(String(e)));
  useEffect(() => { load(); }, []);

  const offCount = (data?.customers || []).filter((c) => c.disabled && !c.deleted).length;
  const trash = (data?.customers || []).filter((c) => c.deleted);
  const list = useMemo(() => (data?.customers || []).filter((c) => !c.deleted && (showOff || !c.disabled) && (!ind || c.industry === ind)).filter((c) => !q || (c.name + c.id + c.orgGroup + c.usages.map((u) => u.repo).join(' ')).toLowerCase().includes(q.toLowerCase())), [data, q, showOff, ind]);
  const cur = data?.customers.find((c) => c.id === sel);

  const restore = async (f: File) => {
    let j: { customers?: unknown[]; exportedAt?: string };
    try { j = JSON.parse(await f.text()); } catch { alert('백업 파일을 읽을 수 없습니다'); return; }
    const n = String(j.customers?.length ?? '?'), at = j.exportedAt || '';
    if (!confirm(`백업(${at ? new Date(at).toLocaleString('ko-KR') : '시각 모름'}, 고객 ${n}곳)으로 고객 정보를 바꿀까요?\n\n지금 고객 목록·버전 정책·설정이 백업 내용으로 바뀝니다(통지 이력은 그대로).\n지금 상태는 서버에 따로 저장해 두므로 필요하면 되돌릴 수 있습니다.`)) return;
    try { const r = await adminCustomersRestore(f); alert(`복원했습니다 — 고객 ${r.customers}곳, 로고 ${r.logos}개.\n이전 상태 사본: ${r.previousCopy}`); setSel(''); load(); } catch (e) { alert('복원 실패: ' + e); }
  };
  const del = async (c: Customer) => {
    if (!confirm(`${c.name} 고객을 삭제할까요?\n\n휴지통(삭제된 고객 탭)으로 옮겨지며 언제든 되살릴 수 있습니다.\n삭제된 동안에는 고객 통지·만료 알림·내 제품에서 빠집니다.`)) return;
    try { await adminCustomerDelete(c.id); setSel(''); load(); } catch (e) { alert('삭제 실패: ' + e); }
  };

  return (
    <>
      <PageHeader title="고객 등록부" description="고객별 담당자·설치 버전·계약·유지보수·통지 정책. 패치 권고는 이 등록부를 기준으로 영향 고객을 찾습니다."
        actions={<div className="flex flex-wrap gap-2">
          <DownloadLink href="/api/customers-backup" className="inline-flex h-9 items-center gap-1.5 rounded-md border px-3 text-sm hover:bg-secondary" title="고객(휴지통 포함)·버전 정책·설정·로고를 JSON 파일 하나로">백업 받기</DownloadLink>
          <label className="inline-flex h-9 cursor-pointer items-center gap-1.5 rounded-md border px-3 text-sm hover:bg-secondary" title="백업 파일로 고객 정보를 되돌립니다">
            복원…
            <input type="file" accept="application/json,.json" className="hidden" onChange={(e) => { const f = e.target.files?.[0]; e.target.value = ''; if (f) restore(f); }} />
          </label>
          <Button onClick={() => setForm({ c: emptyCustomer(), isNew: true })}><Plus size={14} />고객 추가</Button>
        </div>} />
      {err && <Alert tone="crit">오류: {err}</Alert>}
      <div className="mb-4 flex gap-1 border-b">
        {([['list', '고객 목록', Building2], ['expiring', '만료 예정', CalendarClock], ['versions', '제품 버전 정책', Package], ['trash', `삭제된 고객${trash.length ? ` ${trash.length}` : ''}`, Trash2]] as const).map(([k, l, I]) => (
          <button key={k} onClick={() => setTab(k)} className={cn('-mb-px inline-flex items-center gap-1.5 border-b-2 px-3 py-2 text-sm', tab === k ? 'border-primary font-semibold' : 'border-transparent text-muted-foreground hover:text-foreground', k === 'trash' && 'ml-auto')}>
            <I size={14} />{l}
          </button>
        ))}
      </div>
      {!data ? <Loading /> : tab === 'trash' ? <TrashPanel items={trash} onChanged={load} /> : tab === 'expiring' ? <ExpiringPanel settings={data.settings} onSettings={load} /> : tab === 'versions' ? (
        <VersionPolicy products={data.products} repos={[...new Set(data.customers.flatMap((c) => c.usages.map((u) => u.repo)))]} onSaved={load} />
      ) : (
        <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
          <div>
            <div className="mb-2 flex items-center gap-2">
              <Input placeholder="고객·제품·그룹 검색" value={q} onChange={(e) => setQ(e.target.value)} />
              <select className={cn(selectCls, 'shrink-0')} value={ind} onChange={(e) => setInd(e.target.value)} title="업종">
                <option value="">모든 업종</option>
                {INDUSTRIES.filter((x) => (data?.customers || []).some((c) => !c.deleted && c.industry === x)).map((x) => <option key={x}>{x}</option>)}
              </select>
              {offCount > 0 && (
                <label className="flex shrink-0 items-center gap-1.5 text-xs text-muted-foreground" title="폐업·관계 종료·계약 해지로 중지한 회사">
                  <input type="checkbox" checked={showOff} onChange={(e) => setShowOff(e.target.checked)} />중지된 회사 {offCount}곳 보기
                </label>
              )}
            </div>
            <Table>
              <thead><tr><Th>고객</Th><Th>제품</Th><Th>만료·확인</Th></tr></thead>
              <tbody>
                {list.length === 0 ? <tr><Td colSpan={3} className="text-center text-muted-foreground">등록된 고객이 없습니다.</Td></tr> : list.map((c) => {
                  const soon = c.expiry.filter((e) => e.days <= 90).slice(0, 2);
                  return (
                    <tr key={c.id} onClick={() => setSel(c.id)} className={cn('cursor-pointer hover:bg-secondary/60', sel === c.id && 'bg-secondary', c.disabled && 'text-muted-foreground')}>
                      <Td>
                        <div className="flex items-center gap-2.5">
                          <CompanyLogo logo={c.logo} disabled={c.disabled} size={30} />
                          <div className="min-w-0">
                            <div className="font-medium">{c.name}</div>
                            <div className="mt-0.5 flex flex-wrap gap-1 text-xs text-muted-foreground">
                              {c.disabled && <Badge variant="outline">중지 · {CUST_DISABLE_REASONS[c.disabledReason || 'other']}</Badge>}
                              <Ind v={c.industry} />{c.pilot && <Badge variant="outline" title="내부 검증(사전 배포) 고객 — 통지를 먼저 받습니다">내부검증</Badge>}{c.lang === 'en' && <Badge variant="outline">EN</Badge>}{c.orgGroup && <span>{c.orgGroup}</span>}
                            </div>
                          </div>
                        </div>
                      </Td>
                      <Td className="text-xs">{c.usages.map((u) => base(u.repo)).join(', ') || '—'}</Td>
                      <Td>
                        <div className="flex flex-wrap gap-1">
                          {soon.map((e, i) => <DDay key={i} days={e.days} label={EXP_KIND[e.kind]} />)}
                          {c.mismatch.length > 0 && <NeedCheck n={c.mismatch.length} />}
                          {soon.length === 0 && c.mismatch.length === 0 && <span className="text-xs text-muted-foreground">—</span>}
                        </div>
                      </Td>
                    </tr>
                  );
                })}
              </tbody>
            </Table>
          </div>
          <div>{cur ? <CustomerCard c={cur} products={data.products} onEdit={() => setForm({ c: structuredClone(cur), isNew: false })} onDelete={() => del(cur)} onChanged={load} />
            : <Card><CardContent className="p-8 text-center text-sm text-muted-foreground">왼쪽에서 고객을 고르세요.</CardContent></Card>}</div>
        </div>
      )}
      {form && <CustomerForm init={form.c} isNew={form.isNew} onClose={() => setForm(null)} onSaved={(id) => { setForm(null); setSel(id); load(); }} />}
    </>
  );
}

// ---------- 삭제된 고객(휴지통) ----------

function TrashPanel({ items, onChanged }: { items: CustomerView[]; onChanged: () => void }) {
  const [err, setErr] = useState('');
  const undo = async (c: Customer) => { setErr(''); try { await adminCustomerUndelete(c.id); onChanged(); } catch (e) { setErr(String(e)); } };
  const purge = async (c: Customer) => {
    const typed = prompt(`완전 삭제하면 되살릴 수 없습니다(백업 파일로만 복원).\n확인을 위해 고객 이름을 그대로 입력하세요:\n\n${c.name}`);
    if (typed === null) return;
    if (typed.trim() !== c.name) { setErr('이름이 달라 완전 삭제하지 않았습니다.'); return; }
    setErr(''); try { await adminCustomerPurge(c.id, typed.trim()); onChanged(); } catch (e) { setErr(String(e)); }
  };
  return (
    <div>
      <p className="mb-3 text-sm text-muted-foreground">삭제한 고객은 여기 모입니다. <b>되살리기</b>로 원래대로 돌리거나, 이름을 확인한 뒤 <b>완전 삭제</b>합니다. 완전 삭제 전에 위의 <b>백업 받기</b>를 권합니다.</p>
      {err && <Alert tone="crit">{err}</Alert>}
      <Table>
        <thead><tr><Th>고객</Th><Th>삭제한 때</Th><Th>삭제한 사람</Th><Th className="w-56" /></tr></thead>
        <tbody>
          {items.length === 0 ? <tr><Td colSpan={4} className="text-center text-muted-foreground">삭제된 고객이 없습니다.</Td></tr> : items.map((c) => (
            <tr key={c.id}>
              <Td><div className="flex items-center gap-2.5"><CompanyLogo logo={c.logo} size={28} disabled /><div><div className="font-medium">{c.name}</div><div className="text-xs text-muted-foreground">ID {c.id}{c.orgGroup ? ` · ${c.orgGroup}` : ''}</div></div></div></Td>
              <Td className="text-sm">{fmt(c.deletedAt)}</Td>
              <Td className="text-sm">{c.deletedBy || '—'}</Td>
              <Td className="text-right">
                <div className="flex justify-end gap-1">
                  <Button size="sm" variant="outline" onClick={() => undo(c)}>되살리기</Button>
                  <Button size="sm" variant="ghost" className="text-red-600 hover:bg-red-50" onClick={() => purge(c)}><Trash2 size={13} />완전 삭제</Button>
                </div>
              </Td>
            </tr>
          ))}
        </tbody>
      </Table>
    </div>
  );
}

// ---------- 상세 카드 ----------

function Field({ k, v }: { k: string; v?: ReactNode }) {
  return <div className="flex gap-2 text-sm"><span className="w-24 shrink-0 text-muted-foreground">{k}</span><span className="min-w-0 break-words">{v || '—'}</span></div>;
}

// 회사 사용/중지 + 로고
function StatusLogo({ c, onChanged }: { c: CustomerView; onChanged: () => void }) {
  const [off, setOff] = useState(false); // 중지 입력 열림
  const [reason, setReason] = useState<CustDisableReason>('terminated');
  const [note, setNote] = useState('');
  const [err, setErr] = useState('');
  const run = async (f: () => Promise<unknown>) => { setErr(''); try { await f(); setOff(false); onChanged(); } catch (e) { setErr(String(e)); } };
  return (
    <div className="space-y-2">
      {c.disabled ? (
        <div className="flex flex-wrap items-center gap-2 rounded-md border border-slate-300 bg-slate-50 p-3 text-sm">
          <span className="font-medium">중지됨 · {CUST_DISABLE_REASONS[c.disabledReason || 'other']}</span>
          <span className="text-xs text-muted-foreground">{fmt(c.disabledAt)} · {c.disabledBy}{c.disabledNote ? ` · ${c.disabledNote}` : ''}</span>
          <span className="flex-1" />
          <Button size="sm" variant="outline" onClick={() => run(() => adminCustomerStatus(c.id, true))}>다시 사용</Button>
          <p className="w-full text-xs text-muted-foreground">고객 통지·만료 알림·고객 전용 "내 제품" 화면에서 빠졌습니다. 소속 계정과 제품 권한은 그대로이니 필요하면 계정 및 권한에서 따로 정리하세요.</p>
        </div>
      ) : off ? (
        <div className="space-y-2 rounded-md border border-amber-200 bg-amber-50 p-3 text-sm">
          <div className="font-medium">이 회사를 중지합니다 — 지우지 않고 기록은 남깁니다</div>
          <div className="flex flex-wrap gap-2">
            {(Object.keys(CUST_DISABLE_REASONS) as CustDisableReason[]).map((k) => (
              <label key={k} className="flex items-center gap-1"><input type="radio" checked={reason === k} onChange={() => setReason(k)} />{CUST_DISABLE_REASONS[k]}</label>
            ))}
          </div>
          <Input placeholder="메모(선택) — 예: 2026-11 계약 해지 통보" value={note} onChange={(e) => setNote(e.target.value)} />
          <div className="flex gap-2">
            <Button size="sm" onClick={() => run(() => adminCustomerStatus(c.id, false, reason, note))}>중지</Button>
            <Button size="sm" variant="ghost" onClick={() => setOff(false)}>취소</Button>
          </div>
        </div>
      ) : null}
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <label className="cursor-pointer rounded-md border px-2 py-1 hover:bg-secondary">
          로고 {c.logo ? '바꾸기' : '올리기'}
          <input type="file" accept="image/png,image/jpeg,image/webp,image/gif" className="hidden"
            onChange={(e) => { const f = e.target.files?.[0]; if (f) run(() => adminCustomerLogo(c.id, f)); e.target.value = ''; }} />
        </label>
        {c.logo && <button className="rounded-md border px-2 py-1 hover:bg-secondary" onClick={() => run(() => adminCustomerLogoDelete(c.id))}>로고 지우기</button>}
        <span className="text-muted-foreground">PNG·JPEG·WebP·GIF, 512KB 이하 · 서버에만 저장</span>
        <span className="flex-1" />
        {!c.disabled && !off && <Button size="sm" variant="ghost" onClick={() => setOff(true)} title="폐업·관계 종료·계약 해지">사용 중지…</Button>}
      </div>
      {err && <Alert tone="crit">{err}</Alert>}
    </div>
  );
}

// 담당자 명함: 회사 로고·이름 / 이름·직함·부서 / 연락처 / 받는 통지
function BizCard({ ct, company, logo }: { ct: CustContact; company: string; logo?: string }) {
  return (
    <div className="flex aspect-[1.75] min-h-[150px] flex-col justify-between rounded-lg border border-slate-200 bg-gradient-to-br from-white to-slate-50 p-3.5 shadow-sm">
      <div className="flex items-start justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <CompanyLogo logo={logo} size={26} className="border-0 bg-transparent" />
          <span className="truncate text-[11px] font-medium text-slate-500">{company}</span>
        </div>
        <span className="shrink-0 rounded-full bg-slate-800 px-2 py-0.5 text-[10px] font-medium text-white">{ROLES[ct.role]}{ct.lang ? ` · ${ct.lang.toUpperCase()}` : ''}</span>
      </div>
      <div>
        <div className="flex items-baseline gap-1.5">
          <span className="text-base font-bold tracking-tight text-slate-900">{ct.name}</span>
          {ct.title && <span className="text-xs text-slate-600">{ct.title}</span>}
        </div>
        {ct.dept && <div className="text-[11px] text-slate-500">{ct.dept}</div>}
      </div>
      <div className="space-y-0.5 border-t border-slate-200 pt-1.5 text-[11px] text-slate-600">
        <div className="flex items-center gap-1.5"><Mail size={11} className="shrink-0 text-slate-400" /><a href={`mailto:${ct.email}`} className="truncate hover:underline">{ct.email}</a></div>
        {(ct.phone || ct.mobile) && (
          <div className="flex flex-wrap items-center gap-x-3">
            {ct.phone && <span className="inline-flex items-center gap-1.5"><Phone size={11} className="text-slate-400" />{ct.phone}</span>}
            {ct.mobile && <span className="inline-flex items-center gap-1.5"><Phone size={11} className="text-slate-400" />{ct.mobile} (휴대)</span>}
          </div>
        )}
        <div className="flex flex-wrap gap-1 pt-0.5">{ct.notify.length ? ct.notify.map((k) => <span key={k} className="rounded bg-emerald-50 px-1 text-[10px] text-emerald-700">{KINDS[k]}</span>) : <span className="text-amber-700">통지 종류 없음</span>}</div>
      </div>
    </div>
  );
}

function CustomerCard({ c, products, onEdit, onDelete, onChanged }: { c: CustomerView; products: Record<string, VerPolicy[]>; onEdit: () => void; onDelete: () => void; onChanged: () => void }) {
  return (
    <Card>
      <CardContent className="space-y-5 p-5">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-3">
            <CompanyLogo logo={c.logo} disabled={c.disabled} size={44} />
            <div>
              <div className="text-lg font-semibold">{c.name}</div>
              <div className="flex flex-wrap gap-1 text-xs text-muted-foreground"><Ind v={c.industry} />{c.pilot && <Badge variant="outline" title="내부 검증(사전 배포) 고객 — 통지를 먼저 받습니다">내부검증</Badge>}{c.country && <span>{c.country}</span>}<span>· {c.lang === 'en' ? '영어' : '한국어'} 통지</span><span>· ID {c.id}</span></div>
            </div>
          </div>
          <div className="flex gap-1">
            <Button size="sm" variant="outline" onClick={onEdit}><Pencil size={13} />편집</Button>
            <Button size="sm" variant="ghost" onClick={onDelete} title="삭제(휴지통으로 — 되살릴 수 있음)"><Trash2 size={13} /></Button>
          </div>
        </div>
        <StatusLogo c={c} onChanged={onChanged} />
        <div className="grid gap-1 sm:grid-cols-2">
          <Field k="고객사 그룹" v={c.orgGroup ? <span>{c.orgGroup} <span className="text-xs text-muted-foreground">(고객 전용 화면 범위)</span></span> : '연결 안 됨'} />
          <Field k="영업 담당" v={c.salesOwner} />
          <Field k="지원 담당" v={c.supportOwner} />
          <Field k="수정" v={c.updated ? `${fmt(c.updated)} · ${c.updatedBy || ''}` : ''} />
        </div>
        {c.memo && <p className="whitespace-pre-wrap rounded-md bg-secondary/60 p-2 text-sm">{c.memo}</p>}

        {c.mismatch.length > 0 && (
          <div className="rounded-md border border-orange-200 bg-orange-50 p-3 text-sm">
            <div className="mb-1 flex items-center gap-1.5 font-medium text-orange-800"><AlertTriangle size={14} />확인 필요 — 다운로드 기록 추정 버전과 등록 버전이 다릅니다</div>
            {c.mismatch.map((m) => (
              <div key={m.repo} className="text-xs text-orange-900">
                {base(m.repo)}: 추정 <b>{m.estimated}</b> ({fmt(m.at)} · {m.user}) ↔ 등록 {m.installed.length ? m.installed.join(', ') : '없음(등록 안 된 제품)'}
              </div>
            ))}
          </div>
        )}

        <div>
          <div className="mb-2 flex items-center gap-1.5 text-sm font-semibold"><Users size={14} />담당자 {c.contacts.length}</div>
          {c.contacts.length === 0 ? <p className="text-xs text-muted-foreground">담당자가 없습니다 — 통지를 받을 사람이 없습니다.</p> : (
            <div className="grid gap-3 sm:grid-cols-2">
              {c.contacts.map((ct, i) => <BizCard key={ct.email + i} ct={ct} company={c.name} logo={c.logo} />)}
            </div>
          )}
        </div>

        <div>
          <div className="mb-2 flex items-center gap-1.5 text-sm font-semibold"><Package size={14} />제품 사용 {c.usages.length}</div>
          <div className="space-y-2">
            {c.usages.map((u) => {
              const ex = c.expiry.filter((e) => e.usageId === u.id);
              return (
                <div key={u.id} className="rounded-md border p-3 text-sm">
                  <div className="flex flex-wrap items-center gap-2">
                    <b>{u.repo}</b>
                    {u.installs.map((i, k) => {
                      const vp = products[u.repo]?.find((v) => v.tag === i.tag);
                      return <Badge key={k} variant="outline" title={vp?.upgrade ? `권장 업그레이드 ${vp.upgrade}` : undefined}>{i.tag} · {i.env}{i.qty ? ` ×${i.qty}` : ''}</Badge>;
                    })}
                  </div>
                  <div className="mt-2 grid gap-x-4 gap-y-0.5 text-xs sm:grid-cols-2">
                    <Field k="계약" v={[u.contractNo, LIC[u.licenseType || '']].filter((x) => x && x !== '—').join(' · ')} />
                    <Field k="라이선스" v={u.licenseType === 'perpetual' ? '영구' : u.licenseExpiry ? `~ ${u.licenseExpiry}` : ''} />
                    <Field k="유지보수" v={u.maintExpiry ? `${u.maintStart || ''} ~ ${u.maintExpiry}` : ''} />
                    <Field k="지원 등급" v={u.supportTier} />
                    <Field k="통지 수준" v={LEVELS[u.notifyLevel]} />
                    <Field k="통지 대상" v={u.notifyContacts?.length ? u.notifyContacts.join(', ') : '통지 종류가 맞는 모든 담당자'} />
                  </div>
                  {ex.length > 0 && <div className="mt-2 flex flex-wrap gap-1">{ex.map((e, i) => <DDay key={i} days={e.days} label={`${EXP_KIND[e.kind]}${e.tag ? ' ' + e.tag : ''}`} />)}</div>}
                  {u.memo && <p className="mt-1 text-xs text-muted-foreground">{u.memo}</p>}
                </div>
              );
            })}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ---------- 추가·편집 ----------

function Sec({ n, title, children }: { n?: string; title: string; children: ReactNode }) {
  return (
    <fieldset className="space-y-2 rounded-md border p-3">
      <legend className="px-1 text-xs font-semibold text-muted-foreground">{n && <span className="mr-1 text-primary">{n}</span>}{title}</legend>
      {children}
    </fieldset>
  );
}
function F({ label, children, className }: { label: string; children: ReactNode; className?: string }) {
  return <div className={cn('space-y-1', className)}><Label className="text-xs">{label}</Label>{children}</div>;
}

function CustomerForm({ init, isNew, onClose, onSaved }: { init: Customer; isNew: boolean; onClose: () => void; onSaved: (id: string) => void }) {
  const [c, setC] = useState<Customer>(init);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [orgs, setOrgs] = useState<string[]>([]);
  const [users, setUsers] = useState<string[]>([]);
  const [repos, setRepos] = useState<string[]>([]);
  useEffect(() => {
    adminOrgs().then((o) => setOrgs(o.map((x) => x.group))).catch(() => {});
    adminUsers().then((u) => setUsers(u.filter((x) => x.groups.some((g) => g === 'admins' || g === 'developers')).map((x) => x.username))).catch(() => {});
    searchRepos('').then((r) => setRepos(r.map((x) => x.name))).catch(() => {});
  }, []);
  const set = (p: Partial<Customer>) => setC((x) => ({ ...x, ...p }));
  const setCt = (i: number, p: Partial<CustContact>) => setC((x) => ({ ...x, contacts: x.contacts.map((ct, k) => (k === i ? { ...ct, ...p } : ct)) }));
  const setU = (i: number, p: Partial<CustUsage>) => setC((x) => ({ ...x, usages: x.usages.map((u, k) => (k === i ? { ...u, ...p } : u)) }));

  const save = async () => {
    setBusy(true); setErr('');
    try { const r = await adminCustomerSave(c, isNew); onSaved(r.id); } catch (e) { setErr(String(e)); }
    setBusy(false);
  };

  return (
    <Sheet open onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="max-w-3xl">
        <SheetHeader>
          <SheetTitle>{isNew ? '고객 추가' : `${init.name} 편집`}</SheetTitle>
          <SheetDescription>저장하면 감사 기록에 남습니다. Keycloak 사용자·그룹은 바꾸지 않습니다.</SheetDescription>
        </SheetHeader>
        <SheetBody>
          <datalist id="cust-orgs">{orgs.map((o) => <option key={o} value={o} />)}</datalist>
          <datalist id="cust-users">{users.map((o) => <option key={o} value={o} />)}</datalist>
          <datalist id="cust-repos">{repos.map((o) => <option key={o} value={o} />)}</datalist>
          <Sec title="기본 정보">
            <div className="grid gap-2 sm:grid-cols-3">
              <F label="고객 이름 *" className="sm:col-span-2"><Input value={c.name} onChange={(e) => set({ name: e.target.value })} /></F>
              <F label="ID(비우면 자동)"><Input value={c.id} disabled={!isNew} placeholder="alpha-bank" onChange={(e) => set({ id: e.target.value.toLowerCase() })} /></F>
              <F label="업종"><select className={cn(selectCls, 'w-full')} value={c.industry} onChange={(e) => set({ industry: e.target.value as Customer['industry'] })}>{INDUSTRIES.map((x) => <option key={x}>{x}</option>)}</select></F>
              <F label="국가"><Input value={c.country || ''} onChange={(e) => set({ country: e.target.value })} /></F>
              <F label="통지 언어"><select className={cn(selectCls, 'w-full')} value={c.lang} onChange={(e) => set({ lang: e.target.value as Customer['lang'] })}><option value="ko">한국어</option><option value="en">영어</option></select></F>
              <F label="고객사 그룹(선택)" className="sm:col-span-3"><Input list="cust-orgs" placeholder="org-…" value={c.orgGroup || ''} onChange={(e) => set({ orgGroup: e.target.value })} /></F>
              <F label="내부 검증 고객" className="sm:col-span-3">
                <label className="inline-flex items-center gap-2 text-sm">
                  <input type="checkbox" checked={!!c.pilot} onChange={(e) => set({ pilot: e.target.checked })} />
                  내부 테스트팀·QA 등 사전 배포(먼저 쓰는) 고객
                </label>
                <p className="mt-1 text-xs text-muted-foreground">켜면 취약점 통지가 이 고객에게 먼저 나가고, 확인한 뒤에야 외부 고객에게 보낼 수 있습니다.</p>
              </F>
            </div>
          </Sec>

          <Sec title={`담당자 ${c.contacts.length}`}>
            {c.contacts.map((ct, i) => (
              <div key={i} className="space-y-2 rounded-md bg-secondary/40 p-2">
                <div className="grid gap-2 sm:grid-cols-4">
                  <Input placeholder="이름 *" value={ct.name} onChange={(e) => setCt(i, { name: e.target.value })} />
                  <select className={selectCls} value={ct.role} onChange={(e) => setCt(i, { role: e.target.value as CustContact['role'] })}>{Object.entries(ROLES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
                  <Input placeholder="직함(예: 책임)" value={ct.title || ''} onChange={(e) => setCt(i, { title: e.target.value })} />
                  <Input placeholder="부서(예: 정보보호팀)" value={ct.dept || ''} onChange={(e) => setCt(i, { dept: e.target.value })} />
                  <Input placeholder="이메일 *" className="sm:col-span-2" value={ct.email} onChange={(e) => setCt(i, { email: e.target.value })} />
                  <Input placeholder="전화" value={ct.phone || ''} onChange={(e) => setCt(i, { phone: e.target.value })} />
                  <Input placeholder="휴대전화" value={ct.mobile || ''} onChange={(e) => setCt(i, { mobile: e.target.value })} />
                </div>
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <span className="text-muted-foreground">받을 통지</span>
                  {(Object.keys(KINDS) as CustNotifyKind[]).map((k) => (
                    <label key={k} className="inline-flex items-center gap-1">
                      <input type="checkbox" checked={ct.notify.includes(k)} onChange={(e) => setCt(i, { notify: e.target.checked ? [...ct.notify, k] : ct.notify.filter((x) => x !== k) })} />{KINDS[k]}
                    </label>
                  ))}
                  <select className={cn(selectCls, 'h-7 text-xs')} value={ct.lang || ''} onChange={(e) => setCt(i, { lang: e.target.value as CustContact['lang'] })}><option value="">언어: 고객 기본</option><option value="ko">한국어</option><option value="en">영어</option></select>
                  <button className="ml-auto text-muted-foreground hover:text-red-600" title="담당자 삭제" onClick={() => setC((x) => ({ ...x, contacts: x.contacts.filter((_, k) => k !== i) }))}><Trash2 size={13} /></button>
                </div>
              </div>
            ))}
            <Button size="sm" variant="outline" onClick={() => set({ contacts: [...c.contacts, { name: '', role: 'security', email: '', notify: ['vuln', 'vex', 'patch'] }] })}><Plus size={12} />담당자 추가</Button>
          </Sec>

          {c.usages.map((u, i) => (
            <div key={i} className="space-y-2 rounded-lg border-2 border-dashed p-3">
              <div className="flex items-center justify-between">
                <span className="text-sm font-semibold">제품 사용 #{i + 1} {u.repo && <span className="font-normal text-muted-foreground">— {u.repo}</span>}</span>
                <button className="text-muted-foreground hover:text-red-600" title="제품 사용 삭제" onClick={() => setC((x) => ({ ...x, usages: x.usages.filter((_, k) => k !== i) }))}><Trash2 size={14} /></button>
              </div>
              <Sec n="①" title="제품·설치">
                <F label="제품(repo) *"><Input list="cust-repos" placeholder="products/…" value={u.repo} onChange={(e) => setU(i, { repo: e.target.value })} /></F>
                {u.installs.map((ins, k) => (
                  <div key={k} className="flex items-center gap-2">
                    <Input className="w-32" placeholder="버전 *" value={ins.tag} onChange={(e) => setU(i, { installs: u.installs.map((x, j) => (j === k ? { ...x, tag: e.target.value } : x)) })} />
                    <select className={selectCls} value={ins.env} onChange={(e) => setU(i, { installs: u.installs.map((x, j) => (j === k ? { ...x, env: e.target.value as typeof ins.env } : x)) })}>{ENVS.map((x) => <option key={x}>{x}</option>)}</select>
                    <Input className="w-20" type="number" min={0} value={ins.qty} onChange={(e) => setU(i, { installs: u.installs.map((x, j) => (j === k ? { ...x, qty: Number(e.target.value) || 0 } : x)) })} />
                    <span className="text-xs text-muted-foreground">대</span>
                    <button className="text-muted-foreground hover:text-red-600" onClick={() => setU(i, { installs: u.installs.filter((_, j) => j !== k) })}><X size={13} /></button>
                  </div>
                ))}
                <Button size="sm" variant="ghost" onClick={() => setU(i, { installs: [...u.installs, { tag: '', env: '운영', qty: 1 }] })}><Plus size={12} />설치 버전 추가</Button>
              </Sec>
              <Sec n="②" title="라이선스·계약">
                <div className="grid gap-2 sm:grid-cols-4">
                  <F label="계약 번호"><Input value={u.contractNo || ''} onChange={(e) => setU(i, { contractNo: e.target.value })} /></F>
                  <F label="라이선스 유형"><select className={cn(selectCls, 'w-full')} value={u.licenseType || ''} onChange={(e) => setU(i, { licenseType: e.target.value as CustUsage['licenseType'] })}>{Object.entries(LIC).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></F>
                  <F label="사용 시작"><Input type="date" value={u.useStart || ''} onChange={(e) => setU(i, { useStart: e.target.value })} /></F>
                  <F label="라이선스 만료"><Input type="date" disabled={u.licenseType === 'perpetual'} value={u.licenseExpiry || ''} onChange={(e) => setU(i, { licenseExpiry: e.target.value })} /></F>
                </div>
              </Sec>
              <Sec n="③" title="유지보수·지원">
                <div className="grid gap-2 sm:grid-cols-3">
                  <F label="유지보수 시작"><Input type="date" value={u.maintStart || ''} onChange={(e) => setU(i, { maintStart: e.target.value })} /></F>
                  <F label="유지보수 만료"><Input type="date" value={u.maintExpiry || ''} onChange={(e) => setU(i, { maintExpiry: e.target.value })} /></F>
                  <F label="지원 등급"><Input placeholder="예: Gold / 24x7" value={u.supportTier || ''} onChange={(e) => setU(i, { supportTier: e.target.value })} /></F>
                </div>
              </Sec>
              <Sec n="④" title="통지 정책">
                <F label="통지 수준"><select className={cn(selectCls, 'w-full')} value={u.notifyLevel} onChange={(e) => setU(i, { notifyLevel: e.target.value as CustUsage['notifyLevel'] })}>{Object.entries(LEVELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></F>
                <div className="text-xs text-muted-foreground">받을 담당자(선택 안 하면 통지 종류가 맞는 모든 담당자)</div>
                <div className="flex flex-wrap gap-2 text-xs">
                  {c.contacts.filter((ct) => ct.email).map((ct) => (
                    <label key={ct.email} className="inline-flex items-center gap-1">
                      <input type="checkbox" checked={!!u.notifyContacts?.includes(ct.email)}
                        onChange={(e) => setU(i, { notifyContacts: e.target.checked ? [...(u.notifyContacts || []), ct.email] : (u.notifyContacts || []).filter((x) => x !== ct.email) })} />
                      {ct.name}
                    </label>
                  ))}
                </div>
              </Sec>
              <F label="이 제품 메모"><Input value={u.memo || ''} onChange={(e) => setU(i, { memo: e.target.value })} /></F>
            </div>
          ))}
          <Button variant="outline" onClick={() => set({ usages: [...c.usages, emptyUsage()] })}><Plus size={14} />제품 사용 추가</Button>

          <Sec n="⑤" title="우리 쪽·기타">
            <div className="grid gap-2 sm:grid-cols-2">
              <F label="영업 담당(사용자 이름)"><Input list="cust-users" value={c.salesOwner || ''} onChange={(e) => set({ salesOwner: e.target.value })} /></F>
              <F label="지원 담당(사용자 이름)"><Input list="cust-users" value={c.supportOwner || ''} onChange={(e) => set({ supportOwner: e.target.value })} /></F>
            </div>
            <F label="메모(내부용 — 고객 화면·메일에 나가지 않음)">
              <textarea className="min-h-[64px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm" value={c.memo || ''} onChange={(e) => set({ memo: e.target.value })} />
            </F>
          </Sec>
          {err && <Alert tone="crit">{err}</Alert>}
        </SheetBody>
        <SheetFooter>
          <Button variant="outline" onClick={onClose}>취소</Button>
          <Button onClick={save} disabled={busy || !c.name.trim()}><Save size={14} />{busy ? '저장 중…' : '저장'}</Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}

// ---------- 제품 버전 정책 ----------

function VersionPolicy({ products, repos, onSaved }: { products: Record<string, VerPolicy[]>; repos: string[]; onSaved: () => void }) {
  const all = [...new Set([...repos, ...Object.keys(products)])].sort();
  const [repo, setRepo] = useState(all[0] || '');
  const [rows, setRows] = useState<VerPolicy[]>(products[all[0]] || []);
  const [msg, setMsg] = useState('');
  const pick = (r: string) => { setRepo(r); setRows(structuredClone(products[r] || [])); setMsg(''); };
  const setRow = (i: number, p: Partial<VerPolicy>) => setRows((x) => x.map((v, k) => (k === i ? { ...v, ...p } : v)));
  const save = async () => {
    try { await adminCustomerProduct(repo, rows.filter((r) => r.tag.trim())); setMsg('저장했습니다.'); onSaved(); } catch (e) { setMsg('저장 실패: ' + e); }
  };
  return (
    <div className="max-w-3xl space-y-3">
      <p className="text-sm text-muted-foreground">버전별 출시일·지원 종료(EOS)·권장 업그레이드. EOS 는 만료 알림과 고객 메일의 "지원 종료" 안내에 쓰입니다.</p>
      <div className="flex items-center gap-2">
        <Input list="cust-policy-repos" className="max-w-sm" placeholder="제품(repo)" value={repo} onChange={(e) => pick(e.target.value)} />
        <datalist id="cust-policy-repos">{all.map((r) => <option key={r} value={r} />)}</datalist>
      </div>
      <Table>
        <thead><tr><Th>버전</Th><Th>출시일</Th><Th>EOS</Th><Th>권장 업그레이드</Th><Th /></tr></thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i}>
              <Td><Input className="h-8" value={r.tag} onChange={(e) => setRow(i, { tag: e.target.value })} /></Td>
              <Td><Input className="h-8" type="date" value={r.released || ''} onChange={(e) => setRow(i, { released: e.target.value })} /></Td>
              <Td><Input className="h-8" type="date" value={r.eos || ''} onChange={(e) => setRow(i, { eos: e.target.value })} /></Td>
              <Td><Input className="h-8" value={r.upgrade || ''} onChange={(e) => setRow(i, { upgrade: e.target.value })} /></Td>
              <Td><button className="text-muted-foreground hover:text-red-600" onClick={() => setRows((x) => x.filter((_, k) => k !== i))}><Trash2 size={13} /></button></Td>
            </tr>
          ))}
          {rows.length === 0 && <tr><Td colSpan={5} className="text-center text-muted-foreground">버전 정책이 없습니다.</Td></tr>}
        </tbody>
      </Table>
      <div className="flex items-center gap-2">
        <Button size="sm" variant="outline" onClick={() => setRows((x) => [...x, { tag: '' }])}><Plus size={12} />버전 추가</Button>
        <Button size="sm" onClick={save} disabled={!repo}><Save size={12} />저장</Button>
        {msg && <span className="text-xs text-muted-foreground">{msg}</span>}
      </div>
    </div>
  );
}

// ---------- 만료 예정 ----------

function ExpiringPanel({ settings, onSettings }: { settings: CustSettings; onSettings: () => void }) {
  const [d, setD] = useState<{ items: (CustExpiry & { sent: number[] })[]; log: ExpiryRec[]; thresholds: number[] } | null>(null);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');
  const load = () => adminCustomerExpiring(180).then(setD).catch((e) => setErr(String(e)));
  useEffect(() => { load(); }, []);
  const check = async () => {
    setBusy(true); setMsg('');
    try { const r = await adminCustomerExpiryCheck(); setMsg(`점검 완료 — 보낸 메일 ${r.mails}건`); load(); } catch (e) { setMsg(String(e)); }
    setBusy(false);
  };
  const toggle = async (v: boolean) => { try { await adminCustomerSettings({ expiryToCustomer: v }); onSettings(); } catch (e) { alert(String(e)); } };
  if (err) return <Alert tone="crit">{err}</Alert>;
  if (!d) return <Loading />;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <p className="text-sm text-muted-foreground">하루 한 번 라이선스·유지보수·EOS 가 {d.thresholds.join(' / ')}일 안으로 들어오면 영업·지원 담당에게 메일을 보냅니다(임계값마다 한 번).</p>
        <Button size="sm" variant="outline" onClick={check} disabled={busy}><RefreshCw size={13} className={busy ? 'animate-spin' : undefined} />{busy ? '점검 중…' : '지금 점검'}</Button>
        <label className="inline-flex items-center gap-1.5 text-sm"><input type="checkbox" checked={settings.expiryToCustomer} onChange={(e) => toggle(e.target.checked)} />고객 구매(계약)·EOS 담당에게도 보내기</label>
      </div>
      <Busy active={busy} label="만료·EOS 임계값을 점검하고 알림 메일 보내는 중" />
      {msg && <Alert tone="ok">{msg}</Alert>}
      <Table>
        <thead><tr><Th>남은 기간</Th><Th>고객</Th><Th>항목</Th><Th>날짜</Th><Th>보낸 알림</Th></tr></thead>
        <tbody>
          {d.items.length === 0 ? <tr><Td colSpan={5} className="text-center text-muted-foreground">180일 안에 만료되는 항목이 없습니다.</Td></tr> : d.items.map((e, i) => (
            <tr key={i}>
              <Td><DDay days={e.days} /></Td>
              <Td>{e.customer}</Td>
              <Td className="text-sm">{EXP_KIND[e.kind]} — {base(e.repo)}{e.tag ? ` ${e.tag}` : ''}</Td>
              <Td className="text-xs tabular-nums">{e.date}</Td>
              <Td className="text-xs">{e.sent.length ? e.sent.map((t) => <Badge key={t} variant="success" className="mr-1">{t}일 ✓</Badge>) : e.days < 0 ? <span className="text-red-600">만료됨</span> : '—'}</Td>
            </tr>
          ))}
        </tbody>
      </Table>
      <SectionTitle>최근 발송 기록</SectionTitle>
      <Table>
        <thead><tr><Th>시각</Th><Th>고객</Th><Th>대상</Th><Th>내용</Th><Th>결과</Th></tr></thead>
        <tbody>
          {d.log.length === 0 ? <tr><Td colSpan={5} className="text-center text-muted-foreground">기록이 없습니다.</Td></tr> : d.log.map((r, i) => (
            <tr key={i}>
              <Td className="whitespace-nowrap text-xs">{fmt(r.time)}</Td>
              <Td>{r.customer}</Td>
              <Td><Badge variant={r.audience === 'customer' ? 'warn' : 'muted'}>{r.audience === 'customer' ? '고객' : '내부'}</Badge></Td>
              <Td className="text-xs">{r.items.join(' / ')}</Td>
              <Td className="text-xs">
                {r.error ? <span className="text-red-600">실패: {r.error}</span> : r.sent?.length ? `보냄 ${r.sent.length}` : '—'}
                {!!r.dropped?.length && <div className="text-muted-foreground" title={r.dropped.join(', ')}>허용 목록 밖이라 건너뜀 {r.dropped.length}</div>}
              </Td>
            </tr>
          ))}
        </tbody>
      </Table>
    </div>
  );
}
