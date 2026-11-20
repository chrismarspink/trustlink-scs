import { useEffect, useMemo, useState } from 'react';
import { Busy, DownloadLink } from '@/components/Progress';
import { Sparkles, Paperclip, Eye, Send, X } from 'lucide-react';
import {
  adminMailOptions, adminMailPreview, adminMailSuggest, adminMailTest, regReportPdfUrl,
  type MailOptions, type MailSuggestion, type MailCompose as Compose
} from '@/lib/api';
import { Badge, Button, Input } from '@/components/ui/primitives';
import { Alert, selectCls } from './_ui';

const ROLE_BADGE: Record<string, 'default' | 'success' | 'warn' | 'muted' | 'outline'> = { admin: 'default', dev: 'success', sales: 'warn', customer: 'outline', user: 'muted' };
const LANG: Record<string, string> = { ko: '한글', en: '영문' };
const errText = (e: unknown) => String(e).replace(/^Error: /, '');

// 현황 메일 보내기: 넣을 항목(체크) · 첨부 보고서(PDF) · 받는 사람 · AI 추천 · 미리보기.
// 허용 목록(MAIL_ALLOWLIST)이 있으면 서버가 그 주소로만 보낸다.
export default function MailCompose({ allowlist }: { allowlist: string[] }) {
  const [o, setO] = useState<MailOptions | null>(null);
  const [loadErr, setLoadErr] = useState('');
  const [rc, setRc] = useState<string[]>(allowlist.slice(0, 1));
  const [extra, setExtra] = useState('');
  const [secs, setSecs] = useState<string[]>(['summary', 'vulns']);
  const [reps, setReps] = useState<string[]>([]);
  const [subject, setSubject] = useState('');
  const [note, setNote] = useState('');
  const [goal, setGoal] = useState('');
  const [useAI, setUseAI] = useState(true);
  const [sg, setSg] = useState<MailSuggestion | null>(null);
  const [preview, setPreview] = useState<{ subject: string; html: string } | null>(null);
  const [busy, setBusy] = useState('');
  const [res, setRes] = useState<{ tone: 'ok' | 'warn' | 'crit'; text: string } | null>(null);
  const [roleFilter, setRoleFilter] = useState('internal');

  useEffect(() => { adminMailOptions().then(setO).catch((e) => setLoadErr(errText(e))); }, []);
  const allow = useMemo(() => new Set(allowlist.map((a) => a.toLowerCase())), [allowlist]);
  const blocked = (a: string) => allow.size > 0 && !allow.has(a.toLowerCase());
  const reason = useMemo(() => Object.fromEntries((sg?.recipients || []).map((r) => [r.email.toLowerCase(), r.reason])), [sg]);

  if (loadErr) return <Alert tone="crit">메일 옵션을 읽지 못했습니다: {loadErr}</Alert>;
  if (!o) return null;

  const toggle = (l: string[], v: string, set: (x: string[]) => void) => set(l.includes(v) ? l.filter((x) => x !== v) : [...l, v]);
  const compose = (): Compose => ({ recipients: rc, sections: secs, reports: reps, subject, note });
  const addExtra = () => {
    const a = extra.trim();
    if (a && /.+@.+\..+/.test(a) && !rc.includes(a)) setRc([...rc, a]);
    setExtra('');
  };
  const users = o.users.filter((u) => u.email && (roleFilter === 'all' || (roleFilter === 'internal' ? ['admin', 'dev', 'sales'].includes(u.role) : u.role === roleFilter)));
  const latestKo = (aud: string) => o.reports.find((r) => r.lang === 'ko' && r.audience === aud)?.id;

  const suggest = async () => {
    setBusy('suggest'); setRes(null);
    try {
      const s = await adminMailSuggest(goal, useAI && o.ai);
      setSg(s);
      setRc(s.recipients.map((r) => r.email));
      setSecs(s.sections); setReps(o.pdf ? s.reports : []);
      setSubject(s.subject); setNote(s.note);
      if (s.aiError) setRes({ tone: 'warn', text: `AI 추천 대신 규칙 추천을 넣었습니다: ${s.aiError}` });
    } catch (e) { setRes({ tone: 'crit', text: `추천 실패: ${errText(e)}` }); }
    setBusy('');
  };
  const doPreview = async () => {
    setBusy('preview');
    try { setPreview(await adminMailPreview(compose())); } catch (e) { setRes({ tone: 'crit', text: `미리보기 실패: ${errText(e)}` }); }
    setBusy('');
  };
  const send = async () => {
    const out = rc.filter(blocked);
    if (!window.confirm(`${rc.length}명에게 보냅니다${out.length ? ` (허용 목록 밖 ${out.length}명은 서버가 건너뜀)` : ''}.${reps.length ? `\n첨부 PDF ${reps.length}개 — 처음 만드는 PDF 는 수십 초 걸릴 수 있습니다.` : ''}`)) return;
    setBusy('send'); setRes(null);
    try {
      const r = await adminMailTest(compose());
      setRes({ tone: r.dropped?.length ? 'warn' : 'ok', text: `${r.to.join(', ')} 에게 보냈습니다${r.attachments ? ` (첨부 ${r.attachments}개)` : ''}.${r.dropped?.length ? ` 허용 목록 밖이라 건너뜀: ${r.dropped.join(', ')}` : ''}` });
      adminMailOptions().then(setO).catch(() => {});
    } catch (e) { setRes({ tone: 'crit', text: `발송 실패: ${errText(e)}` }); }
    setBusy('');
  };

  const box = 'rounded-lg border bg-card p-4';
  return (
    <div className="space-y-4">
      {/* AI 추천 */}
      <div className={`${box} border-violet-200 bg-violet-50/40`}>
        <div className="mb-2 flex items-center gap-2 text-sm font-semibold"><Sparkles size={15} className="text-violet-600" /> 받는 사람·항목·첨부 추천</div>
        <div className="flex flex-wrap items-center gap-2">
          <Input className="max-w-md" placeholder="메일 목적(선택) 예: 이번 주 취약점 판단 독려, 고객 미팅 전 규제 일정 공유" value={goal} onChange={(e) => setGoal(e.target.value)} />
          <label className="flex items-center gap-1.5 text-sm text-muted-foreground" title={o.ai ? '' : 'AI 연결(보고서 용도)이 꺼져 있어 규칙으로만 추천합니다'}>
            <input type="checkbox" checked={useAI && o.ai} disabled={!o.ai} onChange={(e) => setUseAI(e.target.checked)} /> AI 사용
          </label>
          <Button variant="outline" onClick={suggest} disabled={!!busy}>{busy === 'suggest' ? '추천 중…' : '추천 받기'}</Button>
        </div>
        <p className="mt-2 text-xs text-muted-foreground">역할(관리자·개발/보안·영업)과 현재 취약점·규제 일정·보고서를 보고 고릅니다. 고객사 계정은 후보에서 뺍니다. 외부 AI 에는 메일 주소·계정 이름 대신 번호와 그룹만 보냅니다.</p>
        <Busy className="mt-2" active={busy === 'suggest'} label={useAI && o.ai ? '받는 사람 후보를 모으고 AI 가 고르는 중' : '받는 사람 후보를 모으는 중'} hint={useAI && o.ai ? '로컬 AI 면 1분 안팎' : undefined} />
        {sg && (
          <div className="mt-3 text-xs">
            <Badge variant={sg.by === 'ai' ? 'default' : 'muted'}>{sg.by === 'ai' ? `AI 추천 · ${sg.aiMeta?.model || ''}` : '규칙 추천'}</Badge>
            {!!sg.reasons?.length && <ul className="mt-1.5 list-disc pl-5 text-muted-foreground">{sg.reasons.map((r, i) => <li key={i}>{r}</li>)}</ul>}
          </div>
        )}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        {/* 받는 사람 */}
        <div className={box}>
          <div className="mb-2 flex items-center justify-between">
            <span className="text-sm font-semibold">받는 사람 <span className="font-normal text-muted-foreground">{rc.length}명</span></span>
            <select className={selectCls} value={roleFilter} onChange={(e) => setRoleFilter(e.target.value)}>
              <option value="internal">내부(관리·개발·영업)</option>
              {Object.entries(o.roles).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              <option value="all">전체</option>
            </select>
          </div>
          <div className="mb-2 flex flex-wrap gap-1.5">
            {rc.map((a) => (
              <span key={a} className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs ${blocked(a) ? 'border-amber-300 bg-amber-50 text-amber-800' : 'bg-muted'}`} title={blocked(a) ? '허용 목록 밖 — 서버가 보내지 않습니다' : reason[a.toLowerCase()] || ''}>
                {a}{blocked(a) && ' ⚠'}<button onClick={() => setRc(rc.filter((x) => x !== a))} aria-label="빼기"><X size={12} /></button>
              </span>
            ))}
          </div>
          <div className="max-h-56 overflow-auto rounded border">
            {o.usersError && <div className="p-2 text-xs text-red-600">사용자 목록 오류: {o.usersError}</div>}
            {users.length === 0 && <div className="p-3 text-xs text-muted-foreground">이메일이 등록된 사용자가 없습니다.</div>}
            {users.map((u) => (
              <label key={u.username} className="flex cursor-pointer items-center gap-2 border-b px-2 py-1.5 text-sm last:border-0 hover:bg-muted/50">
                <input type="checkbox" checked={rc.includes(u.email)} onChange={() => toggle(rc, u.email, setRc)} />
                <span className="w-28 truncate">{u.username}</span>
                <Badge variant={ROLE_BADGE[u.role]}>{o.roles[u.role]}</Badge>
                <span className="truncate text-xs text-muted-foreground">{u.email}</span>
                {reason[u.email.toLowerCase()] && <span className="ml-auto truncate text-xs text-violet-700">{reason[u.email.toLowerCase()]}</span>}
              </label>
            ))}
          </div>
          <div className="mt-2 flex gap-2">
            <Input type="email" placeholder="다른 주소 직접 넣기" value={extra} onChange={(e) => setExtra(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && addExtra()} />
            <Button variant="outline" onClick={addExtra}>추가</Button>
          </div>
          {allow.size > 0 && <p className="mt-2 text-xs text-amber-700">시험 기간: 허용 목록({allowlist.join(', ')})에 있는 주소로만 실제 발송됩니다.</p>}
        </div>

        {/* 항목 · 첨부 */}
        <div className="space-y-4">
          <div className={box}>
            <div className="mb-2 text-sm font-semibold">본문에 넣을 항목</div>
            {o.sections.map((x) => (
              <label key={x.id} className="flex cursor-pointer items-start gap-2 py-1 text-sm">
                <input className="mt-1" type="checkbox" checked={secs.includes(x.id)} onChange={() => toggle(secs, x.id, setSecs)} />
                <span><b className="font-medium">{x.label}</b> <span className="text-xs text-muted-foreground">— {x.desc}</span></span>
              </label>
            ))}
          </div>
          <div className={box}>
            <div className="mb-2 flex items-center justify-between">
              <span className="flex items-center gap-1.5 text-sm font-semibold"><Paperclip size={14} /> 첨부 보고서(PDF) <span className="font-normal text-muted-foreground">{reps.length}/4</span></span>
              <span className="flex gap-1">
                {(['dev', 'sales'] as const).map((a) => {
                  const id = latestKo(a);
                  return <Button key={a} variant="ghost" className="h-7 px-2 text-xs" disabled={!id || !o.pdf || reps.includes(id) || reps.length >= 4} onClick={() => id && setReps([...reps, id])}>+ {a === 'dev' ? '개발자용' : '영업용'} 최신</Button>;
                })}
              </span>
            </div>
            {!o.pdf && <Alert tone="warn">PDF 변환 서버(Gotenberg)가 설정되지 않아 첨부할 수 없습니다.</Alert>}
            {o.reports.length === 0 && <p className="text-xs text-muted-foreground">발행한 규제 보고서가 없습니다. 보고서함에서 먼저 만드세요.</p>}
            <div className="max-h-48 overflow-auto">
              {o.reports.map((r) => (
                <label key={r.id} className={`flex items-center gap-2 border-b py-1.5 text-sm last:border-0 ${o.pdf ? 'cursor-pointer' : 'opacity-50'}`}>
                  <input type="checkbox" disabled={!o.pdf || (!reps.includes(r.id) && reps.length >= 4)} checked={reps.includes(r.id)} onChange={() => toggle(reps, r.id, setReps)} />
                  <Badge variant="outline">{r.audienceKo}</Badge><Badge variant="muted">{LANG[r.lang] || r.lang}</Badge>
                  <span className="truncate text-xs">{r.docNo} · {r.created.slice(0, 10)}{r.repo ? ` · ${r.repo}:${r.tag}` : ''}</span>
                  {r.pdf && <DownloadLink className="ml-auto text-xs text-primary hover:underline" href={regReportPdfUrl(r.id)}>PDF</DownloadLink>}
                </label>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className={box}>
        <Input placeholder="제목(비우면 '공급망 보안 현황 — 오늘 날짜')" value={subject} onChange={(e) => setSubject(e.target.value)} />
        <textarea className="mt-2 min-h-20 w-full rounded-md border bg-background p-2 text-sm" placeholder="인사말·전할 말(선택)" value={note} onChange={(e) => setNote(e.target.value)} />
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <Button variant="outline" onClick={doPreview} disabled={!!busy}><Eye size={14} className="mr-1" />{busy === 'preview' ? '만드는 중…' : '미리보기'}</Button>
          <Button onClick={send} disabled={!!busy || rc.length === 0 || !o.configured}><Send size={14} className="mr-1" />{busy === 'send' ? (reps.length ? 'PDF 만들고 보내는 중…' : '보내는 중…') : '보내기'}</Button>
          <span className="text-xs text-muted-foreground">항목·첨부·인사말을 모두 비우면 짧은 시험 메일이 갑니다.</span>
        </div>
        <Busy className="mt-2" active={busy === 'send'} label={reps.length ? `첨부 PDF ${reps.length}개 만들고 보내는 중` : '보내는 중'} hint={reps.length ? '처음 만드는 PDF 는 하나에 수십 초' : undefined} />
        {res && <div className="mt-3"><Alert tone={res.tone}>{res.text}</Alert></div>}
      </div>

      {preview && (
        <div className={box}>
          <div className="mb-2 flex items-center justify-between text-sm"><b>{preview.subject}</b><Button variant="ghost" className="h-7" onClick={() => setPreview(null)}>닫기</Button></div>
          <iframe title="메일 미리보기" sandbox="" srcDoc={preview.html} className="h-[640px] w-full rounded border bg-white" />
        </div>
      )}
    </div>
  );
}
