import { useEffect, useState, type ReactNode } from 'react';
import { Cpu, Cloud, PlugZap, Save, ShieldCheck, FileText } from 'lucide-react';
import {
  adminAIConfig, adminAIConfigSave, adminAITest, type AIConfig, type AIConfigIn, type AIMode, type AIStatus, type AITestResult
} from '@/lib/api';
import { Button, Input, Label, StatusDot } from '@/components/ui/primitives';
import { PageHeader, SectionTitle, Alert, Loading } from './_ui';
import { cn } from '@/lib/utils';

// 시스템 › AI 연결: 로컬 LLM(예: Gemma)과 외부 LLM(Claude 또는 OpenAI 호환)을 함께 등록하고,
// 용도별로 고른다 — VEX 판정·대응 초안 / 규제 보고서·체크리스트 요약·규제 탐색.
//   로컬 LLM — 데이터가 밖으로 나가지 않음. 외부 LLM — 입력 사실이 외부 서비스로 전송됨.

const CLAUDE_MODELS = [
  { id: 'claude-opus-5-5', note: '기본 · 분석·보고서 품질 우선' },
  { id: 'claude-sonnet-5-5', note: '속도·비용 균형' },
  { id: 'claude-haiku-5-5', note: '가장 빠르고 저렴' }
];
const USES = [
  { key: 'mode', label: 'VEX 판정·대응 초안', icon: ShieldCheck, note: '구성요소·취약점 정보와 담당자가 적은 사용 맥락이 입력됩니다.' },
  { key: 'reportMode', label: '규제 보고서·요약·탐색', icon: FileText, note: '공개 규제 정보와 제품 점검 결과가 입력됩니다(체크리스트 요약은 아래 허용 시).' }
] as const;
const MODE_LABEL: Record<AIMode, string> = { off: '사용 안 함', local: '로컬 LLM', external: '외부 LLM' };

function toForm(c: AIConfig): AIConfigIn {
  return {
    mode: c.mode, reportMode: c.reportMode || c.mode, url: c.url || '', model: c.model || '', jsonSchema: c.jsonSchema, sendChecklist: c.sendChecklist,
    external: {
      provider: c.external?.provider || 'anthropic', url: c.external?.url || '', model: c.external?.model || '',
      apiKey: '', jsonSchema: c.external?.jsonSchema ?? true, effort: c.external?.effort || ''
    }
  };
}

function StatusLine({ st }: { st: AIStatus | null }) {
  if (!st?.enabled) return <StatusDot tone="off">꺼짐</StatusDot>;
  const who = st.mode === 'local' ? '로컬' : st.provider === 'anthropic' ? 'Claude' : '외부';
  return (
    <span className="inline-flex flex-wrap items-center gap-2">
      {st.reachable ? <StatusDot tone="ok">연결됨</StatusDot> : <StatusDot tone="crit">응답 없음</StatusDot>}
      <span className="text-muted-foreground">{who} · {st.model || '모델 미상'}{st.ctx ? ` · 컨텍스트 ${st.ctx}` : ''}</span>
      {st.sha256 && <span className="font-mono text-xs text-muted-foreground" title={st.sha256}>SHA-256 {st.sha256.slice(0, 12)}…</span>}
      {st.error && <span className="text-xs text-red-700">{st.error}</span>}
    </span>
  );
}

function TestResult({ t }: { t: AITestResult | null }) {
  if (!t) return null;
  return t.ok
    ? <Alert tone="ok">정상 — {t.model} 가 {(t.elapsedMs / 1000).toFixed(1)}초 만에 JSON 으로 응답했습니다(“{t.answer}”). 저장해야 적용됩니다.</Alert>
    : <Alert tone="crit">실패 — {t.error}</Alert>;
}

function Card({ icon, title, sub, children }: { icon: ReactNode; title: string; sub: string; children: ReactNode }) {
  return (
    <div className="space-y-3 rounded-lg border bg-card p-4">
      <div>
        <div className="flex items-center gap-2 font-medium">{icon} {title}</div>
        <p className="mt-0.5 text-xs text-muted-foreground">{sub}</p>
      </div>
      {children}
    </div>
  );
}

export default function AIConfigPage() {
  const [cfg, setCfg] = useState<AIConfig | null>(null);
  const [st, setSt] = useState<{ vex: AIStatus | null; report: AIStatus | null }>({ vex: null, report: null });
  const [f, setF] = useState<AIConfigIn | null>(null);
  const [err, setErr] = useState('');
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState('');
  const [tests, setTests] = useState<{ local: AITestResult | null; external: AITestResult | null }>({ local: null, external: null });

  useEffect(() => {
    adminAIConfig().then((r) => { setCfg(r.config); setSt({ vex: r.status, report: r.reportStatus }); setF(toForm(r.config)); })
      .catch((e) => setErr(String(e)));
  }, []);

  const head = <PageHeader title="AI 연결" description="로컬 LLM 과 외부 LLM(Claude 등)을 함께 등록하고 용도별로 고릅니다. AI 는 초안만 쓰고, 판정·저장은 사람이 합니다." />;
  if (err) return (<>{head}<Alert tone="crit">오류: {err}</Alert></>);
  if (!cfg || !f) return (<>{head}<Loading /></>);
  const set = (p: Partial<AIConfigIn>) => { setF({ ...f, ...p }); setMsg(''); };
  const setX = (p: Partial<AIConfigIn['external']>) => { setF({ ...f, external: { ...f.external, ...p } }); setMsg(''); setTests({ ...tests, external: null }); };
  const x = f.external;
  const isClaude = x.provider === 'anthropic';
  const usesExternal = f.mode === 'external' || f.reportMode === 'external';

  async function save() {
    setBusy('save'); setMsg('');
    try {
      const r = await adminAIConfigSave(f!);
      setCfg(r.config); setSt({ vex: r.status, report: r.reportStatus }); setF(toForm(r.config));
      setMsg('저장했습니다. 바로 적용됩니다.');
    } catch (e) { setMsg(String(e)); }
    setBusy('');
  }
  async function runTest(target: 'local' | 'external') {
    setBusy('test-' + target); setTests({ ...tests, [target]: null });
    let r: AITestResult;
    try { r = await adminAITest({ ...f!, target }); } catch (e) { r = { ok: false, elapsedMs: 0, error: String(e) }; }
    setTests((t) => ({ ...t, [target]: r }));
    setBusy('');
  }

  return (
    <>
      {head}
      <SectionTitle>용도별 연결</SectionTitle>
      <div className="mb-5 grid gap-3 lg:grid-cols-2">
        {USES.map((u) => (
          <div key={u.key} className="rounded-lg border bg-card p-3">
            <div className="flex items-center gap-2 font-medium"><u.icon size={16} /> {u.label}</div>
            <p className="mt-0.5 text-xs text-muted-foreground">{u.note}</p>
            <div className="mt-2 flex gap-1">
              {(['off', 'local', 'external'] as AIMode[]).map((m) => (
                <button key={m} onClick={() => set({ [u.key]: m } as Partial<AIConfigIn>)}
                  className={cn('rounded-md border px-3 py-1 text-sm transition-colors',
                    f[u.key] === m ? 'border-primary bg-primary/10 font-medium text-primary' : 'hover:bg-secondary')}>
                  {m === 'external' && isClaude ? 'Claude' : MODE_LABEL[m]}
                </button>
              ))}
            </div>
            <div className="mt-2 text-sm"><span className="mr-2 text-xs text-muted-foreground">현재</span><StatusLine st={u.key === 'mode' ? st.vex : st.report} /></div>
          </div>
        ))}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card icon={<Cpu size={16} />} title="로컬 LLM" sub="이 서버의 trustlink-ai(llama.cpp, Gemma 4 26B-A4B) 또는 사내 GPU 서버의 vLLM. 데이터가 외부로 나가지 않습니다.">
          <div>
            <Label>API 주소</Label>
            <Input value={f.url} onChange={(e) => set({ url: e.target.value })} placeholder="http://trustlink-ai:8080 또는 http://<GPU 서버>:8000" />
            <p className="mt-1 text-xs text-muted-foreground">경로가 없으면 /v1/chat/completions 로 요청합니다.</p>
          </div>
          <div>
            <Label>모델 이름 (선택 — vLLM 은 서비스 모델 이름)</Label>
            <Input value={f.model} onChange={(e) => set({ model: e.target.value })} placeholder="비우면 서버 기본 모델" />
          </div>
          <label className="flex items-start gap-2 text-sm">
            <input type="checkbox" className="mt-1" checked={f.jsonSchema} onChange={(e) => set({ jsonSchema: e.target.checked })} />
            <span>JSON 스키마 강제(response_format json_schema)<br /><span className="text-xs text-muted-foreground">llama.cpp·vLLM 은 지원합니다. 시험에서 형식 오류가 나면 끕니다.</span></span>
          </label>
          {cfg.fromEnv && <p className="text-xs text-muted-foreground">환경변수 AI_URL 사용 중 — 저장하면 이 화면 설정이 우선합니다.</p>}
          <div className="flex items-center gap-2">
            <Button size="sm" variant="outline" onClick={() => runTest('local')} disabled={!!busy || !f.url}>
              <PlugZap size={14} /> {busy === 'test-local' ? '시험 중…' : '연결 시험'}
            </Button>
          </div>
          <TestResult t={tests.local} />
        </Card>

        <Card icon={<Cloud size={16} />} title="외부 LLM" sub="Anthropic Claude(공식 SDK) 또는 OpenAI 호환 API. 입력 사실이 외부 서비스로 전송됩니다.">
          <div className="flex gap-1">
            {([['anthropic', 'Anthropic Claude'], ['openai', 'OpenAI 호환']] as const).map(([v, l]) => (
              <button key={v} onClick={() => setX({ provider: v, model: v === x.provider ? x.model : '' })}
                className={cn('rounded-md border px-3 py-1 text-sm', x.provider === v ? 'border-primary bg-primary/10 font-medium text-primary' : 'hover:bg-secondary')}>{l}</button>
            ))}
          </div>
          <div>
            <Label>모델 {isClaude ? '' : '(필수)'}</Label>
            {isClaude ? (
              <div className="space-y-1">
                {CLAUDE_MODELS.map((m) => (
                  <label key={m.id} className="flex items-center gap-2 text-sm">
                    <input type="radio" checked={(x.model || 'claude-opus-5-5') === m.id} onChange={() => setX({ model: m.id })} />
                    <span className="font-mono text-xs">{m.id}</span><span className="text-xs text-muted-foreground">{m.note}</span>
                  </label>
                ))}
              </div>
            ) : <Input value={x.model} onChange={(e) => setX({ model: e.target.value })} placeholder="제공사 모델 ID" />}
          </div>
          {isClaude && (
            <div>
              <Label>추론 수준</Label>
              <select className="h-9 rounded-md border bg-background px-2 text-sm" value={x.effort} onChange={(e) => setX({ effort: e.target.value })}>
                <option value="">기본(medium)</option><option value="low">low — 빠름</option><option value="medium">medium</option><option value="high">high — 깊게</option>
              </select>
            </div>
          )}
          <div>
            <Label>API 주소 {isClaude ? '(비우면 공식 주소)' : '(필수)'}</Label>
            <Input value={x.url} onChange={(e) => setX({ url: e.target.value })}
              placeholder={isClaude ? 'https://api.anthropic.com' : 'https://api.example.com 또는 https://host/v1beta/openai'} />
          </div>
          <div>
            <Label>API 키 {cfg.external.hasKey ? <span className="text-muted-foreground">(저장됨 {cfg.external.keyHint} — 바꿀 때만 입력)</span> : '(필수)'}</Label>
            <div className="flex gap-2">
              <Input type="password" autoComplete="off" value={x.apiKey || ''} onChange={(e) => setX({ apiKey: e.target.value, clearKey: false })}
                placeholder={cfg.external.hasKey ? '••••••••' : isClaude ? 'sk-ant-…' : 'API 키'} />
              {cfg.external.hasKey && <Button size="sm" variant="outline" onClick={() => setX({ apiKey: '', clearKey: !x.clearKey })}>{x.clearKey ? '삭제 취소' : '키 삭제'}</Button>}
            </div>
            <p className="mt-1 text-xs text-muted-foreground">키는 서버 파일(권한 600)에만 저장하고 화면·API 로 다시 내보내지 않습니다.</p>
          </div>
          {!isClaude && (
            <label className="flex items-start gap-2 text-sm">
              <input type="checkbox" className="mt-1" checked={x.jsonSchema} onChange={(e) => setX({ jsonSchema: e.target.checked })} />
              <span>JSON 스키마 강제 사용</span>
            </label>
          )}
          <div className="flex items-center gap-2">
            <Button size="sm" variant="outline" onClick={() => runTest('external')} disabled={!!busy || (!isClaude && !x.url) || (!x.apiKey && !cfg.external.hasKey)}>
              <PlugZap size={14} /> {busy === 'test-external' ? '시험 중…' : '연결 시험'}
            </Button>
          </div>
          <TestResult t={tests.external} />
        </Card>
      </div>

      {usesExternal && (
        <div className="mt-4 max-w-3xl space-y-2">
          <Alert tone="warn">외부 LLM 을 쓰는 용도에서는 입력 사실(구성요소·버전·취약점·사용 맥락 또는 규제 목록·점검 결과)이 외부 서비스로 전송됩니다. 요청 기록(모델·입력 해시)은 원장에 남습니다.</Alert>
          <label className="flex items-start gap-2 text-sm">
            <input type="checkbox" className="mt-1" checked={f.sendChecklist} onChange={(e) => set({ sendChecklist: e.target.checked })} />
            <span>체크리스트 점검 보고서의 AI 요약에 체크리스트 내용 전송 허용<br />
              <span className="text-xs text-muted-foreground">업로드한 체크리스트(대외비일 수 있음)의 항목 문구가 외부로 나갑니다. 끄면 체크리스트 보고서는 규칙 판정만 만듭니다(규제 카탈로그 보고서는 공개 정보라 영향 없음).</span></span>
          </label>
        </div>
      )}

      <div className="mt-4 flex flex-wrap items-center gap-2">
        <Button onClick={save} disabled={!!busy}><Save size={15} /> {busy === 'save' ? '저장 중…' : '저장'}</Button>
        {msg && <span className="text-sm text-muted-foreground">{msg}</span>}
        {cfg.updatedAt && <span className="ml-auto text-xs text-muted-foreground">마지막 변경 {new Date(cfg.updatedAt).toLocaleString('ko-KR')} · {cfg.updatedBy}</span>}
      </div>
    </>
  );
}
