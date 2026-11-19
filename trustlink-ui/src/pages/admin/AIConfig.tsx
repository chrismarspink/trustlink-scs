import { useEffect, useState } from 'react';
import { Cpu, Cloud, Power, PlugZap, Save } from 'lucide-react';
import { adminAIConfig, adminAIConfigSave, adminAITest, type AIConfig, type AIConfigIn, type AIStatus } from '@/lib/api';
import { Button, Input, Label, StatusDot } from '@/components/ui/primitives';
import { PageHeader, SectionTitle, Alert, Loading } from './_ui';
import { cn } from '@/lib/utils';

// 관리 › AI 연결: VEX 판정·대응 초안과 규제 보고서 요약에 쓸 LLM 을 고른다.
//   로컬 LLM — 같은 서버의 trustlink-ai(llama.cpp) 또는 사내 vLLM 등. 데이터가 밖으로 나가지 않음.
//   외부 LLM — OpenAI 호환 API. 입력 사실(구성요소·취약점·사용 맥락)이 외부로 전송됨.

const MODES = [
  { v: 'off', label: '사용 안 함', icon: Power, note: 'AI 초안 기능을 끕니다. 규칙 판정·우선순위는 그대로 동작합니다.' },
  { v: 'local', label: '로컬 LLM', icon: Cpu, note: '이 서버의 trustlink-ai(llama.cpp) 또는 사내 GPU 서버의 vLLM. 데이터가 외부로 나가지 않습니다.' },
  { v: 'external', label: '외부 LLM', icon: Cloud, note: 'OpenAI 호환 API. 구성요소·취약점 정보와 담당자가 적은 사용 맥락이 외부 서비스로 전송됩니다.' }
] as const;

const URL_HINT: Record<string, string> = {
  local: 'http://trustlink-ai:8080 (같은 서버) 또는 http://<GPU 서버>:8000 (vLLM)',
  external: 'https://api.example.com 또는 https://host/v1beta/openai 처럼 OpenAI 호환 기준 주소'
};

export default function AIConfigPage() {
  const [cfg, setCfg] = useState<AIConfig | null>(null);
  const [st, setSt] = useState<AIStatus | null>(null);
  const [f, setF] = useState<AIConfigIn | null>(null);
  const [err, setErr] = useState('');
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState('');
  const [test, setTest] = useState<{ ok: boolean; model?: string; answer?: string; elapsedMs: number; error?: string } | null>(null);

  function load() {
    adminAIConfig().then((r) => {
      setCfg(r.config); setSt(r.status);
      setF({ mode: r.config.mode, url: r.config.url || '', model: r.config.model || '', apiKey: '', jsonSchema: r.config.jsonSchema, sendChecklist: r.config.sendChecklist });
    }).catch((e) => setErr(String(e)));
  }
  useEffect(load, []);

  const head = <PageHeader title="AI 연결" description="VEX 판정·대응 초안과 규제 보고서 요약에 쓸 LLM 을 고릅니다. AI 는 초안만 쓰고, 판정·저장은 사람이 합니다." />;
  if (err) return (<>{head}<Alert tone="crit">오류: {err}</Alert></>);
  if (!cfg || !f) return (<>{head}<Loading /></>);
  const set = (p: Partial<AIConfigIn>) => { setF({ ...f, ...p }); setTest(null); setMsg(''); };

  async function save() {
    setBusy('save'); setMsg('');
    try {
      const r = await adminAIConfigSave(f!);
      setCfg(r.config); setSt(r.status); setF({ ...f!, apiKey: '', clearKey: false });
      setMsg('저장했습니다. 바로 적용됩니다.');
    } catch (e) { setMsg(String(e)); }
    setBusy('');
  }
  async function runTest() {
    setBusy('test'); setTest(null);
    try { setTest(await adminAITest(f!)); } catch (e) { setTest({ ok: false, elapsedMs: 0, error: String(e) }); }
    setBusy('');
  }

  return (
    <>
      {head}
      <div className="mb-4 flex flex-wrap items-center gap-3 rounded-lg border bg-card p-3 text-sm">
        <span className="font-medium">현재 상태</span>
        {!st?.enabled ? <StatusDot tone="off">꺼짐</StatusDot>
          : st.reachable ? <StatusDot tone="ok">연결됨</StatusDot> : <StatusDot tone="crit">응답 없음</StatusDot>}
        {st?.enabled && <span className="text-muted-foreground">{cfg.mode === 'external' ? '외부 LLM' : '로컬 LLM'} · {st.model || cfg.model || '모델 미상'}{st.ctx ? ` · 컨텍스트 ${st.ctx}` : ''}</span>}
        {st?.sha256 && <span className="font-mono text-xs text-muted-foreground" title={st.sha256}>SHA-256 {st.sha256.slice(0, 12)}…</span>}
        {st?.error && <span className="text-xs text-red-700">{st.error}</span>}
        {cfg.fromEnv && <span className="text-xs text-muted-foreground">(환경변수 AI_URL 사용 중 — 저장하면 이 화면 설정이 우선)</span>}
        {cfg.updatedAt && <span className="ml-auto text-xs text-muted-foreground">마지막 변경 {new Date(cfg.updatedAt).toLocaleString('ko-KR')} · {cfg.updatedBy}</span>}
      </div>

      <SectionTitle>연결 방식</SectionTitle>
      <div className="mb-4 grid gap-3 sm:grid-cols-3">
        {MODES.map((m) => (
          <button key={m.v} onClick={() => set({ mode: m.v, url: f.url || (m.v === 'local' ? 'http://trustlink-ai:8080' : '') })}
            className={cn('rounded-lg border p-3 text-left transition-colors',
              f.mode === m.v ? 'border-primary bg-primary/5 ring-1 ring-primary' : 'hover:bg-secondary')}>
            <div className="flex items-center gap-2 font-medium"><m.icon size={16} /> {m.label}</div>
            <p className="mt-1 text-xs text-muted-foreground">{m.note}</p>
          </button>
        ))}
      </div>

      {f.mode !== 'off' && (
        <div className="max-w-2xl space-y-3 rounded-lg border bg-card p-4">
          <div>
            <Label>API 주소</Label>
            <Input value={f.url} onChange={(e) => set({ url: e.target.value })} placeholder={URL_HINT[f.mode]} />
            <p className="mt-1 text-xs text-muted-foreground">경로가 없으면 /v1 을 붙여 /v1/chat/completions 로 요청합니다. 경로가 있으면 그 아래 /chat/completions 로 요청합니다.</p>
          </div>
          <div>
            <Label>모델 이름 {f.mode === 'external' ? '(필수)' : '(선택 — vLLM 은 서비스 모델 이름)'}</Label>
            <Input value={f.model} onChange={(e) => set({ model: e.target.value })} placeholder={f.mode === 'external' ? '예: 제공사 모델 ID' : '비우면 서버 기본 모델'} />
          </div>
          <div>
            <Label>API 키 {cfg.hasKey ? <span className="text-muted-foreground">(저장됨 {cfg.keyHint} — 바꿀 때만 입력)</span> : '(필요한 경우)'}</Label>
            <div className="flex gap-2">
              <Input type="password" autoComplete="off" value={f.apiKey || ''} onChange={(e) => set({ apiKey: e.target.value, clearKey: false })} placeholder={cfg.hasKey ? '••••••••' : '없으면 비워 둡니다'} />
              {cfg.hasKey && (
                <Button size="sm" variant="outline" onClick={() => set({ apiKey: '', clearKey: !f.clearKey })}>{f.clearKey ? '삭제 취소' : '키 삭제'}</Button>
              )}
            </div>
            <p className="mt-1 text-xs text-muted-foreground">키는 서버 파일(권한 600)에만 저장하고 화면·API 로 다시 내보내지 않습니다.</p>
          </div>
          <label className="flex items-start gap-2 text-sm">
            <input type="checkbox" className="mt-1" checked={f.jsonSchema} onChange={(e) => set({ jsonSchema: e.target.checked })} />
            <span>JSON 스키마 강제(response_format json_schema) 사용<br />
              <span className="text-xs text-muted-foreground">llama.cpp·vLLM·대부분의 OpenAI 호환 API 가 지원합니다. 연결 시험에서 형식 오류가 나면 끕니다.</span></span>
          </label>
          {f.mode === 'external' && (
            <>
              <Alert tone="warn">외부 LLM 을 쓰면 VEX 초안 요청 때 구성요소 이름·버전, 취약점 정보, 담당자가 적은 사용 맥락이 외부 서비스로 전송됩니다. 요청 기록(모델·입력 해시)은 원장에 남습니다.</Alert>
              <label className="flex items-start gap-2 text-sm">
                <input type="checkbox" className="mt-1" checked={f.sendChecklist} onChange={(e) => set({ sendChecklist: e.target.checked })} />
                <span>규제 보고서 AI 요약에 체크리스트 내용 전송 허용<br />
                  <span className="text-xs text-muted-foreground">업로드한 체크리스트(대외비일 수 있음)의 항목 문구가 외부로 나갑니다. 끄면 규제 보고서는 규칙 판정만 만듭니다.</span></span>
              </label>
            </>
          )}
        </div>
      )}

      <div className="mt-4 flex flex-wrap items-center gap-2">
        {f.mode !== 'off' && (
          <Button variant="outline" onClick={runTest} disabled={!!busy || !f.url}>
            <PlugZap size={15} /> {busy === 'test' ? '시험 중…' : '연결 시험'}
          </Button>
        )}
        <Button onClick={save} disabled={!!busy}><Save size={15} /> {busy === 'save' ? '저장 중…' : '저장'}</Button>
        {msg && <span className="text-sm text-muted-foreground">{msg}</span>}
      </div>
      {test && (
        <div className="mt-3 max-w-2xl">
          {test.ok
            ? <Alert tone="ok">정상 — {test.model} 가 {(test.elapsedMs / 1000).toFixed(1)}초 만에 JSON 으로 응답했습니다(“{test.answer}”). 저장해야 적용됩니다.</Alert>
            : <Alert tone="crit">실패 — {test.error}</Alert>}
        </div>
      )}
    </>
  );
}
