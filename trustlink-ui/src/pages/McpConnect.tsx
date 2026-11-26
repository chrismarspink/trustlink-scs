import { useEffect, useState } from 'react';
import { Plug, Plus, Trash2, Copy, Check } from 'lucide-react';
import { mcpTokens, mcpTokenCreate, mcpTokenDelete, type McpInfo, type McpIssued } from '@/lib/api';
import { Button, Input, Badge, Card } from '@/components/ui/primitives';
import { HelpScene } from '@/components/HelpScene';

// AI 도구 연결(MCP): Claude 같은 AI 도구가 TrustLink 에 직접 묻게 하는 연결 토큰을 만들고, 등록 명령을 보여 준다.
//   조회만 된다(보내기·저장 없음). 답은 내 권한 범위 그대로이고, 물은 내용은 감사 원장에 남는다.

async function copyText(text: string) {
  if (window.isSecureContext && navigator.clipboard) { await navigator.clipboard.writeText(text); return; }
  const ta = document.createElement('textarea');
  ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
}

function CopyBlock({ label, text }: { label: string; text: string }) {
  const [ok, setOk] = useState(false);
  return (
    <div className="mt-3">
      <div className="mb-1 flex items-center gap-2 text-xs font-semibold text-muted-foreground">
        {label}
        <button type="button" onClick={async () => { await copyText(text); setOk(true); setTimeout(() => setOk(false), 1500); }}
          className="ml-auto inline-flex items-center gap-1 rounded-md border px-2 py-1 font-medium text-foreground hover:bg-secondary">
          {ok ? <Check size={12} /> : <Copy size={12} />} {ok ? '복사됨' : '복사'}
        </button>
      </div>
      <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-md bg-secondary px-3 py-2 font-mono text-xs leading-relaxed">{text}</pre>
    </div>
  );
}

const fmt = (s?: string) => (s ? s.slice(0, 10) : '-');
const EXAMPLES = ['TrustLink 에서 CVE-2026-1234 가 어디에 걸리는지 찾아 줘', 'TrustLink 현황을 요약하고 급한 것부터 정리해 줘', 'log4j 를 쓰는 제품이 있는지 TrustLink 에서 확인해 줘'];

export default function McpConnect() {
  const [info, setInfo] = useState<McpInfo | null>(null);
  const [err, setErr] = useState('');
  const [name, setName] = useState('');
  const [days, setDays] = useState(90);
  const [issued, setIssued] = useState<McpIssued | null>(null);

  const load = () => mcpTokens().then(setInfo).catch((e) => setErr(String(e)));
  useEffect(() => { load(); }, []);

  async function create() {
    setErr('');
    try { setIssued(await mcpTokenCreate(name.trim() || 'AI 도구', days)); setName(''); await load(); } catch (e) { setErr(String(e).replace(/^(Api)?Error:\s*(\d{3}\s*)?/, '')); }
  }
  async function remove(id: string, label: string) {
    if (!confirm(`"${label}" 연결을 끊을까요? 이 토큰을 쓰는 AI 도구는 바로 TrustLink 에 묻지 못하게 됩니다.`)) return;
    try { await mcpTokenDelete(id); if (issued?.id === id) setIssued(null); await load(); } catch (e) { setErr(String(e)); }
  }

  const url = info?.url || `${window.location.origin}/api/mcp`;
  const tok = issued?.token || '<연결 토큰>';
  const codeCmd = `claude mcp add --transport http trustlink ${url} --header "Authorization: Bearer ${tok}"`;
  const desktop = JSON.stringify({ mcpServers: { trustlink: { command: 'npx', args: ['-y', 'mcp-remote', url, '--header', `Authorization: Bearer ${tok}`] } } }, null, 2);

  return (
    <div className="mx-auto max-w-4xl">
      <div className="mb-2 flex flex-wrap items-center gap-3">
        <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight"><Plug size={22} /> AI 도구 연결 <Badge variant="outline">시범</Badge></h1>
        <HelpScene topic="mcp" title="AI 도구 연결(MCP)은 이렇게 동작합니다" />
      </div>
      <p className="mb-5 text-sm text-muted-foreground">
        Claude 같은 AI 도구에 TrustLink 를 연결하면(MCP), 그 도구 안에서 취약점 영향과 현황을 바로 물을 수 있습니다.
        조회만 되고 보내기·저장은 없습니다. 답은 내 권한 범위 그대로이며, 물은 내용은 감사 원장에 남습니다.
      </p>

      <Card className="mb-5 p-4">
        <div className="mb-2 text-sm font-semibold">1. 연결 토큰 만들기</div>
        <div className="flex flex-wrap items-center gap-2">
          <label htmlFor="mcp-name" className="sr-only">토큰 이름</label>
          <Input id="mcp-name" className="w-64 max-w-full" placeholder="어디에 쓰나 (예: 내 노트북 Claude)" value={name} maxLength={40} onChange={(e) => setName(e.target.value)} />
          <label htmlFor="mcp-days" className="sr-only">기한</label>
          <select id="mcp-days" className="h-9 rounded-md border border-input bg-card px-2 text-sm" value={days} onChange={(e) => setDays(Number(e.target.value))}>
            <option value={7}>7일</option><option value={30}>30일</option><option value={90}>90일</option><option value={365}>1년</option>
          </select>
          <Button variant="accent" size="sm" onClick={create}><Plus size={15} /> 만들기</Button>
        </div>
        {err && <div className="mt-3 rounded-md bg-red-50 px-3 py-2 text-sm text-red-700">{err}</div>}
        {issued && (
          <div className="mt-4 rounded-md border border-amber-300 bg-amber-50 p-3">
            <div className="mb-1 text-sm font-semibold text-amber-800">"{issued.name}" 토큰 — 지금 한 번만 보입니다. 아래 명령에 이미 채워져 있습니다.</div>
            <code className="block break-all rounded border bg-white px-2 py-1 font-mono text-xs">{issued.token}</code>
          </div>
        )}

        <div className="mt-5 text-sm font-semibold">2. AI 도구에 등록하기</div>
        <CopyBlock label="Claude Code — 터미널에 붙여 넣기" text={codeCmd} />
        <CopyBlock label="Claude Desktop — 설정 › 개발자 › 구성 편집(claude_desktop_config.json)에 넣고 다시 시작" text={desktop} />
        {!issued && <p className="mt-2 text-xs text-muted-foreground">토큰을 만들면 위 명령의 &lt;연결 토큰&gt; 자리가 채워집니다.</p>}

        <div className="mt-5 text-sm font-semibold">3. AI 도구에서 묻기</div>
        <ul className="mt-2 space-y-1 text-sm text-muted-foreground">
          {EXAMPLES.map((e) => <li key={e} className="rounded-md bg-secondary/60 px-3 py-1.5">“{e}”</li>)}
        </ul>
      </Card>

      <div className="mb-2 text-sm font-semibold">내 연결 토큰 {info && <span className="font-normal text-muted-foreground">({info.tokens.filter((t) => t.user === info.user).length}/{info.max})</span>}</div>
      <div className="overflow-x-auto rounded-lg border bg-card">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-secondary/60 text-left text-muted-foreground">
              <th className="border-b px-3 py-2 font-medium">이름</th><th className="border-b px-3 py-2 font-medium">계정</th><th className="border-b px-3 py-2 font-medium">만든 날</th>
              <th className="border-b px-3 py-2 font-medium">기한</th><th className="border-b px-3 py-2 font-medium">마지막 사용</th><th className="border-b px-3 py-2 font-medium">횟수</th><th className="border-b px-3 py-2 font-medium">끊기</th>
            </tr>
          </thead>
          <tbody>
            {(info?.tokens || []).map((t) => (
              <tr key={t.id} className={t.expired ? 'opacity-60' : ''}>
                <td className="border-b px-3 py-2 font-medium">{t.name}</td>
                <td className="border-b px-3 py-2">{t.user}</td>
                <td className="border-b px-3 py-2">{fmt(t.created)}</td>
                <td className="border-b px-3 py-2">{t.expired ? <Badge variant="danger">기한 지남</Badge> : fmt(t.expires)}</td>
                <td className="border-b px-3 py-2">{fmt(t.lastUsed)}</td>
                <td className="border-b px-3 py-2 tabular-nums">{t.uses}</td>
                <td className="border-b px-3 py-2"><Button size="sm" variant="outline" onClick={() => remove(t.id, t.name)} aria-label={`${t.name} 끊기`}><Trash2 size={14} /></Button></td>
              </tr>
            ))}
            {info && info.tokens.length === 0 && <tr><td className="px-3 py-3 text-muted-foreground" colSpan={7}>만든 토큰이 없습니다</td></tr>}
            {!info && !err && <tr><td className="px-3 py-3 text-muted-foreground" colSpan={7}>불러오는 중…</td></tr>}
          </tbody>
        </table>
      </div>
      <p className="mt-3 text-xs text-muted-foreground">
        토큰은 비밀번호처럼 다루세요. 계정이 꺼지면 토큰도 5분 안에 막히고, 여기서 끊으면 바로 막힙니다. 관리자에게는 모든 사람의 토큰이 보입니다.
      </p>
    </div>
  );
}
