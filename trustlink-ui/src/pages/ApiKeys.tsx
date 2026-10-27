import { useEffect, useState } from 'react';
import { KeyRound, Plus, Trash2, Copy, Check } from 'lucide-react';
import { listApiKeys, createApiKey, deleteApiKey, getSession, type ApiKey } from '@/lib/api';
import { Button, Input, Badge, Card } from '@/components/ui/primitives';

// 내 API 키: oras(명령줄)로 로그인할 때 비밀번호 대신 쓰는 개인 토큰.
//   웹 로그인 비밀번호는 oras 에서 받지 않는다. 권한은 내 역할·고객사·제품 권한을 그대로 따른다.
//   계정이 비활성화되거나 고객사에서 빠지면 키도 즉시 쓸 수 없게 된다.

async function copyText(text: string) {
  if (window.isSecureContext && navigator.clipboard) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  document.execCommand('copy');
  document.body.removeChild(ta);
}

const fmt = (s: string) => (!s || s.startsWith('0001-') ? '-' : s.slice(0, 10));

export default function ApiKeys() {
  const [keys, setKeys] = useState<ApiKey[] | null>(null);
  const [user, setUser] = useState('<내 ID>');
  const [err, setErr] = useState('');
  const [label, setLabel] = useState('');
  const [days, setDays] = useState(90);
  const [issued, setIssued] = useState<{ key: string; label: string } | null>(null);
  const [copied, setCopied] = useState(false);

  async function load() {
    setErr('');
    try {
      setKeys(await listApiKeys());
    } catch (e) {
      setErr(String(e));
    }
  }
  useEffect(() => {
    load();
    getSession().then((s) => s && setUser(s.username)).catch(() => {});
  }, []);

  async function create() {
    const l = label.trim() || 'oras';
    const exp = days > 0 ? new Date(Date.now() + days * 86400000).toISOString().replace(/\.\d+Z$/, 'Z') : '';
    try {
      const r = await createApiKey(l, exp);
      setIssued({ key: r.apiKey, label: l });
      setCopied(false);
      setLabel('');
      await load();
    } catch (e) {
      alert('발급 실패: ' + e);
    }
  }

  async function remove(k: ApiKey) {
    if (!confirm(`API 키 "${k.label}" 를 삭제할까요? 이 키를 쓰는 oras 로그인은 즉시 실패합니다.`)) return;
    try {
      await deleteApiKey(k.uuid);
      await load();
    } catch (e) {
      alert('삭제 실패: ' + e);
    }
  }

  const reg = `${window.location.hostname}:28081`;
  const loginCmd = `printf '%s' '<API 키>' | oras login ${reg} -u ${user} --password-stdin --plain-http`;

  return (
    <div className="mx-auto max-w-4xl">
      <h1 className="mb-2 flex items-center gap-2 text-2xl font-bold"><KeyRound size={22} /> 내 API 키</h1>
      <p className="mb-5 text-sm text-muted-foreground">
        oras(명령줄)로 업로드·다운로드할 때 비밀번호 대신 쓰는 개인 토큰입니다. 웹 로그인 비밀번호로는 oras 에 로그인할 수 없습니다.
        권한은 내 계정 권한과 같고, 계정이 비활성화되면 키도 즉시 막힙니다. 서버·CI 자동화에는 관리자에게 기계 계정을 요청하세요.
      </p>

      <Card className="mb-5 p-4">
        <div className="mb-2 text-sm font-semibold">새 키 발급</div>
        <div className="flex flex-wrap items-center gap-2">
          <Input className="w-64" placeholder="용도 (예: 내 노트북)" value={label} onChange={(e) => setLabel(e.target.value)} />
          <select className="h-9 rounded-md border border-input bg-card px-2 text-sm" value={days} onChange={(e) => setDays(Number(e.target.value))}>
            <option value={30}>30일</option><option value={90}>90일</option><option value={180}>180일</option><option value={365}>1년</option>
          </select>
          <Button variant="accent" size="sm" onClick={create}><Plus size={15} /> 발급</Button>
        </div>
        {issued && (
          <div className="mt-4 rounded-md border border-amber-300 bg-amber-50 p-3">
            <div className="mb-1 text-sm font-semibold text-amber-800">"{issued.label}" 키 — 지금 한 번만 표시됩니다</div>
            <div className="flex items-center gap-2">
              <code className="flex-1 break-all rounded border bg-white px-2 py-1 font-mono text-sm">{issued.key}</code>
              <Button size="sm" variant="outline" onClick={async () => { await copyText(issued.key); setCopied(true); }}>
                {copied ? <Check size={14} /> : <Copy size={14} />} {copied ? '복사됨' : '복사'}
              </Button>
            </div>
          </div>
        )}
        <div className="mt-4 text-xs text-muted-foreground">사용 예</div>
        <code className="mt-1 block rounded bg-secondary px-2 py-1.5 font-mono text-xs">{loginCmd}</code>
      </Card>

      {err && <div className="mb-3 rounded-md bg-red-50 px-4 py-3 text-sm text-red-700">오류: {err}</div>}
      <div className="overflow-x-auto rounded-lg border">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-secondary/60 text-left text-muted-foreground">
              <th className="border-b px-3 py-2 font-medium">용도</th><th className="border-b px-3 py-2 font-medium">발급일</th>
              <th className="border-b px-3 py-2 font-medium">만료일</th><th className="border-b px-3 py-2 font-medium">마지막 사용</th>
              <th className="border-b px-3 py-2 font-medium">관리</th>
            </tr>
          </thead>
          <tbody>
            {(keys || []).map((k) => (
              <tr key={k.uuid} className={k.isExpired ? 'opacity-60' : ''}>
                <td className="border-b px-3 py-2 font-medium">{k.label}</td>
                <td className="border-b px-3 py-2">{fmt(k.createdAt)}</td>
                <td className="border-b px-3 py-2">{k.isExpired ? <Badge variant="danger">만료됨</Badge> : fmt(k.expirationDate)}</td>
                <td className="border-b px-3 py-2">{fmt(k.lastUsed)}</td>
                <td className="border-b px-3 py-2"><Button size="sm" variant="outline" onClick={() => remove(k)} title="삭제"><Trash2 size={14} /></Button></td>
              </tr>
            ))}
            {keys && keys.length === 0 && <tr><td className="px-3 py-3 text-muted-foreground" colSpan={5}>발급한 키가 없습니다</td></tr>}
            {!keys && !err && <tr><td className="px-3 py-3 text-muted-foreground" colSpan={5}>로딩…</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}
