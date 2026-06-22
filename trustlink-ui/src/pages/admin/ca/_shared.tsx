import { useState } from 'react';
import { Alert } from '../_ui';

// CA 하위 페이지 공용 유틸.

export const ACTION_KO: Record<string, string> = {
  issue: '발급', revoke: '폐기', sign: 'CMS 서명', bind: 'referrer 바인딩',
  'recipient-import': '수신자 임포트', 'recipient-delete': '수신자 삭제'
};

export const TTL = [
  { v: '24h', l: '24시간 (서명용·기본)' }, { v: '720h', l: '30일' },
  { v: '2160h', l: '90일' }, { v: '8760h', l: '1년 (고객용 최대)' }
];

export function fmtTime(s?: string) { return s ? s.replace('T', ' ').replace('Z', ' UTC') : '-'; }

export function download(name: string, text: string) {
  const a = document.createElement('a');
  a.href = 'data:application/x-pem-file;charset=utf-8,' + encodeURIComponent(text);
  a.download = name; a.click();
}

export type Msg = { tone: 'ok' | 'warn' | 'crit'; text: string } | null;

// 쓰기 액션 래퍼 — 실행 후 reload, 결과 배너.
export function useAction(reload: () => void) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<Msg>(null);
  async function run(fn: () => Promise<string>) {
    setBusy(true); setMsg(null);
    try { setMsg({ tone: 'ok', text: await fn() }); reload(); }
    catch (e) { setMsg({ tone: 'crit', text: String(e) }); }
    finally { setBusy(false); }
  }
  return { busy, msg, run };
}

export function MsgBar({ msg }: { msg: Msg }) {
  return msg ? <Alert tone={msg.tone}>{msg.text}</Alert> : null;
}

// 페이지 상단 용어/도움 설명 박스(문서·관리 일관 패턴).
export function HelpNote({ children }: { children: React.ReactNode }) {
  return <div className="mb-4 rounded-md border border-border bg-secondary/40 px-4 py-3 text-xs leading-relaxed text-muted-foreground">{children}</div>;
}
