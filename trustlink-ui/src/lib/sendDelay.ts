import { useState } from 'react';

// 보내기 전 기다리는 시간(초) — 그동안 "보내기 취소"가 된다. 사용자별로 브라우저에 기억.
const KEY = 'tl-mail-delay';
export const DELAYS = [[0, '바로'], [10, '10초'], [30, '30초'], [60, '1분'], [120, '2분']] as const;
export function useSendDelay(): [number, (n: number) => void] {
  const [d, setD] = useState(() => { try { const v = Number(localStorage.getItem(KEY)); return DELAYS.some(([s]) => s === v) && localStorage.getItem(KEY) !== null ? v : 30; } catch { return 30; } });
  return [d, (n: number) => { setD(n); try { localStorage.setItem(KEY, String(n)); } catch { /* 저장소 차단 */ } }];
}
