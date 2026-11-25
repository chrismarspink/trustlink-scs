import { useSyncExternalStore } from 'react';

// 다른 화면에서 바로 묻게 한다: askOpen('CVE-… VEX 판정 초안') — 에이전트 패널의 "묻기"가 열려 답한다.
export const askOpen = (q: string) => window.dispatchEvent(new CustomEvent('tl-ask', { detail: { q } }));

// 오른쪽 아래 묻고 찾기 버튼을 껐는가(에이전트 설정). null = 아직 설정을 받지 못함.
let off: boolean | null = null;
const subs = new Set<() => void>();
export const setAskOff = (v: boolean) => { if (off !== v) { off = v; subs.forEach((x) => x()); } };
export const useAskOff = () => useSyncExternalStore((cb) => { subs.add(cb); return () => subs.delete(cb); }, () => off);
