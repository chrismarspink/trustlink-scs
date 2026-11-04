import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function fmtBytes(n: number) {
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}

// oras 레지스트리 주소: https(앞단 프록시, /v2/ → zot) 접속이면 웹과 같은 도메인, 아니면 zot 직접 진입점 :28081(평문 HTTP)
const tls = window.location.protocol === 'https:';
export const registry = tls ? window.location.host : `${window.location.hostname}:28081`;
export const plainHttp = tls ? '' : ' --plain-http';
