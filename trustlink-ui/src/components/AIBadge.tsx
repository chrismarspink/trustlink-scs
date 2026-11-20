import { Sparkles } from 'lucide-react';
import { cn } from '@/lib/utils';

// AI 기능 표시 — 어디서든 같은 모양(보라→자홍 그라데이션 + 반짝임)으로 "AI 가 한 일/할 수 있는 일"을 알린다.
export function AIBadge({ label = 'AI 판정', className, pulse }: { label?: string; className?: string; pulse?: boolean }) {
  return (
    <span className={cn('inline-flex items-center gap-1 rounded-full bg-gradient-to-r from-violet-600 to-fuchsia-500 px-2 py-0.5 text-[11px] font-semibold text-white shadow-sm', className)}>
      <Sparkles size={11} className={pulse ? 'animate-pulse' : undefined} /> {label}
    </span>
  );
}

// 큰 AI 아이콘(원형) — 카드 머리 등에.
export function AIIcon({ size = 28, spin }: { size?: number; spin?: boolean }) {
  return (
    <span className="inline-flex items-center justify-center rounded-full bg-gradient-to-br from-violet-600 to-fuchsia-500 text-white shadow"
      style={{ width: size, height: size }}>
      <Sparkles size={Math.round(size * 0.55)} className={spin ? 'animate-pulse' : undefined} />
    </span>
  );
}
