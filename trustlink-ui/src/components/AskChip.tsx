import { MessageCircleQuestion } from 'lucide-react';
import { askOpen } from '@/lib/askOpen';
import { cn } from '@/lib/utils';

// 화면 곳곳에서 묻고 찾기에 일을 넘기는 단추 — 누르면 창이 열리고 그 문장으로 바로 묻는다.
export function AskChip({ q, label, className }: { q: string; label: string; className?: string }) {
  return (
    <button type="button" onClick={() => askOpen(q)} title={`묻고 찾기: "${q}"`}
      className={cn('inline-flex items-center gap-1 whitespace-nowrap rounded-full border border-primary/40 px-2.5 py-1 text-xs font-medium text-primary hover:bg-primary/5', className)}>
      <MessageCircleQuestion size={13} /> {label}
    </button>
  );
}
