import { useEffect, useRef, type ReactNode } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { CircleHelp, X } from 'lucide-react';
import type { StorySpec } from '@/lib/scenes';

// 막대 인형 장면 창: 소개 자료의 장면 재생기(/intro.html)에 이야기를 넘겨 보여 준다.
// mode: prepend = 넘긴 이야기를 앞에 두고 기본 소개를 뒤에, replace = 넘긴 이야기만.
export function SceneDialog({ open, onOpenChange, title, stories, mode = 'replace', footer }: { open: boolean; onOpenChange: (v: boolean) => void; title: string; stories?: StorySpec[]; mode?: 'prepend' | 'replace'; footer?: ReactNode }) {
  const frame = useRef<HTMLIFrameElement>(null);
  const post = () => { if (stories?.length) frame.current?.contentWindow?.postMessage({ type: 'tl-scenes', mode, stories }, window.location.origin); };
  useEffect(() => { // 재생기가 준비됐다고 알리면 넘긴다(이야기가 바뀌어도 다시 넘긴다)
    if (!open) return;
    const h = (e: MessageEvent) => { if (e.origin === window.location.origin && e.data?.type === 'tl-scenes-ready') post(); };
    window.addEventListener('message', h);
    post();
    return () => window.removeEventListener('message', h);
  }, [open, stories, mode]); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-[60] bg-black/40" />
        <Dialog.Content aria-describedby={undefined} className="fixed left-1/2 top-1/2 z-[60] flex max-h-[94vh] w-[min(1040px,96vw)] -translate-x-1/2 -translate-y-1/2 flex-col overflow-hidden rounded-xl border bg-background shadow-xl">
          <div className="flex items-center gap-2 border-b px-4 py-2.5">
            <CircleHelp size={16} className="text-violet-700" />
            <Dialog.Title className="min-w-0 flex-1 truncate text-sm font-semibold">{title}</Dialog.Title>
            <Dialog.Close className="rounded p-1 text-muted-foreground hover:bg-secondary" aria-label="닫기"><X size={16} /></Dialog.Close>
          </div>
          {open && <iframe ref={frame} src="/intro.html?wait=1" title={title} onLoad={post} className="block h-[min(500px,62vh)] w-full shrink-0 border-0 bg-white" />}
          {footer && <div className="flex flex-wrap items-center gap-2 border-t px-4 py-2.5 text-sm">{footer}</div>}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
