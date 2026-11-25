import { useState } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { CircleHelp, X } from 'lucide-react';

// 도움말: 화면이 어떻게 동작하는지 막대 인형 장면(소개 자료와 같은 방식)으로 보여 준다. topic 은 intro.html 의 HELP 키.
export function HelpScene({ topic, title }: { topic: 'vex' | 'ask' | 'mcp'; title: string }) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      <Dialog.Trigger asChild>
        <button className="inline-flex items-center gap-1 whitespace-nowrap rounded-md border border-violet-300 bg-violet-50 px-2.5 py-1.5 text-xs font-semibold text-violet-800 hover:bg-violet-100" title={title}>
          <CircleHelp size={14} /> 도움말
        </button>
      </Dialog.Trigger>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/40" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-[min(1040px,94vw)] -translate-x-1/2 -translate-y-1/2 overflow-hidden rounded-xl border bg-background shadow-xl">
          <div className="flex items-center gap-2 border-b px-4 py-2.5">
            <CircleHelp size={16} className="text-violet-700" />
            <Dialog.Title className="flex-1 text-sm font-semibold">{title}</Dialog.Title>
            <Dialog.Close className="rounded p-1 text-muted-foreground hover:bg-secondary" aria-label="닫기"><X size={16} /></Dialog.Close>
          </div>
          {open && <iframe src={`/intro.html?help=${topic}`} title={title} className="block h-[min(480px,70vh)] w-full border-0 bg-white" />}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
