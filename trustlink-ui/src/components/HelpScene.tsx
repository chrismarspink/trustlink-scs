import { useState } from 'react';
import { CircleHelp } from 'lucide-react';
import { SceneDialog } from '@/components/SceneDialog';

// 도움말: 화면이 어떻게 동작하는지 막대 인형 장면으로 보여 준다(AI 답변 장면과 같은 틀 — SceneDialog).
// topic 은 intro.html 의 HELP 키.
export function HelpScene({ topic, title }: { topic: 'vex' | 'ask' | 'mcp' | 'mobile'; title: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button type="button" onClick={() => setOpen(true)} title={title} className="inline-flex items-center gap-1 whitespace-nowrap rounded-md border border-violet-300 bg-violet-50 px-2.5 py-1.5 text-xs font-semibold text-violet-800 hover:bg-violet-100">
        <CircleHelp size={14} /> 도움말
      </button>
      <SceneDialog open={open} onOpenChange={setOpen} title={title} helpTopic={topic} />
    </>
  );
}
