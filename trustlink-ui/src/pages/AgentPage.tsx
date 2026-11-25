import { AgentView, useAgent } from '@/components/Agent';

// 에이전트를 한 화면으로 본다(사이드바 메뉴). 상단 버튼으로 여는 패널과 같은 내용이다.
export function AgentPage() {
  const { d, load } = useAgent();
  return (
    <div className="max-w-[720px]">
      <h1 className="text-xl font-bold">에이전트</h1>
      <p className="mb-3 mt-1 text-sm text-muted-foreground">내 권한에 맞는 할 일을 모아 제안하고, 고르면 대신 실행합니다. 고객에게 나가는 것은 내용을 보고 승인해야 나갑니다.</p>
      {d ? <div className="flex h-[calc(100vh-220px)] min-h-[420px] flex-col rounded-lg border"><div className="pt-3" /><AgentView d={d} load={load} /></div>
        : <div className="rounded-lg border border-dashed p-10 text-center text-sm text-muted-foreground">로그인하면 할 일을 볼 수 있습니다.</div>}
    </div>
  );
}
