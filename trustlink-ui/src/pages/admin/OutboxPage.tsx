import { useState } from 'react';
import { OutboxPanel, HoldPanel } from '@/components/Outbox';
import { PageHeader, selectCls } from './_ui';
import type { OutboxItem } from '@/lib/api';

// 관리 › 발송함: TrustLink 가 내보낸 모든 메일 한 목록 — 사람이 승인한 메일은 대기 동안 취소, 자동 메일은 결과 기록.
const KINDS: [OutboxItem['kind'] | '', string][] = [['', '전체'], ['custnotify', '고객 통지'], ['devreq', '개발자 수정 요청'], ['digest', '현황 메일'], ['notify', '통보(내부·VEX 발행)'], ['expiry', '만료 안내']];

export default function OutboxPage() {
  const [kind, setKind] = useState<OutboxItem['kind'] | ''>('');
  const [tick, setTick] = useState(0);
  return (
    <>
      <PageHeader title="발송함" description="TrustLink 가 내보낸 모든 메일입니다. 사람이 승인한 메일은 정한 시간 동안 기다렸다 나가며 그 사이 취소할 수 있고, 내부로 가는 자동 메일은 결과가 남습니다. 고객에게 가는 자동 메일(VEX 발행 통보·만료 안내)은 여기서 승인해야 나갑니다." />
      <HoldPanel onChange={() => setTick((n) => n + 1)} />
      <div className="mb-3 flex items-center gap-2 text-sm">
        <span className="text-muted-foreground">종류</span>
        <select className={selectCls} value={kind} onChange={(e) => setKind(e.target.value as OutboxItem['kind'] | '')}>
          {KINDS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}
        </select>
        <span className="text-xs text-muted-foreground">최근 50건</span>
      </div>
      <OutboxPanel kind={kind || undefined} refreshKey={tick} />
    </>
  );
}
