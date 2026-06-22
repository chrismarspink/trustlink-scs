import { useEffect, useState } from 'react';
import { caAudit, type CAEvent } from '@/lib/api';
import { Badge } from '@/components/ui/primitives';
import { PageTitle, Table, Th, Td, Loading } from '../_ui';
import { fmtTime, ACTION_KO, HelpNote } from './_shared';

export default function CaAudit() {
  const [events, setEvents] = useState<CAEvent[] | null>(null);
  useEffect(() => { caAudit().then((r) => setEvents(r.events || [])).catch(() => setEvents([])); }, []);

  return (
    <>
      <PageTitle>CA · 감사 로그</PageTitle>
      <HelpNote>
        <b>SoR(System of Record)</b> = 발급·폐기·서명·바인딩·수신자 임포트 등 모든 신뢰 행위의 <b>추가 전용(append-only) 감사 기록</b>
        (누가·언제·무엇을). 규정 준수 증거 체인의 기반입니다.
      </HelpNote>

      {!events ? <Loading /> : events.length === 0 ? (
        <p className="text-sm text-muted-foreground">기록이 없습니다.</p>
      ) : (
        <Table>
          <thead><tr><Th>시각</Th><Th>행위</Th><Th>행위자</Th><Th>대상</Th><Th>상태</Th></tr></thead>
          <tbody>
            {events.slice(0, 100).map((e, i) => (
              <tr key={i}>
                <Td className="text-xs">{fmtTime(e.time)}</Td>
                <Td><Badge variant="muted">{ACTION_KO[e.action] || e.action}</Badge></Td>
                <Td className="text-xs">{e.actor || '-'}</Td>
                <Td className="text-xs">{e.repo ? `${e.repo}:${e.tag}` : (e.subject || (e.serial ? e.serial.slice(0, 16) : '-'))}</Td>
                <Td className="text-xs">{e.status || '-'}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </>
  );
}
