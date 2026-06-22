import { useEffect, useState } from 'react';
import { caCerts, caRevoke, caReissue, type CACert } from '@/lib/api';
import { Badge, Button } from '@/components/ui/primitives';
import { PageTitle, Table, Th, Td, Loading } from '../_ui';
import { fmtTime, useAction, MsgBar, HelpNote } from './_shared';

export default function CaCertificates() {
  const [certs, setCerts] = useState<CACert[] | null>(null);
  const reload = () => { caCerts().then((r) => setCerts(r.certs || [])).catch(() => setCerts([])); };
  useEffect(reload, []);
  const { busy, msg, run } = useAction(reload);

  return (
    <>
      <PageTitle>CA · 인증서</PageTitle>
      <HelpNote>
        <b>폐기(revoke)</b> = 만료 전 인증서를 무효화(예: 키 유출) → CRL 에 등재되어 검증 시 거부됩니다.
        <b> 재발급(reissue)</b> = 같은 주체(CN)로 새 인증서 발급(짧은수명 운영에서 갱신 대신 사용). 발급 목록은 TrustLink 가
        기록한 SoR 기준입니다.
      </HelpNote>
      <MsgBar msg={msg} />

      {!certs ? <Loading /> : certs.length === 0 ? (
        <p className="text-sm text-muted-foreground">발급된 인증서가 없습니다.</p>
      ) : (
        <Table>
          <thead><tr><Th>시리얼</Th><Th>주체</Th><Th>만료</Th><Th>상태</Th><Th>발급자</Th><Th>작업</Th></tr></thead>
          <tbody>
            {certs.map((c) => (
              <tr key={c.serial}>
                <Td className="font-mono text-xs">{c.serial.slice(0, 20)}</Td>
                <Td className="text-xs">{c.subject}</Td>
                <Td className="text-xs">{fmtTime(c.notAfter)}</Td>
                <Td><Badge variant={c.status === 'revoked' ? 'warn' : 'success'}>{c.status === 'revoked' ? '폐기됨' : '유효'}</Badge></Td>
                <Td className="text-xs">{c.actor || '-'}</Td>
                <Td>
                  <div className="flex gap-1">
                    <Button size="sm" variant="outline" disabled={busy} onClick={() => {
                      if (!confirm(`동일 CN 으로 재발급할까요?\n${c.subject}`)) return;
                      run(async () => { const r = await caReissue(c.serial); return `재발급: ${r.serial.slice(0, 16)}…`; });
                    }}>재발급</Button>
                    {c.status !== 'revoked' && (
                      <Button size="sm" variant="destructive" disabled={busy} onClick={() => {
                        const reason = prompt('폐기 사유 (선택):', 'superseded');
                        if (reason === null) return;
                        run(async () => { await caRevoke(c.serial, reason); return `폐기됨: ${c.serial.slice(0, 16)}…`; });
                      }}>폐기</Button>
                    )}
                  </div>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </>
  );
}
