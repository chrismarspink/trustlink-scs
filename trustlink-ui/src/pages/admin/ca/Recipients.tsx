import { useEffect, useState } from 'react';
import { caRecipients, caRecipientImport, caRecipientDelete, downloadSharePackage, type Recipient } from '@/lib/api';
import { Card, CardContent, Button } from '@/components/ui/primitives';
import { PageTitle, Table, Th, Td, Loading, selectCls } from '../_ui';
import { fmtTime, useAction, MsgBar, HelpNote } from './_shared';

export default function CaRecipients() {
  const [recips, setRecips] = useState<Recipient[] | null>(null);
  const reload = () => { caRecipients().then((r) => setRecips(r.recipients || [])).catch(() => setRecips([])); };
  useEffect(reload, []);
  const { busy, msg, run } = useAction(reload);
  const [pem, setPem] = useState('');
  // 서명 패키지 다운로드 폼 (.p7s 서명만 / .p7m 수신자 암호화)
  const [pkgFmt, setPkgFmt] = useState<'p7s' | 'p7m'>('p7s');
  const [pkgRecip, setPkgRecip] = useState('');
  const [pkgRepo, setPkgRepo] = useState('');
  const [pkgTag, setPkgTag] = useState('');

  return (
    <>
      <PageTitle>CA · 수신자 인증서</PageTitle>
      <HelpNote>
        <b>수신자 인증서</b>는 외부 협력사·고객의 <b>공개 인증서</b>로, <b>CMS 암호화(EnvelopedData)</b> 시
        그 수신자만 복호할 수 있도록 암호화 대상으로 씁니다(개인키는 고객이 보유, 우리는 공개 인증서만 보관).
        고객이 자체 PKI 로 발급받은 인증서를 여기에 <b>임포트</b>한 뒤, 아래에서 산출물을
        <b> 서명+암호화 패키지(.p7m)</b>로 만들어 전달하세요.
      </HelpNote>
      <MsgBar msg={msg} />

      <Card>
        <CardContent className="space-y-2 pt-4">
          <textarea className={selectCls + ' h-24 w-full font-mono text-xs'} placeholder="고객 공개 인증서 PEM (-----BEGIN CERTIFICATE-----)" value={pem} onChange={(e) => setPem(e.target.value)} />
          <Button disabled={busy || !pem.includes('BEGIN CERTIFICATE')} onClick={() => run(async () => {
            const r = await caRecipientImport(pem); setPem('');
            return `임포트됨: ${r.subject}`;
          })}>인증서 임포트</Button>
          <p className="text-xs text-muted-foreground">공개 인증서만 저장합니다(개인키 없음).</p>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="space-y-2 pt-4">
          <div className="text-sm font-medium">서명 패키지 다운로드</div>
          <p className="text-xs text-muted-foreground">
            산출물 번들(바이너리·SBOM·VEX)을 CMS 서명합니다. <b>서명만(.p7s)</b>은 누구나 신뢰 앵커(루트)로 검증 가능,
            <b> 수신자 암호화(.p7m)</b>는 선택한 수신자만 개인키로 복호할 수 있습니다.
          </p>
          <div className="flex flex-wrap items-center gap-3">
            <label className="flex items-center gap-1 text-sm"><input type="radio" name="pkgfmt" checked={pkgFmt === 'p7s'} onChange={() => setPkgFmt('p7s')} /> 서명만 (.p7s)</label>
            <label className="flex items-center gap-1 text-sm"><input type="radio" name="pkgfmt" checked={pkgFmt === 'p7m'} onChange={() => setPkgFmt('p7m')} /> 수신자 암호화 (.p7m)</label>
          </div>
          <div className="flex flex-wrap gap-2">
            {pkgFmt === 'p7m' && (
              <select className={selectCls} value={pkgRecip} onChange={(e) => setPkgRecip(e.target.value)}>
                <option value="">수신자 선택…</option>
                {(recips || []).map((r) => <option key={r.id} value={r.id}>{r.subject}</option>)}
              </select>
            )}
            <input className={selectCls} placeholder="레포 (예: innotium/trustlink-scs)" value={pkgRepo} onChange={(e) => setPkgRepo(e.target.value)} />
            <input className={selectCls} placeholder="태그 (예: latest)" value={pkgTag} onChange={(e) => setPkgTag(e.target.value)} />
            <Button disabled={busy || !pkgRepo || !pkgTag || (pkgFmt === 'p7m' && !pkgRecip)} onClick={() => run(async () => {
              const res = await downloadSharePackage(pkgRepo.trim(), pkgTag.trim(), pkgFmt === 'p7m' ? { recipientId: pkgRecip } : {});
              return `다운로드: ${res.filename} (FIPS=${res.fips}, serial=${res.serial})`;
            })}>패키지 생성·다운로드</Button>
          </div>
          <p className="text-xs text-muted-foreground">
            수신측 검증: <code className="font-mono">{pkgFmt === 'p7m'
              ? 'openssl cms -decrypt -inform DER -in pkg.signed.p7m -recip cert.pem -inkey key.pem | openssl cms -verify -inform DER -CAfile root_ca.crt -purpose any'
              : 'openssl cms -verify -inform DER -in pkg.signed.p7s -CAfile root_ca.crt -purpose any -out bundle.zip'}</code>
          </p>
        </CardContent>
      </Card>

      {!recips ? <Loading /> : recips.length > 0 && (
        <Table>
          <thead><tr><Th>주체</Th><Th>만료</Th><Th>임포트</Th><Th>지문</Th><Th>작업</Th></tr></thead>
          <tbody>
            {recips.map((r) => (
              <tr key={r.id}>
                <Td className="text-xs">{r.subject}</Td>
                <Td className="text-xs">{fmtTime(r.notAfter)}</Td>
                <Td className="text-xs">{r.importedBy} · {fmtTime(r.importedAt).slice(0, 10)}</Td>
                <Td className="font-mono text-[10px]">{r.id.slice(0, 16)}</Td>
                <Td>
                  <Button size="sm" variant="destructive" disabled={busy} onClick={() => {
                    if (!confirm(`수신자를 삭제할까요?\n${r.subject}`)) return;
                    run(async () => { await caRecipientDelete(r.id); return '삭제됨'; });
                  }}>삭제</Button>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </>
  );
}
