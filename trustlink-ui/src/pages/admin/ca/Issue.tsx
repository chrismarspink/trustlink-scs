import { useState } from 'react';
import { caIssue, caSignCSR } from '@/lib/api';
import { Card, CardHeader, CardContent, Button, Input } from '@/components/ui/primitives';
import { PageTitle, selectCls } from '../_ui';
import { TTL, download, useAction, MsgBar, HelpNote } from './_shared';

export default function CaIssue() {
  const { busy, msg, run } = useAction(() => {});
  const [cn, setCn] = useState('');
  const [sans, setSans] = useState('');
  const [ttl, setTtl] = useState('24h');
  const [csr, setCsr] = useState('');
  const [csrTtl, setCsrTtl] = useState('8760h');
  const [signed, setSigned] = useState('');

  return (
    <>
      <PageTitle>CA · 발급·서명</PageTitle>
      <HelpNote>
        <b>리프(leaf) 인증서</b> = CA 가 발급하는 최종 사용자 인증서(루트/중간 CA 와 구분). <b>CSR</b>(인증서 서명 요청)은
        고객이 <b>자기 개인키로 만든 공개 서명 요청</b>으로, 우리가 서명해주면 고객은 개인키를 노출하지 않고 인증서를 받습니다.
        <br /><b>키 생성 범위:</b> GUI 는 리프 인증서만 발급합니다(루트/중간 CA 생성은 오프라인/CLI 전용 — 신뢰 기반 보호).
      </HelpNote>
      <MsgBar msg={msg} />

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="font-semibold">인증서 발급 (리프 · 서버 키 생성)</CardHeader>
          <CardContent className="space-y-2">
            <Input placeholder="CN (예: trustlink-release-signer)" value={cn} onChange={(e) => setCn(e.target.value)} />
            <Input placeholder="SAN (쉼표 구분, 선택)" value={sans} onChange={(e) => setSans(e.target.value)} />
            <select className={selectCls + ' w-full'} value={ttl} onChange={(e) => setTtl(e.target.value)}>
              {TTL.map((t) => <option key={t.v} value={t.v}>{t.l}</option>)}
            </select>
            <Button disabled={busy || !cn} onClick={() => {
              if (!confirm(`인증서를 발급할까요?\nCN=${cn}`)) return;
              run(async () => {
                const r = await caIssue({ cn, sans: sans ? sans.split(',').map((x) => x.trim()) : undefined, notAfter: ttl });
                setCn(''); setSans('');
                return `발급됨: ${r.serial.slice(0, 16)}… (${r.subject})`;
              });
            }}>발급</Button>
            <p className="text-xs text-muted-foreground">개인키는 서버측에 보관되며 응답·화면에 노출되지 않습니다(§4). 서명 워크플로 안에서만 사용됩니다.</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="font-semibold">고객 인증서 발급 (CSR 서명)</CardHeader>
          <CardContent className="space-y-2">
            <textarea className={selectCls + ' h-24 w-full font-mono text-xs'} placeholder="-----BEGIN CERTIFICATE REQUEST-----" value={csr} onChange={(e) => setCsr(e.target.value)} />
            <select className={selectCls + ' w-full'} value={csrTtl} onChange={(e) => setCsrTtl(e.target.value)}>
              {TTL.map((t) => <option key={t.v} value={t.v}>{t.l}</option>)}
            </select>
            <Button disabled={busy || !csr.includes('CERTIFICATE REQUEST')} onClick={() => run(async () => {
              const r = await caSignCSR({ csr, notAfter: csrTtl });
              setSigned(r.cert); setCsr('');
              return `서명됨: ${r.serial.slice(0, 16)}… (${r.subject}) — 고객은 자신의 개인키를 그대로 사용`;
            })}>CSR 서명</Button>
            {signed && (
              <div className="space-y-1">
                <Button variant="outline" size="sm" onClick={() => download('signed.crt', signed)}>서명 인증서 다운로드</Button>
                <pre className="max-h-24 overflow-auto rounded bg-secondary p-2 text-[10px]">{signed}</pre>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </>
  );
}
