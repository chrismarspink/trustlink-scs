import { useEffect, useState } from 'react';
import { caInfo, type CAInfo } from '@/lib/api';
import { Card, CardHeader, CardContent } from '@/components/ui/primitives';
import { PageTitle, StatCard, Loading, Alert } from '../_ui';
import { fmtTime, HelpNote } from './_shared';

export default function CaOverview() {
  const [info, setInfo] = useState<CAInfo | null>(null);
  const [err, setErr] = useState('');
  useEffect(() => { caInfo().then(setInfo).catch((e) => setErr(String(e))); }, []);

  if (err) return (<><PageTitle>CA · 개요</PageTitle><Alert tone="crit">오류: {err}</Alert></>);
  if (!info) return (<><PageTitle>CA · 개요</PageTitle><Loading /></>);
  if (!info.enabled) return (<><PageTitle>CA · 개요</PageTitle><Alert tone="warn">CA(step-ca) 가 구성되지 않았습니다.</Alert></>);

  return (
    <>
      <PageTitle>CA · 개요</PageTitle>
      <HelpNote>
        <b>인증기관(CA)</b>은 TrustLink 서명에 쓰는 인증서를 발급·관리합니다. <b>신뢰 앵커(Root CA)</b>는 수신자가 서명을 검증할 때
        기준이 되는 최상위 인증서로, 협력사·고객에 <b>사전 배포</b>합니다(루트 하나만 신뢰하면 모든 TrustLink 서명 검증 가능).
        <br /><b>평면 1(독립):</b> step-ca 는 TrustLink 와 별개 포트로 동작 → TrustLink 가 멈춰도 검증·CRL·발급이 살아있습니다.
      </HelpNote>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="step-ca 도달성 (평면1)" value={info.reachable ? '정상' : '중단'} />
        <StatCard label="provisioner" value={info.provisioner || '-'} />
        <StatCard label="루트 만료" value={fmtTime(info.rootNotAfter).slice(0, 10)} />
        <StatCard label="엔드포인트" value={(info.url || '').replace('https://', '')} />
      </div>

      <Card className="mt-4">
        <CardHeader className="font-semibold">신뢰 앵커 (Root CA — 수신자 사전 배포 대상)</CardHeader>
        <CardContent className="space-y-1 text-sm">
          <div><span className="text-muted-foreground">주체:</span> {info.rootSubject || '-'}</div>
          <div className="break-all"><span className="text-muted-foreground">SHA-256 지문:</span> <code className="text-xs">{info.rootFingerprint || '-'}</code></div>
          <div><span className="text-muted-foreground">엔드포인트:</span> <code className="text-xs">{info.url}</code> <span className="text-xs text-muted-foreground">(검증자 직접 접근)</span></div>
          <div className="flex flex-wrap gap-3 pt-2 text-sm">
            <a className="text-primary underline" href="/api/ca/root" target="_blank" rel="noreferrer">루트 인증서(.crt)</a>
            <span className="text-xs text-muted-foreground">— 수신자에 사전 배포(검증 신뢰 앵커)</span>
          </div>
          <div className="flex flex-wrap gap-3 text-sm">
            <a className="text-primary underline" href="/api/ca/issuer" target="_blank" rel="noreferrer">발급(중간) CA 인증서(.crt)</a>
            <span className="text-xs text-muted-foreground">— 리프 체인은 서명에 이미 임베드, 운영 참고용</span>
          </div>
          <div><a className="text-primary underline" href="/api/ca/crl" target="_blank" rel="noreferrer">CRL 내려받기</a> <span className="text-xs text-muted-foreground">— 폐기 목록(검증 시 확인)</span></div>
        </CardContent>
      </Card>
    </>
  );
}
