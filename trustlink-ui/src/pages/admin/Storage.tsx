import { useEffect, useState } from 'react';
import { adminStorage, adminStoragePreview, type StorageInfo, type StoragePreview } from '@/lib/api';
import { Button, Input } from '@/components/ui/primitives';
import { PageTitle, SectionTitle, StatCard, Loading, Alert } from './_ui';

export default function Storage() {
  const [info, setInfo] = useState<StorageInfo | null>(null);
  const [err, setErr] = useState('');

  // S3/MinIO 미리보기 폼
  const [endpoint, setEndpoint] = useState('');
  const [bucket, setBucket] = useState('');
  const [region, setRegion] = useState('');
  const [accessKey, setAccessKey] = useState('');
  const [secretKey, setSecretKey] = useState('');
  const [secure, setSecure] = useState(false);
  const [preview, setPreview] = useState<StoragePreview | null>(null);

  useEffect(() => {
    adminStorage().then(setInfo).catch((e) => setErr(String(e)));
  }, []);

  async function gen() {
    if (!bucket.trim()) { alert('bucket 을 입력하세요'); return; }
    try {
      setPreview(await adminStoragePreview({ endpoint, bucket, region, accessKey, secretKey, secure }));
    } catch (e) {
      alert(String(e));
    }
  }

  if (err) return (<><PageTitle>설정 · 스토리지</PageTitle><Alert tone="crit">오류: {err}</Alert></>);
  if (!info) return (<><PageTitle>설정 · 스토리지</PageTitle><Loading /></>);

  return (
    <>
      <PageTitle>설정 · 오브젝트 스토리지 (확장용)</PageTitle>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="현재 드라이버" value={<span className="text-base">{info.driver || '-'}</span>} />
        <StatCard label="루트" value={<span className="break-all text-sm font-mono">{info.rootDirectory || '-'}</span>} />
        <StatCard label="dedupe" value={String(info.dedupe)} />
        <StatCard label="GC / 리텐션" value={`${info.gc ? 'on' : 'off'} / ${info.retention ? '설정됨' : '없음'}`} />
      </div>

      <Alert tone="ok">
        현재 <b>로컬 스토리지</b> 운영 중. 아래는 온프레→SaaS 확장 시 적용할 S3/MinIO 설정을 미리 생성합니다(실시간 전환 아님).
      </Alert>

      <SectionTitle>S3 / MinIO 설정 생성</SectionTitle>
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <Input className="w-64" placeholder="endpoint (예: http://minio:9000)" value={endpoint} onChange={(e) => setEndpoint(e.target.value)} />
        <Input className="w-40" placeholder="bucket" value={bucket} onChange={(e) => setBucket(e.target.value)} />
        <Input className="w-40" placeholder="region (us-east-1)" value={region} onChange={(e) => setRegion(e.target.value)} />
      </div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Input className="w-48" placeholder="accessKey" value={accessKey} onChange={(e) => setAccessKey(e.target.value)} />
        <Input className="w-48" placeholder="secretKey" type="password" value={secretKey} onChange={(e) => setSecretKey(e.target.value)} />
        <label className="flex items-center gap-1.5 text-sm">
          <input type="checkbox" checked={secure} onChange={(e) => setSecure(e.target.checked)} /> secure (https)
        </label>
        <Button variant="accent" size="sm" onClick={gen}>설정 생성</Button>
      </div>

      {preview && (
        <div className="space-y-3">
          <SectionTitle>적용할 config 블록</SectionTitle>
          <pre className="overflow-auto rounded-lg bg-primary p-4 text-xs leading-relaxed text-primary-foreground">{preview.configBlock}</pre>
          <SectionTitle>전환 절차</SectionTitle>
          <ol className="ml-5 list-decimal space-y-1 text-sm">
            {preview.steps.map((s, i) => <li key={i}>{s}</li>)}
          </ol>
          <p className="text-sm text-muted-foreground">{preview.note}</p>
        </div>
      )}
    </>
  );
}
