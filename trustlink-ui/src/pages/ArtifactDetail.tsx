import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ArrowLeft, ShieldCheck, ShieldAlert, FileText, ChevronsUpDown, Search, Check, Download, Copy } from 'lucide-react';
import VexPanel from './VexPanel';
import { getImage, listTags, getReferrerContent, getPullInfo, caRecipients, downloadSharePackage, type ImageDetail, type Referrer, type Recipient } from '@/lib/api';
import { Card, CardContent, CardHeader, Badge, Button } from '@/components/ui/primitives';
import { fmtBytes, cn } from '@/lib/utils';

// 검색형 태그 선택기 (버전이 많아도 필터로 빠르게 선택)
function TagPicker({ tags, value, onChange }: { tags: string[]; value: string; onChange: (t: string) => void }) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState('');
  const filtered = tags.filter((t) => t.toLowerCase().includes(q.toLowerCase()));
  return (
    <div className="relative ml-auto">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex h-9 min-w-[12rem] items-center justify-between gap-2 rounded-md border bg-card px-3 text-sm"
      >
        <span className="truncate">{value}</span>
        <ChevronsUpDown size={14} className="text-muted-foreground" />
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} />
          <div className="absolute right-0 z-20 mt-1 w-72 rounded-md border bg-card shadow-lg">
            <div className="flex items-center gap-2 border-b px-3 py-2">
              <Search size={14} className="text-muted-foreground" />
              <input
                autoFocus
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="태그 검색…"
                className="w-full bg-transparent text-sm outline-none"
              />
            </div>
            <div className="max-h-72 overflow-auto py-1">
              {filtered.length === 0 ? (
                <div className="px-3 py-2 text-sm text-muted-foreground">결과 없음</div>
              ) : (
                filtered.map((t) => (
                  <button
                    key={t}
                    onClick={() => {
                      onChange(t);
                      setOpen(false);
                      setQ('');
                    }}
                    className={cn('flex w-full items-center gap-2 px-3 py-1.5 text-left text-sm hover:bg-secondary', t === value && 'font-semibold')}
                  >
                    {t === value ? <Check size={14} className="text-accent" /> : <span className="w-[14px]" />}
                    <span className="truncate">{t}</span>
                  </button>
                ))
              )}
            </div>
            <div className="border-t px-3 py-1.5 text-xs text-muted-foreground">{tags.length}개 태그</div>
          </div>
        </>
      )}
    </div>
  );
}

const isVex = (t: string) => /vex/i.test(t);

// TrustLink가 발행한 VEX 중 가장 최신(created)이 "현재 유효" 본. 발행물은 불변, 최신이 권위.
function currentVexDigest(refs: Referrer[]): string {
  const pub = refs
    .filter((r) => isVex(r.artifactType) && r.annotations['com.trustlink.vex.source'] === 'trustlink-triage')
    .sort((a, b) => (b.annotations['org.opencontainers.image.created'] || '').localeCompare(a.annotations['org.opencontainers.image.created'] || ''));
  return pub[0]?.digest || '';
}

function StructuredView({ obj }: { obj: any }) {
  if (obj && typeof obj['@context'] === 'string' && /openvex/i.test(obj['@context']) && Array.isArray(obj.statements)) {
    return (
      <Table
        title={`VEX (OpenVEX) · ${obj.statements.length}건`}
        head={['취약점', '상태', '근거']}
        rows={obj.statements.map((s: any) => [s.vulnerability?.name || '', s.status || '', s.justification || s.impact_statement || ''])}
      />
    );
  }
  if (/cyclonedx/i.test(obj?.bomFormat || '')) {
    if (Array.isArray(obj.vulnerabilities) && obj.vulnerabilities.length) {
      return (
        <Table
          title={`VEX (CycloneDX) · ${obj.vulnerabilities.length}건`}
          head={['취약점', '심각도', '분석상태']}
          rows={obj.vulnerabilities.map((v: any) => [v.id || '', (v.ratings || []).map((r: any) => r.severity).join(', '), v.analysis?.state || ''])}
        />
      );
    }
    return (
      <Table
        title={`SBOM (CycloneDX) · 컴포넌트 ${(obj.components || []).length}`}
        head={['컴포넌트', '버전', '라이선스']}
        rows={(obj.components || []).map((c: any) => [c.name || '', c.version || '', (c.licenses || []).map((l: any) => l.license?.id || l.license?.name).join(', ')])}
      />
    );
  }
  if (typeof obj?.spdxVersion === 'string' && Array.isArray(obj.packages)) {
    return (
      <Table
        title={`SBOM (SPDX ${obj.spdxVersion}) · 패키지 ${obj.packages.length}`}
        head={['패키지', '버전', '라이선스']}
        rows={obj.packages.map((p: any) => [p.name || '', p.versionInfo || '', p.licenseDeclared || p.licenseConcluded || ''])}
      />
    );
  }
  return null;
}

function Table({ title, head, rows }: { title: string; head: string[]; rows: string[][] }) {
  return (
    <div>
      <p className="mb-1 text-sm font-semibold">{title}</p>
      <table className="w-full border-collapse text-xs">
        <thead>
          <tr className="bg-secondary">
            {head.map((h) => (
              <th key={h} className="border-b p-2 text-left">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} className="even:bg-secondary/40">
              {r.map((c, j) => (
                <td key={j} className="border-b p-2 align-top">{c}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// 복사 가능한 명령 박스
function CmdBox({ cmd }: { cmd: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex items-center gap-2 rounded-md bg-primary px-3 py-2">
      <code className="flex-1 overflow-auto whitespace-nowrap text-xs text-primary-foreground">{cmd}</code>
      <button
        onClick={() => {
          navigator.clipboard.writeText(cmd);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        }}
        className="shrink-0 text-primary-foreground/80 hover:text-primary-foreground"
      >
        {copied ? <Check size={14} /> : <Copy size={14} />}
      </button>
    </div>
  );
}

// 다운로드 카드: 전체 zip + pull 명령(oras 항상, 컨테이너 이미지면 docker 도)
function DownloadCard({ repo, tag }: { repo: string; tag: string }) {
  const host = window.location.host;
  const ref = `${host}/${repo}:${tag}`;
  const bundleUrl = `/api/artifact/bundle?repo=${encodeURIComponent(repo)}&tag=${encodeURIComponent(tag)}`;
  const [isImage, setIsImage] = useState(false);
  useEffect(() => {
    getPullInfo(repo, tag).then((i) => setIsImage(i.isImage)).catch(() => setIsImage(false));
  }, [repo, tag]);
  return (
    <Card className="mb-5">
      <CardHeader className="flex items-center gap-2 font-semibold">
        <Download size={16} /> 다운로드
      </CardHeader>
      <CardContent className="space-y-3">
        <div>
          <p className="mb-1 text-sm text-muted-foreground">전체(바이너리 + SBOM/VEX/서명)를 한 번에</p>
          <a href={bundleUrl}>
            <Button variant="accent">
              <Download size={14} /> 전체 다운로드 (zip)
            </Button>
          </a>
        </div>
        <div>
          <p className="mb-1 text-sm text-muted-foreground">
            ORAS (CLI) — 먼저 로그인: <code>oras login {host} -u ci -p &lt;PW&gt; --plain-http</code>
          </p>
          <CmdBox cmd={`oras pull --plain-http ${ref} -o ./download`} />
        </div>
        {isImage && (
          <div>
            <p className="mb-1 text-sm text-muted-foreground">
              Docker (컨테이너 이미지) — 평문 HTTP면 데몬 <code>insecure-registries</code> 에 <code>{host}</code> 추가
            </p>
            <CmdBox cmd={`docker pull ${ref}`} />
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// CMS 서명·암호화 카드: 4모드 선택 → 다운로드
function CmsCard({ repo, tag }: { repo: string; tag: string }) {
  type Mode = 'sign' | 'enc-cert' | 'sign-enc-cert' | 'sign-enc-pw';
  const [mode, setMode] = useState<Mode>('sign');
  const [recips, setRecips] = useState<Recipient[]>([]);
  const [recip, setRecip] = useState('');
  const [pw, setPw] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');
  const needCert = mode === 'enc-cert' || mode === 'sign-enc-cert';
  const needPw = mode === 'sign-enc-pw';
  useEffect(() => {
    if (needCert && recips.length === 0) caRecipients().then((r) => setRecips(r.recipients || [])).catch(() => {});
  }, [needCert, recips.length]);
  const fieldCls = 'rounded-md border bg-card px-3 py-1.5 text-sm';
  const opts: Record<Mode, { sign?: boolean; recipientId?: string; password?: string }> = {
    'sign': {},
    'enc-cert': { sign: false, recipientId: recip },
    'sign-enc-cert': { recipientId: recip },
    'sign-enc-pw': { password: pw },
  };
  const go = async () => {
    setBusy(true); setMsg('');
    try {
      const res = await downloadSharePackage(repo, tag, opts[mode]);
      setMsg(`다운로드: ${res.filename}${res.serial ? ` (serial ${res.serial})` : ''}`);
    } catch (e) {
      setMsg('실패: ' + (e as Error).message);
    }
    setBusy(false);
  };
  const M = ({ v, label }: { v: Mode; label: string }) => (
    <label className="flex items-center gap-2"><input type="radio" name="cmsmode" checked={mode === v} onChange={() => setMode(v)} /> {label}</label>
  );
  return (
    <Card className="mb-5">
      <CardHeader className="flex items-center gap-2 font-semibold">
        <ShieldCheck size={16} /> CMS 서명·암호화
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex flex-col gap-1.5 text-sm">
          <M v="sign" label="서명 (.p7s) — 루트로 누구나 검증, 복호 불필요" />
          <M v="enc-cert" label="암호화·인증서 (.p7m) — 수신자만 복호" />
          <M v="sign-enc-cert" label="서명+암호화·인증서 (.p7m)" />
          <M v="sign-enc-pw" label="서명+암호화·패스워드 (.p7m)" />
        </div>
        {needCert && (
          <select className={fieldCls} value={recip} onChange={(e) => setRecip(e.target.value)}>
            <option value="">수신자 인증서 선택… (수신자 페이지에서 임포트)</option>
            {recips.map((r) => <option key={r.id} value={r.id}>{r.subject}</option>)}
          </select>
        )}
        {needPw && (
          <input type="password" className={fieldCls} placeholder="공유 패스워드 (수신측 복호에 필요)" value={pw} onChange={(e) => setPw(e.target.value)} />
        )}
        <Button onClick={go} disabled={busy || (needCert && !recip) || (needPw && !pw)}>
          <Download size={14} /> 생성·다운로드
        </Button>
        {msg && <p className="text-xs text-muted-foreground">{msg}</p>}
      </CardContent>
    </Card>
  );
}

function ReferrerRow({ name, referrer: rf, isCurrent }: { name: string; referrer: Referrer; isCurrent?: boolean }) {
  const blobUrl = `/api/artifact/blob?repo=${encodeURIComponent(name)}&digest=${encodeURIComponent(rf.digest)}`;
  const [open, setOpen] = useState(false);
  const [obj, setObj] = useState<any>(null);
  const [raw, setRaw] = useState('');
  const [showRaw, setShowRaw] = useState(false);
  const [err, setErr] = useState('');

  const load = async () => {
    if (raw) { setOpen(!open); return; }
    setOpen(true);
    try {
      const text = await getReferrerContent(name, rf.digest);
      setRaw(text);
      try { setObj(JSON.parse(text)); } catch { setObj(null); }
    } catch (e) { setErr(String(e)); }
  };

  return (
    <Card>
      <CardContent className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <FileText size={16} className="text-accent" />
          <span className="font-medium text-sm">{rf.artifactType}</span>
          <Badge variant={isVex(rf.artifactType) ? 'warn' : 'muted'}>{isVex(rf.artifactType) ? 'VEX' : 'SBOM'}</Badge>
          {isCurrent && <Badge variant="success">현재 유효 VEX</Badge>}
          {rf.annotations['com.trustlink.vex.author'] && (
            <span className="text-xs text-muted-foreground">발행: {rf.annotations['com.trustlink.vex.author']}</span>
          )}
          <span className="text-xs text-muted-foreground">{fmtBytes(rf.size)}</span>
          <div className="flex-1" />
          <Button size="sm" variant="outline" onClick={load}>{open ? '숨기기' : '내용 보기'}</Button>
          {raw && obj && <Button size="sm" variant="ghost" onClick={() => setShowRaw(!showRaw)}>{showRaw ? '표' : '원문'}</Button>}
          <a href={blobUrl} className="inline-flex">
            <Button size="sm" variant="ghost"><Download size={13} /> 다운로드</Button>
          </a>
        </div>
        <p className="break-all text-[11px] text-muted-foreground">{rf.digest}</p>
        {open && (
          <div className="overflow-auto">
            {err ? (
              <div className="rounded bg-red-100 p-2 text-xs text-red-700">{err}</div>
            ) : !raw ? (
              <p className="text-xs text-muted-foreground">불러오는 중…</p>
            ) : !showRaw && obj && StructuredView({ obj }) ? (
              <StructuredView obj={obj} />
            ) : (
              <pre className="max-h-80 overflow-auto rounded bg-primary p-3 text-[11px] text-primary-foreground">{raw}</pre>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default function ArtifactDetail() {
  const { name = '', tag = 'latest' } = useParams();
  const repo = decodeURIComponent(name);
  const [tags, setTags] = useState<string[]>([]);
  const [sel, setSel] = useState(tag);
  const [img, setImg] = useState<ImageDetail | null>(null);
  const [err, setErr] = useState('');

  useEffect(() => { listTags(repo).then(setTags); }, [repo]);
  useEffect(() => {
    setImg(null); setErr('');
    getImage(repo, sel).then(setImg).catch((e) => setErr(String(e)));
  }, [repo, sel]);

  return (
    <div>
      <Link to="/" className="mb-4 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft size={16} /> 목록
      </Link>
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <h1 className="text-2xl font-bold">{repo}</h1>
        {img?.isSigned ? (
          <Badge variant="success"><ShieldCheck size={14} className="mr-1" /> 서명됨</Badge>
        ) : (
          <Badge variant="danger"><ShieldAlert size={14} className="mr-1" /> 미서명</Badge>
        )}
        <TagPicker tags={tags.includes(sel) ? tags : [sel, ...tags]} value={sel} onChange={setSel} />
      </div>

      {err && <div className="rounded-md bg-red-100 p-3 text-sm text-red-700">{err}</div>}
      {img && (
        <>
          <Card className="mb-5">
            <CardHeader className="font-semibold">개요</CardHeader>
            <CardContent className="grid gap-2 text-sm md:grid-cols-2">
              <div><span className="text-muted-foreground">태그</span> · {img.tag}</div>
              <div><span className="text-muted-foreground">크기</span> · {fmtBytes(img.size)}</div>
              <div className="md:col-span-2 break-all"><span className="text-muted-foreground">digest</span> · {img.digest}</div>
              {img.vulnerabilities?.Count != null && (
                <div><span className="text-muted-foreground">취약점</span> · {img.vulnerabilities.Count} ({img.vulnerabilities.MaxSeverity})</div>
              )}
            </CardContent>
          </Card>

          <DownloadCard repo={repo} tag={img.tag} />
          <CmsCard repo={repo} tag={img.tag} />

          <h2 className="mb-2 text-lg font-semibold">SBOM / VEX (Referrers)</h2>
          {img.referrers.length === 0 ? (
            <p className="text-sm text-muted-foreground">첨부된 SBOM/VEX가 없습니다.</p>
          ) : (
            <div className="space-y-3">
              {img.referrers.map((rf) => <ReferrerRow key={rf.digest} name={repo} referrer={rf} isCurrent={rf.digest === currentVexDigest(img.referrers)} />)}
            </div>
          )}

          <h2 className="mb-2 mt-6 text-lg font-semibold">취약점 분석 · VEX</h2>
          <VexPanel repo={repo} tag={img.tag} />
        </>
      )}
    </div>
  );
}
