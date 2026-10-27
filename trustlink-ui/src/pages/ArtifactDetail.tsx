import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ArrowLeft, ShieldCheck, ShieldAlert, ChevronsUpDown, Search, Check, Download, Copy, ChevronDown } from 'lucide-react';
import VexPanel from './VexPanel';
import { getImage, listTags, getReferrerContent, getPullInfo, type ImageDetail, type Referrer } from '@/lib/api';
import { Card, CardContent, CardHeader, Badge, Button } from '@/components/ui/primitives';
import { fmtBytes, cn } from '@/lib/utils';

// 검색형 태그 선택기 (버전이 많아도 필터로 빠르게 선택)
function TagPicker({ tags, value, onChange }: { tags: string[]; value: string; onChange: (t: string) => void }) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState('');
  const filtered = tags.filter((t) => t.toLowerCase().includes(q.toLowerCase()));
  return (
    <div className="relative">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex h-9 min-w-[10rem] items-center justify-between gap-2 rounded-md border bg-background px-3 text-sm shadow-sm"
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
                    {t === value ? <Check size={14} /> : <span className="w-[14px]" />}
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
// referrer 종류 라벨(BFF bundle.go kindDir 와 같은 기준)
const kindLabel = (t: string) =>
  isVex(t) ? 'VEX' : /spdx|cyclonedx/i.test(t) ? 'SBOM' : /guide|manual|markdown|pdf/i.test(t) ? '문서'
    : /sigstore|cosign|signature/i.test(t) ? '서명' : '기타';

// 사람이 읽는 형식명(원래 MIME 타입은 보조 정보로)
const formatLabel = (t: string) =>
  /openvex/i.test(t) ? 'OpenVEX' : isVex(t) ? 'CycloneDX VEX' : /cyclonedx/i.test(t) ? 'CycloneDX SBOM' : /spdx/i.test(t) ? 'SPDX SBOM'
    : /markdown/i.test(t) ? 'Markdown 문서' : /pdf/i.test(t) ? 'PDF 문서' : /sigstore|cosign|signature/i.test(t) ? '서명' : t;

// 긴 digest 는 앞 12자·뒤 4자만 + 복사
function ShortDigest({ digest }: { digest: string }) {
  const [copied, setCopied] = useState(false);
  const hex = digest.replace(/^sha256:/, '');
  return (
    <span className="inline-flex items-center gap-1.5 font-mono text-xs text-muted-foreground" title={digest}>
      sha256:{hex.slice(0, 12)}…{hex.slice(-4)}
      <button
        onClick={() => { navigator.clipboard.writeText(digest); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
        className="rounded p-0.5 hover:bg-secondary hover:text-foreground" aria-label="digest 복사"
      >
        {copied ? <Check size={12} /> : <Copy size={12} />}
      </button>
    </span>
  );
}

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
          <tr>
            {head.map((h) => (
              <th key={h} className="border-b p-2 text-left font-medium text-muted-foreground">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i}>
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
    <div className="flex items-center gap-2 rounded-md bg-zinc-950 px-3 py-2">
      <code className="flex-1 overflow-auto whitespace-nowrap font-mono text-xs text-zinc-100">{cmd}</code>
      <button
        onClick={() => {
          navigator.clipboard.writeText(cmd);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        }}
        className="shrink-0 text-zinc-400 hover:text-zinc-100"
      >
        {copied ? <Check size={14} /> : <Copy size={14} />}
      </button>
    </div>
  );
}

// 명령줄 다운로드 안내(oras 항상, 컨테이너 이미지면 docker 도). 웹 전체 다운로드는 상단 버튼.
function CliCard({ repo, tag }: { repo: string; tag: string }) {
  // 레지스트리는 웹(28080)이 아니라 zot 직접 진입점(28081). 사람 계정은 웹 비밀번호 대신 '내 API 키'로 로그인.
  const host = `${window.location.hostname}:28081`;
  const ref = `${host}/${repo}:${tag}`;
  const [isImage, setIsImage] = useState(false);
  useEffect(() => {
    getPullInfo(repo, tag).then((i) => setIsImage(i.isImage)).catch(() => setIsImage(false));
  }, [repo, tag]);
  return (
    <Card className="mb-6">
      <CardHeader>
        <div className="font-semibold">명령줄로 받기</div>
        <p className="mt-0.5 text-sm text-muted-foreground">
          비밀번호 자리에 <Link to="/apikeys" className="font-medium text-foreground underline underline-offset-4">내 API 키</Link>를 씁니다. 서버 자동화는 관리자가 발급한 계정 토큰을 씁니다.
        </p>
      </CardHeader>
      <CardContent className="space-y-1.5">
        <CmdBox cmd={`printf '%s' '<API 키>' | oras login ${host} -u <내 ID> --password-stdin --plain-http`} />
        <CmdBox cmd={`oras pull --plain-http ${ref} -o ./download`} />
        {isImage && (
          <>
            <p className="pt-2 text-sm text-muted-foreground">
              컨테이너 이미지 — 평문 HTTP면 Docker 데몬 <code className="font-mono">insecure-registries</code>에 <code className="font-mono">{host}</code> 추가
            </p>
            <CmdBox cmd={`docker pull ${ref}`} />
          </>
        )}
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
    <div className="px-4 py-3">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <div className="w-14 shrink-0">
          <Badge variant={isVex(rf.artifactType) ? 'warn' : 'muted'}>{kindLabel(rf.artifactType)}</Badge>
        </div>
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <span className="font-medium">{formatLabel(rf.artifactType)}</span>
            {isCurrent && <span className="text-xs text-emerald-700">● 현재 유효</span>}
            {rf.annotations['com.trustlink.vex.author'] && (
              <span className="text-xs text-muted-foreground">발행 {rf.annotations['com.trustlink.vex.author']}</span>
            )}
          </div>
          <div className="mt-0.5 flex flex-wrap items-center gap-x-3"><ShortDigest digest={rf.digest} /><span className="text-xs text-muted-foreground">{fmtBytes(rf.size)}</span></div>
        </div>
        <div className="ml-auto flex items-center gap-1">
          <Button size="sm" variant="ghost" onClick={load}>
            {open ? '접기' : '보기'} <ChevronDown size={13} className={cn('transition-transform', open && 'rotate-180')} />
          </Button>
          {raw && obj && open && <Button size="sm" variant="ghost" onClick={() => setShowRaw(!showRaw)}>{showRaw ? '표로' : '원문'}</Button>}
          <a href={blobUrl} className="inline-flex">
            <Button size="sm" variant="outline"><Download size={13} /> 받기</Button>
          </a>
        </div>
      </div>
      {open && (
        <div className="mt-3 overflow-auto">
          {err ? (
            <div className="rounded bg-red-50 p-2 text-xs text-red-700">{err}</div>
          ) : !raw ? (
            <p className="text-xs text-muted-foreground">불러오는 중…</p>
          ) : !showRaw && obj && StructuredView({ obj }) ? (
            <StructuredView obj={obj} />
          ) : (
            <pre className="max-h-80 overflow-auto rounded-md bg-zinc-950 p-3 font-mono text-[11px] text-zinc-100">{raw}</pre>
          )}
        </div>
      )}
    </div>
  );
}

export default function ArtifactDetail() {
  const { name = '', tag = 'latest' } = useParams();
  const repo = decodeURIComponent(name);
  const [tags, setTags] = useState<string[]>([]);
  const [sel, setSel] = useState(tag);
  const [img, setImg] = useState<ImageDetail | null>(null);
  const [err, setErr] = useState('');

  // latest 태그가 없는 제품은 가장 높은 버전을 기본으로
  useEffect(() => {
    listTags(repo).then((ts) => {
      setTags(ts);
      if (ts.length && !ts.includes(sel)) {
        setSel([...ts].sort((a, b) => b.localeCompare(a, undefined, { numeric: true }))[0]);
      }
    });
  }, [repo]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    // 버전 전환 시 이전 요청의 늦은 응답이 화면을 덮어쓰지 않게 무시
    let stale = false;
    setImg(null); setErr('');
    getImage(repo, sel)
      .then((d) => { if (!stale) setImg(d); })
      .catch((e) => { if (!stale) setErr(String(e)); });
    return () => { stale = true; };
  }, [repo, sel]);

  const bundleUrl = `/api/artifact/bundle?repo=${encodeURIComponent(repo)}&tag=${encodeURIComponent(sel)}`;
  return (
    <div>
      <Link to="/" className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft size={15} /> 아티팩트 목록
      </Link>
      <div className="mb-6 flex flex-wrap items-center gap-3">
        <h1 className="text-2xl font-semibold tracking-tight">{repo}</h1>
        {img && (img.isSigned
          ? <span className="inline-flex items-center gap-1 text-sm text-emerald-700"><ShieldCheck size={15} /> 서명됨</span>
          : <span className="inline-flex items-center gap-1 text-sm text-muted-foreground" title="cosign 등으로 서명되지 않은 산출물"><ShieldAlert size={15} /> 서명 없음</span>)}
        <div className="ml-auto flex items-center gap-2">
          <TagPicker tags={tags.includes(sel) ? tags : [sel, ...tags]} value={sel} onChange={setSel} />
          <a href={bundleUrl}><Button><Download size={15} /> 전체 다운로드</Button></a>
        </div>
      </div>

      {err && <div className="rounded-md bg-red-50 p-3 text-sm text-red-700">{err}</div>}
      {img && (
        <>
          <div className="mb-6 grid grid-cols-2 gap-px overflow-hidden rounded-lg border bg-border md:grid-cols-4">
            {[
              ['버전', <span className="font-medium">{img.tag}</span>],
              ['크기', fmtBytes(img.size)],
              ['첨부', `${img.referrers.length}개`],
              ['다이제스트', <ShortDigest digest={img.digest} />]
            ].map(([k, v], i) => (
              <div key={i} className="bg-card px-4 py-3">
                <div className="text-xs text-muted-foreground">{k}</div>
                <div className="mt-1 text-sm">{v}</div>
              </div>
            ))}
          </div>
          {(img.vulnerabilities?.Count ?? 0) > 0 && (
            <p className="-mt-3 mb-6 text-sm text-muted-foreground">레지스트리 스캔 취약점 {img.vulnerabilities?.Count}건 (최고 {img.vulnerabilities?.MaxSeverity})</p>
          )}

          <h2 className="mb-1 text-base font-semibold">첨부 파일</h2>
          <p className="mb-3 text-sm text-muted-foreground">이 버전에 연결된 SBOM, VEX, 문서입니다. 전체 다운로드 zip에 모두 포함됩니다.</p>
          {img.referrers.length === 0 ? (
            <p className="mb-6 rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">첨부된 파일이 없습니다.</p>
          ) : (
            <div className="mb-6 divide-y rounded-lg border bg-card">
              {img.referrers.map((rf) => <ReferrerRow key={rf.digest} name={repo} referrer={rf} isCurrent={rf.digest === currentVexDigest(img.referrers)} />)}
            </div>
          )}

          <CliCard repo={repo} tag={img.tag} />

          <h2 className="mb-3 text-base font-semibold">취약점 분석 · VEX</h2>
          <VexPanel repo={repo} tag={img.tag} />
        </>
      )}
    </div>
  );
}
