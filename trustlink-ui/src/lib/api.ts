// zot/BFF API 클라이언트 — 단일 오리진(TrustLink 프론트) 전제. 세션 쿠키 사용.
// X-ZOT-API-CLIENT: zot-ui → zot이 401 시 Basic 챌린지(브라우저 팝업)를 생략.
const H = { 'X-ZOT-API-CLIENT': 'zot-ui' };

async function zfetch(url: string, init: RequestInit = {}) {
  return fetch(url, { credentials: 'include', ...init, headers: { ...H, ...(init.headers || {}) } });
}

// 로그인 여부: /v2/ 가 200이면 인증됨, 401이면 미인증.
export async function isAuthed(): Promise<boolean> {
  const r = await zfetch('/v2/');
  return r.status === 200;
}

export function oidcLogin() {
  const cb = encodeURIComponent(window.location.origin + '/');
  window.location.href = `/zot/auth/login?provider=oidc&callback_ui=${cb}`;
}

export async function logout() {
  // zot 세션 로그아웃은 POST (GET 네비게이션은 404). 그 후 BFF 로그아웃으로 이동해
  // BFF 세션 정리 + Keycloak SSO 종료(end-session)까지 일괄 처리하고 앱 홈으로 복귀한다.
  try {
    await zfetch('/zot/auth/logout', { method: 'POST' });
  } catch {
    /* zot 세션이 이미 없어도 무시하고 SSO 종료로 진행 */
  }
  window.location.href = '/admin/logout';
}

export type Repo = {
  name: string;
  size?: number;
  downloads?: number;
  lastUpdated?: string;
  isSigned?: boolean;
  vulnerabilities?: { MaxSeverity?: string; Count?: number };
};

// zot search GraphQL — 전역 검색(레포 목록)
export async function searchRepos(query = ''): Promise<Repo[]> {
  const gql = `{ GlobalSearch(query:"${query}"){ Repos{ Name LastUpdated Size DownloadCount NewestImage{ IsSigned Vulnerabilities{ MaxSeverity Count } } } } }`;
  const r = await zfetch(`/v2/_zot/ext/search?query=${encodeURIComponent(gql)}`);
  if (!r.ok) throw new Error(`search ${r.status}`);
  const j = await r.json();
  const repos = j?.data?.GlobalSearch?.Repos || [];
  return repos.map((x: any) => ({
    name: x.Name,
    size: Number(x.Size) || 0,
    downloads: x.DownloadCount,
    lastUpdated: x.LastUpdated,
    isSigned: x.NewestImage?.IsSigned,
    vulnerabilities: x.NewestImage?.Vulnerabilities
  }));
}

export type Referrer = { artifactType: string; mediaType: string; size: number; digest: string; annotations: Record<string, string> };

export type ImageDetail = {
  name: string;
  tag: string;
  digest: string;
  size: number;
  isSigned: boolean;
  referrers: Referrer[];
  vulnerabilities?: { MaxSeverity?: string; Count?: number };
};

export async function getImage(name: string, tag: string): Promise<ImageDetail> {
  const gql = `{ Image(image:"${name}:${tag}"){ RepoName Tag IsSigned Vulnerabilities{ MaxSeverity Count } Manifests{ Digest Size } Referrers{ MediaType ArtifactType Size Digest Annotations{ Key Value } } } }`;
  const r = await zfetch(`/v2/_zot/ext/search?query=${encodeURIComponent(gql)}`);
  if (!r.ok) throw new Error(`image ${r.status}`);
  const j = await r.json();
  const img = j?.data?.Image;
  const m = img?.Manifests?.[0];
  return {
    name: img?.RepoName || name,
    tag: img?.Tag || tag,
    digest: m?.Digest || '',
    size: Number(m?.Size) || 0,
    isSigned: !!img?.IsSigned,
    vulnerabilities: img?.Vulnerabilities,
    referrers: (img?.Referrers || []).map((x: any) => ({
      artifactType: x.ArtifactType,
      mediaType: x.MediaType,
      size: Number(x.Size) || 0,
      digest: x.Digest,
      annotations: Object.fromEntries((x.Annotations || []).map((a: any) => [a.Key, a.Value]))
    }))
  };
}

export async function listTags(name: string): Promise<string[]> {
  const r = await zfetch(`/v2/${name}/tags/list`);
  if (!r.ok) return [];
  const j = await r.json();
  return (j.tags || []).sort();
}

// ---------- VEX 편집(BFF) ----------
// 제품 페이지의 VEX 분류/발행은 BFF 세션(Keycloak 그룹) 기반. zot 세션과 별개지만 같은 Keycloak SSO.

export type Session = { username: string; groups: string[]; canEditVex: boolean };

// BFF 세션 조회. 미인증(401)이면 null.
export async function getSession(): Promise<Session | null> {
  const r = await zfetch('/api/session');
  if (r.status === 401) return null;
  if (!r.ok) throw new Error(`session ${r.status}`);
  return r.json();
}

// BFF OIDC 로그인(현재 경로로 복귀). zot 로그인과 별개지만 Keycloak SSO 로 보통 무중단.
export function bffLogin(returnPath: string) {
  window.location.href = `/admin/login?return=${encodeURIComponent(returnPath)}`;
}

export async function vexEnabled(): Promise<boolean> {
  try {
    const r = await zfetch('/api/vex/enabled');
    if (!r.ok) return false;
    return !!(await r.json()).enabled;
  } catch {
    return false;
  }
}

export type Finding = {
  component: { uuid: string; name: string; version?: string; purl?: string };
  vulnerability: {
    uuid: string; vulnId: string; source?: string; severity?: string;
    description?: string; cvssV3BaseScore?: number; cvssV3Vector?: string;
    cvssV2BaseScore?: number; epssScore?: number; epssPercentile?: number;
    cweId?: number; cweName?: string; references?: string; published?: number;
  };
  analysis?: { state?: string; isSuppressed?: boolean };
  attribution?: { analyzerIdentity?: string };
};

// DT findings 조회. repo/tag 를 함께 보내면 DT 프로젝트가 없을 때 zot SBOM 을 자동 적재한다.
export async function vexFindings(project: string, version: string, repo: string, tag: string): Promise<{ uuid: string; findings: Finding[] }> {
  const qs = `project=${encodeURIComponent(project)}&version=${encodeURIComponent(version)}&repo=${encodeURIComponent(repo)}&tag=${encodeURIComponent(tag)}`;
  const r = await zfetch(`/api/vex/findings?${qs}`);
  if (!r.ok) {
    const e = await r.json().catch(() => ({}));
    throw new Error(e.error || `findings ${r.status}`);
  }
  const uuid = r.headers.get('X-Project-Uuid') || '';
  return { uuid, findings: await r.json() };
}

// 분석 결정 기록(CycloneDX 어휘). DT 감사 이력에 남는다.
export async function putAnalysis(body: {
  project: string; component: string; vulnerability: string;
  status: string; justification?: string; comment?: string; suppressed?: boolean;
}): Promise<void> {
  const r = await zfetch('/api/vex/analysis', {
    method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
  });
  if (!r.ok) {
    const e = await r.json().catch(() => ({}));
    throw new Error(e.error || `analysis ${r.status}`);
  }
}

// VEX 발행: DT 추출 → zot 새 referrer 부착(원본 불변).
export async function publishVex(body: { repo: string; tag: string; project: string; version: string }): Promise<{ digest: string; created: string }> {
  const r = await zfetch('/api/vex/publish', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || `publish ${r.status}`);
  return j;
}

// ---------- 관리 콘솔 (BFF admin API, admins 그룹 전용) ----------
// 기존 vanilla-JS 콘솔(page.go)을 대체하는 React 관리 페이지가 호출한다.

// status 코드를 보존하는 에러(401=로그인, 403=권한없음 분기에 사용).
export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

// admin JSON 호출: 비-2xx 면 {error} 를 담아 ApiError 로 던진다.
async function aj<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await zfetch(url, init);
  if (!r.ok) {
    let e = '';
    try {
      e = (await r.json()).error || '';
    } catch {
      /* 본문 없음 */
    }
    throw new ApiError(r.status, `${r.status}${e ? ' ' + e : ''}`);
  }
  return r.json();
}

const jsonInit = (method: string, body: unknown): RequestInit => ({
  method,
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body)
});

export type Me = { username: string; groups: string[] };
// 관리 콘솔 진입 게이트. 미인증=401, admins 아님=403.
export const adminMe = () => aj<Me>('/api/me');

export type AdminUser = { id: string; username: string; email: string; enabled: boolean; groups: string[] };
export const adminUsers = () => aj<AdminUser[]>('/api/users');
export const adminGroups = () => aj<string[]>('/api/groups');
export const adminCreateUser = (b: { username: string; email: string; group: string; password: string }) =>
  aj('/api/users', jsonInit('POST', b));
export const adminSetUserGroup = (id: string, group: string) =>
  aj(`/api/users/${id}/group`, jsonInit('POST', { group }));

export type DiskInfo = { totalBytes: number; freeBytes: number; usedBytes: number; usedPct: number; path: string };
export type Metrics = {
  disk?: DiskInfo;
  repos?: { repo: string; bytes: number }[];
  repoCount?: number;
  repoTotalBytes?: number;
};
export const adminMetrics = () => aj<Metrics>('/api/metrics');

export type Health = { zot: boolean; keycloak: boolean };
export const adminHealth = () => aj<Health>('/api/health');

export type LogsResult = {
  file: string;
  total: number;
  page: number;
  pageSize: number;
  pages: number;
  lines: string[];
  error?: string;
};
export const adminLogs = (p: { page: number; q: string; level: string }) =>
  aj<LogsResult>(`/api/logs?page=${p.page}&pageSize=100&q=${encodeURIComponent(p.q)}&level=${encodeURIComponent(p.level)}`);

export type RepoEntry = { repo: string; tags: string[]; tagCount: number };
export const adminRepos = () => aj<RepoEntry[]>('/api/repos');
export const adminDeleteTag = (repo: string, tag: string) =>
  aj('/api/registry/delete-tag', jsonInit('POST', { repo, tag }));

export type RetentionCand = { Repository: string; Reference: string; Reason: string };
export type Retention = { candidates: RetentionCand[]; count: number; note: string };
export const adminRetention = () => aj<Retention>('/api/retention');

export type ACLPolicy = { groups?: string[]; users?: string[]; actions?: string[] };
export type ACL = {
  accessControl?: { repositories?: Record<string, { policies?: ACLPolicy[] }>; adminPolicy?: ACLPolicy };
  error?: string;
};
export const adminACL = () => aj<ACL>('/api/acl');

export type StorageInfo = {
  driver?: string;
  rootDirectory?: string;
  dedupe?: boolean;
  gc?: boolean;
  retention?: boolean;
  error?: string;
};
export const adminStorage = () => aj<StorageInfo>('/api/storage');
export type StoragePreview = { configBlock: string; steps: string[]; note: string };
export const adminStoragePreview = (b: {
  endpoint: string;
  bucket: string;
  region: string;
  accessKey: string;
  secretKey: string;
  secure: boolean;
}) => aj<StoragePreview>('/api/storage/preview', jsonInit('POST', b));

// 대시보드 통계: 제품(repo)별 버전 추이 — 컴포넌트 수/취약점 수/영향있음/수정됨.
export type VersionStat = {
  tag: string;
  components: number;
  vulnerabilities: number;
  affected: number;
  fixed: number;
  vex: Record<string, number>; // VEX 상태별 카운트(affected/not_affected/fixed/under_investigation)
  synthetic: boolean; // 취약점/VEX(또는 컴포넌트)가 더미면 true
};
export type ProductStat = { repo: string; versions: VersionStat[] };
export type Stats = { products: ProductStat[] };
export const adminStats = () => aj<Stats>('/api/stats');

// ── CA(step-ca) / 신뢰 — 평면2·3 (읽기 우선) ──
export type CAInfo = {
  enabled: boolean;
  url?: string;
  provisioner?: string;
  rootSubject?: string;
  rootFingerprint?: string;
  rootNotAfter?: string;
  reachable?: boolean;
};
export type CACert = { serial: string; subject: string; notAfter: string; issuedAt: string; status: string; actor?: string };
export type CAEvent = {
  time: string; actor?: string; action: string; serial?: string;
  subject?: string; repo?: string; tag?: string; status?: string; detail?: Record<string, unknown>;
};
export const caInfo = () => aj<CAInfo>('/api/ca/info');
export const caCerts = () => aj<{ certs: CACert[] }>('/api/ca/certs');
export const caAudit = () => aj<{ events: CAEvent[] }>('/api/ca/audit');

// 쓰기(발급/폐기/재발급/CSR 서명) — admins. §7: 이중확인 후 호출.
export const caIssue = (body: { cn: string; sans?: string[]; notAfter?: string }) =>
  aj<{ serial: string; subject: string; notAfter: string }>('/api/ca/issue', jsonInit('POST', body));
export const caSignCSR = (body: { csr: string; notAfter?: string }) =>
  aj<{ serial: string; subject: string; notAfter: string; cert: string }>('/api/ca/sign-csr', jsonInit('POST', body));
export const caRevoke = (serial: string, reason: string) =>
  aj<{ status: string; serial: string }>('/api/ca/revoke', jsonInit('POST', { serial, reason }));
export const caReissue = (serial: string, notAfter?: string) =>
  aj<{ status: string; serial: string; subject: string }>('/api/ca/reissue', jsonInit('POST', { serial, notAfter }));

// 수신자 인증서 레지스트리 (EnvelopedData 수신자 — 임포트)
export type Recipient = { id: string; subject: string; notAfter: string; importedAt: string; importedBy: string; certPem: string };
export const caRecipients = () => aj<{ recipients: Recipient[] }>('/api/ca/recipients');
export const caRecipientImport = (cert: string) => aj<{ id: string; subject: string; notAfter: string }>('/api/ca/recipients', jsonInit('POST', { cert }));
export const caRecipientDelete = (id: string) => aj<{ status: string }>('/api/ca/recipients/' + encodeURIComponent(id), { method: 'DELETE' });

// 이미지 여부 감지 — config.mediaType 가 컨테이너 이미지 config 면 docker pull 가능.
// (oras artifact 는 empty/커스텀 config → oras 전용). index 면 첫 child 로 판별.
const IMAGE_CONFIG_TYPES = [
  'application/vnd.oci.image.config.v1+json',
  'application/vnd.docker.container.image.v1+json',
];
export async function getPullInfo(repo: string, tag: string): Promise<{ isImage: boolean }> {
  const accept = 'application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json';
  try {
    const r = await zfetch(`/v2/${repo}/manifests/${encodeURIComponent(tag)}`, { headers: { Accept: accept } });
    if (!r.ok) return { isImage: false };
    const m = await r.json();
    let cfgType: string | undefined = m?.config?.mediaType;
    if (Array.isArray(m?.manifests) && m.manifests.length) {
      const cr = await zfetch(`/v2/${repo}/manifests/${m.manifests[0].digest}`, { headers: { Accept: accept } });
      if (cr.ok) cfgType = (await cr.json())?.config?.mediaType;
    }
    return { isImage: !!cfgType && IMAGE_CONFIG_TYPES.includes(cfgType) };
  } catch {
    return { isImage: false };
  }
}

// CMS 패키지 다운로드 — 4모드: 서명(.p7s) / 암호화(인증서·.p7m) / 서명+암호화(인증서·.p7m) / 서명+암호화(패스워드·.p7m).
// 성공 시 브라우저 다운로드를 트리거. 실패 시 BFF JSON 오류를 throw.
export async function downloadSharePackage(
  repo: string, tag: string,
  opts: { sign?: boolean; recipientId?: string; password?: string } = {}
) {
  const p = new URLSearchParams({ repo, tag });
  if (opts.sign === false) p.set('sign', '0');
  if (opts.recipientId) p.set('recipientId', opts.recipientId);
  if (opts.password) p.set('password', opts.password);
  const url = `/api/share/package?${p.toString()}`;
  const r = await zfetch(url);
  if (!r.ok) {
    const j = await r.json().catch(() => ({ error: r.statusText }));
    throw new Error((j as { error?: string }).error || `다운로드 실패 (${r.status})`);
  }
  const blob = await r.blob();
  const fn = r.headers.get('Content-Disposition')?.match(/filename=([^;]+)/)?.[1]?.trim() || 'package.signed.p7m';
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = fn;
  a.click();
  URL.revokeObjectURL(a.href);
  return { fips: r.headers.get('X-TrustLink-Fips'), serial: r.headers.get('X-TrustLink-Serial'), filename: fn };
}

// referrer(SBOM/VEX) 본문 조회: manifest → layer blob
export async function getReferrerContent(name: string, digest: string): Promise<string> {
  const mr = await zfetch(`/v2/${name}/manifests/${digest}`, {
    headers: { Accept: 'application/vnd.oci.image.manifest.v1+json' }
  });
  if (!mr.ok) throw new Error(`manifest ${mr.status}`);
  const manifest = await mr.json();
  const blobDigest = manifest?.layers?.[0]?.digest;
  const br = await zfetch(`/v2/${name}/blobs/${blobDigest}`);
  if (!br.ok) throw new Error(`blob ${br.status}`);
  return br.text();
}
