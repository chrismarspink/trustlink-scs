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
  status: string; justification?: string; response?: string; details?: string; comment?: string; suppressed?: boolean;
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
// syft 로 이 버전의 바이너리를 스캔해 CycloneDX SBOM 을 만들어 첨부(개발자·관리자, 제품 쓰기 권한).
export async function generateSbom(repo: string, tag: string): Promise<{ components: number; referrer: string }> {
  const r = await zfetch('/api/sbom/generate', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ repo, tag })
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || `sbom ${r.status}`);
  return j;
}

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
export type IssuedCredential = { username: string; password: string };
export const ROLES = ['admins', 'developers', 'users'] as const;
export const ORG_PREFIX = 'org-';
export const adminCreateUser = (b: { username: string; email: string; role: string; orgs: string[]; password: string }) =>
  aj<IssuedCredential & { id: string; group: string }>('/api/users', jsonInit('POST', b));
export const adminUpdateUser = (id: string, b: { username: string; role?: string; orgs?: string[]; enabled?: boolean; email?: string }) =>
  aj(`/api/users/${id}`, jsonInit('PUT', b));
export const adminDeleteUser = (id: string, username: string) =>
  aj(`/api/users/${id}?username=${encodeURIComponent(username)}`, { method: 'DELETE' });
export const adminResetPassword = (id: string, username: string) =>
  aj<IssuedCredential>(`/api/users/${id}/reset-password`, jsonInit('POST', { username }));
export const adminCICredential = () => aj<IssuedCredential>('/api/credentials/ci');

// 고객사(조직) = Keycloak 그룹 org-<name>
export type Org = { name: string; group: string; members: string[]; emails: Record<string, string>; contacts: string[]; products: string[] };
export const adminSetOrgContacts = (name: string, emails: string[]) =>
  aj<{ contacts: string[] }>(`/api/orgs/${encodeURIComponent(name)}/contacts`, jsonInit('PUT', { emails }));
export const adminOrgs = () => aj<Org[]>('/api/orgs');
export const adminCreateOrg = (name: string) => aj('/api/orgs', jsonInit('POST', { name }));
export const adminDeleteOrg = (name: string) => aj(`/api/orgs/${encodeURIComponent(name)}`, { method: 'DELETE' });

// 제품 권한 — zot accessControl 로 렌더되어 zot 이 판정
export type Principal = { type: 'group' | 'user'; name: string };
export type ProductAccess = { repo: string; explicit: boolean; writers: Principal[]; readers: Principal[] };
export const adminProductAccess = () => aj<ProductAccess[]>('/api/access/products');
export const adminSetProductAccess = (b: { repo: string; writers: Principal[]; readers: Principal[] }) =>
  aj('/api/access/products', jsonInit('PUT', b));
export const adminResetProductAccess = (repo: string) =>
  aj(`/api/access/products?repo=${encodeURIComponent(repo)}`, { method: 'DELETE' });
export const adminPrincipals = () => aj<{ groups: string[]; users: string[] }>('/api/access/principals');

// 자동화 계정(ci-*: 업로드, robot-*: 다운로드) — oras 로그인용 ID + 비밀값
export type RobotAccount = {
  name: string; kind: 'push' | 'pull'; note: string; created: string; createdBy: string;
  expires: string; valid: boolean; products: string[];
};
export type IssuedRobot = IssuedCredential & { kind: 'push' | 'pull'; expires: string; products?: string[] };
export const adminRobots = () => aj<RobotAccount[]>('/api/robots');
export const adminCreateRobot = (b: { name: string; kind: 'push' | 'pull'; products: string[]; days: number; note: string }) =>
  aj<IssuedRobot>('/api/robots', jsonInit('POST', b));
export const adminReissueRobot = (name: string) => aj<IssuedRobot>(`/api/robots/${name}/reissue`, jsonInit('POST', {}));
export const adminDeleteRobot = (name: string) => aj(`/api/robots/${name}`, { method: 'DELETE' });

export type DiskInfo = { totalBytes: number; freeBytes: number; usedBytes: number; usedPct: number; path: string };
export type Metrics = {
  disk?: DiskInfo;
  repos?: { repo: string; bytes: number }[];
  repoCount?: number;
  repoTotalBytes?: number;
};
export const adminMetrics = () => aj<Metrics>('/api/metrics');

export type Health = { zot: boolean; keycloak: boolean; dtrack?: boolean };
export const adminHealth = () => aj<Health>('/api/health');
export type NoticeItem = { id: string; time: string; kind: string; repo: string; tag: string; title: string; body: string; read: boolean };
// 내 통보(로그인 필요). BFF 세션이 없으면 null.
export async function getNotifications(): Promise<{ items: NoticeItem[]; unread: number } | null> {
  const r = await zfetch('/api/notifications');
  if (!r.ok) return null;
  return r.json();
}
export const markNotificationsRead = (id = '') => zfetch('/api/notifications/read', jsonInit('POST', { id }));
export type NoticeLog = {
  items: { id: string; time: string; kind: string; audience: string; repo: string; tag: string; title: string; to: string[]; mailed?: string[]; dropped?: string[]; noEmail?: string[]; mailError?: string }[];
  total: number; page: number; size: number; days: number;
  lastSync: string; lastSyncMsg: string; quietUntil?: string; tracked: number; pending: number; initialized: boolean;
};
export const adminNotifyLog = (page = 1, size = 20, days = 0) => aj<NoticeLog>(`/api/notify/log?page=${page}&size=${size}&days=${days}`);
export const adminNotifySync = () => aj<{ message: string }>('/api/notify/sync', jsonInit('POST', {}));
export type VulnSources = { osv: string[]; ecosystems: string[]; github: boolean; githubTokenSet: boolean; quietUntil: string; waiting: string[] };
export const adminVulnSources = () => aj<VulnSources>('/api/vulnsources');
export const adminVulnSourcesSave = (b: { osv: string[]; github: boolean; githubToken?: string }) =>
  aj<{ status: string; changed: number; quietUntil: string }>('/api/vulnsources', jsonInit('PUT', b));
export const adminVulnReanalyze = () => aj<{ requested: number; failed: number }>('/api/vulnsources/reanalyze', jsonInit('POST', {}));
export type MailStatus = { configured: boolean; host: string; port: string; from: string; allowlist: string[] };
// 취약점 DB 미러(vuln-mirror) — 정책·상태·DT 연결
export type MirrorSourcePolicy = { enabled: boolean; intervalH: number };
export type MirrorPolicy = { mode: 'scheduled' | 'offline'; windowStart: string; windowEnd: string; upstream: string; minFreeGB: number; sources: Record<string, MirrorSourcePolicy> };
export type MirrorSource = {
  id: string; name: string; group: string; category: string; use: string; license: string; hosts: string[]; defaultIntervalH: number;
  enabled: boolean; intervalH: number; staleH: number; status: 'never' | 'running' | 'ok' | 'error'; error?: string;
  lastSuccess?: string; lastAttempt?: string; localAsOf?: string; nextAccess?: string; stale: boolean; files: number; bytes: number;
};
export type MirrorRun = { id: string; trigger: string; start: string; end: string; status: string; error?: string; changed: number; bytes: number; snapshot: string };
export type MirrorStatus = {
  now: string; policy: MirrorPolicy; inWindow: boolean; nextWindow?: string; running?: string; snapshot: string;
  totalBytes: number; fileCount: number; diskFree: number; diskTotal: number; allowedHosts: string[]; sources: MirrorSource[]; runs: MirrorRun[];
};
export type DtMirrorProp = { name: string; value: string; mirrorValue?: string; usingMirror: boolean; original?: string };
export type MirrorInfo = { installed: boolean; reachable?: boolean; error?: string; status?: MirrorStatus; mirrorUrl?: string; dt?: DtMirrorProp[]; dtError?: string };
export const adminMirror = () => aj<MirrorInfo>('/api/mirror');
export const adminMirrorPolicy = (p: MirrorPolicy) => aj<MirrorStatus>('/api/mirror/policy', jsonInit('PUT', p));
export const adminMirrorSync = (id: string) => aj<{ queued: string[] }>(`/api/mirror/sync/${encodeURIComponent(id)}`, jsonInit('POST', {}));
export const adminMirrorDT = (use: boolean) => aj<{ changed: Record<string, string> }>('/api/mirror/dt', jsonInit('PUT', { use }));
export const adminMailStatus = () => aj<MailStatus>('/api/mail');
// 현황 메일: 넣을 항목(체크)·첨부 보고서(PDF)·받는 사람. 항목 없이 보내면 짧은 시험 메일.
export type MailSection = { id: string; label: string; desc: string };
export type MailRole = 'admin' | 'dev' | 'sales' | 'customer' | 'user';
export type MailUser = { username: string; email: string; groups: string[]; role: MailRole };
export type MailReport = {
  id: string; docNo: string; title: string; audience: string; audienceKo: string; lang: string; edition: number;
  created: string; fileName: string; repo?: string; tag?: string; pdf: boolean;
};
export type MailOptions = {
  sections: MailSection[]; reports: MailReport[]; users: MailUser[]; usersError?: string;
  pdf: boolean; ai: boolean; allowlist: string[]; configured: boolean; roles: Record<string, string>;
};
export type MailCompose = { recipients: string[]; sections: string[]; reports: string[]; subject: string; note: string; delay?: number };
// 발송함: 보내기 전 잠깐 기다리고(취소 가능) 보낸다
export type OutboxItem = {
  id: string; kind: 'digest' | 'custnotify' | 'devreq' | 'notify' | 'expiry'; label: string; ref?: string; recipients: string[]; subject: string; createdBy: string; createdAt: string; sendAt: string;
  status: 'pending' | 'sent' | 'blocked' | 'failed' | 'cancelled' | 'lost'; sent?: string[]; dropped?: string[]; error?: string; doneAt?: string; doneBy?: string; attachments?: number; resendOf?: string; resentAs?: string; canResend?: boolean;
};
export const adminOutbox = () => aj<{ items: OutboxItem[]; now: string }>('/api/mail/outbox');
export const adminOutboxResend = (id: string) => aj<OutboxItem>(`/api/mail/outbox/${encodeURIComponent(id)}/resend`, jsonInit('POST', {}));
export const adminOutboxCancel = (id: string) => aj<OutboxItem>(`/api/mail/outbox/${encodeURIComponent(id)}`, { method: 'DELETE' });
export type MailTemplate = { id: string; name: string; subject: string; note: string; sections: string[]; builtin?: boolean; updatedBy?: string; updatedAt?: string };
export const adminMailTemplates = () => aj<MailTemplate[]>('/api/mail/templates');
export const adminMailTemplatesSave = (custom: MailTemplate[]) => aj<MailTemplate[]>('/api/mail/templates', jsonInit('PUT', custom));
export type MailSuggestion = {
  by: 'ai' | 'rule'; recipients: { username: string; email: string; role: MailRole; reason: string }[];
  sections: string[]; reports: string[]; subject: string; note: string; reasons?: string[]; aiError?: string; aiMeta?: { model: string; provider?: string };
};
export const adminMailOptions = () => aj<MailOptions>('/api/mail/options');
export const adminMailPreview = (c: MailCompose) => aj<{ subject: string; html: string; text: string }>('/api/mail/preview', jsonInit('POST', c));
export const adminMailSuggest = (goal: string, ai: boolean) => aj<MailSuggestion>('/api/mail/suggest', jsonInit('POST', { goal, ai }));
export const adminMailTest = (c: string | MailCompose) =>
  aj<{ status: string; to: string[]; dropped?: string[]; attachments?: number; outbox?: OutboxItem }>('/api/mail/test', jsonInit('POST', typeof c === 'string' ? { to: c } : c));
export const regReportPdfUrl = (id: string) => `/api/regs-report/${encodeURIComponent(id)}/pdf`;

export type LogEntry = {
  off: number; time: string; level: string; msg: string; event: string; user?: string; method?: string; path?: string;
  status?: number; latency?: string; ip?: string; err?: string; raw: string;
};
export type LogsResult = {
  entries: LogEntry[]; next: number; more: boolean; partial?: boolean; scanned: number; scope: number;
  byLevel: Record<string, number>; byEvent: Record<string, number>; countsComplete: boolean;
  fileSize: number; firstTime: string; lastTime: string; events: { Key: string; Label: string }[]; ms: number; error?: string;
};
export type LogsQuery = { cursor?: number; limit?: number; q?: string; levels?: string[]; event?: string; user?: string; from?: string; to?: string; all?: boolean };
export const adminLogs = (p: LogsQuery) => {
  const u = new URLSearchParams();
  if (p.cursor !== undefined) u.set('cursor', String(p.cursor));
  u.set('limit', String(p.limit ?? 100));
  if (p.q) u.set('q', p.q);
  if (p.levels?.length) u.set('levels', p.levels.join(','));
  if (p.event) u.set('event', p.event);
  if (p.user) u.set('user', p.user);
  if (p.from) u.set('from', p.from);
  if (p.to) u.set('to', p.to);
  if (p.all) u.set('all', '1');
  return aj<LogsResult>('/api/logs?' + u.toString());
};

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

// 관리 대시보드 집계(GET /api/dashboard, 5분 캐시 — refresh 로 즉시 재집계)
export type DashCount = { label: string; value: number };
export type DashTodo = { kind: string; tone: 'crit' | 'warn'; text: string; count: number; link?: string };
export type DashDay = { date: string; critical?: number; high?: number; medium?: number; low?: number; unaudited?: number; uploads?: number; downloads?: number };
export type DashDownload = { time: string; user: string; org?: string; repo: string; tag: string; latest?: string };
export type Dashboard = {
  generated: string;
  dt: boolean;
  todo: DashTodo[];
  security: {
    pending: Record<string, number>; total: number; analyzed: number; aging: DashCount[]; trend: DashDay[] | null;
    products: { repo: string; tag: string; critical: number; high: number; total: number; pending: number }[] | null;
    mttrHours: number; mttrSamples: number; recent: { time: string; repo: string; tag: string; title: string }[] | null;
  };
  quality: {
    versions: number; withSbom: number; sbomSupplier: number; sbomSyft: number; withVex: number;
    components: number; noVersion: number; noPurl: number; noLicense: number; copyleft: number;
    licenses: DashCount[] | null; top: { name: string; products: number; versions: number; vulns: number }[] | null;
  };
  customers: { orgs: DashCount[] | null; recent: DashDownload[] | null; outdated: DashDownload[] | null; notices: number };
  ops: { daily: DashDay[] | null; actors: DashCount[] | null; mailed: number; mailFailed: number; lastSync: string; lastSyncMsg: string; certDays: number };
};
export const adminDashboard = (refresh = false) => aj<Dashboard>('/api/dashboard' + (refresh ? '?refresh=1' : ''));

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

// 내 API 키(zot 기본 기능) — oras 로그인용 개인 토큰. zot 웹 세션(제품 화면 로그인)으로 발급·삭제.
//   권한은 계정의 역할·고객사·제품 권한을 그대로 따른다(범위 지정은 zot 이 강제하지 않아 사용 안 함).
export type ApiKey = { uuid: string; label: string; createdAt: string; expirationDate: string; isExpired: boolean; lastUsed: string };
export async function listApiKeys(): Promise<ApiKey[]> {
  const r = await zfetch('/zot/auth/apikey');
  if (!r.ok) throw new Error(`API 키 목록 ${r.status}`);
  return (await r.json()).apiKeys || [];
}
export async function createApiKey(label: string, expirationDate: string): Promise<ApiKey & { apiKey: string }> {
  const r = await zfetch('/zot/auth/apikey', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(expirationDate ? { label, expirationDate } : { label })
  });
  if (!r.ok) throw new Error(`API 키 발급 ${r.status}`);
  return r.json();
}
export async function deleteApiKey(id: string): Promise<void> {
  const r = await zfetch(`/zot/auth/apikey?id=${encodeURIComponent(id)}`, { method: 'DELETE' });
  if (!r.ok) throw new Error(`API 키 삭제 ${r.status}`);
}

// ---------- 로컬 AI (초안 전용 — 판정은 규칙·사람) ----------
export type AIStatus = {
  enabled: boolean; reachable: boolean; mode?: string; model?: string; modelFile?: string;
  sha256?: string; sizeBytes?: number; ctx?: number; error?: string; provider?: string;
};
export type AIFact = { id: string; text: string; untrusted?: boolean };
export type VexDraft = {
  status: string; justification: string; response: string; detail: string;
  plan: string[]; workaround: string;
  citations: string[]; missing: string[]; confidence: 'low' | 'medium' | 'high';
};
export type Exploits = { edb?: string[]; msf?: string[]; nuclei?: boolean; checked: boolean };
// 규칙 계산(AI 아님): 우선순위·OSV 수정 버전·KEV 기한·공개 익스플로잇
export type VexRemedy = {
  priority: number; targetVersion?: string; fixedVersions?: string[]; inRange?: string;
  osvId?: string; ranges?: string[]; osvNote?: string; dueBy?: string; exploits: Exploits;
};
export type VexDraftResult = {
  component: string; vulnerability: string; vulnId: string; at: string;
  draft: VexDraft; remedy: VexRemedy; facts: AIFact[]; warnings: string[]; kev: boolean;
  meta: { model: string; factsSha256: string; dbSnapshot?: string; elapsedMs: number; method?: 'rule' | 'rule+card' | 'ai-slim' | 'ai-full'; cached?: boolean };
};
export const aiStatus = (use?: 'report') => aj<AIStatus>('/api/ai/status' + (use ? `?use=${use}` : ''));
// AI 연결 설정(관리자). 로컬·외부 LLM 을 함께 등록하고 용도(VEX / 보고서)별로 고른다. 키는 다시 내려오지 않는다(hasKey·keyHint 만).
export type AIMode = 'off' | 'local' | 'external';
export type AIExternal = {
  provider: 'anthropic' | 'openai'; url?: string; model?: string; jsonSchema: boolean; effort?: '' | 'low' | 'medium' | 'high';
  hasKey: boolean; keyHint?: string;
};
export type AIConfig = {
  mode: AIMode; reportMode: AIMode; url: string; model?: string; jsonSchema: boolean; external: AIExternal; sendChecklist: boolean;
  fromEnv: boolean; updatedBy?: string; updatedAt?: string;
};
export type AIConfigIn = {
  mode: AIMode; reportMode: AIMode; url: string; model: string; jsonSchema: boolean; sendChecklist: boolean;
  external: { provider: AIExternal['provider']; url: string; model: string; apiKey?: string; clearKey?: boolean; jsonSchema: boolean; effort: string };
};
export type AITestResult = { ok: boolean; model?: string; answer?: string; elapsedMs: number; error?: string };
export const adminAIConfig = () => aj<{ config: AIConfig; status: AIStatus; reportStatus: AIStatus }>('/api/ai/config');
export const adminAIConfigSave = (b: AIConfigIn) => aj<{ config: AIConfig; status: AIStatus; reportStatus: AIStatus }>('/api/ai/config', jsonInit('PUT', b));
export const adminAITest = (b: AIConfigIn & { target: 'local' | 'external' }) => aj<AITestResult>('/api/ai/test', jsonInit('POST', b));
export const aiVexDraft = (b: { project: string; component: string; vulnerability: string; context?: string; repo: string; tag: string }) =>
  aj<VexDraftResult>('/api/ai/vex-draft', jsonInit('POST', b));
export type KevInfo = {
  available: boolean; exploitsAvailable?: boolean; asOf?: string;
  items?: Record<string, { kev: boolean; kevAdded?: string; kevDue?: string; ransomware?: boolean; exploit?: boolean; exploits?: Exploits }>;
};
export type VexBatch = {
  state: 'none' | 'running' | 'done' | 'cancelled' | 'error'; project?: string; total?: number; done?: number;
  current?: string; started?: string; finished?: string; error?: string; message?: string;
  phase?: 'judge' | 'enrich'; judgedAt?: string; enrichTotal?: number; enrichDone?: number; // 빠른 경로: ① 판정 ② 권고문 요약 보강
  results?: Record<string, VexDraftResult>; failed?: Record<string, string>;
};
export const aiVexBatchStart = (b: { project: string; repo: string; tag: string; context?: string; limit?: number }) =>
  aj<VexBatch>('/api/ai/vex-batch', jsonInit('POST', b));
export const aiVexBatchCancel = (project: string) => aj<{ status: string }>('/api/ai/vex-batch', jsonInit('POST', { project, cancel: true }));
export const aiVexBatch = (project: string) => aj<VexBatch>(`/api/ai/vex-batch?project=${encodeURIComponent(project)}`);
// VEX 판단 대기열(전 제품·버전, 급한 순)
export type VexQueueRow = {
  repo: string; tag: string; project: string; total: number; analyzed: number; pending: number;
  pendCritical: number; pendHigh: number; pendKev: number; affected: number;
  batchState?: string; batchDone?: number; batchTotal?: number; batchDrafts?: number; batchAt?: string;
  batchPhase?: 'enrich'; enrichDone?: number; enrichTotal?: number;
};
export type VexQueue = { dt: boolean; rows: VexQueueRow[]; summary?: Record<string, number>; ai?: boolean; generated?: string };
export const vexQueue = (refresh = false) => aj<VexQueue>(`/api/vex/queue${refresh ? '?refresh=1' : ''}`);
export const vexKev = (ids: string[]) => aj<KevInfo>(`/api/vex/kev?ids=${encodeURIComponent(ids.join(','))}`);

// ---------- 규제 대응 검증 ----------
export type CompRegs = { id: string; name: string; basis: string; mandate: boolean; items: number; noSource?: boolean };
export type CompCheck = { id: string; name: string; result: 'pass' | 'partial' | 'fail' | 'na'; value: string; fix?: string };
export type CompItem = {
  id: string; stage: string; activity: string; question: string; roles: string[]; regs: string[];
  side: 'supplier' | 'buyer'; result: 'met' | 'partial' | 'unmet' | 'doc'; checks?: string[];
  selfEval?: string; problem?: string; remedy?: string; aiCitations?: string[]; source?: 'rule' | 'ai';
};
export type CompReport = {
  id: string; repo: string; tag: string; createdAt: string; createdBy: string; checklist: string; checklistSha256: string;
  profile: { markets: string[] }; regs: CompRegs[]; evidence: CompCheck[]; info: Record<string, string>;
  items: CompItem[]; counts: Record<string, number>; state: 'running' | 'done' | 'error'; progress?: string;
  steps?: string[]; stage?: number; done?: number; total?: number;
  summary?: { summary: string; risks: { title: string; detail: string; citations: string[] }[]; actions: { priority: string; action: string; citations: string[] }[] };
  ai?: { model: string; modelSha256?: string; dbSnapshot?: string; elapsedMs: number }; aiError?: string; sha256?: string;
};
export type CompInfo = {
  ai: AIStatus; markets: Record<string, string>;
  checklist?: { name: string; importedAt: string; sha256: string; sheet: string; items: number; regs: Record<string, number>; stages: Record<string, number> };
  profiles: Record<string, { markets: string[] }>;
  products: { repo: string; tags: string[] }[];
  reports: { id: string; repo: string; tag: string; createdAt: string; counts: Record<string, number>; ai: boolean }[];
  running?: { id: string; progress: string };
};
export const adminCompliance = () => aj<CompInfo>('/api/compliance');
export const adminComplianceUpload = async (f: File) =>
  aj<CompInfo['checklist']>(`/api/compliance/checklist?name=${encodeURIComponent(f.name)}`, { method: 'PUT', body: await f.arrayBuffer() });
export const adminComplianceRun = (b: { repo: string; tag: string; profile: { markets: string[] }; ai: boolean }) =>
  aj<{ id: string }>('/api/compliance/report', jsonInit('POST', b));
export const adminComplianceReport = (id: string) => aj<CompReport>(`/api/compliance/report/${encodeURIComponent(id)}`);
export const complianceMdUrl = (id: string) => `/api/compliance/report/${encodeURIComponent(id)}?format=md`;

// ---------- 규제 요구사항 카탈로그·탐색·보고서(관리자) ----------
export type RegDate = { date: string; label: string };
export type RegSource = { title: string; url: string };
export type RegAudience = 'dev' | 'admin' | 'sales';
export type RegReq = {
  id: string; clause: string; title: string; text: string; evidence: string[];
  actions: Partial<Record<RegAudience, string>>;
};
export type Regulation = {
  id: string; region: string; name: string; nameKo: string; kind: string; authority: string; binding: string;
  status: string; scope: string; markets: string[]; tags: string[]; dates: RegDate[]; sources: RegSource[];
  requirements: RegReq[]; rev: number; origin?: string; edited?: boolean; builtinRev?: number;
  verified: boolean; verifiedBy?: string; verifiedAt?: string; note?: string; updatedBy?: string; updatedAt?: string;
};
export type RegDiff = { id: string; name: string; change: 'added' | 'changed' | 'removed'; localEdit: boolean; builtinRev: number; currentRev: number };
export type RegsInfo = {
  catalog: { version: string; builtinVersion: string; note?: string; updatedAt?: string; regulations: Regulation[] };
  builtin: { version: string; diff: RegDiff[] };
  audiences: Record<string, string>; regions: Record<string, string>; checks: Record<string, string>;
  analyses?: Record<string, RegAnalysis>; lawOC?: boolean; // 국내 법규 분석(한국 규제)
};
export const adminRegs = () => aj<RegsInfo>('/api/regs');
export const adminRegSave = (r: Regulation) => aj<{ regulation: Regulation }>(`/api/regs/${encodeURIComponent(r.id)}`, jsonInit('PUT', r));
export const adminRegDelete = (id: string) => aj(`/api/regs/${encodeURIComponent(id)}`, { method: 'DELETE' });
export const adminRegVerify = (id: string, verified: boolean, note?: string) =>
  aj<{ regulation: Regulation }>(`/api/regs/${encodeURIComponent(id)}/verify`, jsonInit('POST', { verified, note }));
export const adminRegBuiltinApply = (ids: string[], overwrite: boolean) =>
  aj<{ applied: string[]; skipped: string[] }>('/api/regs-builtin/apply', jsonInit('POST', { ids, overwrite }));

export type RegCandidate = {
  id: string; source: 'federal-register' | 'law-kr' | 'watch' | 'ai'; region: string; title: string; summary?: string;
  url?: string; date?: string; keyword?: string; regId?: string; state: 'new' | 'dismissed' | 'adopted'; foundAt: string;
};
export type RegDiscoverInfo = {
  state: { running: boolean; started?: string; finished?: string; log: string[]; added: number };
  candidates: RegCandidate[]; config: { keywordsUS: string[]; keywordsKR: string[] }; hasLawOC: boolean;
  aiReady?: boolean; watchBase?: number; // 출처별 사용 가능 여부(AI 연결·변경 감지 기준값 수)
};
export const adminRegDiscover = () => aj<RegDiscoverInfo>('/api/regs-discover');
export const adminRegDiscoverRun = (sources: string[]) => aj('/api/regs-discover', jsonInit('POST', { sources }));
export const adminRegDiscoverCfg = (b: { keywordsUS: string[]; keywordsKR: string[]; lawOC?: string; clearLawOC?: boolean }) =>
  aj<{ hasLawOC: boolean }>('/api/regs-discover/config', jsonInit('PUT', b));
export const adminRegCandidate = (id: string, action: 'adopt' | 'dismiss' | 'restore') =>
  aj<{ candidate: RegCandidate }>(`/api/regs-candidates/${encodeURIComponent(id)}`, jsonInit('POST', { action }));

export type RegReportReq = RegReq & { status: 'met' | 'partial' | 'unmet' | 'manual'; checks?: CompCheck[]; action?: string };
export type RegReportReg = Regulation & { reqs: RegReportReq[]; counts: Record<string, number>; next?: RegDate; untranslated?: boolean };
export type RegChange = { kind: 'added' | 'removed' | 'revised' | 'date' | 'status'; reg: string; detail?: string };
export type RegReport = {
  id: string; state: 'running' | 'done'; lang: 'ko' | 'en'; edition: number; docNo: string; fileName: string;
  prevId?: string; prevDate?: string; changes?: RegChange[];
  title: string; audience: string; audienceKo: string; regions: string[]; regionNames: Record<string, string>;
  repo?: string; tag?: string; created: string; createdBy: string; catalogVersion: string; builtinVersion: string;
  regs: RegReportReg[]; totals: Record<string, number>;
  timeline: { date: string; label: string; reg: string; region: string; future: boolean }[];
  evidence?: CompCheck[]; unverified: number;
  summary?: { headline: string; points: string[]; priority: string[]; citations: string[] };
  aiError?: string; aiMeta?: { model: string; elapsedMs: number; provider?: string }; disclaimer: string;
  law?: RegLawSection[]; // 국내 법규 분석 및 대응 방안(한글 보고서)
};
export type RegReportItem = {
  id: string; title: string; audienceKo: string; repo?: string; tag?: string; created: string; createdBy: string; regs: number; state: string;
  lang: 'ko' | 'en'; docNo?: string; edition?: number; fileName?: string; key?: string; audience?: string; regions?: string[]; summary?: boolean;
};
export const adminRegReportRun = (b: { audience: string; regions: string[]; repo?: string; tag?: string; ai: boolean; lang: 'ko' | 'en' }) =>
  aj<RegReport>('/api/regs-report', jsonInit('POST', b));
export const adminRegReports = () => aj<RegReportItem[]>('/api/regs-report');
export const adminRegReport = (id: string) => aj<RegReport>(`/api/regs-report/${encodeURIComponent(id)}`);

// 공개 저장소(상류) 분석 — 제품 SBOM 구성요소의 상류 저장소 건강도 / 공개 GitHub 저장소 단건 점검
export type UpRating = 'risk' | 'warn' | 'ok' | 'unknown';
export type UpRate = { limit: number; remaining: number; reset?: string; hit: boolean; auth: boolean };
export type UpRepo = {
  id: string; url: string; host: string; stars?: number; forks?: number; openIssues?: number;
  scorecard?: number; scorecardDate?: string; checks?: Record<string, number>;
  archived: boolean; disabled: boolean; fork?: boolean; pushedAt?: string; license?: string; release?: string; releaseAt?: string;
  secPolicy?: boolean; secPolicySrc?: string; advisories?: number; advCritical?: number; advHigh?: number; advOpenCritical?: number;
  depsDev: string; github: string; fetchedAt?: string; cached?: boolean; rating?: UpRating; reasons?: string[]; comps?: number;
};
export type UpComp = {
  name: string; version?: string; purl?: string; system?: string; repo?: string; repoSrc?: string; deprecated?: boolean;
  vulns?: string[]; vulnCritical?: number; vulnHigh?: number; rating: UpRating; reasons?: string[];
};
export type UpFlag = { name: string; version?: string; repo?: string; rating: UpRating; reasons: string[] };
export type UpReport = {
  id: string; kind: 'product' | 'repo'; repo?: string; tag?: string; target?: string; created: string; createdBy: string; finished?: string;
  state: 'running' | 'done' | 'error'; progress?: string; error?: string; sbom?: string;
  steps?: string[]; stage?: number; done?: number; total?: number;
  comps: UpComp[]; repos: Record<string, UpRepo>; counts?: Record<UpRating, number>; top?: UpFlag[]; replace?: UpFlag[];
  rate?: UpRate; notes?: string[]; depGraph?: { packages: number; ecosystems?: Record<string, number>; sample?: string[]; error?: string };
  summary?: { headline: string; points: string[]; actions: string[]; citations: string[] };
  aiError?: string; aiMeta?: { model: string; elapsedMs: number; provider?: string }; disclaimer: string;
};
export type UpReportItem = {
  id: string; kind: 'product' | 'repo'; repo?: string; tag?: string; target?: string; created: string; createdBy: string;
  state: string; progress?: string; comps: number; repos: number; counts?: Record<UpRating, number>; rating?: UpRating; summary: boolean;
};
export type UpConfig = { hasToken: boolean; tokenHint?: string; maxRepos: number; effective: number; updatedBy?: string; updatedAt?: string };
export const adminUpstreamConfig = () => aj<{ config: UpConfig; ai: boolean; rate?: UpRate; rateError?: string }>('/api/upstream/config');
export const adminUpstreamConfigSave = (b: { githubToken?: string; clearToken?: boolean; maxRepos: number }) =>
  aj<{ config: UpConfig }>('/api/upstream/config', jsonInit('PUT', b));
export const adminUpstreamRun = (b: { repo: string; tag: string; ai: boolean }) => aj<{ id: string }>('/api/upstream/run', jsonInit('POST', b));
export const adminUpstreamRepo = (b: { url: string; ai: boolean }) => aj<{ id: string }>('/api/upstream/repo', jsonInit('POST', b));
export const adminUpstreamReports = () => aj<UpReportItem[]>('/api/upstream/reports');
export const adminUpstreamReport = (id: string) => aj<UpReport>(`/api/upstream/report/${encodeURIComponent(id)}`);

// ---------- 국내 법규 분석 및 대응 방안 ----------
export type LawArticle = {
  law: string; kind?: 'law' | 'admrul'; article?: string; title?: string; gist: string; url?: string; check?: boolean;
  text?: string; fetchedAt?: string;
};
export type LawStep = { stage: 'now' | '3m' | '6m'; do: string };
export type RegAnalysis = {
  nature: string; duty: 'legal' | 'conditional' | 'voluntary'; dutyNote?: string; questions: string[]; subjects: string[];
  articles: LawArticle[]; sanctions: string; plans: Partial<Record<RegAudience, LawStep[]>>; evidence: string[];
  trustlink: { feature: string; how: string }[]; talking?: string[]; checks?: string[]; sources?: RegSource[];
  asOf?: string; rev: number; origin?: 'builtin' | 'ai'; verified: boolean; verifiedBy?: string; verifiedAt?: string;
  updatedBy?: string; updatedAt?: string; aiMeta?: { model: string; elapsedMs: number; provider?: string }; citations?: string[];
  draft?: RegAnalysis; running?: boolean; aiError?: string; builtinNewer?: boolean;
};
export type RegLawSection = { regId: string; name: string; analysis: RegAnalysis };
export type LawFetchResult = {
  status: 'done' | 'no-oc'; fetched: number; message?: string;
  results?: { law: string; article: string; ok: boolean; error?: string }[];
};
export const adminRegLawFetch = (id: string) => aj<LawFetchResult>(`/api/regs/${encodeURIComponent(id)}/law-fetch`, { method: 'POST' });
export const adminRegLawAnalyze = (id: string) => aj<{ status: string }>(`/api/regs/${encodeURIComponent(id)}/law-analyze`, { method: 'POST' });
export const adminRegLawReview = (id: string, action: 'verify' | 'unverify' | 'adopt' | 'discard' | 'reset') =>
  aj<{ status: string }>(`/api/regs/${encodeURIComponent(id)}/law-review`, jsonInit('POST', { action }));
// KEV·치명 자동 초안(BFF vex_autodraft.go) — 새 취약점 통보 뒤 자동으로 건 일괄 판정은 trigger='auto', 그 초안은 auto=true.
export type VexDraftResultAuto = VexDraftResult & { auto?: boolean };
export type VexBatchAuto = VexBatch & { trigger?: string; results?: Record<string, VexDraftResultAuto> };
export type VexQueueRowAuto = VexQueueRow & { batchAuto?: number };

// ---------- 고객 등록부 · 고객 통지(패치 권고) ----------
export type CustNotifyKind = 'vuln' | 'vex' | 'incident' | 'patch' | 'eos' | 'contract';
export type CustContact = { name: string; role: 'security' | 'itops' | 'purchase' | 'other'; email: string; phone?: string; mobile?: string; dept?: string; title?: string; notify: CustNotifyKind[]; lang?: '' | 'ko' | 'en' };
export type CustInstall = { tag: string; env: '운영' | 'DR' | '검증' | '개발'; qty: number };
export type CustUsage = {
  id?: string; repo: string; installs: CustInstall[]; contractNo?: string; licenseType?: '' | 'perpetual' | 'subscription' | 'term';
  useStart?: string; licenseExpiry?: string; maintStart?: string; maintExpiry?: string; supportTier?: string;
  notifyLevel: 'critical_kev' | 'high' | 'all'; notifyContacts?: string[]; memo?: string;
};
export type Customer = {
  id: string; name: string; industry: CustIndustry; country?: string; lang: 'ko' | 'en'; orgGroup?: string;
  salesOwner?: string; supportOwner?: string; memo?: string; contacts: CustContact[]; usages: CustUsage[]; updated?: string; updatedBy?: string;
  // 사용/중지(폐업·관계 종료·계약 해지)와 로고 — 전용 API 로만 바뀐다
  disabled?: boolean; disabledReason?: CustDisableReason; disabledNote?: string; disabledAt?: string; disabledBy?: string; logo?: string;
  deleted?: boolean; deletedAt?: string; deletedBy?: string; // 휴지통
};
export const CUST_INDUSTRIES = ['공공', '금융', '방산', '제조', '통신', '에너지', '의료', '일반', '해외'] as const;
export type CustIndustry = (typeof CUST_INDUSTRIES)[number];
// 업종 배지 색
export const INDUSTRY_CLS: Record<string, string> = {
  공공: 'bg-sky-100 text-sky-800', 금융: 'bg-emerald-100 text-emerald-800', 방산: 'bg-indigo-100 text-indigo-800', 제조: 'bg-amber-100 text-amber-800',
  통신: 'bg-cyan-100 text-cyan-800', 에너지: 'bg-orange-100 text-orange-800', 의료: 'bg-rose-100 text-rose-800', 일반: 'bg-slate-100 text-slate-700', 해외: 'bg-violet-100 text-violet-800',
};
export type CustDisableReason = 'closed' | 'ended' | 'terminated' | 'other';
export const CUST_DISABLE_REASONS: Record<CustDisableReason, string> = { closed: '폐업', ended: '관계 종료', terminated: '계약 해지', other: '기타' };
export const customerLogoUrl = (logo?: string) => (logo ? `/api/customer-logo/${logo}` : '');
export const adminCustomerStatus = (id: string, enabled: boolean, reason?: CustDisableReason, note?: string) =>
  aj<Customer>(`/api/customers/${encodeURIComponent(id)}/status`, jsonInit('PUT', { enabled, reason, note }));
export const adminCustomerLogo = (id: string, file: Blob) =>
  aj<Customer>(`/api/customers/${encodeURIComponent(id)}/logo`, { method: 'PUT', headers: { 'Content-Type': file.type || 'application/octet-stream' }, body: file });
export const adminCustomerUndelete = (id: string) => aj<Customer>(`/api/customers/${encodeURIComponent(id)}/restore`, { method: 'POST' });
export const adminCustomerPurge = (id: string, confirm: string) => aj<{ purged: string }>(`/api/customers/${encodeURIComponent(id)}/purge`, jsonInit('DELETE', { confirm }));
export const adminCustomersRestore = (file: Blob) =>
  aj<{ customers: number; logos: number; previousCopy: string }>('/api/customers-restore', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: file });
export const adminCustomerLogoDelete = (id: string) => aj<Customer>(`/api/customers/${encodeURIComponent(id)}/logo`, { method: 'DELETE' });
export type CustExpiry = { customerId: string; customer: string; usageId: string; repo: string; kind: 'license' | 'maint' | 'eos'; tag?: string; date: string; days: number };
export type CustMismatch = { repo: string; estimated: string; at: string; user: string; installed: string[] };
export type CustomerView = Customer & { expiry: CustExpiry[]; mismatch: CustMismatch[] };
export type VerPolicy = { tag: string; released?: string; eos?: string; upgrade?: string };
export type CustSettings = { expiryToCustomer: boolean };
export const adminCustomers = () =>
  aj<{ customers: CustomerView[]; products: Record<string, VerPolicy[]>; settings: CustSettings }>('/api/customers');
export const adminCustomerSave = (c: Customer, isNew: boolean) =>
  aj<Customer>(isNew ? '/api/customers' : `/api/customers/${encodeURIComponent(c.id)}`, jsonInit(isNew ? 'POST' : 'PUT', c));
export const adminCustomerDelete = (id: string) => aj<{ deleted: string }>(`/api/customers/${encodeURIComponent(id)}`, { method: 'DELETE' });
export const adminCustomerProduct = (repo: string, versions: VerPolicy[]) => aj<unknown>('/api/customer-products', jsonInit('PUT', { repo, versions }));
export const adminCustomerSettings = (s: CustSettings) => aj<CustSettings>('/api/customer-settings', jsonInit('PUT', s));
export type ExpiryRec = { time: string; customerId: string; customer: string; audience: 'internal' | 'customer'; items: string[]; sent?: string[]; dropped?: string[]; error?: string };
export const adminCustomerExpiring = (days = 90) =>
  aj<{ items: (CustExpiry & { sent: number[] })[]; log: ExpiryRec[]; thresholds: number[]; settings: CustSettings }>(`/api/customer-expiring?days=${days}`);
export const adminCustomerExpiryCheck = () => aj<{ mails: number }>('/api/customer-expiring/check', { method: 'POST' });

export type CustVulnCand = { vulnId: string; repo: string; severity: string; kev: boolean; component: string; tags: string[]; states: string[]; customers: string[]; notified?: string };
export type FixStep = { tag: string; status: 'fixed' | 'affected' | 'present' | 'unknown'; compVersion?: string; note?: string };
export type CustFix = {
  found: boolean; tag?: string; compVersion?: string; note?: string; from?: string; steps: FixStep[];
  osv?: { id: string; target?: string; fixed?: string[]; ranges?: string[] }; osvNote?: string; message?: string;
};
export type CustSendResult = { at: string; sent?: string[]; dropped?: string[]; error?: string; outbox?: string; pending?: boolean; sendAt?: string; cancelled?: boolean };
export type CustTarget = {
  key: string; customerId: string; customer: string; usageId: string; lang: 'ko' | 'en'; tags: string[]; recommend?: string; recComp?: string;
  notes?: string[]; internal?: string[]; contacts: string[]; to: string[]; cc?: string[]; subject: string; text: string; html: string; result?: CustSendResult;
};
export type CustAIText = { summary: string; impact: string; action: string; citations: string[]; source: 'ai' | 'rule'; model?: string; warnings?: string[] };
export type CustNotice = {
  id: string; kind: 'patch' | 'notaffected'; status: 'draft' | 'queued' | 'sent' | 'partial' | 'dropped' | 'failed'; created: string; createdBy: string;
  aiState?: 'running' | 'done'; aiStarted?: string;
  sentAt?: string; sentBy?: string; repo: string; vulnId: string; severity: string; cvss?: number; kev: boolean; component: string; compVersion: string;
  fix: CustFix; facts: AIFact[]; ai: Record<string, CustAIText>; aiError?: string; targets: CustTarget[]; skipped: { customerId: string; customer: string; reason: string }[];
};
export type CustNoticeRow = {
  id: string; kind: CustNotice['kind']; status: CustNotice['status']; created: string; createdBy: string; sentAt?: string; repo: string; vulnId: string;
  severity: string; kev: boolean; recommend?: string; targets: number; sent: number; dropped: number; failed: number;
};
export const adminCustNotifyVulns = (kind: CustNotice['kind']) => aj<{ items: CustVulnCand[]; error?: string }>(`/api/custnotify/vulns?kind=${kind}`);
export const adminCustNotifyCreate = (b: { kind: CustNotice['kind']; repo: string; vulnId: string }) => aj<CustNotice>('/api/custnotify', jsonInit('POST', b));
export const adminCustNotifyAI = (id: string) => aj<CustNotice>(`/api/custnotify/${encodeURIComponent(id)}/ai`, { method: 'POST' });
export const adminCustNotifySend = (id: string, keys: string[], delay?: number) => aj<CustNotice>(`/api/custnotify/${encodeURIComponent(id)}/send`, jsonInit('POST', { keys, delay }));
export const adminCustNotifyList = () => aj<CustNoticeRow[]>('/api/custnotify');
export const adminCustNotifyGet = (id: string) => aj<CustNotice>(`/api/custnotify/${encodeURIComponent(id)}`);
export const adminCustNotifyDelete = (id: string) => aj<{ deleted: string }>(`/api/custnotify/${encodeURIComponent(id)}`, { method: 'DELETE' });

// 고객 전용: 로그인 사용자의 고객사 그룹에 연결된 고객만
export type MyVuln = { vulnId: string; severity: string; state: string; kev: boolean; component: string; recommend?: string };
export type MyInstall = { tag: string; env: string; qty: number; eos?: string; eosDays?: number; upgrade?: string; analyzed: boolean; vulns: MyVuln[] };
export type MyUsage = { repo: string; licenseType?: string; licenseExpiry?: string; maintExpiry?: string; supportTier?: string; installs: MyInstall[] };
export type MyNotice = { id: string; kind: string; repo: string; vulnId: string; severity: string; sentAt: string; subject: string; text: string; recommend?: string };
export const myProducts = () => aj<{ customers: { name: string; logo?: string; usages: MyUsage[]; notices: MyNotice[] }[]; user: string }>('/api/my/products');

// ---------- AI 성능·자원 (대시보드 › AI 탭) ----------
export type AIPerfCall = {
  at: string; feature: string; use: string; kind: string; model?: string; waitMs: number; ms: number;
  promptTok: number; genTok: number; promptTps?: number; genTps?: number; ok: boolean; fail?: string;
};
export type AIPerfBench = AIPerfCall & { cpuDuring: number; err?: string; by?: string };
export type AIPerfFeature = {
  feature: string; kind?: string; sensitive?: string; count: number; fails: number; timeouts: number;
  p50Ms: number; p90Ms: number; avgWaitMs: number; genTps: number; lastAt: string;
  recommend: 'local' | 'external' | 'either'; why: string;
};
export type AIPerf = {
  config: { mode: string; reportMode: string; localUrl: boolean; external: string; externalReady: boolean };
  live: { configured: boolean; reachable?: boolean; busy?: boolean; nCtx?: number };
  verdict: { level: 'local' | 'hybrid' | 'external'; title: string; reasons: { tone: 'ok' | 'warn' | 'crit'; text: string }[] };
  local: { genTps: number; calls: number; fails: number; failRate: number };
  external: { genTps: number; calls: number };
  features: AIPerfFeature[];
  benches: AIPerfBench[];
  bench: { running: boolean; started?: string; target?: string };
  system: {
    cpus: number; aiCpus: string; aiMemLimit: number; memTotal: number; memAvail: number; swapTotal: number; swapUsed: number;
    modelFile: string; modelBytes: number; aiMemEst: number; cpuBusy: number; cpuIdle: number; busySamples: number; samples: number;
    disks: { label: string; free: number; total: number }[];
    series: { t: number; cpu: number; mem: number; ai: boolean }[];
  };
};
export const aiPerf = () => aj<AIPerf>('/api/ai-perf');
export const aiPerfBench = (target: 'local' | 'external') => aj<{ started: boolean }>('/api/ai-perf/bench', jsonInit('POST', { target }));

// ---------- 자동 대응(탐지 → AI 분석 → 패치 확인 → 관리자 승인 → 고객 통지 / 개발자 통보) ----------
export type AutoStage = { key: 'detect' | 'ai' | 'fix' | 'approve' | 'notify' | 'devreq'; label: string; state: 'todo' | 'active' | 'done' | 'skip' | 'error' | 'wait'; at?: string; detail?: string };
export type AutoRun = {
  id: string; trigger: 'auto' | 'manual' | 'sweep' | 'patch'; by: string; repo: string; tag: string; vulnId: string; component?: string; severity?: string; kev?: boolean; epss?: number;
  started: string; finished?: string; state: 'running' | 'waiting' | 'done' | 'error';
  outcome?: 'approval' | 'approval-dev' | 'sent' | 'rejected' | 'dev-request' | 'patched' | 'not-affected' | 'no-customers' | 'error';
  stages: AutoStage[]; aiStatus?: string; aiSummary?: string; aiModel?: string; fixTag?: string; fixComp?: string; upstream?: string;
  noticeId?: string; recommended?: string[]; customers?: string[]; waiting?: string[]; devTo?: string[]; approver?: string; error?: string;
  devSubject?: string; devBody?: string; devCandidates?: { username: string; email?: string }[]; outbox?: string[];
  followedBy?: string; followOf?: string; patchTag?: string;
};
export type AutoSettings = { mode: 'on' | 'off'; maxPerVersion: number; sweepHours: number; sweepMax: number; lastSweep?: string; sweepMsg?: string; sweeping?: boolean; updatedBy?: string };
export const adminAutoSweep = () => aj<{ started: boolean }>('/api/auto-response/sweep', { method: 'POST' });
export const adminAutoResponse = () => aj<{ settings: AutoSettings; runs: AutoRun[]; ai: boolean }>('/api/auto-response');
export const adminAutoSettings = (s: AutoSettings) => aj<AutoSettings>('/api/auto-response/settings', jsonInit('PUT', s));
export const adminAutoRun = (repo: string, tag: string, vulnId: string) => aj<AutoRun>('/api/auto-response/run', jsonInit('POST', { repo, tag, vulnId }));
export const adminAutoApprove = (id: string, keys: string[], delay: number) => aj<{ run: AutoRun }>(`/api/auto-response/${encodeURIComponent(id)}/approve`, jsonInit('POST', { keys, delay }));
export const adminAutoReject = (id: string, reason: string) => aj<AutoRun>(`/api/auto-response/${encodeURIComponent(id)}/reject`, jsonInit('POST', { reason }));

// ---------- 승인 대기함(사람이 결정할 일 모음) ----------
export type InboxItem = { kind: 'auto-customer' | 'auto-dev' | 'vex' | 'reg' | 'expiry' | 'outbox'; title: string; detail?: string; link: string; urgent?: boolean; at?: string; ref?: string };
export type InboxGroup = { key: 'auto' | 'vex' | 'reg' | 'expiry' | 'outbox'; label: string; count: number; link: string; items: InboxItem[] };
export const adminInbox = () => aj<{ groups: InboxGroup[]; decisions: number; generated: string }>('/api/inbox');

// ---------- 묻고 찾기(로그인한 누구나, 자기 권한 안에서) ----------
export type AskRow = { title: string; detail?: string; link?: string; tone?: 'crit' | 'warn' | 'ok' | '' };
export type AskAnswer = {
  id: string; intent: 'vuln' | 'component' | 'my' | 'todo' | 'help'; title: string; lead: string;
  rows: AskRow[]; more?: number; sources: string[]; suggest?: string[]; canAI: boolean;
};
export const ask = (q: string) => aj<AskAnswer>('/api/ask', jsonInit('POST', { q }));
export const askSummary = (id: string) =>
  aj<{ answer: string; model: string; provider?: string; elapsedMs: number }>(`/api/ask/${encodeURIComponent(id)}/summary`, jsonInit('POST', {}));
