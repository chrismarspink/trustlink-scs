// trustlink-admin: TrustLink 관리 BFF (Backend-for-Frontend).
//
// 적정기술 원칙: 외부 의존성 없이 Go 표준 라이브러리만 사용한다(오프라인 빌드 용이).
//   - OIDC Authorization Code 플로우 + 서버측 세션으로 관리자 로그인
//   - admins 그룹만 접근 허용 (관리자 게이트)
//   - Keycloak Admin REST API(service-account)로 사용자/그룹 관리 → 관리자가 Keycloak을 직접 안 봐도 됨
//   - zot /metrics + statfs 로 용량, 로그 파일 tail 로 로그 제공
//
// PoC 한계: 토큰은 백채널(코드 교환) 응답을 신뢰해 서명 미검증, 세션은 인메모리. 운영은 서명검증/외부세션.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ---------- config ----------

type Config struct {
	Addr            string
	KCPublic        string // 브라우저용 (authorize/logout)
	KCInternal      string // 서버용 (token/admin api)
	Realm           string
	ClientID        string
	ClientSecret    string
	RedirectURI     string
	MetricsURL      string
	MetricsUser     string
	MetricsPass     string
	DataDir         string // statfs 대상
	LogFile         string
	ZotAPIURL       string // 카탈로그/태그/삭제
	ZotAdminUser    string // delete 권한 보유 htpasswd 계정(adminPolicy)
	ZotAdminPass    string
	ConfigFile      string // accessControl 매트릭스용 zot 설정 경로
	DTBaseURL       string // Dependency-Track API Server (헤드리스)
	DTApiKey        string // DT 서비스 API 키 (X-Api-Key). 비면 키 파일 → 부트스트랩(dt_bootstrap.go)
	DTAdminPassword string // DT admin 비밀번호(부트스트랩용)
	DTKeyFile       string // 발급된 DT API 키 보관 파일(볼륨)
	UIDir           string // 신규 trustlink-ui dist 경로 (단일 프론트도어 서빙)
	KCProxyTarget   string // /auth/* 리버스 프록시 타깃 (relative-path 미포함 베이스)
	SoRPath         string // 감사 SoR(JSONL) 경로
	SessionsPath    string // 로그인 세션 영속 파일 경로 (재시작/재배포 시 세션 유지)
	ZotTemplate     string // zot 설정 템플릿(설정 시 접근 정책 관리 모드 — access.go)
	ZotManagedDir   string // 렌더된 zot 설정·htpasswd 를 쓰는 디렉터리(zot 과 공유 볼륨)
	AccessStore     string // 제품 권한·자동화 계정 저장 파일
	ZotOIDCSecret   string // zot OIDC 클라이언트 시크릿(oidc-credentials.json 렌더용)
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func loadConfig() Config {
	return Config{
		Addr:            env("ADDR", ":9100"),
		KCPublic:        env("KC_PUBLIC", "http://localhost:8085"),
		KCInternal:      env("KC_INTERNAL", "http://localhost:8085"),
		Realm:           env("REALM", "trustlink"),
		ClientID:        env("CLIENT_ID", "trustlink-admin"),
		ClientSecret:    env("CLIENT_SECRET", ""),
		RedirectURI:     env("REDIRECT_URI", "http://localhost:9100/admin/callback"),
		MetricsURL:      env("ZOT_METRICS_URL", "http://localhost:28080/metrics"),
		MetricsUser:     env("ZOT_METRICS_USER", "ci"),
		MetricsPass:     env("ZOT_METRICS_PASS", ""),
		DataDir:         env("ZOT_DATA", "/tmp/zot"),
		LogFile:         env("LOG_FILE", "/tmp/trustlink-zot.log"),
		ZotAPIURL:       env("ZOT_API_URL", "http://localhost:28080"),
		ZotAdminUser:    env("ZOT_ADMIN_USER", "svc-bff"),
		ZotAdminPass:    env("ZOT_ADMIN_PASS", ""),
		ConfigFile:      env("CONFIG_FILE", "/tmp/zot-run.json"),
		DTBaseURL:       env("DT_BASE_URL", ""),
		DTApiKey:        env("DT_API_KEY", ""),
		DTAdminPassword: env("DT_ADMIN_PASSWORD", ""),
		DTKeyFile:       env("DT_KEY_FILE", "/var/lib/trustlink/dt-api-key"),
		UIDir:           env("UI_DIR", ""),
		KCProxyTarget:   env("KC_PROXY_TARGET", env("KC_INTERNAL", "http://localhost:8085")),
		SoRPath:         env("SOR_PATH", "/var/lib/trustlink/sor.jsonl"),
		SessionsPath:    env("SESSIONS_PATH", "/var/lib/trustlink/sessions.json"),
		ZotTemplate:     env("ZOT_CONFIG_TEMPLATE", ""),
		ZotManagedDir:   env("ZOT_MANAGED_DIR", "/etc/zot-managed"),
		AccessStore:     env("ACCESS_STORE", "/var/lib/trustlink/access-policy.json"),
		ZotOIDCSecret:   env("ZOT_OIDC_CLIENT_SECRET", ""),
	}
}

// ---------- session ----------

type Session struct {
	Username string
	Groups   []string
	Expiry   time.Time
}

// SessionStore — 로그인 세션 저장소. 인메모리 map 을 워킹셋으로 두되, 변경 시마다
// 파일(볼륨)로 영속화하여 BFF 재시작/재배포에도 세션을 유지한다(SoR·recipients 와 동일 패턴).
// 외부 의존성 없이 stdlib 만 사용. (다중 인스턴스 HA 가 필요해지면 동일 put/get/del
// 인터페이스를 Redis 백엔드로 교체 가능 — S2)
type SessionStore struct {
	mu   sync.Mutex
	m    map[string]Session
	path string // 영속 파일 경로(빈 문자열이면 영속화 비활성=인메모리)
}

// newStore: 영속 파일이 있으면 로드(만료분 제거)하고, 없으면 빈 스토어로 시작한다.
func newStore(path string) *SessionStore {
	s := &SessionStore{m: map[string]Session{}, path: path}
	if path == "" {
		return s
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("세션 파일 로드 실패(%s): %v — 빈 세션으로 시작", path, err)
		}
		return s
	}
	var loaded map[string]Session
	if err := json.Unmarshal(b, &loaded); err != nil {
		log.Printf("세션 파일 파싱 실패(%s): %v — 빈 세션으로 시작", path, err)
		return s
	}
	now := time.Now()
	for id, sess := range loaded {
		if now.After(sess.Expiry) {
			continue // 만료분은 로드하지 않음
		}
		s.m[id] = sess
	}
	log.Printf("세션 %d건 복원(%s)", len(s.m), path)
	return s
}

// persist: 현재 map 을 파일에 원자적으로 기록(temp 작성 후 rename). 호출자가 mu 보유 가정.
func (s *SessionStore) persist() {
	if s.path == "" {
		return
	}
	b, err := json.Marshal(s.m)
	if err != nil {
		log.Printf("세션 직렬화 실패: %v", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		log.Printf("세션 디렉토리 생성 실패: %v", err)
		return
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		log.Printf("세션 임시파일 쓰기 실패: %v", err)
		return
	}
	if err := os.Rename(tmp, s.path); err != nil {
		log.Printf("세션 파일 교체 실패: %v", err)
	}
}

func (s *SessionStore) put(sess Session) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	id := base64.RawURLEncoding.EncodeToString(b)
	s.mu.Lock()
	s.m[id] = sess
	s.persist()
	s.mu.Unlock()
	return id
}

func (s *SessionStore) get(id string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[id]
	if ok && time.Now().After(sess.Expiry) {
		delete(s.m, id)
		s.persist()
		return Session{}, false
	}
	return sess, ok
}

func (s *SessionStore) del(id string) {
	s.mu.Lock()
	delete(s.m, id)
	s.persist()
	s.mu.Unlock()
}

// ---------- server ----------

type Server struct {
	cfg   Config
	store *SessionStore
	http  *http.Client
	// service-account admin token cache
	saMu   sync.Mutex
	saTok  string
	saExp  time.Time
	states map[string]stateData // oauth state 임시 저장 (만료 + 로그인 후 복귀 경로)
	stMu   sync.Mutex
	sor    *SoR           // 감사 기록(SBOM 생성 등)
	mail   *Mailer        // 통보 메일(SMTP)
	notify *notifier      // 보안 이슈 통보(notify.go)
	oidc   *oidcVerifier  // OIDC 액세스 토큰 서명/클레임 검증기
	dtKey  atomic.Value   // DT API 키(string) — initDTKey 가 설정
	access *accessManager // 제품 권한·자동화 계정(관리 모드일 때만)
}

// stateData: OIDC state 에 만료시각과 로그인 후 복귀 경로를 함께 보관.
type stateData struct {
	exp time.Time
	ret string
}

const cookieName = "tl_admin_sid"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "mirror" { // 취약점 DB 미러(별도 컨테이너) — mirror.go
		runMirror()
		return
	}
	cfg := loadConfig()
	if cfg.ClientSecret == "" {
		log.Fatal("CLIENT_SECRET (trustlink-admin) 가 필요합니다")
	}
	s := &Server{
		cfg:    cfg,
		store:  newStore(cfg.SessionsPath),
		http:   &http.Client{Timeout: 15 * time.Second},
		states: map[string]stateData{},
	}
	s.sor = newSoR(cfg.SoRPath)
	s.mail = newMailer()
	s.oidc = newOIDCVerifier(cfg, s.http)
	s.initDTKey()
	s.initNotify()
	if err := s.initAccess(); err != nil {
		log.Fatalf("접근 정책 초기화 실패: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/login", s.handleLogin)
	mux.HandleFunc("GET /admin/callback", s.handleCallback)
	mux.HandleFunc("GET /admin/logout", s.handleLogout)
	// /admin·/admin/* 은 신규 React UI(SPA)가 프론트도어(serveUI)로 서빙한다. (구 vanilla 콘솔 제거)
	mux.HandleFunc("GET /api/me", s.guardSession(s.apiMe)) // 로그인 사용자 본인 정보(그룹) — UI 메뉴 게이팅용
	mux.HandleFunc("GET /api/users", s.guard(s.apiUsers))
	mux.HandleFunc("GET /api/groups", s.guard(s.apiGroups))
	mux.HandleFunc("POST /api/users", s.guard(s.apiCreateUser))
	mux.HandleFunc("PUT /api/users/{id}", s.guard(s.apiUpdateUser)) // 역할·고객사·활성 상태
	mux.HandleFunc("DELETE /api/users/{id}", s.guard(s.apiDeleteUser))
	mux.HandleFunc("GET /api/orgs", s.guard(s.apiOrgs)) // 고객사 = Keycloak 그룹 org-*
	mux.HandleFunc("POST /api/orgs", s.guard(s.apiOrgCreate))
	mux.HandleFunc("DELETE /api/orgs/{name}", s.guard(s.apiOrgDelete))
	mux.HandleFunc("PUT /api/orgs/{name}/contacts", s.guard(s.apiOrgContacts)) // 고객사 보안 담당 통보 주소
	// 고객 등록부·고객 통지
	mux.HandleFunc("GET /api/customers", s.guard(s.apiCustomers))
	mux.HandleFunc("POST /api/customers", s.guard(s.apiCustomerSave))
	mux.HandleFunc("PUT /api/customers/{id}", s.guard(s.apiCustomerSave))
	mux.HandleFunc("DELETE /api/customers/{id}", s.guard(s.apiCustomerDelete))
	mux.HandleFunc("PUT /api/customers/{id}/status", s.guard(s.apiCustomerStatus)) // 사용/중지(폐업·관계 종료·계약 해지)
	mux.HandleFunc("PUT /api/customers/{id}/logo", s.guard(s.apiCustomerLogoPut))  // 회사 로고(서버 데이터에만)
	mux.HandleFunc("DELETE /api/customers/{id}/logo", s.guard(s.apiCustomerLogoDelete))
	mux.HandleFunc("GET /api/customer-logo/{file}", s.guardSession(s.apiCustomerLogoGet))
	mux.HandleFunc("POST /api/customers/{id}/restore", s.guard(s.apiCustomerUndelete)) // 휴지통에서 되살리기
	mux.HandleFunc("DELETE /api/customers/{id}/purge", s.guard(s.apiCustomerPurge))    // 휴지통에서 완전 삭제(이름 확인)
	mux.HandleFunc("GET /api/customers-backup", s.guard(s.apiCustomersBackup))         // 고객 정보 백업(JSON)
	mux.HandleFunc("POST /api/customers-restore", s.guard(s.apiCustomersRestore))      // 백업 복원(복원 전 사본 저장)
	mux.HandleFunc("PUT /api/customer-products", s.guard(s.apiCustomerProductPut))     // 제품 버전 정책(출시·EOS·권장 업그레이드)
	mux.HandleFunc("PUT /api/customer-settings", s.guard(s.apiCustomerSettings))
	mux.HandleFunc("GET /api/customer-expiring", s.guard(s.apiCustomerExpiring)) // 만료·EOS 예정
	mux.HandleFunc("POST /api/customer-expiring/check", s.guard(s.apiCustomerExpiryCheck))
	mux.HandleFunc("GET /api/custnotify/vulns", s.guard(s.apiCustNotifyVulns)) // 고객 통지 ① 취약점 후보
	mux.HandleFunc("GET /api/custnotify", s.guard(s.apiCustNotifyList))
	mux.HandleFunc("POST /api/custnotify", s.guard(s.apiCustNotifyCreate)) // ②③ 영향 고객 + 규칙 패치 버전
	mux.HandleFunc("GET /api/custnotify/{id}", s.guard(s.apiCustNotifyGet))
	mux.HandleFunc("DELETE /api/custnotify/{id}", s.guard(s.apiCustNotifyDelete))
	mux.HandleFunc("POST /api/custnotify/{id}/ai", s.guard(s.apiCustNotifyAI))                   // ③ AI 설명
	mux.HandleFunc("POST /api/custnotify/{id}/send", s.guard(s.apiCustNotifySend))               // ⑤ 발송
	mux.HandleFunc("GET /api/my/products", s.guardSession(s.apiMyProducts))                      // 고객 전용: 내 고객사 제품만
	go s.aiSysLoop()                                                                             // 서버 CPU·메모리 표본(30초, AI 탭)
	go s.custExpiryLoop()                                                                        // 만료·EOS 알림(하루 1회)
	go func() { time.Sleep(20 * time.Second); s.dashboardCached(false); s.statsCached(false) }() // 대시보드·통계 미리 계산(첫 화면 대기 없앰)
	mux.HandleFunc("GET /api/access/products", s.guard(s.apiAccessProducts))                     // 제품별 읽기/쓰기 대상
	mux.HandleFunc("PUT /api/access/products", s.guard(s.apiAccessProductPut))
	mux.HandleFunc("DELETE /api/access/products", s.guard(s.apiAccessProductDelete))
	mux.HandleFunc("GET /api/access/principals", s.guard(s.apiAccessPrincipals))
	mux.HandleFunc("GET /api/robots", s.guard(s.apiRobots)) // 자동화 계정(ci-*, robot-*)
	mux.HandleFunc("POST /api/robots", s.guard(s.apiRobotCreate))
	mux.HandleFunc("POST /api/robots/{name}/reissue", s.guard(s.apiRobotReissue))
	mux.HandleFunc("DELETE /api/robots/{name}", s.guard(s.apiRobotDelete))
	mux.HandleFunc("POST /api/users/{id}/reset-password", s.guard(s.apiResetPassword)) // 임시 비밀번호 재발급(1회 표시)
	mux.HandleFunc("GET /api/credentials/ci", s.guard(s.apiCICredential))              // 공용 업로드(ci) 계정 전달
	mux.HandleFunc("GET /api/metrics", s.guard(s.apiMetrics))
	mux.HandleFunc("GET /api/logs", s.guard(s.apiLogs))
	mux.HandleFunc("GET /api/health", s.guard(s.apiHealth))
	mux.HandleFunc("GET /api/mail", s.guard(s.apiMailStatus))                              // 통보 메일 설정 상태
	mux.HandleFunc("POST /api/mail/test", s.guard(s.apiMailTest))                          // 시험 메일 발송
	mux.HandleFunc("GET /api/mail/options", s.guard(s.apiMailOptions))                     // 메일에 넣을 항목·첨부 보고서·받을 사람 후보
	mux.HandleFunc("POST /api/mail/preview", s.guard(s.apiMailPreview))                    // 본문 미리보기
	mux.HandleFunc("POST /api/mail/suggest", s.guard(s.apiMailSuggest))                    // 받는 사람·항목·첨부 추천(규칙 + AI)
	mux.HandleFunc("GET /api/regs-report/{id}/pdf", s.guard(s.apiRegReportPDF))            // 규제 보고서 PDF(Gotenberg)
	mux.HandleFunc("GET /api/notifications", s.guardSession(s.apiNotifications))           // 내 통보
	mux.HandleFunc("POST /api/notifications/read", s.guardSession(s.apiNotificationsRead)) // 읽음 표시
	mux.HandleFunc("GET /api/notify/log", s.guard(s.apiNotifyLog))                         // 전체 통보 기록
	mux.HandleFunc("POST /api/notify/sync", s.guard(s.apiNotifySync))                      // 지금 동기화
	mux.HandleFunc("GET /api/vulnsources", s.guard(s.apiVulnSources))                      // 취약점 DB(OSV·GitHub) 설정
	mux.HandleFunc("PUT /api/vulnsources", s.guard(s.apiVulnSourcesPut))
	mux.HandleFunc("POST /api/vulnsources/reanalyze", s.guard(s.apiVulnReanalyze))
	mux.HandleFunc("GET /api/mirror", s.guard(s.apiMirror)) // 취약점 DB 미러 상태·정책
	mux.HandleFunc("PUT /api/mirror/policy", s.guard(s.apiMirrorPolicy))
	mux.HandleFunc("POST /api/mirror/sync/{id}", s.guard(s.apiMirrorSync))
	mux.HandleFunc("PUT /api/mirror/dt", s.guard(s.apiMirrorDT)) // DT 가 미러를 보게 전환/되돌리기
	mux.HandleFunc("GET /api/repos", s.guardSession(s.apiRepos)) // 제품 열람: 로그인 사용자(그룹 read 는 zot RBAC 이 최종 판정)
	mux.HandleFunc("POST /api/registry/delete-tag", s.guard(s.apiDeleteTag))
	mux.HandleFunc("GET /api/retention", s.guard(s.apiRetention))
	mux.HandleFunc("GET /api/acl", s.guard(s.apiACL))
	mux.HandleFunc("GET /api/artifact/blob", s.guardSession(s.apiArtifactBlob))     // 웹 다운로드: 로그인 사용자(본인 자격으로 zot RBAC)
	mux.HandleFunc("GET /api/artifact/bundle", s.guardSession(s.apiArtifactBundle)) // 웹 다운로드: 로그인 사용자(본인 자격으로 zot RBAC)
	mux.HandleFunc("GET /api/storage", s.guard(s.apiStorageGet))
	mux.HandleFunc("POST /api/storage/preview", s.guard(s.apiStoragePreview))
	mux.HandleFunc("GET /api/stats", s.guardSession(s.apiStats))  // 대시보드 통계: 로그인 사용자
	mux.HandleFunc("GET /api/dashboard", s.guard(s.apiDashboard)) // 관리 대시보드 집계(할 일·보안·품질·고객·운영)
	// 제품 페이지용 경량 세션(그룹 무관, 로그인만)
	mux.HandleFunc("GET /api/session", s.guardSession(s.apiSession))
	// Dependency-Track 헤드리스 연동 (취약점 분석 → VEX). security/developers/admins 편집 가능.
	vexEdit := s.guardGroups(vexEditors...)
	mux.HandleFunc("GET /api/vex/enabled", s.guardSession(s.apiVexEnabled))
	mux.HandleFunc("POST /api/vex/upload", vexEdit(s.apiVexUpload))
	mux.HandleFunc("GET /api/vex/status", vexEdit(s.apiVexStatus))
	mux.HandleFunc("GET /api/vex/findings", vexEdit(s.apiVexFindings))
	mux.HandleFunc("PUT /api/vex/analysis", vexEdit(s.apiVexAnalysis))
	mux.HandleFunc("GET /api/vex/export", vexEdit(s.apiVexExport))
	mux.HandleFunc("POST /api/vex/publish", vexEdit(s.apiVexPublish))     // DT VEX → OCI 새 referrer 발행
	mux.HandleFunc("POST /api/sbom/generate", vexEdit(s.apiSBOMGenerate)) // syft SBOM 생성·부착(제품 쓰기 권한, self 는 admins)
	mux.HandleFunc("GET /api/vex/queue", vexEdit(s.apiVexQueue))          // VEX 판단 대기열(전 제품)
	mux.HandleFunc("GET /api/vex/kev", vexEdit(s.apiVexKEV))              // KEV 등재 여부(미러 사본) — 우선순위 정렬용
	mux.HandleFunc("POST /api/ai/vex-draft", vexEdit(s.apiAIVexDraft))    // AI VEX 판정·대응 초안(저장은 사람이)
	mux.HandleFunc("POST /api/ai/vex-batch", vexEdit(s.apiAIVexBatch))    // 미분석 항목 일괄 초안(비동기)·취소
	mux.HandleFunc("GET /api/ai/vex-batch", vexEdit(s.apiAIVexBatchGet))  // 일괄 초안 진행·결과
	mux.HandleFunc("GET /api/ai/status", s.guardSession(s.apiAIStatus))
	mux.HandleFunc("GET /api/ai/config", s.guard(s.apiAIConfigGet)) // AI 연결 설정(로컬·외부 LLM) — 키는 끝 4자리만
	mux.HandleFunc("PUT /api/ai/config", s.guard(s.apiAIConfigPut))
	mux.HandleFunc("POST /api/ai/test", s.guard(s.apiAITest))
	mux.HandleFunc("GET /api/ai-perf", s.guard(s.apiAIPerf))             // AI 성능·자원·외부 LLM 판단(대시보드 AI 탭)
	mux.HandleFunc("POST /api/ai-perf/bench", s.guard(s.apiAIPerfBench)) // 고정 문장으로 속도 측정
	// 규제 요구사항 카탈로그·탐색·보고서(관리자)
	mux.HandleFunc("GET /api/regs", s.guard(s.apiRegs))
	mux.HandleFunc("PUT /api/regs/{id}", s.guard(s.apiRegPut))
	mux.HandleFunc("DELETE /api/regs/{id}", s.guard(s.apiRegDelete))
	mux.HandleFunc("POST /api/regs/{id}/verify", s.guard(s.apiRegVerify))
	mux.HandleFunc("POST /api/regs-builtin/apply", s.guard(s.apiRegBuiltinApply))
	mux.HandleFunc("GET /api/regs-discover", s.guard(s.apiRegDiscoverGet))
	mux.HandleFunc("POST /api/regs-discover", s.guard(s.apiRegDiscover))
	mux.HandleFunc("PUT /api/regs-discover/config", s.guard(s.apiRegDiscoverCfg))
	mux.HandleFunc("POST /api/regs-candidates/{id}", s.guard(s.apiRegCandidate))
	mux.HandleFunc("POST /api/regs-report", s.guard(s.apiRegReport))
	mux.HandleFunc("GET /api/regs-report", s.guard(s.apiRegReports))
	mux.HandleFunc("GET /api/regs-report/{id}", s.guard(s.apiRegReportGet))
	// 국내 법규 분석
	mux.HandleFunc("POST /api/regs/{id}/law-fetch", s.guard(s.apiRegLawFetch))
	mux.HandleFunc("POST /api/regs/{id}/law-analyze", s.guard(s.apiRegLawAnalyze))
	mux.HandleFunc("POST /api/regs/{id}/law-review", s.guard(s.apiRegLawReview))
	// 규제 대응 검증(체크리스트 기준 리포트) — 관리자
	mux.HandleFunc("GET /api/compliance", s.guard(s.apiComplianceInfo))
	mux.HandleFunc("PUT /api/compliance/checklist", s.guard(s.apiComplianceUpload))
	mux.HandleFunc("POST /api/compliance/report", s.guard(s.apiComplianceRun))
	mux.HandleFunc("GET /api/compliance/report/{id}", s.guard(s.apiComplianceGet))
	// 공개 저장소(상류) 분석
	mux.HandleFunc("GET /api/upstream/config", s.guard(s.apiUpstreamConfigGet))
	mux.HandleFunc("PUT /api/upstream/config", s.guard(s.apiUpstreamConfigPut))
	mux.HandleFunc("POST /api/upstream/run", s.guard(s.apiUpstreamRun))
	mux.HandleFunc("POST /api/upstream/repo", s.guard(s.apiUpstreamRepo))
	mux.HandleFunc("GET /api/upstream/reports", s.guard(s.apiUpstreamList))
	mux.HandleFunc("GET /api/upstream/report/{id}", s.guard(s.apiUpstreamGet))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	// 단일 프론트도어: 신규 UI 서빙 + /v2·/zot·/auth 리버스 프록시 (UI_DIR 설정 시 활성)
	if s.cfg.UIDir != "" {
		s.registerFrontDoor(mux)
	}

	log.Printf("trustlink-admin BFF listening on %s (realm=%s, kc=%s)", cfg.Addr, cfg.Realm, cfg.KCPublic)
	log.Fatal(http.ListenAndServe(cfg.Addr, mux))
}

// ---------- auth: OIDC code flow ----------

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	state := base64.RawURLEncoding.EncodeToString(b)
	ret := r.URL.Query().Get("return") // 로그인 후 복귀 경로(제품 페이지 등). 상대경로만 허용.
	if ret == "" || !strings.HasPrefix(ret, "/") || strings.HasPrefix(ret, "//") {
		ret = "/admin"
	}
	s.stMu.Lock()
	s.states[state] = stateData{exp: time.Now().Add(10 * time.Minute), ret: ret}
	s.stMu.Unlock()

	q := url.Values{}
	q.Set("client_id", s.cfg.ClientID)
	q.Set("redirect_uri", s.cfg.RedirectURI)
	q.Set("response_type", "code")
	q.Set("scope", "openid")
	q.Set("state", state)
	authURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/auth?%s", s.cfg.KCPublic, s.cfg.Realm, q.Encode())
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	s.stMu.Lock()
	st, ok := s.states[state]
	delete(s.states, state)
	s.stMu.Unlock()
	if !ok || time.Now().After(st.exp) {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", s.cfg.RedirectURI)
	form.Set("client_id", s.cfg.ClientID)
	form.Set("client_secret", s.cfg.ClientSecret)

	tokURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", s.cfg.KCInternal, s.cfg.Realm)
	resp, err := s.http.PostForm(tokURL, form)
	if err != nil {
		http.Error(w, "token exchange failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error_description"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tok)
	if tok.AccessToken == "" {
		http.Error(w, "no token: "+tok.Error, http.StatusUnauthorized)
		return
	}

	username, groups, err := s.oidc.verify(tok.AccessToken)
	if err != nil {
		// fail-closed: 서명/클레임 검증 실패 토큰은 세션을 발급하지 않는다.
		log.Printf("OIDC 토큰 검증 실패: %v", err)
		http.Error(w, "token verification failed", http.StatusUnauthorized)
		return
	}
	// 인증된 사용자는 모두 세션 발급(그룹 보존). 실제 권한은 엔드포인트별 가드가 그룹으로 판정한다.
	// (관리 콘솔 API 는 admins 전용 guard, VEX 편집은 guardGroups 로 별도 게이트)
	sid := s.store.put(Session{Username: username, Groups: groups, Expiry: time.Now().Add(8 * time.Hour)})
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: sid, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, st.ret, http.StatusFound)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.store.del(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1})
	// Keycloak end-session: client_id + post_logout_redirect_uri 를 줘야 로그아웃 후 앱으로 복귀한다.
	// (미지정 시 Keycloak 자체 "로그아웃됨" 페이지에 머물러 끊긴 것처럼 보임)
	appHome := strings.TrimSuffix(s.cfg.RedirectURI, "/admin/callback") + "/"
	q := url.Values{}
	q.Set("client_id", s.cfg.ClientID)
	q.Set("post_logout_redirect_uri", appHome)
	logoutURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/logout?%s", s.cfg.KCPublic, s.cfg.Realm, q.Encode())
	http.Redirect(w, r, logoutURL, http.StatusFound)
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

// guard: 세션 + admins 그룹 필수 (api/me 제외 동일 처리)
func (s *Server) guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
			return
		}
		sess, ok := s.store.get(c.Value)
		if !ok {
			// 쿠키는 있으나 세션이 없음(만료/BFF 재시작으로 인메모리 세션 소실) → 401 로 재로그인 유도.
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "session expired"})
			return
		}
		if !contains(sess.Groups, "admins") {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "admins only"})
			return
		}
		r = r.WithContext(r.Context())
		w.Header().Set("X-User", sess.Username)
		h(w, r)
	}
}

// guardSession: 유효한 세션이면 통과(그룹 무관). 미인증 시 401.
func (s *Server) guardSession(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.sessionOf(r); !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
			return
		}
		h(w, r)
	}
}

// guardGroups: 세션 + 허용 그룹 중 하나 보유 시 통과. 미인증 401, 권한부족 403.
func (s *Server) guardGroups(allowed ...string) func(http.HandlerFunc) http.HandlerFunc {
	return func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			sess, ok := s.sessionOf(r)
			if !ok {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
				return
			}
			for _, g := range allowed {
				if contains(sess.Groups, g) {
					w.Header().Set("X-User", sess.Username)
					h(w, r)
					return
				}
			}
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "권한 없음: " + strings.Join(allowed, "/") + " 그룹 필요"})
		}
	}
}

// sessionOf: 쿠키에서 현재 세션을 조회.
func (s *Server) sessionOf(r *http.Request) (Session, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return Session{}, false
	}
	return s.store.get(c.Value)
}

// vexEditors: VEX 분류/발행 권한 그룹.
var vexEditors = []string{"security", "developers", "admins"}

// GET /api/session — 제품 페이지용 경량 세션 정보(그룹 무관, 로그인만 필요).
func (s *Server) apiSession(w http.ResponseWriter, r *http.Request) {
	sess, _ := s.sessionOf(r)
	canEdit := false
	for _, g := range vexEditors {
		if contains(sess.Groups, g) {
			canEdit = true
			break
		}
	}
	writeJSON(w, 200, map[string]any{"username": sess.Username, "groups": sess.Groups, "canEditVex": canEdit})
}

// ---------- Keycloak Admin API (service-account) ----------

func (s *Server) adminToken() (string, error) {
	s.saMu.Lock()
	defer s.saMu.Unlock()
	if s.saTok != "" && time.Now().Before(s.saExp) {
		return s.saTok, nil
	}
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", s.cfg.ClientID)
	form.Set("client_secret", s.cfg.ClientSecret)
	tokURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", s.cfg.KCInternal, s.cfg.Realm)
	resp, err := s.http.PostForm(tokURL, form)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var t struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return "", err
	}
	if t.AccessToken == "" {
		return "", fmt.Errorf("no service-account token")
	}
	s.saTok = t.AccessToken
	s.saExp = time.Now().Add(time.Duration(t.ExpiresIn-30) * time.Second)
	return s.saTok, nil
}

func (s *Server) kcAdmin(method, path string, body io.Reader) (*http.Response, error) {
	tok, err := s.adminToken()
	if err != nil {
		return nil, err
	}
	u := fmt.Sprintf("%s/admin/realms/%s%s", s.cfg.KCInternal, s.cfg.Realm, path)
	req, _ := http.NewRequest(method, u, body)
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return s.http.Do(req)
}

type kcGroup struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	Attributes map[string][]string `json:"attributes,omitempty"`
}
type kcUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Enabled  bool   `json:"enabled"`
}

func (s *Server) listGroups() ([]kcGroup, error) {
	resp, err := s.kcAdmin("GET", "/groups?max=200&briefRepresentation=false", nil) // 속성(고객사 통보 주소) 포함
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var gs []kcGroup
	err = json.NewDecoder(resp.Body).Decode(&gs)
	return gs, err
}

// ---------- API handlers ----------

func (s *Server) apiMe(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie(cookieName)
	sess, _ := s.store.get(c.Value)
	writeJSON(w, 200, map[string]any{"username": sess.Username, "groups": sess.Groups})
}

func (s *Server) apiGroups(w http.ResponseWriter, r *http.Request) {
	gs, err := s.listGroups()
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	names := []string{}
	for _, g := range gs {
		names = append(names, g.Name)
	}
	writeJSON(w, 200, names)
}

func (s *Server) apiUsers(w http.ResponseWriter, r *http.Request) {
	resp, err := s.kcAdmin("GET", "/users?max=200", nil)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	var users []kcUser
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	out := []map[string]any{}
	for _, u := range users {
		groups := s.userGroupNames(u.ID)
		out = append(out, map[string]any{
			"id": u.ID, "username": u.Username, "email": u.Email, "enabled": u.Enabled, "groups": groups,
		})
	}
	writeJSON(w, 200, out)
}

func (s *Server) userGroupNames(uid string) []string {
	resp, err := s.kcAdmin("GET", "/users/"+uid+"/groups", nil)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var gs []kcGroup
	_ = json.NewDecoder(resp.Body).Decode(&gs)
	names := []string{}
	for _, g := range gs {
		names = append(names, g.Name)
	}
	return names
}

// userGroupsFor: 역할 1개 + 고객사 여러 개 → Keycloak 그룹 이름 목록.
func userGroupsFor(role string, orgs []string) ([]string, error) {
	if !contains(roleGroups, role) {
		return nil, fmt.Errorf("역할은 %s 중 하나", strings.Join(roleGroups, "/"))
	}
	gs := []string{role}
	for _, o := range orgs {
		o = strings.TrimPrefix(o, orgPrefix)
		if !reOrgName.MatchString(o) {
			return nil, fmt.Errorf("고객사 ID 형식 오류: %s", o)
		}
		gs = append(gs, orgPrefix+o)
	}
	return gs, nil
}

func (s *Server) apiCreateUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string   `json:"username"`
		Email    string   `json:"email"`
		Role     string   `json:"role"`
		Orgs     []string `json:"orgs"`
		Password string   `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Username == "" {
		writeJSON(w, 400, map[string]string{"error": "username 필수"})
		return
	}
	if reservedUserPrefix.MatchString(in.Username) {
		writeJSON(w, 400, map[string]string{"error": "ci-·robot-·svc- 로 시작하는 이름은 자동화 계정 전용입니다"})
		return
	}
	groups, err := userGroupsFor(in.Role, in.Orgs)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if msg := checkUserEmail(in.Role, in.Email); msg != "" {
		writeJSON(w, 400, map[string]string{"error": msg})
		return
	}
	if in.Password == "" { // 미입력 시 무작위 임시 비밀번호 자동 생성(응답으로 1회 전달)
		pw, err := genTempPassword()
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		in.Password = pw
	}
	if in.Email == "" {
		in.Email = in.Username + "@innotium.local"
	}
	body, _ := json.Marshal(map[string]any{
		"username": in.Username, "email": in.Email, "enabled": true, "emailVerified": true,
		"firstName": in.Username, "lastName": "user",
	})
	resp, err := s.kcAdmin("POST", "/users", strings.NewReader(string(body)))
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	resp.Body.Close()
	if resp.StatusCode != 201 {
		writeJSON(w, resp.StatusCode, map[string]string{"error": "사용자 생성 실패(이미 존재?)"})
		return
	}
	uid := s.findUserID(in.Username)
	if uid == "" {
		writeJSON(w, 502, map[string]string{"error": "생성 후 조회 실패"})
		return
	}
	// 임시 비밀번호
	if err := s.setTempPassword(uid, in.Password); err != nil {
		writeJSON(w, 502, map[string]string{"error": "임시 비밀번호 설정 실패: " + err.Error()})
		return
	}
	if err := s.setUserGroups(uid, groups); err != nil {
		writeJSON(w, 502, map[string]string{"error": "그룹 배정 실패: " + err.Error()})
		return
	}
	s.refreshAccess()
	_ = s.sor.append(SoREvent{Actor: w.Header().Get("X-User"), Action: "user-create", Subject: in.Username, Detail: map[string]any{"groups": groups}})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 201, map[string]any{"id": uid, "username": in.Username, "group": in.Role, "groups": groups, "password": in.Password})
}

// checkUserEmail: 외부 사용자는 보안 통보를 받아야 하므로 이메일 필수. 형식도 확인. 문제 없으면 "".
func checkUserEmail(role, email string) string {
	email = strings.TrimSpace(email)
	if email == "" {
		if role == "users" {
			return "외부 사용자는 보안 통보를 받을 이메일이 필요합니다"
		}
		return ""
	}
	if a, err := mail.ParseAddress(email); err != nil || a.Address != email {
		return "이메일 형식 오류: " + email
	}
	return ""
}

// PUT /api/users/{id} {role, orgs[], enabled, email, username} — 역할·고객사·활성 상태·이메일 변경
func (s *Server) apiUpdateUser(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("id")
	var in struct {
		Username string   `json:"username"` // 감사 기록용
		Role     string   `json:"role"`
		Orgs     []string `json:"orgs"`
		Enabled  *bool    `json:"enabled"`
		Email    *string  `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "요청 형식 오류"})
		return
	}
	detail := map[string]any{}
	if in.Email != nil {
		email := strings.TrimSpace(*in.Email)
		if msg := checkUserEmail(in.Role, email); msg != "" {
			writeJSON(w, 400, map[string]string{"error": msg})
			return
		}
		body, _ := json.Marshal(map[string]any{"email": email})
		resp, err := s.kcAdmin("PUT", "/users/"+uid, strings.NewReader(string(body)))
		if err != nil {
			writeJSON(w, 502, map[string]string{"error": err.Error()})
			return
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusConflict {
			writeJSON(w, 409, map[string]string{"error": "다른 사용자가 이미 쓰는 이메일입니다"})
			return
		}
		if resp.StatusCode != http.StatusNoContent {
			writeJSON(w, 502, map[string]string{"error": fmt.Sprintf("이메일 변경 실패(%d)", resp.StatusCode)})
			return
		}
		detail["email"] = email
	}
	if in.Role != "" {
		groups, err := userGroupsFor(in.Role, in.Orgs)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if err := s.setUserGroups(uid, groups); err != nil {
			writeJSON(w, 502, map[string]string{"error": err.Error()})
			return
		}
		detail["groups"] = groups
	}
	if in.Enabled != nil {
		body, _ := json.Marshal(map[string]any{"enabled": *in.Enabled})
		resp, err := s.kcAdmin("PUT", "/users/"+uid, strings.NewReader(string(body)))
		if err != nil {
			writeJSON(w, 502, map[string]string{"error": err.Error()})
			return
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			writeJSON(w, 502, map[string]string{"error": fmt.Sprintf("활성 상태 변경 실패(%d)", resp.StatusCode)})
			return
		}
		detail["enabled"] = *in.Enabled
	}
	s.refreshAccess() // 비활성화·고객사 해제 즉시 zot 판정에서 제외(API 키 포함)
	_ = s.sor.append(SoREvent{Actor: w.Header().Get("X-User"), Action: "user-update", Subject: in.Username, Detail: detail})
	writeJSON(w, 200, map[string]any{"id": uid, "updated": detail})
}

// DELETE /api/users/{id}?username= — 사람 계정 삭제(본인 삭제 불가)
func (s *Server) apiDeleteUser(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("id")
	name := r.URL.Query().Get("username")
	if sess, ok := s.sessionOf(r); ok && sess.Username == name {
		writeJSON(w, 400, map[string]string{"error": "자기 자신은 삭제할 수 없습니다"})
		return
	}
	resp, err := s.kcAdmin("DELETE", "/users/"+uid, nil)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		writeJSON(w, 502, map[string]string{"error": fmt.Sprintf("삭제 실패(%d)", resp.StatusCode)})
		return
	}
	s.refreshAccess()
	_ = s.sor.append(SoREvent{Actor: w.Header().Get("X-User"), Action: "user-delete", Subject: name})
	writeJSON(w, 200, map[string]string{"id": uid})
}

// setUserGroups: 사용자의 그룹을 정확히 desired 로 맞춘다(추가·제거).
func (s *Server) setUserGroups(uid string, desired []string) error {
	groups, err := s.listGroups()
	if err != nil {
		return err
	}
	byName := map[string]string{}
	for _, g := range groups {
		byName[g.Name] = g.ID
	}
	for _, d := range desired {
		if byName[d] == "" {
			return fmt.Errorf("그룹 %q 없음", d)
		}
	}
	cur := s.userGroupNames(uid)
	for _, c := range cur {
		if !contains(desired, c) && byName[c] != "" {
			resp, err := s.kcAdmin("DELETE", "/users/"+uid+"/groups/"+byName[c], nil)
			if err != nil {
				return err
			}
			resp.Body.Close()
		}
	}
	for _, d := range desired {
		if !contains(cur, d) {
			resp, err := s.kcAdmin("PUT", "/users/"+uid+"/groups/"+byName[d], nil)
			if err != nil {
				return err
			}
			resp.Body.Close()
		}
	}
	return nil
}

func (s *Server) findUserID(username string) string {
	resp, err := s.kcAdmin("GET", "/users?exact=true&username="+url.QueryEscape(username), nil)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var users []kcUser
	_ = json.NewDecoder(resp.Body).Decode(&users)
	if len(users) > 0 {
		return users[0].ID
	}
	return ""
}

// ---------- metrics / capacity ----------

func (s *Server) apiMetrics(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{}

	// 디스크 사용량 (statfs) — "저장 공간 부족"의 핵심 지표
	var fs syscall.Statfs_t
	if err := syscall.Statfs(s.cfg.DataDir, &fs); err == nil {
		bsize := uint64(fs.Bsize)
		total := fs.Blocks * bsize
		free := fs.Bavail * bsize
		used := total - free
		usedPct := 0.0
		if total > 0 {
			usedPct = float64(used) / float64(total) * 100
		}
		out["disk"] = map[string]any{
			"totalBytes": total, "freeBytes": free, "usedBytes": used,
			"usedPct": int(usedPct + 0.5), "path": s.cfg.DataDir,
		}
	}

	// repo별 사용량 (zot /metrics: zot_repo_storage_bytes)
	repos, totalBytes := s.scrapeRepoSizes()
	out["repos"] = repos
	out["repoCount"] = len(repos)
	out["repoTotalBytes"] = totalBytes

	writeJSON(w, 200, out)
}

func (s *Server) scrapeRepoSizes() ([]map[string]any, uint64) {
	repos := []map[string]any{}
	var total uint64
	req, _ := http.NewRequest("GET", s.cfg.MetricsURL, nil)
	if s.cfg.MetricsUser != "" {
		req.SetBasicAuth(s.cfg.MetricsUser, s.cfg.MetricsPass)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return repos, 0
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "zot_repo_storage_bytes{") {
			continue
		}
		// zot_repo_storage_bytes{repo="innotium/foo"} 12345
		repo := ""
		if i := strings.Index(line, `repo="`); i >= 0 {
			rest := line[i+6:]
			if j := strings.Index(rest, `"`); j >= 0 {
				repo = rest[:j]
			}
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || repo == "" {
			continue
		}
		val, _ := strconv.ParseFloat(fields[len(fields)-1], 64)
		repos = append(repos, map[string]any{"repo": repo, "bytes": uint64(val)})
		total += uint64(val)
	}
	return repos, total
}

// ---------- logs ----------
// apiLogs 는 logs.go

func atoiDefault(s string, def int) int {
	if x, err := strconv.Atoi(s); err == nil {
		return x
	}
	return def
}

// ---------- util ----------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
