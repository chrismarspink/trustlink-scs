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
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ---------- config ----------

type Config struct {
	Addr          string
	KCPublic      string // 브라우저용 (authorize/logout)
	KCInternal    string // 서버용 (token/admin api)
	Realm         string
	ClientID      string
	ClientSecret  string
	RedirectURI   string
	MetricsURL    string
	MetricsUser   string
	MetricsPass   string
	DataDir       string // statfs 대상
	LogFile       string
	ZotAPIURL     string // 카탈로그/태그/삭제
	ZotAdminUser  string // delete 권한 보유 htpasswd 계정(adminPolicy)
	ZotAdminPass  string
	ConfigFile    string // accessControl 매트릭스용 zot 설정 경로
	DTBaseURL     string // Dependency-Track API Server (헤드리스)
	DTApiKey      string // DT 서비스 API 키 (X-Api-Key)
	UIDir         string // 신규 trustlink-ui dist 경로 (단일 프론트도어 서빙)
	KCProxyTarget string // /auth/* 리버스 프록시 타깃 (relative-path 미포함 베이스)
	// 외부 CA·서명 어플라이언스(bigfoot) 위임. 설정 시 발급/서명/암호화를 bigfoot API 로 위임
	// (TrustLink 는 키·step-ca 미보유 → 모듈 독립). 미설정 시 아래 내장 step-ca 사용.
	BigfootURL string // http://bigfoot:9100 (예). 빈 값이면 내장 CA.
	// CA(step-ca) 연동 — 평면2. 미설정 시 CA 기능 비활성.
	StepCaURL         string // https://step-ca:9000 (평면1 독립 엔드포인트)
	StepCaRoot        string // 신뢰 앵커(CAfile) 경로
	StepCaIssuer      string // 발급(중간) CA 인증서 경로 (다운로드 제공용)
	StepCaProvisioner string // JWK provisioner 이름
	StepCaPassFile    string // provisioner 비밀번호 파일
	SoRPath           string // 감사 SoR(JSONL) 경로
	RecipientsPath    string // 수신자 인증서 레지스트리 경로
	SessionsPath      string // 로그인 세션 영속 파일 경로 (재시작/재배포 시 세션 유지)
	// CMS EnvelopedData 암호화 알고리즘 — FIPS 승인값을 기본으로 두되 배포 OE 에서 env 로 교체 가능.
	CMSContentCipher string // 콘텐츠 암호화 (기본 -aes-256-gcm, FIPS 승인 AEAD)
	CMSRsaPadding    string // RSA 키전송 패딩 (기본 oaep, FIPS 권장; pkcs1 은 레거시)
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func loadConfig() Config {
	return Config{
		Addr:              env("ADDR", ":9100"),
		KCPublic:          env("KC_PUBLIC", "http://localhost:8085"),
		KCInternal:        env("KC_INTERNAL", "http://localhost:8085"),
		Realm:             env("REALM", "trustlink"),
		ClientID:          env("CLIENT_ID", "trustlink-admin"),
		ClientSecret:      env("CLIENT_SECRET", ""),
		RedirectURI:       env("REDIRECT_URI", "http://localhost:9100/admin/callback"),
		MetricsURL:        env("ZOT_METRICS_URL", "http://localhost:28080/metrics"),
		MetricsUser:       env("ZOT_METRICS_USER", "ci"),
		MetricsPass:       env("ZOT_METRICS_PASS", ""),
		DataDir:           env("ZOT_DATA", "/tmp/zot"),
		LogFile:           env("LOG_FILE", "/tmp/trustlink-zot.log"),
		ZotAPIURL:         env("ZOT_API_URL", "http://localhost:28080"),
		ZotAdminUser:      env("ZOT_ADMIN_USER", "svc-bff"),
		ZotAdminPass:      env("ZOT_ADMIN_PASS", ""),
		ConfigFile:        env("CONFIG_FILE", "/tmp/zot-run.json"),
		DTBaseURL:         env("DT_BASE_URL", ""),
		DTApiKey:          env("DT_API_KEY", ""),
		UIDir:             env("UI_DIR", ""),
		KCProxyTarget:     env("KC_PROXY_TARGET", env("KC_INTERNAL", "http://localhost:8085")),
		StepCaURL:         env("STEPCA_URL", ""),
		BigfootURL:        env("BIGFOOT_URL", ""),
		StepCaRoot:        env("STEPCA_ROOT", "/etc/trustlink/step-root.crt"),
		StepCaIssuer:      env("STEPCA_ISSUER", "/etc/trustlink/step-issuer.crt"),
		StepCaProvisioner: env("STEPCA_PROVISIONER", "trustlink"),
		StepCaPassFile:    env("STEPCA_PROVISIONER_PASSWORD_FILE", "/etc/trustlink/ca-password"),
		SoRPath:           env("SOR_PATH", "/var/lib/trustlink/sor.jsonl"),
		RecipientsPath:    env("RECIPIENTS_PATH", "/var/lib/trustlink/recipients.json"),
		SessionsPath:      env("SESSIONS_PATH", "/var/lib/trustlink/sessions.json"),
		CMSContentCipher:  env("CMS_CONTENT_CIPHER", "-aes-256-gcm"),
		CMSRsaPadding:     env("CMS_RSA_PADDING", "oaep"),
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
	ca     CAAdapter       // 평면2 CA 어댑터 (nil = 미구성)
	sor    *SoR            // 감사 기록
	recips *RecipientStore // 수신자 인증서 레지스트리
	oidc   *oidcVerifier   // OIDC 액세스 토큰 서명/클레임 검증기
}

// stateData: OIDC state 에 만료시각과 로그인 후 복귀 경로를 함께 보관.
type stateData struct {
	exp time.Time
	ret string
}

const cookieName = "tl_admin_sid"

func main() {
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
	s.recips = newRecipientStore(cfg.RecipientsPath)
	s.oidc = newOIDCVerifier(cfg, s.http)
	if cfg.StepCaURL != "" {
		s.ca = NewStepCaAdapter(cfg, s.sor, s.http)
		log.Printf("CA 어댑터 활성: step-ca=%s provisioner=%s", cfg.StepCaURL, cfg.StepCaProvisioner)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/login", s.handleLogin)
	mux.HandleFunc("GET /admin/callback", s.handleCallback)
	mux.HandleFunc("GET /admin/logout", s.handleLogout)
	// /admin·/admin/* 은 신규 React UI(SPA)가 프론트도어(serveUI)로 서빙한다. (구 vanilla 콘솔 제거)
	mux.HandleFunc("GET /api/me", s.guard(s.apiMe))
	mux.HandleFunc("GET /api/users", s.guard(s.apiUsers))
	mux.HandleFunc("GET /api/groups", s.guard(s.apiGroups))
	mux.HandleFunc("POST /api/users", s.guard(s.apiCreateUser))
	mux.HandleFunc("POST /api/users/{id}/group", s.guard(s.apiSetUserGroup))
	mux.HandleFunc("GET /api/metrics", s.guard(s.apiMetrics))
	mux.HandleFunc("GET /api/logs", s.guard(s.apiLogs))
	mux.HandleFunc("GET /api/health", s.guard(s.apiHealth))
	mux.HandleFunc("GET /api/repos", s.guard(s.apiRepos))
	mux.HandleFunc("POST /api/registry/delete-tag", s.guard(s.apiDeleteTag))
	mux.HandleFunc("GET /api/retention", s.guard(s.apiRetention))
	mux.HandleFunc("GET /api/acl", s.guard(s.apiACL))
	mux.HandleFunc("GET /api/artifact/blob", s.apiArtifactBlob)     // 단일 파일 다운로드
	mux.HandleFunc("GET /api/artifact/bundle", s.apiArtifactBundle) // 전체 zip 다운로드
	mux.HandleFunc("GET /api/storage", s.guard(s.apiStorageGet))
	mux.HandleFunc("POST /api/storage/preview", s.guard(s.apiStoragePreview))
	mux.HandleFunc("GET /api/stats", s.guard(s.apiStats)) // 버전별 SBOM/VEX 통계(대시보드)
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
	mux.HandleFunc("POST /api/vex/publish", vexEdit(s.apiVexPublish)) // DT VEX → OCI 새 referrer 발행
	// CA(step-ca) 관리 — 평면2·3. 읽기는 admins guard, 쓰기(발급)는 admins.
	mux.HandleFunc("GET /api/ca/info", s.guard(s.apiCAInfo))
	mux.HandleFunc("GET /api/ca/certs", s.guard(s.apiCACerts))
	mux.HandleFunc("GET /api/ca/crl", s.guard(s.apiCACRL))
	mux.HandleFunc("GET /api/ca/root", s.guard(s.apiCARoot))     // 루트(신뢰앵커) PEM 다운로드
	mux.HandleFunc("GET /api/ca/issuer", s.guard(s.apiCAIssuer)) // 발급(중간) CA PEM 다운로드
	mux.HandleFunc("GET /api/ca/audit", s.guard(s.apiCAAudit))
	mux.HandleFunc("POST /api/ca/issue", s.guard(s.apiCAIssue))
	mux.HandleFunc("POST /api/ca/sign-csr", s.guard(s.apiCASignCSR)) // 고객 CSR 서명
	mux.HandleFunc("POST /api/ca/revoke", s.guard(s.apiCARevoke))
	mux.HandleFunc("POST /api/ca/reissue", s.guard(s.apiCAReissue))
	mux.HandleFunc("GET /api/ca/recipients", s.guard(s.apiRecipientsList))
	mux.HandleFunc("POST /api/ca/recipients", s.guard(s.apiRecipientImport))
	mux.HandleFunc("DELETE /api/ca/recipients/{id}", s.guard(s.apiRecipientDelete))
	// 신뢰된 외부 공유: 게이트 통과분 CMS 서명 + Zot referrer 바인딩 (고가치 → admins).
	mux.HandleFunc("POST /api/sbom/generate", s.guard(s.apiSBOMGenerate)) // syft 자체 SBOM 생성·부착
	mux.HandleFunc("POST /api/share/sign", s.guard(s.apiShareSign))
	mux.HandleFunc("GET /api/share/package", s.guard(s.apiSharePackage)) // 서명+암호화 .p7m 다운로드(외부 협력사)
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
	ID   string `json:"id"`
	Name string `json:"name"`
}
type kcUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Enabled  bool   `json:"enabled"`
}

func (s *Server) listGroups() ([]kcGroup, error) {
	resp, err := s.kcAdmin("GET", "/groups?max=200", nil)
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

func (s *Server) apiCreateUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Group    string `json:"group"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Username == "" || in.Group == "" {
		writeJSON(w, 400, map[string]string{"error": "username, group 필수"})
		return
	}
	if in.Password == "" {
		in.Password = "Passw0rd!"
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
	pwBody, _ := json.Marshal(map[string]any{"type": "password", "value": in.Password, "temporary": true})
	rp, _ := s.kcAdmin("PUT", "/users/"+uid+"/reset-password", strings.NewReader(string(pwBody)))
	if rp != nil {
		rp.Body.Close()
	}
	if err := s.setUserGroup(uid, in.Group); err != nil {
		writeJSON(w, 502, map[string]string{"error": "그룹 배정 실패: " + err.Error()})
		return
	}
	writeJSON(w, 201, map[string]string{"id": uid, "username": in.Username, "group": in.Group})
}

func (s *Server) apiSetUserGroup(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("id")
	var in struct {
		Group string `json:"group"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Group == "" {
		writeJSON(w, 400, map[string]string{"error": "group 필수"})
		return
	}
	if err := s.setUserGroup(uid, in.Group); err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"id": uid, "group": in.Group})
}

// setUserGroup: 대상 그룹만 남기고 나머지 RBAC 그룹에서 제거 (단일 역할).
func (s *Server) setUserGroup(uid, group string) error {
	groups, err := s.listGroups()
	if err != nil {
		return err
	}
	var targetID string
	byName := map[string]string{}
	for _, g := range groups {
		byName[g.Name] = g.ID
		if g.Name == group {
			targetID = g.ID
		}
	}
	if targetID == "" {
		return fmt.Errorf("그룹 %q 없음", group)
	}
	// 기존 그룹에서 제거
	for _, cur := range s.userGroupNames(uid) {
		if cur != group {
			if id, ok := byName[cur]; ok {
				resp, _ := s.kcAdmin("DELETE", "/users/"+uid+"/groups/"+id, nil)
				if resp != nil {
					resp.Body.Close()
				}
			}
		}
	}
	resp, err := s.kcAdmin("PUT", "/users/"+uid+"/groups/"+targetID, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
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

// apiLogs: 검색(q) + 레벨필터 + 페이지네이션(page/pageSize), 최신순.
func (s *Server) apiLogs(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(r.URL.Query().Get("q"))
	level := strings.ToLower(r.URL.Query().Get("level"))
	page := atoiDefault(r.URL.Query().Get("page"), 1)
	pageSize := atoiDefault(r.URL.Query().Get("pageSize"), 100)
	if pageSize < 1 || pageSize > 500 {
		pageSize = 100
	}

	data, err := os.ReadFile(s.cfg.LogFile)
	if err != nil {
		writeJSON(w, 200, map[string]any{"file": s.cfg.LogFile, "total": 0, "page": 1, "pageSize": pageSize,
			"lines": []string{}, "error": "로그 파일을 읽을 수 없음: " + err.Error()})
		return
	}
	all := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	// 필터 (최신순으로 뒤집어 수집)
	filtered := make([]string, 0, len(all))
	for i := len(all) - 1; i >= 0; i-- {
		ln := all[i]
		if ln == "" {
			continue
		}
		low := strings.ToLower(ln)
		if q != "" && !strings.Contains(low, q) {
			continue
		}
		if level != "" && !strings.Contains(low, `"level":"`+level+`"`) {
			continue
		}
		filtered = append(filtered, ln)
	}
	total := len(filtered)
	start := (page - 1) * pageSize
	if start < 0 {
		start = 0
	}
	end := start + pageSize
	var pageLines []string
	if start < total {
		if end > total {
			end = total
		}
		pageLines = filtered[start:end]
	} else {
		pageLines = []string{}
	}
	writeJSON(w, 200, map[string]any{
		"file": filepath.Clean(s.cfg.LogFile), "total": total, "page": page, "pageSize": pageSize,
		"pages": (total + pageSize - 1) / pageSize, "lines": pageLines,
	})
}

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
