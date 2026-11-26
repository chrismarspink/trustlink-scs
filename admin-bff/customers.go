package main

// customers.go: 고객 등록부(CRM 카드) — 고객·담당자·제품 사용 현황(설치 버전·계약·유지보수·통지 정책)과
// 제품 버전 정책(출시·EOS·권장 업그레이드). Keycloak 데이터는 건드리지 않는다(고객사 그룹은 이름으로만 연결).
//   - 저장: 파일 하나(CUSTOMERS_STORE, 0600) — 접근 정책·통보와 같은 방식(stdlib, 외부 DB 없음).
//   - 만료 D-day(라이선스·유지보수·EOS)와 "다운로드 기록 추정 버전 ≠ 등록 버전"(확인 필요)을 계산해 보여 준다.
//   - 변경은 모두 감사 원장(SoR)에 남긴다.
// 고객 통지(패치 권고) 흐름은 custnotify.go, 만료 알림·고객 전용 화면은 custnotify_extra.go.

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	custIndustries = []string{"공공", "금융", "방산", "제조", "통신", "에너지", "의료", "일반", "해외"}
	custRoles      = []string{"security", "itops", "purchase", "other"}
	custKinds      = []string{"vuln", "vex", "incident", "patch", "eos", "contract"}
	custEnvs       = []string{"운영", "DR", "검증", "개발"}
	custLicTypes   = []string{"perpetual", "subscription", "term"}
	custLevels     = []string{"critical_kev", "high", "all"}
	reCustID       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,40}$`)
	reDate         = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

type CustContact struct {
	Name   string   `json:"name"`
	Role   string   `json:"role"` // security | itops | purchase | other
	Email  string   `json:"email"`
	Phone  string   `json:"phone,omitempty"`
	Mobile string   `json:"mobile,omitempty"`
	Dept   string   `json:"dept,omitempty"`  // 부서(명함 표시)
	Title  string   `json:"title,omitempty"` // 직함(명함 표시)
	Notify []string `json:"notify"`          // 받을 통지 종류(custKinds)
	Lang   string   `json:"lang,omitempty"`  // 비면 고객 언어
}

type CustInstall struct {
	Tag string `json:"tag"`
	Env string `json:"env"` // 운영 | DR | 검증 | 개발
	Qty int    `json:"qty"`
}

type CustUsage struct {
	ID             string        `json:"id"`
	Repo           string        `json:"repo"`
	Installs       []CustInstall `json:"installs"`
	ContractNo     string        `json:"contractNo,omitempty"`
	LicenseType    string        `json:"licenseType,omitempty"` // perpetual | subscription | term
	UseStart       string        `json:"useStart,omitempty"`
	LicenseExpiry  string        `json:"licenseExpiry,omitempty"`
	MaintStart     string        `json:"maintStart,omitempty"`
	MaintExpiry    string        `json:"maintExpiry,omitempty"`
	SupportTier    string        `json:"supportTier,omitempty"`
	NotifyLevel    string        `json:"notifyLevel"`              // critical_kev | high | all
	NotifyContacts []string      `json:"notifyContacts,omitempty"` // 담당자 이메일(비면 통지 종류가 맞는 모든 담당자)
	Memo           string        `json:"memo,omitempty"`
}

type Customer struct {
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	Industry     string        `json:"industry"`
	Country      string        `json:"country,omitempty"`
	Lang         string        `json:"lang"`               // ko | en
	OrgGroup     string        `json:"orgGroup,omitempty"` // 연결된 고객사 그룹(org-*) — 고객 전용 화면 범위
	SalesOwner   string        `json:"salesOwner,omitempty"`
	SupportOwner string        `json:"supportOwner,omitempty"`
	Memo         string        `json:"memo,omitempty"`
	Contacts     []CustContact `json:"contacts"`
	Usages       []CustUsage   `json:"usages"`
	Updated      string        `json:"updated,omitempty"`
	UpdatedBy    string        `json:"updatedBy,omitempty"`
	// 내부 검증(사전 배포) 고객 — 우리 테스트팀/QA 처럼 새 버전과 통지를 외부 고객보다 "먼저" 받는 링.
	// 통지는 이 고객에게 먼저 보내 확인한 뒤에야 외부 고객에게 나간다(custnotify.go 의 발송 게이트).
	// 코드/JSON 은 pilot — "internal" 은 이미 '우리 담당자'를 뜻해(notify.go) 섞이지 않도록 다른 이름을 쓴다.
	Pilot bool `json:"pilot,omitempty"`
	// 사용/중지: 폐업·관계 종료·계약 해지 등으로 더는 거래하지 않는 회사. 지우지 않고 중지해 기록을 남긴다.
	// 중지된 회사는 고객 통지·만료 알림·내 제품에서 빠지고, 목록에서 기본으로 숨는다. (PUT /api/customers/{id}/status 로만 바꾼다)
	Disabled       bool   `json:"disabled,omitempty"`
	DisabledReason string `json:"disabledReason,omitempty"` // closed(폐업) / ended(관계 종료) / terminated(계약 해지) / other
	DisabledNote   string `json:"disabledNote,omitempty"`
	DisabledAt     string `json:"disabledAt,omitempty"`
	DisabledBy     string `json:"disabledBy,omitempty"`
	Logo           string `json:"logo,omitempty"` // 서버 데이터의 로고 파일 이름(+?v=) — PUT /api/customers/{id}/logo 로만 바꾼다
	// 삭제(휴지통): DELETE 는 표시만 한다. 휴지통에서 되살리거나(restore) 이름을 확인한 뒤 완전 삭제(purge)한다.
	Deleted   bool   `json:"deleted,omitempty"`
	DeletedAt string `json:"deletedAt,omitempty"`
	DeletedBy string `json:"deletedBy,omitempty"`
}

// VerPolicy: 제품 버전 정책 한 줄.
type VerPolicy struct {
	Tag      string `json:"tag"`
	Released string `json:"released,omitempty"`
	EOS      string `json:"eos,omitempty"`
	Upgrade  string `json:"upgrade,omitempty"` // 권장 업그레이드 버전
}

type custSettings struct {
	ExpiryToCustomer bool `json:"expiryToCustomer"` // 계약 만료는 고객 구매 담당, EOS 는 EOS 통지 담당에게도
}

type custData struct {
	Customers  []Customer             `json:"customers"`
	Products   map[string][]VerPolicy `json:"products"`   // repo → 버전 정책
	Notices    []CustNotice           `json:"notices"`    // 고객 통지 이력(custnotify.go)
	ExpirySent map[string]string      `json:"expirySent"` // 만료 알림 중복 방지 키 → 보낸 시각
	ExpiryLog  []expiryRec            `json:"expiryLog"`  // 만료 알림 발송 기록(최근)
	Settings   custSettings           `json:"settings"`
}

type custStore struct {
	mu      sync.Mutex
	path    string
	d       custData
	emailOf func(username string) string // 우리 쪽 담당자(Keycloak 사용자) 이메일
	now     func() time.Time
	logPath string // zot 접근 로그(다운로드 기록 추정 버전)
}

const custNoticeKeep = 500

// 서버별 저장소(Server 구조체를 바꾸지 않으려고 따로 둔다).
var (
	custMu    sync.Mutex
	custByOwn = map[*Server]*custStore{}
)

func (s *Server) cust() *custStore {
	custMu.Lock()
	defer custMu.Unlock()
	if c := custByOwn[s]; c != nil {
		return c
	}
	c := &custStore{path: env("CUSTOMERS_STORE", "/var/lib/trustlink/customers.json"), now: time.Now, logPath: s.cfg.LogFile}
	c.emailOf = s.userEmail
	if b, err := os.ReadFile(c.path); err == nil {
		_ = json.Unmarshal(b, &c.d)
	}
	if c.d.Products == nil {
		c.d.Products = map[string][]VerPolicy{}
	}
	if c.d.ExpirySent == nil {
		c.d.ExpirySent = map[string]string{}
	}
	custByOwn[s] = c
	return c
}

func (c *custStore) saveLocked() error {
	b, _ := json.MarshalIndent(c.d, "", "  ")
	if err := os.MkdirAll(filepath.Dir(c.path), 0o750); err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

// snapshot: 깊은 복사(JSON 왕복) — 잠금 밖에서 안전하게 읽기.
func (c *custStore) snapshot() custData {
	c.mu.Lock()
	b, _ := json.Marshal(c.d)
	c.mu.Unlock()
	var d custData
	_ = json.Unmarshal(b, &d)
	if d.Products == nil {
		d.Products = map[string][]VerPolicy{}
	}
	return d
}

func (c *custStore) find(id string) (Customer, bool) {
	for _, x := range c.snapshot().Customers {
		if x.ID == id {
			return x, true
		}
	}
	return Customer{}, false
}

// userEmail: Keycloak 사용자 이름 → 이메일(없거나 조회 실패면 "").
func (s *Server) userEmail(username string) string {
	if username == "" {
		return ""
	}
	resp, err := s.kcAdmin("GET", "/users?exact=true&username="+url.QueryEscape(username), nil)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var us []kcUser
	_ = json.NewDecoder(resp.Body).Decode(&us)
	if len(us) == 0 {
		return ""
	}
	return us[0].Email
}

func newCustID(prefix string) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// ---------- 검증 ----------

func validDate(d string) bool {
	if d == "" {
		return true
	}
	if !reDate.MatchString(d) {
		return false
	}
	_, err := time.Parse("2006-01-02", d)
	return err == nil
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// normalizeCustomer: 형식 검사 + 기본값. 문제가 있으면 한국어 오류.
func normalizeCustomer(c *Customer) error {
	c.Name = clip(c.Name, 100)
	if c.Name == "" {
		return fmt.Errorf("고객 이름 필수")
	}
	if c.ID == "" {
		c.ID = newCustID("c-")
	}
	if !reCustID.MatchString(c.ID) {
		return fmt.Errorf("고객 ID 형식 오류(영소문자·숫자·-)")
	}
	if !inList(c.Industry, custIndustries) {
		return fmt.Errorf("업종은 %s 중 하나", strings.Join(custIndustries, "/"))
	}
	if c.Lang == "" {
		c.Lang = "ko"
	}
	if c.Lang != "ko" && c.Lang != "en" {
		return fmt.Errorf("언어는 ko/en")
	}
	if c.OrgGroup != "" {
		if !strings.HasPrefix(c.OrgGroup, orgPrefix) {
			c.OrgGroup = orgPrefix + c.OrgGroup
		}
		if !reOrgName.MatchString(strings.TrimPrefix(c.OrgGroup, orgPrefix)) {
			return fmt.Errorf("고객사 그룹 형식 오류: %s", c.OrgGroup)
		}
	}
	c.Country, c.SalesOwner, c.SupportOwner, c.Memo = clip(c.Country, 40), clip(c.SalesOwner, 64), clip(c.SupportOwner, 64), clip(c.Memo, 2000)
	if len(c.Contacts) > 50 || len(c.Usages) > 100 {
		return fmt.Errorf("담당자 50명·제품 100개까지")
	}
	emails := []string{}
	for i := range c.Contacts {
		ct := &c.Contacts[i]
		ct.Name, ct.Email, ct.Phone = clip(ct.Name, 60), strings.TrimSpace(ct.Email), clip(ct.Phone, 40)
		if ct.Name == "" {
			return fmt.Errorf("담당자 이름 필수")
		}
		if !inList(ct.Role, custRoles) {
			return fmt.Errorf("담당자 역할은 %s 중 하나", strings.Join(custRoles, "/"))
		}
		if ct.Email == "" {
			return fmt.Errorf("담당자 %s: 이메일 필수", ct.Name)
		}
		if msg := checkUserEmail("", ct.Email); msg != "" {
			return fmt.Errorf("%s", msg)
		}
		if inList(strings.ToLower(ct.Email), emails) {
			return fmt.Errorf("담당자 이메일 중복: %s", ct.Email)
		}
		emails = append(emails, strings.ToLower(ct.Email))
		if ct.Lang != "" && ct.Lang != "ko" && ct.Lang != "en" {
			return fmt.Errorf("담당자 언어는 ko/en")
		}
		if ct.Notify == nil {
			ct.Notify = []string{}
		}
		for _, k := range ct.Notify {
			if !inList(k, custKinds) {
				return fmt.Errorf("통지 종류 오류: %s", k)
			}
		}
	}
	for i := range c.Usages {
		u := &c.Usages[i]
		if u.ID == "" {
			u.ID = newCustID("u-")
		}
		if !reRepo.MatchString(u.Repo) {
			return fmt.Errorf("제품(repo) 형식 오류: %s", u.Repo)
		}
		for j := range u.Installs {
			in := &u.Installs[j]
			in.Tag = strings.TrimSpace(in.Tag)
			if in.Tag == "" || len(in.Tag) > 128 {
				return fmt.Errorf("%s: 설치 버전 필수", u.Repo)
			}
			if in.Env == "" {
				in.Env = "운영"
			}
			if !inList(in.Env, custEnvs) {
				return fmt.Errorf("설치 환경은 %s 중 하나", strings.Join(custEnvs, "/"))
			}
			if in.Qty < 0 || in.Qty > 100000 {
				return fmt.Errorf("설치 수량 오류")
			}
		}
		if u.LicenseType != "" && !inList(u.LicenseType, custLicTypes) {
			return fmt.Errorf("라이선스 유형 오류: %s", u.LicenseType)
		}
		for _, d := range []string{u.UseStart, u.LicenseExpiry, u.MaintStart, u.MaintExpiry} {
			if !validDate(d) {
				return fmt.Errorf("날짜 형식은 YYYY-MM-DD: %s", d)
			}
		}
		if u.NotifyLevel == "" {
			u.NotifyLevel = "high"
		}
		if !inList(u.NotifyLevel, custLevels) {
			return fmt.Errorf("통지 수준 오류: %s", u.NotifyLevel)
		}
		for _, e := range u.NotifyContacts {
			if !inList(strings.ToLower(e), emails) {
				return fmt.Errorf("%s: 통지 담당자 %s 가 담당자 목록에 없음", u.Repo, e)
			}
		}
		u.ContractNo, u.SupportTier, u.Memo = clip(u.ContractNo, 60), clip(u.SupportTier, 40), clip(u.Memo, 1000)
	}
	if c.Contacts == nil {
		c.Contacts = []CustContact{}
	}
	if c.Usages == nil {
		c.Usages = []CustUsage{}
	}
	return nil
}

func normalizeVersions(vs []VerPolicy) error {
	seen := map[string]bool{}
	for i := range vs {
		v := &vs[i]
		v.Tag, v.Upgrade = strings.TrimSpace(v.Tag), strings.TrimSpace(v.Upgrade)
		if v.Tag == "" || seen[v.Tag] {
			return fmt.Errorf("버전 비었거나 중복: %q", v.Tag)
		}
		seen[v.Tag] = true
		if !validDate(v.Released) || !validDate(v.EOS) {
			return fmt.Errorf("%s: 날짜 형식은 YYYY-MM-DD", v.Tag)
		}
	}
	sort.Slice(vs, func(i, j int) bool { return cmpVersion(vs[i].Tag, vs[j].Tag) < 0 })
	return nil
}

// ---------- 계산: D-day · 확인 필요 ----------

// daysUntil: 오늘(KST) 기준 남은 날(지났으면 음수). ok=false 면 날짜 없음.
func daysUntil(date string, now time.Time) (int, bool) {
	if date == "" {
		return 0, false
	}
	t, err := time.ParseInLocation("2006-01-02", date, kst)
	if err != nil {
		return 0, false
	}
	n := now.In(kst)
	today := time.Date(n.Year(), n.Month(), n.Day(), 0, 0, 0, 0, kst)
	return int(t.Sub(today).Hours() / 24), true
}

type custExpiry struct {
	CustomerID string `json:"customerId"`
	Customer   string `json:"customer"`
	UsageID    string `json:"usageId"`
	Repo       string `json:"repo"`
	Kind       string `json:"kind"` // license | maint | eos
	Tag        string `json:"tag,omitempty"`
	Date       string `json:"date"`
	Days       int    `json:"days"`
}

func verPolicyOf(products map[string][]VerPolicy, repo, tag string) (VerPolicy, bool) {
	for _, v := range products[repo] {
		if v.Tag == tag {
			return v, true
		}
	}
	return VerPolicy{}, false
}

// custExpiries: 고객 1곳의 라이선스·유지보수·설치 버전 EOS 날짜와 남은 날.
func custExpiries(c Customer, products map[string][]VerPolicy, now time.Time) []custExpiry {
	var out []custExpiry
	add := func(u CustUsage, kind, tag, date string) {
		if d, ok := daysUntil(date, now); ok {
			out = append(out, custExpiry{CustomerID: c.ID, Customer: c.Name, UsageID: u.ID, Repo: u.Repo, Kind: kind, Tag: tag, Date: date, Days: d})
		}
	}
	for _, u := range c.Usages {
		if u.LicenseType != "perpetual" {
			add(u, "license", "", u.LicenseExpiry)
		}
		add(u, "maint", "", u.MaintExpiry)
		seen := map[string]bool{}
		for _, in := range u.Installs {
			if vp, ok := verPolicyOf(products, u.Repo, in.Tag); ok && !seen[in.Tag] {
				seen[in.Tag] = true
				add(u, "eos", in.Tag, vp.EOS)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Days < out[j].Days })
	return out
}

type dlEst struct {
	Tag  string `json:"tag"`
	Time string `json:"time"`
	User string `json:"user"`
}

// downloadEstimates: zot 접근 로그 → 고객사 그룹별·제품별 마지막 다운로드 버전(추정 설치 버전).
func downloadEstimates(r io.Reader, orgOf map[string]string) map[string]map[string]dlEst {
	out := map[string]map[string]dlEst{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		kind, user, repo, tag, t := parseZotAccess(sc.Bytes())
		org := orgOf[user]
		if kind != "download" || org == "" || tag == "latest" {
			continue
		}
		if out[org] == nil {
			out[org] = map[string]dlEst{}
		}
		ts := t.UTC().Format(time.RFC3339)
		if ts >= out[org][repo].Time {
			out[org][repo] = dlEst{Tag: tag, Time: ts, User: user}
		}
	}
	return out
}

type custMismatch struct {
	Repo      string   `json:"repo"`
	Estimated string   `json:"estimated"` // 다운로드 기록 추정 버전
	At        string   `json:"at"`
	User      string   `json:"user"`
	Installed []string `json:"installed"` // 등록된 설치 버전(비면 등록 안 된 제품)
}

// custMismatches: 추정 버전이 등록된 설치 버전에 없으면 "확인 필요".
func custMismatches(c Customer, est map[string]dlEst) []custMismatch {
	out := []custMismatch{}
	repos := []string{}
	for repo := range est {
		repos = append(repos, repo)
	}
	sort.Strings(repos)
	for _, repo := range repos {
		e := est[repo]
		inst := []string{}
		for _, u := range c.Usages {
			if u.Repo == repo {
				for _, in := range u.Installs {
					inst = append(inst, in.Tag)
				}
			}
		}
		if !inList(e.Tag, inst) {
			out = append(out, custMismatch{Repo: repo, Estimated: e.Tag, At: e.Time, User: e.User, Installed: inst})
		}
	}
	return out
}

// estCache: 접근 로그는 수백 MB 라 매번 읽으면 목록이 수 초 걸린다 — 연결 그룹 구성이 같으면 5분간 재사용.
var estCache struct {
	sync.Mutex
	key string
	at  time.Time
	v   map[string]map[string]dlEst
}

// estimatesFor: 고객사 그룹 구성원(Keycloak) + 접근 로그. 조회 실패 시 빈 결과(화면은 그대로 동작).
func (s *Server) estimatesFor(cs []Customer) map[string]map[string]dlEst {
	linked := map[string]bool{}
	keys := []string{}
	for _, c := range cs {
		if c.OrgGroup != "" && !linked[c.OrgGroup] {
			linked[c.OrgGroup] = true
			keys = append(keys, c.OrgGroup)
		}
	}
	sort.Strings(keys)
	key := strings.Join(keys, ",")
	estCache.Lock()
	defer estCache.Unlock()
	if estCache.key == key && estCache.v != nil && time.Since(estCache.at) < 5*time.Minute {
		return estCache.v
	}
	v := s.estimatesUncached(linked)
	estCache.key, estCache.at, estCache.v = key, time.Now(), v
	return v
}

func (s *Server) estimatesUncached(linked map[string]bool) map[string]map[string]dlEst {
	lp := s.cust().logPath
	if len(linked) == 0 || lp == "" {
		return nil
	}
	gs, err := s.listGroups()
	if err != nil {
		return nil
	}
	orgOf := map[string]string{}
	for _, g := range gs {
		if linked[g.Name] {
			for _, u := range s.groupUsers(g.ID) {
				orgOf[u.Username] = g.Name
			}
		}
	}
	f, err := os.Open(lp)
	if err != nil {
		return nil
	}
	defer f.Close()
	return downloadEstimates(f, orgOf)
}

// ---------- API ----------

type custView struct {
	Customer
	Expiry   []custExpiry   `json:"expiry"`
	Mismatch []custMismatch `json:"mismatch"`
}

// GET /api/customers — 고객 목록(D-day·확인 필요 포함) + 버전 정책 + 설정.
func (s *Server) apiCustomers(w http.ResponseWriter, r *http.Request) {
	c := s.cust()
	d := c.snapshot()
	est := s.estimatesFor(d.Customers)
	out := []custView{}
	for _, x := range d.Customers {
		v := custView{Customer: x, Expiry: custExpiries(x, d.Products, c.now()), Mismatch: custMismatches(x, est[x.OrgGroup])}
		if v.Expiry == nil {
			v.Expiry = []custExpiry{}
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, 200, map[string]any{"customers": out, "products": d.Products, "settings": d.Settings})
}

// POST /api/customers (신규) · PUT /api/customers/{id} (전체 교체)
func (s *Server) apiCustomerSave(w http.ResponseWriter, r *http.Request) {
	var in Customer
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "요청 형식 오류"})
		return
	}
	id := r.PathValue("id")
	if id != "" {
		in.ID = id
	}
	if err := normalizeCustomer(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	actor := w.Header().Get("X-User")
	c := s.cust()
	in.Updated, in.UpdatedBy = c.now().UTC().Format(time.RFC3339), actor
	c.mu.Lock()
	idx := -1
	for i, x := range c.d.Customers {
		if x.ID == in.ID {
			idx = i
		}
	}
	switch {
	case id == "" && idx >= 0:
		c.mu.Unlock()
		writeJSON(w, 409, map[string]string{"error": "같은 ID 의 고객이 있음"})
		return
	case id != "" && idx < 0:
		c.mu.Unlock()
		writeJSON(w, 404, map[string]string{"error": "고객 없음"})
		return
	case idx >= 0:
		old := c.d.Customers[idx] // 상태·로고는 전용 API 로만 바뀐다(편집 화면 저장이 지우지 않게)
		in.Disabled, in.DisabledReason, in.DisabledNote, in.DisabledAt, in.DisabledBy, in.Logo = old.Disabled, old.DisabledReason, old.DisabledNote, old.DisabledAt, old.DisabledBy, old.Logo
		in.Deleted, in.DeletedAt, in.DeletedBy = old.Deleted, old.DeletedAt, old.DeletedBy
		c.d.Customers[idx] = in
	default:
		in.Disabled, in.DisabledReason, in.DisabledNote, in.DisabledAt, in.DisabledBy, in.Logo = false, "", "", "", "", ""
		in.Deleted, in.DeletedAt, in.DeletedBy = false, "", ""
		c.d.Customers = append(c.d.Customers, in)
	}
	err := c.saveLocked()
	c.mu.Unlock()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	action := map[bool]string{true: "customer-create", false: "customer-update"}[id == ""]
	_ = s.sor.append(SoREvent{Actor: actor, Action: action, Subject: in.ID, Detail: map[string]any{"name": in.Name,
		"contacts": len(in.Contacts), "usages": len(in.Usages), "orgGroup": in.OrgGroup}})
	writeJSON(w, map[bool]int{true: 201, false: 200}[id == ""], in)
}

// DELETE /api/customers/{id} — 휴지통으로(삭제 표시). 되살리기·완전 삭제는 customer_trash.go.
func (s *Server) apiCustomerDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	actor := w.Header().Get("X-User")
	c := s.cust()
	x, ok, err := c.updateOne(id, func(x *Customer) {
		x.Deleted, x.DeletedAt, x.DeletedBy = true, c.now().UTC().Format(time.RFC3339), actor
	})
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "고객 없음"})
		return
	}
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_ = s.sor.append(SoREvent{Actor: actor, Action: "customer-delete", Subject: id, Detail: map[string]any{"name": x.Name, "soft": true}})
	writeJSON(w, 200, map[string]any{"deleted": id, "trash": true})
}

// PUT /api/customer-products {repo, versions[]} — 제품 버전 정책(빈 목록이면 삭제).
func (s *Server) apiCustomerProductPut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Repo     string      `json:"repo"`
		Versions []VerPolicy `json:"versions"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil || !reRepo.MatchString(in.Repo) {
		writeJSON(w, 400, map[string]string{"error": "요청 형식 오류(repo)"})
		return
	}
	if err := normalizeVersions(in.Versions); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	c := s.cust()
	c.mu.Lock()
	if len(in.Versions) == 0 {
		delete(c.d.Products, in.Repo)
	} else {
		c.d.Products[in.Repo] = in.Versions
	}
	err := c.saveLocked()
	c.mu.Unlock()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_ = s.sor.append(SoREvent{Actor: w.Header().Get("X-User"), Action: "product-versions", Repo: in.Repo, Detail: map[string]any{"versions": len(in.Versions)}})
	writeJSON(w, 200, in)
}

// PUT /api/customer-settings {expiryToCustomer}
func (s *Server) apiCustomerSettings(w http.ResponseWriter, r *http.Request) {
	var in custSettings
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "요청 형식 오류"})
		return
	}
	c := s.cust()
	c.mu.Lock()
	c.d.Settings = in
	err := c.saveLocked()
	c.mu.Unlock()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_ = s.sor.append(SoREvent{Actor: w.Header().Get("X-User"), Action: "customer-settings", Detail: map[string]any{"expiryToCustomer": in.ExpiryToCustomer}})
	writeJSON(w, 200, in)
}
