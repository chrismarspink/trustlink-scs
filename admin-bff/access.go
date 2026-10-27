package main

// 접근 정책: 제품별 읽기/쓰기 권한 + 기계 계정(ci-*, robot-*).
//   - 판정은 zot 기본 기능(accessControl)이 한다. TrustLink 는 관리 화면에서 받은 정책을
//     zot 설정 파일과 htpasswd 로 "렌더링"만 한다(zot 은 두 파일 변경을 재시작 없이 반영).
//   - 저장: tl-sor 볼륨의 access-policy.json
//   - 렌더: compose 템플릿(zot 설정 원본) + 제품 정책 → ZOT_MANAGED_DIR/config.json
//           ci·svc-bff(.env) + 유효한 기계 계정 → ZOT_MANAGED_DIR/htpasswd
//   - 웹 경로는 BFF 가 svc-bff 로 대리 조회하므로, 같은 설정으로 canRead/canWrite 를 판정해
//     zot 과 동일한 규칙을 강제한다.

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type Principal struct {
	Type string `json:"type"` // group | user
	Name string `json:"name"`
}

type ProductPolicy struct {
	Repo    string      `json:"repo"`
	Writers []Principal `json:"writers"`
	Readers []Principal `json:"readers"`
}

type Robot struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"` // push(업로드) | pull(다운로드)
	Hash      string `json:"hash"` // bcrypt(htpasswd 형식)
	Note      string `json:"note,omitempty"`
	Created   string `json:"created"`
	CreatedBy string `json:"createdBy"`
	Expires   string `json:"expires"` // RFC3339, 빈 값이면 무기한
}

type AccessPolicy struct {
	Products []ProductPolicy `json:"products"`
	Robots   []Robot         `json:"robots"`
}

var (
	reRobotName = regexp.MustCompile(`^(ci|robot)-[a-z0-9][a-z0-9-]{1,38}$`)
	reOrgName   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,30}$`)
	reRepo      = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*$`)
	// 기계 계정과 이름이 겹치는 사람 계정 금지(zot 에서는 같은 사용자로 취급되므로)
	reservedUserPrefix = regexp.MustCompile(`^(ci|robot|svc)(-|$)`)
)

const orgPrefix = "org-"

var roleGroups = []string{"admins", "developers", "users"}

// ---------- zot accessControl 평가 (zot 과 같은 규칙) ----------

type aclPolicy struct {
	Users   []string `json:"users"`
	Groups  []string `json:"groups"`
	Actions []string `json:"actions"`
}

type aclRepo struct {
	Policies      []aclPolicy `json:"policies"`
	DefaultPolicy []string    `json:"defaultPolicy"`
}

type aclConfig struct {
	Repositories map[string]aclRepo `json:"repositories"`
	AdminPolicy  aclPolicy          `json:"adminPolicy"`
}

// globMatch: doublestar 규칙(zot 과 동일) — '*' 는 한 경로 단계, '**' 는 0개 이상 단계.
func globMatch(pattern, name string) bool {
	return matchSegs(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

func matchSegs(p, n []string) bool {
	if len(p) == 0 {
		return len(n) == 0
	}
	if p[0] == "**" {
		for i := 0; i <= len(n); i++ {
			if matchSegs(p[1:], n[i:]) {
				return true
			}
		}
		return false
	}
	if len(n) == 0 {
		return false
	}
	ok, err := path.Match(p[0], n[0])
	return err == nil && ok && matchSegs(p[1:], n[1:])
}

func policyHas(p aclPolicy, user string, groups []string, action string) bool {
	if !contains(p.Actions, action) {
		return false
	}
	if contains(p.Users, user) {
		return true
	}
	for _, g := range groups {
		if contains(p.Groups, g) {
			return true
		}
	}
	return false
}

// allowed: 가장 긴(구체적인) 패턴의 정책 + defaultPolicy + adminPolicy.
func (a *aclConfig) allowed(user string, groups []string, repo, action string) bool {
	if a == nil {
		return false
	}
	if policyHas(a.AdminPolicy, user, groups, action) {
		return true
	}
	longest := ""
	found := false
	for pat := range a.Repositories {
		if globMatch(pat, repo) && (!found || len(pat) > len(longest)) {
			longest, found = pat, true
		}
	}
	if !found {
		return false
	}
	rp := a.Repositories[longest]
	for _, p := range rp.Policies {
		if policyHas(p, user, groups, action) {
			return true
		}
	}
	return contains(rp.DefaultPolicy, action)
}

// ---------- 저장소 ----------

type accessManager struct {
	mu        sync.Mutex
	storePath string
	tmplPath  string // zot 설정 템플릿(compose configs)
	outDir    string // zot 이 읽는 디렉터리(config.json, htpasswd, oidc-credentials.json)
	baseUsers string // ci·svc-bff htpasswd 줄(기동 시 1회 해시)
	oidcCreds []byte
	hasher    func(user, pw string) (string, error)
	now       func() time.Time
	p         AccessPolicy
	acl       *aclConfig
}

func (m *accessManager) load() error {
	b, err := os.ReadFile(m.storePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &m.p)
}

func (m *accessManager) saveLocked() error {
	b, _ := json.MarshalIndent(m.p, "", "  ")
	if err := os.MkdirAll(filepath.Dir(m.storePath), 0o750); err != nil {
		return err
	}
	tmp := m.storePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.storePath)
}

// htpasswdHash: apache htpasswd(bcrypt). 비밀번호는 stdin 으로 전달(프로세스 인자 노출 방지).
func htpasswdHash(user, pw string) (string, error) {
	cmd := exec.Command("htpasswd", "-niB", user)
	cmd.Stdin = strings.NewReader(pw + "\n")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("htpasswd: %w", err)
	}
	line := strings.TrimSpace(string(out))
	if !strings.HasPrefix(line, user+":") {
		return "", fmt.Errorf("htpasswd 출력 형식 오류")
	}
	return line, nil
}

func (m *accessManager) robotValid(r Robot) bool {
	if r.Expires == "" {
		return true
	}
	t, err := time.Parse(time.RFC3339, r.Expires)
	return err == nil && m.now().Before(t)
}

func principalsToPolicy(ps []Principal, actions []string) aclPolicy {
	p := aclPolicy{Users: []string{}, Groups: []string{}, Actions: actions}
	for _, x := range ps {
		if x.Type == "group" {
			p.Groups = append(p.Groups, x.Name)
		} else {
			p.Users = append(p.Users, x.Name)
		}
	}
	return p
}

// renderLocked: 템플릿 + 정책 → zot 설정/htpasswd. 내용이 같으면 쓰지 않는다(불필요한 zot 리로드 방지).
func (m *accessManager) renderLocked() error {
	tb, err := os.ReadFile(m.tmplPath)
	if err != nil {
		return fmt.Errorf("zot 설정 템플릿: %w", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(tb, &cfg); err != nil {
		return fmt.Errorf("zot 설정 템플릿 파싱: %w", err)
	}
	httpCfg, _ := cfg["http"].(map[string]any)
	ac, _ := httpCfg["accessControl"].(map[string]any)
	if ac == nil {
		return fmt.Errorf("템플릿에 http.accessControl 없음")
	}
	repos, _ := ac["repositories"].(map[string]any)
	if repos == nil {
		repos = map[string]any{}
		ac["repositories"] = repos
	}
	for _, pp := range m.p.Products {
		entry := map[string]any{
			"policies": []aclPolicy{
				principalsToPolicy(pp.Writers, []string{"read", "create", "update"}),
				principalsToPolicy(pp.Readers, []string{"read"}),
			},
			"defaultPolicy": []string{},
		}
		repos[pp.Repo] = entry
		repos[pp.Repo+"/**"] = entry
	}
	out, _ := json.MarshalIndent(cfg, "", "  ")

	var acl aclConfig
	ab, _ := json.Marshal(ac)
	if err := json.Unmarshal(ab, &acl); err != nil {
		return err
	}

	var hp strings.Builder
	hp.WriteString(m.baseUsers)
	for _, r := range m.p.Robots {
		if m.robotValid(r) {
			hp.WriteString(r.Hash + "\n")
		}
	}

	if err := os.MkdirAll(m.outDir, 0o755); err != nil {
		return err
	}
	// zot 은 config.json 변경을 감시해 리로드하며, 이때 htpasswd 도 다시 읽는다(htpasswd 단독 변경은 감지 안 됨 — 실측).
	// 그래서 계정 파일을 먼저 쓰고 config.json 을 마지막에 쓰며, 계정만 바뀐 경우에도 config.json 을 다시 써서 리로드를 일으킨다.
	// rename 대신 제자리 쓰기(감시 대상 inode 유지).
	changed := false
	for _, f := range []struct {
		name string
		data []byte
	}{
		{"htpasswd", []byte(hp.String())},
		{"oidc-credentials.json", m.oidcCreds},
		{"config.json", out},
	} {
		fp := filepath.Join(m.outDir, f.name)
		if cur, err := os.ReadFile(fp); err == nil && bytes.Equal(cur, f.data) && !(f.name == "config.json" && changed) {
			continue
		}
		if err := os.WriteFile(fp, f.data, 0o644); err != nil {
			return err
		}
		changed = true
	}
	m.acl = &acl
	return nil
}

func (m *accessManager) render() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.renderLocked()
}

// update: 정책 변경 → 저장 → 렌더. 렌더 실패 시 이전 정책으로 되돌린다.
func (m *accessManager) update(fn func(p *AccessPolicy) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	prev, _ := json.Marshal(m.p)
	if err := fn(&m.p); err != nil {
		return err
	}
	if err := m.renderLocked(); err != nil {
		_ = json.Unmarshal(prev, &m.p)
		return err
	}
	return m.saveLocked()
}

func (m *accessManager) snapshot() AccessPolicy {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, _ := json.Marshal(m.p)
	var c AccessPolicy
	_ = json.Unmarshal(b, &c)
	return c
}

func (m *accessManager) allowed(user string, groups []string, repo, action string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.acl.allowed(user, groups, repo, action)
}

// ---------- 서버 연동 ----------

// initAccess: 관리 모드(ZOT_CONFIG_TEMPLATE 지정) 시 정책 로드·렌더, 만료 처리 주기 실행.
func (s *Server) initAccess() error {
	if s.cfg.ZotTemplate == "" {
		return nil
	}
	m := &accessManager{
		storePath: s.cfg.AccessStore, tmplPath: s.cfg.ZotTemplate, outDir: s.cfg.ZotManagedDir,
		hasher: htpasswdHash, now: time.Now,
	}
	for _, u := range [][2]string{{s.cfg.MetricsUser, s.cfg.MetricsPass}, {s.cfg.ZotAdminUser, s.cfg.ZotAdminPass}} {
		if u[0] == "" || u[1] == "" {
			continue
		}
		line, err := m.hasher(u[0], u[1])
		if err != nil {
			return err
		}
		m.baseUsers += line + "\n"
	}
	m.oidcCreds, _ = json.Marshal(map[string]string{"clientid": "zot", "clientsecret": s.cfg.ZotOIDCSecret})
	if err := m.load(); err != nil {
		return err
	}
	if err := m.render(); err != nil {
		return err
	}
	s.access = m
	go func() { // 만료된 기계 계정을 htpasswd 에서 제외
		for range time.Tick(10 * time.Minute) {
			if err := m.render(); err != nil {
				log.Printf("zot 설정 렌더 실패: %v", err)
			}
		}
	}()
	return nil
}

// canAccess: 웹 경로 권한 판정. 관리 모드가 아니면(개발용) 기존 동작 유지.
func (s *Server) canAccess(r *http.Request, repo, action string) bool {
	if s.access == nil {
		return true
	}
	sess, ok := s.sessionOf(r)
	if !ok {
		return false
	}
	return s.access.allowed(sess.Username, sess.Groups, repo, action)
}

// requireRepo: 권한 없으면 403 응답 후 false.
func (s *Server) requireRepo(w http.ResponseWriter, r *http.Request, repo, action string) bool {
	if s.canAccess(r, repo, action) {
		return true
	}
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "이 제품에 대한 권한이 없습니다"})
	return false
}

func (s *Server) requireAccessMgr(w http.ResponseWriter) bool {
	if s.access == nil {
		writeJSON(w, 501, map[string]string{"error": "접근 정책 관리 비활성(ZOT_CONFIG_TEMPLATE 미설정)"})
		return false
	}
	return true
}

func genSecret(n int) (string, error) {
	const al = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
	b := make([]byte, n)
	for i := range b {
		k, err := rand.Int(rand.Reader, big.NewInt(int64(len(al))))
		if err != nil {
			return "", err
		}
		b[i] = al[k.Int64()]
	}
	return string(b), nil
}

// ---------- API: 제품 권한 ----------

type productView struct {
	Repo     string      `json:"repo"`
	Explicit bool        `json:"explicit"` // false = 개별 설정 없음(기본 규칙: 내부 전용)
	Writers  []Principal `json:"writers"`
	Readers  []Principal `json:"readers"`
}

// GET /api/access/products — 레지스트리의 레포 + 정책이 있는 레포
func (s *Server) apiAccessProducts(w http.ResponseWriter, r *http.Request) {
	if !s.requireAccessMgr(w) {
		return
	}
	p := s.access.snapshot()
	byRepo := map[string]ProductPolicy{}
	for _, pp := range p.Products {
		byRepo[pp.Repo] = pp
	}
	set := map[string]bool{}
	for _, repo := range s.svcCatalog() {
		set[repo] = true
	}
	for repo := range byRepo {
		set[repo] = true
	}
	out := []productView{}
	for repo := range set {
		pp, ok := byRepo[repo]
		v := productView{Repo: repo, Explicit: ok, Writers: pp.Writers, Readers: pp.Readers}
		if v.Writers == nil {
			v.Writers = []Principal{}
		}
		if v.Readers == nil {
			v.Readers = []Principal{}
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Repo < out[j].Repo })
	writeJSON(w, 200, out)
}

func validPrincipals(ps []Principal) error {
	for _, x := range ps {
		switch x.Type {
		case "group":
			if !contains(roleGroups, x.Name) && !(strings.HasPrefix(x.Name, orgPrefix) && reOrgName.MatchString(strings.TrimPrefix(x.Name, orgPrefix))) {
				return fmt.Errorf("허용되지 않는 그룹: %s", x.Name)
			}
		case "user":
			if x.Name != "ci" && !reRobotName.MatchString(x.Name) {
				return fmt.Errorf("기계 계정만 지정 가능: %s", x.Name)
			}
		default:
			return fmt.Errorf("principal type 은 group|user")
		}
	}
	return nil
}

// PUT /api/access/products — 제품 1개의 쓰기/읽기 대상 설정
func (s *Server) apiAccessProductPut(w http.ResponseWriter, r *http.Request) {
	if !s.requireAccessMgr(w) {
		return
	}
	var in ProductPolicy
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || !reRepo.MatchString(in.Repo) {
		writeJSON(w, 400, map[string]string{"error": "repo 형식 오류(예: products/npouch)"})
		return
	}
	if err := validPrincipals(append(append([]Principal{}, in.Writers...), in.Readers...)); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	err := s.access.update(func(p *AccessPolicy) error {
		for i := range p.Products {
			if p.Products[i].Repo == in.Repo {
				p.Products[i] = in
				return nil
			}
		}
		p.Products = append(p.Products, in)
		return nil
	})
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_ = s.sor.append(SoREvent{Actor: w.Header().Get("X-User"), Action: "access-product-set", Repo: in.Repo,
		Detail: map[string]any{"writers": in.Writers, "readers": in.Readers}})
	writeJSON(w, 200, in)
}

// DELETE /api/access/products?repo= — 개별 설정 해제(기본 규칙으로)
func (s *Server) apiAccessProductDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireAccessMgr(w) {
		return
	}
	repo := r.URL.Query().Get("repo")
	err := s.access.update(func(p *AccessPolicy) error {
		out := p.Products[:0]
		for _, pp := range p.Products {
			if pp.Repo != repo {
				out = append(out, pp)
			}
		}
		p.Products = out
		return nil
	})
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_ = s.sor.append(SoREvent{Actor: w.Header().Get("X-User"), Action: "access-product-reset", Repo: repo})
	writeJSON(w, 200, map[string]string{"repo": repo})
}

// GET /api/access/principals — 권한 대상 후보(역할·조직 그룹, 기계 계정)
func (s *Server) apiAccessPrincipals(w http.ResponseWriter, r *http.Request) {
	groups := []string{}
	if gs, err := s.listGroups(); err == nil {
		for _, g := range gs {
			if contains(roleGroups, g.Name) || strings.HasPrefix(g.Name, orgPrefix) {
				groups = append(groups, g.Name)
			}
		}
	}
	users := []string{"ci"}
	if s.access != nil {
		for _, rb := range s.access.snapshot().Robots {
			users = append(users, rb.Name)
		}
	}
	sort.Strings(groups)
	writeJSON(w, 200, map[string]any{"groups": groups, "users": users})
}

// ---------- API: 기계 계정 ----------

type robotView struct {
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	Note      string   `json:"note"`
	Created   string   `json:"created"`
	CreatedBy string   `json:"createdBy"`
	Expires   string   `json:"expires"`
	Valid     bool     `json:"valid"`
	Products  []string `json:"products"`
}

func (s *Server) apiRobots(w http.ResponseWriter, r *http.Request) {
	if !s.requireAccessMgr(w) {
		return
	}
	p := s.access.snapshot()
	out := []robotView{}
	for _, rb := range p.Robots {
		v := robotView{Name: rb.Name, Kind: rb.Kind, Note: rb.Note, Created: rb.Created, CreatedBy: rb.CreatedBy,
			Expires: rb.Expires, Valid: s.access.robotValid(rb), Products: []string{}}
		for _, pp := range p.Products {
			for _, x := range append(append([]Principal{}, pp.Writers...), pp.Readers...) {
				if x.Type == "user" && x.Name == rb.Name {
					v.Products = append(v.Products, pp.Repo)
					break
				}
			}
		}
		out = append(out, v)
	}
	writeJSON(w, 200, out)
}

// POST /api/robots {name, kind, products[], days, note} — 비밀값은 응답으로 1회만
func (s *Server) apiRobotCreate(w http.ResponseWriter, r *http.Request) {
	if !s.requireAccessMgr(w) {
		return
	}
	var in struct {
		Name     string   `json:"name"`
		Kind     string   `json:"kind"`
		Products []string `json:"products"`
		Days     int      `json:"days"`
		Note     string   `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || !reRobotName.MatchString(in.Name) {
		writeJSON(w, 400, map[string]string{"error": "이름은 ci-… 또는 robot-… (영소문자·숫자·-)"})
		return
	}
	if in.Kind != "push" && in.Kind != "pull" {
		writeJSON(w, 400, map[string]string{"error": "kind 는 push(업로드) 또는 pull(다운로드)"})
		return
	}
	for _, repo := range in.Products {
		if !reRepo.MatchString(repo) {
			writeJSON(w, 400, map[string]string{"error": "제품 경로 형식 오류: " + repo})
			return
		}
	}
	if s.findUserID(in.Name) != "" {
		writeJSON(w, 409, map[string]string{"error": "같은 이름의 사람 계정이 있습니다"})
		return
	}
	secret, err := genSecret(32)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	hash, err := s.access.hasher(in.Name, secret)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	now := time.Now().UTC()
	rb := Robot{Name: in.Name, Kind: in.Kind, Hash: hash, Note: in.Note, Created: now.Format(time.RFC3339),
		CreatedBy: w.Header().Get("X-User")}
	if in.Days > 0 {
		rb.Expires = now.AddDate(0, 0, in.Days).Format(time.RFC3339)
	}
	err = s.access.update(func(p *AccessPolicy) error {
		for _, x := range p.Robots {
			if x.Name == in.Name {
				return fmt.Errorf("이미 있는 기계 계정: %s", in.Name)
			}
		}
		p.Robots = append(p.Robots, rb)
		pr := Principal{Type: "user", Name: in.Name}
		for _, repo := range in.Products {
			idx := -1
			for i := range p.Products {
				if p.Products[i].Repo == repo {
					idx = i
				}
			}
			if idx < 0 { // 개별 설정이 없던 제품: 기본 쓰기 대상(개발자·ci)을 유지하며 생성
				p.Products = append(p.Products, ProductPolicy{Repo: repo,
					Writers: []Principal{{"group", "developers"}, {"user", "ci"}}, Readers: []Principal{}})
				idx = len(p.Products) - 1
			}
			if in.Kind == "push" {
				p.Products[idx].Writers = append(p.Products[idx].Writers, pr)
			} else {
				p.Products[idx].Readers = append(p.Products[idx].Readers, pr)
			}
		}
		return nil
	})
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	_ = s.sor.append(SoREvent{Actor: rb.CreatedBy, Action: "robot-create", Subject: in.Name,
		Detail: map[string]any{"kind": in.Kind, "products": in.Products, "expires": rb.Expires}})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 201, map[string]any{"username": in.Name, "password": secret, "kind": in.Kind, "expires": rb.Expires, "products": in.Products})
}

// POST /api/robots/{name}/reissue — 비밀값 재발급(기존 값 즉시 무효)
func (s *Server) apiRobotReissue(w http.ResponseWriter, r *http.Request) {
	if !s.requireAccessMgr(w) {
		return
	}
	name := r.PathValue("name")
	secret, err := genSecret(32)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	hash, err := s.access.hasher(name, secret)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	var kind, expires string
	err = s.access.update(func(p *AccessPolicy) error {
		for i := range p.Robots {
			if p.Robots[i].Name == name {
				p.Robots[i].Hash = hash
				kind, expires = p.Robots[i].Kind, p.Robots[i].Expires
				return nil
			}
		}
		return fmt.Errorf("기계 계정 없음: %s", name)
	})
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	_ = s.sor.append(SoREvent{Actor: w.Header().Get("X-User"), Action: "robot-reissue", Subject: name})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"username": name, "password": secret, "kind": kind, "expires": expires})
}

// DELETE /api/robots/{name} — 계정 폐기 + 모든 제품 권한에서 제거
func (s *Server) apiRobotDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireAccessMgr(w) {
		return
	}
	name := r.PathValue("name")
	err := s.access.update(func(p *AccessPolicy) error {
		rs := p.Robots[:0]
		for _, x := range p.Robots {
			if x.Name != name {
				rs = append(rs, x)
			}
		}
		p.Robots = rs
		for i := range p.Products {
			p.Products[i].Writers = withoutPrincipal(p.Products[i].Writers, "user", name)
			p.Products[i].Readers = withoutPrincipal(p.Products[i].Readers, "user", name)
		}
		return nil
	})
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_ = s.sor.append(SoREvent{Actor: w.Header().Get("X-User"), Action: "robot-delete", Subject: name})
	writeJSON(w, 200, map[string]string{"name": name})
}

func withoutPrincipal(ps []Principal, typ, name string) []Principal {
	out := []Principal{}
	for _, x := range ps {
		if !(x.Type == typ && x.Name == name) {
			out = append(out, x)
		}
	}
	return out
}

// ---------- API: 고객사(조직) = Keycloak 그룹 org-<이름> ----------

func (s *Server) apiOrgs(w http.ResponseWriter, r *http.Request) {
	gs, err := s.listGroups()
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	type orgView struct {
		Name     string   `json:"name"`
		Group    string   `json:"group"`
		Members  []string `json:"members"`
		Products []string `json:"products"`
	}
	var pol AccessPolicy
	if s.access != nil {
		pol = s.access.snapshot()
	}
	out := []orgView{}
	for _, g := range gs {
		if !strings.HasPrefix(g.Name, orgPrefix) {
			continue
		}
		v := orgView{Name: strings.TrimPrefix(g.Name, orgPrefix), Group: g.Name, Members: s.groupMembers(g.ID), Products: []string{}}
		for _, pp := range pol.Products {
			for _, x := range pp.Readers {
				if x.Type == "group" && x.Name == g.Name {
					v.Products = append(v.Products, pp.Repo)
				}
			}
		}
		out = append(out, v)
	}
	writeJSON(w, 200, out)
}

func (s *Server) groupMembers(gid string) []string {
	resp, err := s.kcAdmin("GET", "/groups/"+gid+"/members?max=500&briefRepresentation=true", nil)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()
	var us []kcUser
	_ = json.NewDecoder(resp.Body).Decode(&us)
	names := []string{}
	for _, u := range us {
		names = append(names, u.Username)
	}
	return names
}

func (s *Server) apiOrgCreate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || !reOrgName.MatchString(in.Name) {
		writeJSON(w, 400, map[string]string{"error": "고객사 ID 는 영소문자·숫자·- (2~31자)"})
		return
	}
	body, _ := json.Marshal(map[string]string{"name": orgPrefix + in.Name})
	resp, err := s.kcAdmin("POST", "/groups", bytes.NewReader(body))
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	resp.Body.Close()
	if resp.StatusCode == 409 {
		writeJSON(w, 409, map[string]string{"error": "이미 있는 고객사"})
		return
	}
	if resp.StatusCode != 201 {
		writeJSON(w, 502, map[string]string{"error": fmt.Sprintf("Keycloak 그룹 생성 실패(%d)", resp.StatusCode)})
		return
	}
	_ = s.sor.append(SoREvent{Actor: w.Header().Get("X-User"), Action: "org-create", Subject: orgPrefix + in.Name})
	writeJSON(w, 201, map[string]string{"name": in.Name, "group": orgPrefix + in.Name})
}

// DELETE /api/orgs/{name} — 그룹 삭제(소속 해제) + 제품 권한에서 제거
func (s *Server) apiOrgDelete(w http.ResponseWriter, r *http.Request) {
	group := orgPrefix + r.PathValue("name")
	gs, err := s.listGroups()
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	gid := ""
	for _, g := range gs {
		if g.Name == group {
			gid = g.ID
		}
	}
	if gid == "" {
		writeJSON(w, 404, map[string]string{"error": "고객사 없음"})
		return
	}
	resp, err := s.kcAdmin("DELETE", "/groups/"+gid, nil)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	resp.Body.Close()
	if s.access != nil {
		_ = s.access.update(func(p *AccessPolicy) error {
			for i := range p.Products {
				p.Products[i].Writers = withoutPrincipal(p.Products[i].Writers, "group", group)
				p.Products[i].Readers = withoutPrincipal(p.Products[i].Readers, "group", group)
			}
			return nil
		})
	}
	_ = s.sor.append(SoREvent{Actor: w.Header().Get("X-User"), Action: "org-delete", Subject: group})
	writeJSON(w, 200, map[string]string{"group": group})
}
