package main

// 공개 저장소(상류) 분석 — CRA "제3자 구성요소 실사(due diligence)" 증거.
//  - 제품 SBOM 의 구성요소(purl) → 상류 소스 저장소를 찾고(deps.dev GetVersion·purl·SBOM vcs 참조) 건강도를 본다.
//  - 신호: deps.dev GetProject(OpenSSF Scorecard·별·포크·열린 이슈) + GitHub REST(보관·비활성·마지막 push·라이선스·
//    최근 릴리스·SECURITY.md·공개 보안 권고). 이 버전에 걸린 권고는 deps.dev advisoryKeys + GetAdvisory(CVSS).
//  - GitHub 토큰이 없으면 시간당 60회 한도 → 저장소 결과를 디스크에 24시간 캐시, 실행당 GitHub 조회 저장소 수 상한,
//    한도에 걸리면 남은 저장소는 deps.dev 정보만으로 판정하고 보고서에 밝힌다.
//  - 등급: 위험 / 주의 / 양호 / 미확인(저장소 못 찾음) + 사유. 판정은 규칙, AI 는 요약만.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	depsDevBase   = "https://api.deps.dev"   // 시험에서 바꾼다
	githubAPIBase = "https://api.github.com" // 시험에서 바꾼다
	upHTTP        = &http.Client{Timeout: 25 * time.Second}
	upCacheTTL    = 24 * time.Hour
	upAdvTTL      = 7 * 24 * time.Hour
	upMaxComps    = 1000 // 실행당 구성요소 상한
	upKeyChecks   = []string{"Maintained", "Code-Review", "Signed-Releases", "Security-Policy", "Vulnerabilities",
		"Branch-Protection", "Dangerous-Workflow", "Pinned-Dependencies", "SAST", "Fuzzing"}
	errGHLimit = errors.New("GitHub API 요청 한도 도달")

	ghRateMu       sync.Mutex
	ghRate         upRate    // 마지막으로 본 GitHub 한도 헤더
	ghLimitedUntil time.Time // 이 시각까지 GitHub 호출을 쉰다(한도 초과)
)

func upstreamDir() string { return env("UPSTREAM_DIR", "/var/lib/trustlink/upstream") }

// ---------- 자료형 ----------

type upRate struct {
	Limit     int    `json:"limit"`
	Remaining int    `json:"remaining"`
	Reset     string `json:"reset,omitempty"` // RFC3339
	Hit       bool   `json:"hit"`             // 이번 실행 중 한도에 걸림
	Auth      bool   `json:"auth"`            // 토큰 사용
}

type upRepo struct {
	ID            string         `json:"id"` // github.com/owner/repo
	URL           string         `json:"url"`
	Host          string         `json:"host"`
	Stars         int            `json:"stars,omitempty"`
	Forks         int            `json:"forks,omitempty"`
	OpenIssues    int            `json:"openIssues,omitempty"`
	Scorecard     *float64       `json:"scorecard,omitempty"`
	ScorecardDate string         `json:"scorecardDate,omitempty"`
	Checks        map[string]int `json:"checks,omitempty"` // 주요 Scorecard 점검 점수(-1 = 해당 없음)
	Archived      bool           `json:"archived"`
	Disabled      bool           `json:"disabled"`
	Fork          bool           `json:"fork,omitempty"`
	PushedAt      string         `json:"pushedAt,omitempty"`
	License       string         `json:"license,omitempty"`
	Release       string         `json:"release,omitempty"` // 최근 릴리스 태그
	ReleaseAt     string         `json:"releaseAt,omitempty"`
	SecPolicy     *bool          `json:"secPolicy,omitempty"` // nil = 확인 못함
	SecPolicySrc  string         `json:"secPolicySrc,omitempty"`
	Advisories    *int           `json:"advisories,omitempty"` // 공개된 저장소 보안 권고 수
	AdvCritical   int            `json:"advCritical,omitempty"`
	AdvHigh       int            `json:"advHigh,omitempty"`
	AdvOpenCrit   int            `json:"advOpenCritical,omitempty"` // 패치 버전이 없는 치명 권고
	DepsDev       string         `json:"depsDev"`                   // ok / not-found / error
	GitHub        string         `json:"github"`                    // ok / not-found / rate-limited / skipped / error / n/a
	FetchedAt     string         `json:"fetchedAt,omitempty"`
	Cached        bool           `json:"cached,omitempty"`
	Rating        string         `json:"rating,omitempty"`
	Reasons       []string       `json:"reasons,omitempty"`
	Comps         int            `json:"comps,omitempty"` // 이 저장소를 쓰는 구성요소 수
}

type upComp struct {
	Name         string   `json:"name"`
	Version      string   `json:"version,omitempty"`
	Purl         string   `json:"purl,omitempty"`
	System       string   `json:"system,omitempty"` // deps.dev 시스템(NPM·GO·…)
	Repo         string   `json:"repo,omitempty"`   // upRepo.ID
	RepoSrc      string   `json:"repoSrc,omitempty"`
	Deprecated   bool     `json:"deprecated,omitempty"`
	Vulns        []string `json:"vulns,omitempty"` // 이 버전에 걸린 권고 ID
	VulnCritical int      `json:"vulnCritical,omitempty"`
	VulnHigh     int      `json:"vulnHigh,omitempty"`
	Rating       string   `json:"rating"` // risk / warn / ok / unknown
	Reasons      []string `json:"reasons,omitempty"`
}

type upInput struct{ Name, Version, Purl, VCS string }

type upFlag struct {
	Name    string   `json:"name"`
	Version string   `json:"version,omitempty"`
	Repo    string   `json:"repo,omitempty"`
	Rating  string   `json:"rating"`
	Reasons []string `json:"reasons"`
}

type upDepGraph struct {
	Packages   int            `json:"packages"`
	Ecosystems map[string]int `json:"ecosystems,omitempty"`
	Sample     []string       `json:"sample,omitempty"`
	Error      string         `json:"error,omitempty"`
}

type upSummary struct {
	Headline  string   `json:"headline"`
	Points    []string `json:"points"`
	Actions   []string `json:"actions"`
	Citations []string `json:"citations"`
}

type upReport struct {
	ID         string             `json:"id"`
	Kind       string             `json:"kind"` // product / repo
	Repo       string             `json:"repo,omitempty"`
	Tag        string             `json:"tag,omitempty"`
	Target     string             `json:"target,omitempty"` // 단건 분석 저장소 URL
	Created    string             `json:"created"`
	CreatedBy  string             `json:"createdBy"`
	Finished   string             `json:"finished,omitempty"`
	State      string             `json:"state"` // running / done / error
	Progress   string             `json:"progress,omitempty"`
	Error      string             `json:"error,omitempty"`
	SBOM       string             `json:"sbom,omitempty"`
	Comps      []upComp           `json:"comps"`
	Repos      map[string]*upRepo `json:"repos"`
	Counts     map[string]int     `json:"counts"`
	Top        []upFlag           `json:"top"`
	Replace    []upFlag           `json:"replace"`
	Rate       *upRate            `json:"rate,omitempty"`
	Notes      []string           `json:"notes,omitempty"`
	DepGraph   *upDepGraph        `json:"depGraph,omitempty"`
	Summary    *upSummary         `json:"summary,omitempty"`
	AIError    string             `json:"aiError,omitempty"`
	AIMeta     *aiMeta            `json:"aiMeta,omitempty"`
	Disclaimer string             `json:"disclaimer"`
}

const upDisclaimer = "공개 데이터(deps.dev·OpenSSF Scorecard·GitHub)를 조회 시점 기준으로 규칙 판정한 결과입니다. " +
	"저장소 매핑은 패키지 메타데이터에 의존하므로 틀릴 수 있으며, 교체·포크 결정 전 사람이 확인해야 합니다."

// ---------- purl · 저장소 주소 ----------

// purl 해석은 ai_remedy.go 의 parsePurl 을 쓴다.

// depsDevPkg: purl → deps.dev 시스템·패키지 이름. 지원하지 않는 종류면 빈 값.
func depsDevPkg(pp purlParts) (system, name string) {
	join := func(sep string) string {
		if pp.Namespace == "" {
			return pp.Name
		}
		return pp.Namespace + sep + pp.Name
	}
	switch pp.Type {
	case "npm":
		return "NPM", join("/")
	case "golang":
		return "GO", join("/")
	case "maven":
		return "MAVEN", join(":")
	case "pypi":
		return "PYPI", strings.ToLower(pp.Name)
	case "cargo":
		return "CARGO", pp.Name
	case "nuget":
		return "NUGET", pp.Name
	case "gem":
		return "RUBYGEMS", pp.Name
	}
	return "", ""
}

// purlRepo: purl 자체가 저장소를 가리키는 경우(github·Go 모듈 github.com/…·GitHub Actions).
func purlRepo(pp purlParts) string {
	switch pp.Type {
	case "github", "githubactions":
		if pp.Namespace != "" {
			return strings.ToLower("github.com/" + strings.Split(pp.Namespace, "/")[0] + "/" + strings.Split(pp.Name, "/")[0])
		}
	case "golang":
		return goVanityRepo(pp.Namespace + "/" + pp.Name)
	}
	return ""
}

// goVanityRepo: Go 모듈 경로 → GitHub 저장소. 자주 쓰는 별칭 경로(golang.org/x 등)는 공식 GitHub 미러로.
func goVanityRepo(mod string) string {
	if r := repoFromURL(mod); r != "" {
		return r
	}
	seg := strings.Split(mod, "/")
	if len(seg) < 2 {
		return ""
	}
	gh := func(o, r string) string { return strings.ToLower("github.com/" + o + "/" + r) }
	switch {
	case seg[0] == "golang.org" && seg[1] == "x" && len(seg) > 2:
		return gh("golang", seg[2])
	case seg[0] == "k8s.io":
		return gh("kubernetes", seg[1])
	case seg[0] == "sigs.k8s.io":
		return gh("kubernetes-sigs", seg[1])
	case seg[0] == "google.golang.org":
		return map[string]string{"grpc": gh("grpc", "grpc-go"), "protobuf": gh("protocolbuffers", "protobuf-go"),
			"genproto": gh("googleapis", "go-genproto"), "api": gh("googleapis", "google-api-go-client")}[seg[1]]
	case seg[0] == "go.opentelemetry.io" && seg[1] == "otel":
		return gh("open-telemetry", "opentelemetry-go")
	case seg[0] == "gopkg.in": // gopkg.in/yaml.v3 → go-yaml/yaml, gopkg.in/user/pkg.v1 → user/pkg
		name := seg[len(seg)-1]
		if i := strings.LastIndex(name, ".v"); i > 0 {
			name = name[:i]
		}
		if len(seg) == 2 {
			return gh("go-"+name, name)
		}
		return gh(seg[1], name)
	}
	return ""
}

var upRepoHosts = map[string]bool{"github.com": true, "gitlab.com": true, "bitbucket.org": true}

// repoFromURL: 여러 형태의 VCS 주소 → host/owner/repo (소문자). 지원 호스트가 아니면 "".
// 예) git+https://github.com/o/r.git, git@github.com:o/r.git, https://github.com/o/r/tree/main, github.com/o/r/v2
func repoFromURL(u string) string {
	s := strings.TrimSpace(u)
	s = strings.TrimPrefix(s, "git+")
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if at := strings.Index(s, "@"); at >= 0 && at < strings.IndexAny(s+"/", "/:") { // user@host
		s = s[at+1:]
	}
	s = strings.Replace(s, ":", "/", 1) // git@host:o/r
	s = strings.TrimPrefix(s, "www.")
	seg := strings.Split(s, "/")
	if len(seg) < 3 {
		return ""
	}
	host := strings.ToLower(seg[0])
	if i := strings.LastIndex(host, "/"); i >= 0 {
		host = host[i+1:]
	}
	if !upRepoHosts[host] {
		return ""
	}
	owner, repo := seg[1], strings.TrimSuffix(seg[2], ".git")
	if !ghNameRe.MatchString(owner) || !ghNameRe.MatchString(repo) {
		return ""
	}
	return strings.ToLower(host + "/" + owner + "/" + repo)
}

var ghNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

// ---------- 캐시 ----------

func upCachePath(key string) string {
	return filepath.Join(upstreamDir(), "cache", sha256hex([]byte(key))[:32]+".json")
}

func upCacheGet(key string, ttl time.Duration, v any) bool {
	var w struct {
		Key string          `json:"key"`
		At  time.Time       `json:"at"`
		V   json.RawMessage `json:"v"`
	}
	if readJSONFile(upCachePath(key), &w) != nil || w.Key != key || time.Since(w.At) > ttl {
		return false
	}
	return json.Unmarshal(w.V, v) == nil
}

func upCachePut(key string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	p := upCachePath(key)
	_ = os.MkdirAll(filepath.Dir(p), 0o750)
	_ = writeJSONFile(p, map[string]any{"key": key, "at": time.Now().UTC(), "v": json.RawMessage(b)})
}

// ---------- HTTP ----------

// ddGet: deps.dev v3. 404 는 (404, nil).
func ddGet(path string, v any) (int, error) {
	resp, err := upHTTP.Get(depsDevBase + path)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return resp.StatusCode, nil
	}
	return 200, json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(v)
}

func ghLimited() bool {
	ghRateMu.Lock()
	defer ghRateMu.Unlock()
	return time.Now().Before(ghLimitedUntil)
}

func ghRateNow() upRate {
	ghRateMu.Lock()
	defer ghRateMu.Unlock()
	return ghRate
}

// ghNote: 응답의 한도 헤더를 기록. 남은 횟수가 바닥이면 재설정 시각까지 쉰다.
func ghNote(h http.Header, status int) bool {
	ghRateMu.Lock()
	defer ghRateMu.Unlock()
	reset := time.Time{}
	if v, err := strconv.ParseInt(h.Get("X-RateLimit-Reset"), 10, 64); err == nil {
		reset = time.Unix(v, 0)
		ghRate.Reset = reset.UTC().Format(time.RFC3339)
	}
	if v, err := strconv.Atoi(h.Get("X-RateLimit-Limit")); err == nil {
		ghRate.Limit = v
	}
	rem, remErr := strconv.Atoi(h.Get("X-RateLimit-Remaining"))
	if remErr == nil {
		ghRate.Remaining = rem
	}
	limited := false
	if status == 403 || status == 429 {
		if ra, err := strconv.Atoi(h.Get("Retry-After")); err == nil { // 2차 한도
			ghLimitedUntil, limited = time.Now().Add(time.Duration(ra)*time.Second), true
		} else if remErr == nil && rem == 0 {
			limited = true
		}
	}
	if remErr == nil && rem == 0 && !reset.IsZero() {
		ghLimitedUntil = reset
	}
	if limited {
		ghRate.Hit = true
		if ghLimitedUntil.Before(time.Now()) {
			ghLimitedUntil = time.Now().Add(time.Minute)
		}
	}
	return limited
}

// ghGet: GitHub REST. path 는 /repos/… 또는 같은 API 의 절대 주소. 200 이 아니면 (코드, nil), 한도면 errGHLimit.
func ghGet(token, path string, v any) (int, error) {
	if ghLimited() {
		return 0, errGHLimit
	}
	u := path
	if !strings.HasPrefix(u, "http") {
		u = githubAPIBase + path
	}
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "trustlink-upstream")
	if token != "" && strings.HasPrefix(u, githubAPIBase) {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := upHTTP.Do(req)
	if err != nil {
		return 0, errors.New(redactKey(err.Error(), token))
	}
	defer resp.Body.Close()
	if ghNote(resp.Header, resp.StatusCode) {
		return resp.StatusCode, errGHLimit
	}
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return resp.StatusCode, nil
	}
	if v == nil {
		return resp.StatusCode, nil
	}
	return resp.StatusCode, json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(v)
}

// ---------- deps.dev ----------

type ddVersion struct {
	IsDeprecated bool `json:"isDeprecated"`
	AdvisoryKeys []struct {
		ID string `json:"id"`
	} `json:"advisoryKeys"`
	Links []struct {
		Label string `json:"label"`
		URL   string `json:"url"`
	} `json:"links"`
	RelatedProjects []struct {
		ProjectKey struct {
			ID string `json:"id"`
		} `json:"projectKey"`
		RelationType string `json:"relationType"`
	} `json:"relatedProjects"`
	NotFound bool `json:"notFound,omitempty"` // 캐시용
}

func ddVersionGet(system, name, version string) (*ddVersion, error) {
	key := "ddv|" + system + "|" + name + "|" + version
	var v ddVersion
	if upCacheGet(key, upCacheTTL, &v) {
		return &v, nil
	}
	code, err := ddGet("/v3/systems/"+url.PathEscape(strings.ToLower(system))+"/packages/"+url.QueryEscape(name)+"/versions/"+url.QueryEscape(version), &v)
	if err != nil {
		return nil, err
	}
	if code == 404 {
		v = ddVersion{NotFound: true}
	} else if code != 200 {
		return nil, fmt.Errorf("deps.dev %d", code)
	}
	upCachePut(key, v)
	return &v, nil
}

// repo: 관련 프로젝트(SOURCE_REPO 우선) → 링크 SOURCE_REPO 순.
func (v *ddVersion) repo() string {
	for _, pass := range []bool{true, false} {
		for _, p := range v.RelatedProjects {
			if (!pass || p.RelationType == "SOURCE_REPO") && p.ProjectKey.ID != "" {
				if r := repoFromURL(p.ProjectKey.ID); r != "" {
					return r
				}
			}
		}
	}
	for _, l := range v.Links {
		if l.Label == "SOURCE_REPO" {
			if r := repoFromURL(l.URL); r != "" {
				return r
			}
		}
	}
	return ""
}

// ddAdvScore: 권고 CVSS3 점수(모르면 0). 7일 캐시.
func ddAdvScore(id string) float64 {
	var a struct {
		CVSS3Score float64 `json:"cvss3Score"`
	}
	key := "dda|" + id
	if upCacheGet(key, upAdvTTL, &a) {
		return a.CVSS3Score
	}
	if code, err := ddGet("/v3/advisories/"+url.PathEscape(id), &a); err != nil || code != 200 {
		return 0
	}
	upCachePut(key, a)
	return a.CVSS3Score
}

type ddProject struct {
	OpenIssuesCount int    `json:"openIssuesCount"`
	StarsCount      int    `json:"starsCount"`
	ForksCount      int    `json:"forksCount"`
	License         string `json:"license"`
	Scorecard       *struct {
		Date         string  `json:"date"`
		OverallScore float64 `json:"overallScore"`
		Checks       []struct {
			Name  string `json:"name"`
			Score int    `json:"score"`
		} `json:"checks"`
	} `json:"scorecard"`
}

// ---------- 저장소 신호 ----------

type upEngine struct {
	token    string
	maxRepos int
	mu       sync.Mutex
	ghRepos  int // 이번 실행에서 GitHub 을 조회한 저장소 수
	limitHit bool
}

// fetchRepo: 저장소 신호(캐시 우선). 완전한 결과만 캐시한다.
func (e *upEngine) fetchRepo(id string) *upRepo {
	var r upRepo
	if upCacheGet("repo|"+id, upCacheTTL, &r) {
		r.Cached = true
		return &r
	}
	host := strings.SplitN(id, "/", 2)[0]
	r = upRepo{ID: id, URL: "https://" + id, Host: host, DepsDev: "ok", GitHub: "n/a"}
	var p ddProject
	if code, err := ddGet("/v3/projects/"+url.QueryEscape(id), &p); err != nil || (code != 200 && code != 404) {
		r.DepsDev = "error"
	} else if code == 404 {
		r.DepsDev = "not-found"
	} else {
		r.Stars, r.Forks, r.OpenIssues, r.License = p.StarsCount, p.ForksCount, p.OpenIssuesCount, p.License
		if sc := p.Scorecard; sc != nil {
			s := sc.OverallScore
			r.Scorecard, r.ScorecardDate, r.Checks = &s, sc.Date, map[string]int{}
			for _, c := range sc.Checks {
				if inList(c.Name, upKeyChecks) {
					r.Checks[c.Name] = c.Score
				}
			}
			if v, ok := r.Checks["Security-Policy"]; ok && v >= 0 {
				b := v > 0
				r.SecPolicy, r.SecPolicySrc = &b, "scorecard"
			}
		}
	}
	if host == "github.com" {
		e.mu.Lock()
		skip := e.ghRepos >= e.maxRepos
		if !skip {
			e.ghRepos++
		}
		e.mu.Unlock()
		if skip {
			r.GitHub = "skipped"
		} else {
			r.GitHub = e.github(&r)
		}
	}
	r.FetchedAt = time.Now().UTC().Format(time.RFC3339)
	if r.DepsDev != "error" && r.GitHub != "rate-limited" && r.GitHub != "skipped" && r.GitHub != "error" {
		upCachePut("repo|"+id, r)
	}
	return &r
}

// github: 저장소·최근 릴리스·보안 권고·SECURITY.md. 반환: 상태.
func (e *upEngine) github(r *upRepo) string {
	owner, name, _ := strings.Cut(strings.TrimPrefix(r.ID, "github.com/"), "/")
	base := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name)
	st := func(err error) string {
		if errors.Is(err, errGHLimit) {
			e.mu.Lock()
			e.limitHit = true
			e.mu.Unlock()
			return "rate-limited"
		}
		return "error"
	}
	var g struct {
		HTMLURL  string `json:"html_url"`
		Archived bool   `json:"archived"`
		Disabled bool   `json:"disabled"`
		Fork     bool   `json:"fork"`
		PushedAt string `json:"pushed_at"`
		Stars    int    `json:"stargazers_count"`
		License  *struct {
			SPDX string `json:"spdx_id"`
		} `json:"license"`
	}
	code, err := ghGet(e.token, base, &g)
	if err != nil {
		return st(err)
	}
	if code == 404 || code == 451 {
		return "not-found"
	}
	if code != 200 {
		return "error"
	}
	r.URL, r.Archived, r.Disabled, r.Fork, r.PushedAt = firstNonEmpty(g.HTMLURL, r.URL), g.Archived, g.Disabled, g.Fork, g.PushedAt
	if r.Stars == 0 {
		r.Stars = g.Stars
	}
	if g.License != nil && okLic(g.License.SPDX) {
		r.License = g.License.SPDX
	}
	var rel struct {
		Tag         string `json:"tag_name"`
		PublishedAt string `json:"published_at"`
	}
	if _, err := ghGet(e.token, base+"/releases/latest", &rel); err != nil {
		return st(err)
	}
	r.Release, r.ReleaseAt = rel.Tag, rel.PublishedAt
	var advs []struct {
		Severity        string `json:"severity"`
		Vulnerabilities []struct {
			Patched *string `json:"patched_versions"`
		} `json:"vulnerabilities"`
	}
	code, err = ghGet(e.token, base+"/security-advisories?state=published&per_page=100", &advs)
	if err != nil {
		return st(err)
	}
	if code == 200 {
		n := len(advs)
		r.Advisories = &n
		for _, a := range advs {
			switch a.Severity {
			case "critical":
				r.AdvCritical++
				open := len(a.Vulnerabilities) == 0
				for _, v := range a.Vulnerabilities {
					if v.Patched == nil || strings.TrimSpace(*v.Patched) == "" {
						open = true
					}
				}
				if open {
					r.AdvOpenCrit++
				}
			case "high":
				r.AdvHigh++
			}
		}
	}
	if r.SecPolicy == nil { // Scorecard 에 없을 때만 직접 확인(호출 수 절약)
		found := false
		for _, p := range []string{"SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"} {
			code, err := ghGet(e.token, base+"/contents/"+p, nil)
			if err != nil {
				return st(err)
			}
			if code == 200 {
				found = true
				break
			}
		}
		r.SecPolicy, r.SecPolicySrc = &found, "github"
	}
	return "ok"
}

// ---------- 등급 ----------

func ageDays(ts string, now time.Time) int {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return -1
	}
	return int(now.Sub(t).Hours() / 24)
}

func yearsKo(d int) string {
	if d >= 365 {
		return fmt.Sprintf("%.1f년", float64(d)/365)
	}
	return itoa(d/30) + "개월"
}

// rateRepo: 저장소 신호 → 위험·주의 사유.
func rateRepo(r *upRepo, now time.Time) (risk, warn []string) {
	if r.Archived {
		risk = append(risk, "저장소 보관(archived) — 유지보수 종료")
	}
	if r.Disabled {
		risk = append(risk, "저장소 비활성(disabled)")
	}
	if d := ageDays(r.PushedAt, now); d >= 730 {
		risk = append(risk, "마지막 커밋 "+yearsKo(d)+" 전(2년 이상)")
	} else if d >= 365 {
		warn = append(warn, "마지막 커밋 "+yearsKo(d)+" 전(1년 이상)")
	} else if d < 0 {
		if v, ok := r.Checks["Maintained"]; ok && v == 0 {
			warn = append(warn, "Scorecard Maintained 0점 — 최근 90일 활동 없음")
		}
	}
	if r.Scorecard != nil {
		if *r.Scorecard < 3 {
			risk = append(risk, fmt.Sprintf("OpenSSF Scorecard %.1f (3 미만)", *r.Scorecard))
		} else if *r.Scorecard < 5 {
			warn = append(warn, fmt.Sprintf("OpenSSF Scorecard %.1f (5 미만)", *r.Scorecard))
		}
	}
	if v, ok := r.Checks["Dangerous-Workflow"]; ok && v == 0 {
		warn = append(warn, "위험한 GitHub Actions 워크플로 패턴(Dangerous-Workflow 0점)")
	}
	if r.AdvOpenCrit > 0 {
		risk = append(risk, "패치 버전이 없는 치명 보안 권고 "+itoa(r.AdvOpenCrit)+"건")
	}
	if r.SecPolicy != nil && !*r.SecPolicy {
		warn = append(warn, "보안 정책(SECURITY.md) 없음 — 취약점 신고 창구 불명")
	}
	if d := ageDays(r.ReleaseAt, now); d >= 730 && ageDays(r.PushedAt, now) < 730 {
		warn = append(warn, "최근 릴리스 "+yearsKo(d)+" 전")
	}
	return
}

// hasSignals: 판정에 쓸 신호가 하나라도 있는가.
func (r *upRepo) hasSignals() bool {
	return r.DepsDev == "ok" || r.GitHub == "ok"
}

func rateLevel(risk, warn []string, known bool) string {
	switch {
	case len(risk) > 0:
		return "risk"
	case len(warn) > 0:
		return "warn"
	case known:
		return "ok"
	}
	return "unknown"
}

func rateComp(c *upComp, r *upRepo, now time.Time) {
	var risk, warn []string
	if c.VulnCritical > 0 {
		risk = append(risk, "이 버전에 치명(CVSS 9+) 취약점 권고 "+itoa(c.VulnCritical)+"건")
	}
	if c.VulnHigh > 0 {
		warn = append(warn, "이 버전에 높음(CVSS 7+) 취약점 권고 "+itoa(c.VulnHigh)+"건")
	}
	if c.Deprecated {
		warn = append(warn, "패키지 레지스트리에서 사용 중단(deprecated) 표시")
	}
	known := false
	if r != nil {
		rr, rw := rateRepo(r, now)
		risk, warn = append(risk, rr...), append(warn, rw...)
		known = r.hasSignals()
		if !known {
			warn = append(warn, "저장소 신호 조회 실패")
		}
	}
	c.Rating = rateLevel(risk, warn, known)
	c.Reasons = append(risk, warn...)
	if r == nil && c.Rating != "risk" {
		c.Rating = "unknown"
		c.Reasons = append(c.Reasons, firstNonEmpty(c.RepoSrc, "상류 저장소를 찾지 못함"))
	}
}

// replaceCandidate: 교체·포크 검토 대상(유지보수 중단 징후).
func replaceCandidate(r *upRepo, deprecated bool, now time.Time) bool {
	return deprecated || (r != nil && (r.Archived || r.Disabled || ageDays(r.PushedAt, now) >= 730))
}

// summarize: 등급 집계·상위 위험·교체 후보.
func summarize(rep *upReport, now time.Time) {
	rep.Counts = map[string]int{"risk": 0, "warn": 0, "ok": 0, "unknown": 0}
	rep.Top, rep.Replace = []upFlag{}, []upFlag{}
	for _, r := range rep.Repos {
		r.Comps = 0
		risk, warn := rateRepo(r, now)
		r.Rating, r.Reasons = rateLevel(risk, warn, r.hasSignals()), append(risk, warn...)
	}
	seen := map[string]bool{}
	idx := []int{}
	for i := range rep.Comps {
		c := &rep.Comps[i]
		rep.Counts[c.Rating]++
		r := rep.Repos[c.Repo]
		if r != nil {
			r.Comps++
		}
		if c.Rating == "risk" {
			idx = append(idx, i)
		}
		if replaceCandidate(r, c.Deprecated, now) && !seen[c.Repo+"|"+c.Name] {
			seen[c.Repo+"|"+c.Name] = true
			rep.Replace = append(rep.Replace, upFlag{c.Name, c.Version, c.Repo, c.Rating, c.Reasons})
		}
	}
	sort.SliceStable(idx, func(a, b int) bool { return len(rep.Comps[idx[a]].Reasons) > len(rep.Comps[idx[b]].Reasons) })
	for i, k := range idx {
		if i >= 15 {
			break
		}
		c := rep.Comps[k]
		rep.Top = append(rep.Top, upFlag{c.Name, c.Version, c.Repo, c.Rating, c.Reasons})
	}
}

// ---------- 구성요소 → 저장소 ----------

// resolve: 구성요소 하나의 시스템·저장소·버전 권고.
func resolveComp(in upInput) upComp {
	c := upComp{Name: in.Name, Version: in.Version, Purl: in.Purl}
	pp, ok := parsePurl(in.Purl)
	if ok {
		if c.Version == "" {
			c.Version = pp.Version
		}
		if r := purlRepo(pp); r != "" {
			c.Repo, c.RepoSrc = r, "purl"
		}
		sys, name := depsDevPkg(pp)
		c.System = sys
		if sys != "" && pp.Version != "" {
			if v, err := ddVersionGet(sys, name, pp.Version); err == nil && !v.NotFound {
				c.Deprecated = v.IsDeprecated
				if c.Repo == "" {
					if r := v.repo(); r != "" {
						c.Repo, c.RepoSrc = r, "deps.dev"
					}
				}
				for i, a := range v.AdvisoryKeys {
					c.Vulns = append(c.Vulns, a.ID)
					if i >= 25 {
						continue // 점수 조회는 25건까지
					}
					switch sc := ddAdvScore(a.ID); {
					case sc >= 9:
						c.VulnCritical++
					case sc >= 7:
						c.VulnHigh++
					}
				}
			}
		}
	}
	if c.Repo == "" && in.VCS != "" {
		if r := repoFromURL(in.VCS); r != "" {
			c.Repo, c.RepoSrc = r, "sbom"
		}
	}
	if c.Repo == "" {
		switch {
		case !ok:
			c.RepoSrc = "purl 없음 — 저장소 매핑 불가"
		case c.System == "":
			c.RepoSrc = pp.Type + " 패키지 — 상류 저장소 자동 매핑 미지원"
		default:
			c.RepoSrc = "패키지 메타데이터에 소스 저장소 정보 없음"
		}
	}
	return c
}

// parseUpInputs: CycloneDX(중첩 components 포함)·SPDX → 구성요소 목록(purl·VCS 주소).
func parseUpInputs(b []byte) ([]upInput, string) {
	type cdxComp struct {
		Name     string                       `json:"name"`
		Version  string                       `json:"version"`
		Purl     string                       `json:"purl"`
		ExtRefs  []struct{ Type, URL string } `json:"externalReferences"`
		Children []json.RawMessage            `json:"components"`
	}
	var cdx struct {
		BomFormat   string            `json:"bomFormat"`
		SpecVersion string            `json:"specVersion"`
		Components  []json.RawMessage `json:"components"`
	}
	out := []upInput{}
	if json.Unmarshal(b, &cdx) == nil && cdx.BomFormat != "" {
		var walk func([]json.RawMessage, int)
		walk = func(l []json.RawMessage, depth int) {
			for _, raw := range l {
				var c cdxComp
				if json.Unmarshal(raw, &c) != nil {
					continue
				}
				in := upInput{Name: c.Name, Version: c.Version, Purl: c.Purl}
				for _, r := range c.ExtRefs {
					if r.Type == "vcs" && in.VCS == "" {
						in.VCS = r.URL
					}
				}
				out = append(out, in)
				if depth < 8 {
					walk(c.Children, depth+1)
				}
			}
		}
		walk(cdx.Components, 0)
		return out, "CycloneDX " + cdx.SpecVersion
	}
	var spdx struct {
		SpdxVersion string `json:"spdxVersion"`
		Packages    []struct {
			Name         string `json:"name"`
			VersionInfo  string `json:"versionInfo"`
			Download     string `json:"downloadLocation"`
			ExternalRefs []struct {
				Type    string `json:"referenceType"`
				Locator string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
	}
	if json.Unmarshal(b, &spdx) == nil && spdx.SpdxVersion != "" {
		for _, p := range spdx.Packages {
			in := upInput{Name: p.Name, Version: p.VersionInfo}
			for _, e := range p.ExternalRefs {
				if e.Type == "purl" && in.Purl == "" {
					in.Purl = e.Locator
				}
			}
			if repoFromURL(p.Download) != "" {
				in.VCS = p.Download
			}
			out = append(out, in)
		}
		return out, strings.Replace(spdx.SpdxVersion, "SPDX-", "SPDX ", 1)
	}
	return nil, ""
}

// dedupInputs: purl(없으면 이름@버전) 기준 중복 제거.
func dedupInputs(in []upInput) []upInput {
	seen := map[string]bool{}
	out := []upInput{}
	for _, c := range in {
		k := c.Purl
		if k == "" {
			k = c.Name + "@" + c.Version
		}
		if c.Name == "" && c.Purl == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, c)
	}
	return out
}

// parallel: n 개 작업을 w 개씩 동시에.
func parallel(n, w int, f func(i int)) {
	var wg sync.WaitGroup
	ch := make(chan int)
	for k := 0; k < w; k++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range ch {
				f(i)
			}
		}()
	}
	for i := 0; i < n; i++ {
		ch <- i
	}
	close(ch)
	wg.Wait()
}

// analyze: 구성요소 목록 → 보고서 본문. progress 는 진행 상황 기록.
func (e *upEngine) analyze(inputs []upInput, progress func(string)) (comps []upComp, repos map[string]*upRepo, notes []string) {
	inputs = dedupInputs(inputs)
	if len(inputs) > upMaxComps {
		notes = append(notes, fmt.Sprintf("구성요소 %d개 중 앞 %d개만 분석했습니다(실행당 상한).", len(inputs), upMaxComps))
		inputs = inputs[:upMaxComps]
	}
	comps = make([]upComp, len(inputs))
	var mu sync.Mutex
	done := 0
	parallel(len(inputs), 6, func(i int) {
		comps[i] = resolveComp(inputs[i])
		mu.Lock()
		done++
		d := done
		mu.Unlock()
		if d%10 == 0 || d == len(inputs) {
			progress(fmt.Sprintf("구성요소 %d/%d — 상류 저장소 찾는 중", d, len(inputs)))
		}
	})
	// 저장소: 쓰는 구성요소가 많은 순(GitHub 조회 상한 안에서 중요한 것부터)
	use := map[string]int{}
	for _, c := range comps {
		if c.Repo != "" {
			use[c.Repo]++
		}
	}
	ids := make([]string, 0, len(use))
	for id := range use {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(a, b int) bool {
		if use[ids[a]] != use[ids[b]] {
			return use[ids[a]] > use[ids[b]]
		}
		return ids[a] < ids[b]
	})
	repos = map[string]*upRepo{}
	list := make([]*upRepo, len(ids))
	done = 0
	// 캐시에 있는 것을 먼저 꺼내 GitHub 상한을 새 저장소에 쓴다
	pending := []int{}
	for i, id := range ids {
		var r upRepo
		if upCacheGet("repo|"+id, upCacheTTL, &r) {
			r.Cached = true
			list[i] = &r
		} else {
			pending = append(pending, i)
		}
	}
	parallel(len(pending), 3, func(k int) {
		i := pending[k]
		list[i] = e.fetchRepo(ids[i])
		mu.Lock()
		done++
		d := done
		mu.Unlock()
		progress(fmt.Sprintf("저장소 %d/%d 점검 중 (캐시 %d)", d, len(pending), len(ids)-len(pending)))
	})
	for i, id := range ids {
		repos[id] = list[i]
	}
	now := time.Now()
	for i := range comps {
		rateComp(&comps[i], repos[comps[i].Repo], now)
	}
	sk, rl := 0, 0
	for _, r := range repos {
		switch r.GitHub {
		case "skipped":
			sk++
		case "rate-limited":
			rl++
		}
	}
	if sk > 0 {
		notes = append(notes, fmt.Sprintf("GitHub 조회 상한(실행당 %d개)을 넘어 저장소 %d개는 deps.dev 정보만으로 판정했습니다. 다시 실행하면 캐시 덕분에 나머지를 이어서 조회합니다.", e.maxRepos, sk))
	}
	if rl > 0 {
		rt := ghRateNow()
		notes = append(notes, fmt.Sprintf("GitHub API 요청 한도에 걸려 저장소 %d개는 deps.dev 정보만으로 판정했습니다(한도 재설정 %s). GitHub 토큰을 등록하면 시간당 5,000회까지 조회합니다.", rl, firstNonEmpty(rt.Reset, "—")))
	}
	return comps, repos, notes
}
