package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// upTestEnv: 캐시·보고서·설정을 임시 디렉터리로, AI 끔, GitHub 한도 상태 초기화.
func upTestEnv(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	t.Setenv("UPSTREAM_DIR", filepath.Join(d, "up"))
	t.Setenv("UPSTREAM_CONFIG", filepath.Join(d, "upstream-config.json"))
	t.Setenv("AI_CONFIG", filepath.Join(d, "none.json"))
	t.Setenv("AI_URL", "")
	ghRateMu.Lock()
	ghRate, ghLimitedUntil = upRate{}, time.Time{}
	ghRateMu.Unlock()
	return d
}

func setBases(t *testing.T, dd, gh string) {
	t.Helper()
	od, og := depsDevBase, githubAPIBase
	depsDevBase, githubAPIBase = dd, gh
	t.Cleanup(func() { depsDevBase, githubAPIBase = od, og })
}

func TestRepoFromURL(t *testing.T) {
	cases := map[string]string{
		"git+https://github.com/expressjs/express.git": "github.com/expressjs/express",
		"git@github.com:Owner/Repo.git":                "github.com/owner/repo",
		"https://github.com/o/r/tree/main/sub":         "github.com/o/r",
		"github.com/golang/net/v2":                     "github.com/golang/net",
		"git://gitlab.com/g/p":                         "gitlab.com/g/p",
		"https://gitbox.apache.org/repos/asf?p=x.git":  "",
		"https://github.com/onlyowner":                 "",
		"https://example.com/github.com/a/b":           "",
		"ssh://git@github.com/a/b.git":                 "github.com/a/b",
	}
	for in, want := range cases {
		if got := repoFromURL(in); got != want {
			t.Errorf("repoFromURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDepsDevPkgAndPurlRepo(t *testing.T) {
	type c struct{ purl, sys, name, repo string }
	for _, x := range []c{
		{"pkg:npm/%40babel/core@7.24.0", "NPM", "@babel/core", ""},
		{"pkg:maven/org.apache.commons/commons-lang3@3.12.0", "MAVEN", "org.apache.commons:commons-lang3", ""},
		{"pkg:golang/github.com/sirupsen/logrus@v1.9.3", "GO", "github.com/sirupsen/logrus", "github.com/sirupsen/logrus"},
		{"pkg:pypi/Django@4.2", "PYPI", "django", ""},
		{"pkg:github/Owner/Repo@v1", "", "", "github.com/owner/repo"},
		{"pkg:githubactions/actions/checkout@v4", "", "", "github.com/actions/checkout"},
		{"pkg:deb/debian/openssl@3.0.11?arch=amd64", "", "", ""},
		{"pkg:golang/golang.org/x/net@v0.20.0", "GO", "golang.org/x/net", "github.com/golang/net"},
		{"pkg:golang/gopkg.in/yaml.v3@v3.0.1", "GO", "gopkg.in/yaml.v3", "github.com/go-yaml/yaml"},
		{"pkg:golang/k8s.io/client-go@v0.30.0", "GO", "k8s.io/client-go", "github.com/kubernetes/client-go"},
	} {
		pp, ok := parsePurl(x.purl)
		if !ok {
			t.Fatalf("parsePurl(%q) 실패", x.purl)
		}
		sys, name := depsDevPkg(pp)
		if sys != x.sys || name != x.name {
			t.Errorf("%s: depsDevPkg = %s %s", x.purl, sys, name)
		}
		if r := purlRepo(pp); r != x.repo {
			t.Errorf("%s: purlRepo = %q", x.purl, r)
		}
	}
}

func f64(v float64) *float64 { return &v }
func bptr(v bool) *bool      { return &v }

func TestRateRepoAndComp(t *testing.T) {
	now := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	old := now.AddDate(-3, 0, 0).Format(time.RFC3339)
	mid := now.AddDate(-1, -2, 0).Format(time.RFC3339)
	fresh := now.AddDate(0, -1, 0).Format(time.RFC3339)

	r := &upRepo{ID: "github.com/a/b", DepsDev: "ok", GitHub: "ok", Archived: true, PushedAt: old, Scorecard: f64(2.1)}
	risk, _ := rateRepo(r, now)
	if len(risk) != 3 {
		t.Fatalf("보관·오래된 커밋·낮은 Scorecard = 위험 3건이어야: %v", risk)
	}
	r = &upRepo{DepsDev: "ok", GitHub: "ok", PushedAt: mid, Scorecard: f64(4.2), SecPolicy: bptr(false)}
	risk, warn := rateRepo(r, now)
	if len(risk) != 0 || len(warn) != 3 {
		t.Fatalf("1년+ 커밋·Scorecard 4.2·보안 정책 없음 = 주의 3건: %v %v", risk, warn)
	}
	r = &upRepo{DepsDev: "ok", GitHub: "ok", PushedAt: fresh, Scorecard: f64(7.5), SecPolicy: bptr(true), AdvOpenCrit: 1}
	if risk, _ := rateRepo(r, now); len(risk) != 1 || !strings.Contains(risk[0], "패치") {
		t.Fatalf("패치 없는 치명 권고 = 위험: %v", risk)
	}
	// 구성요소: 양호 / 버전 치명 권고 / 저장소 없음
	good := &upRepo{DepsDev: "ok", GitHub: "ok", PushedAt: fresh, Scorecard: f64(8), SecPolicy: bptr(true)}
	c := upComp{Name: "x"}
	rateComp(&c, good, now)
	if c.Rating != "ok" || len(c.Reasons) != 0 {
		t.Fatalf("양호여야: %+v", c)
	}
	c = upComp{Name: "x", VulnCritical: 2}
	rateComp(&c, good, now)
	if c.Rating != "risk" {
		t.Fatalf("치명 권고 = 위험: %+v", c)
	}
	c = upComp{Name: "x", RepoSrc: "purl 없음 — 저장소 매핑 불가"}
	rateComp(&c, nil, now)
	if c.Rating != "unknown" || c.Reasons[0] != "purl 없음 — 저장소 매핑 불가" {
		t.Fatalf("미확인이어야: %+v", c)
	}
	// 신호가 하나도 없으면(조회 실패) 미확인이 아니라 주의 + 사유
	c = upComp{Name: "x"}
	rateComp(&c, &upRepo{DepsDev: "error", GitHub: "rate-limited"}, now)
	if c.Rating != "warn" {
		t.Fatalf("조회 실패 = 주의: %+v", c)
	}
	if !replaceCandidate(&upRepo{PushedAt: old}, false, now) || replaceCandidate(good, false, now) || !replaceCandidate(nil, true, now) {
		t.Fatal("교체·포크 검토 대상 판정 오류")
	}
}

func TestUpCacheTTL(t *testing.T) {
	upTestEnv(t)
	upCachePut("k1", map[string]int{"a": 1})
	var v map[string]int
	if !upCacheGet("k1", time.Hour, &v) || v["a"] != 1 {
		t.Fatal("캐시 읽기 실패")
	}
	if upCacheGet("k2", time.Hour, &v) {
		t.Fatal("없는 키가 읽힘")
	}
	// 만료: 기록 시각을 과거로
	p := upCachePath("k1")
	var w map[string]any
	_ = readJSONFile(p, &w)
	w["at"] = time.Now().Add(-2 * time.Hour)
	_ = writeJSONFile(p, w)
	if upCacheGet("k1", time.Hour, &v) {
		t.Fatal("만료된 캐시가 읽힘")
	}
}

func TestParseUpInputs(t *testing.T) {
	cdx := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
	 {"name":"a","version":"1","purl":"pkg:npm/a@1","components":[{"name":"b","version":"2","externalReferences":[{"type":"vcs","url":"https://github.com/x/b"}]}]},
	 {"name":"a","version":"1","purl":"pkg:npm/a@1"}]}`
	in, f := parseUpInputs([]byte(cdx))
	if f != "CycloneDX 1.5" || len(in) != 3 || in[1].VCS != "https://github.com/x/b" {
		t.Fatalf("CycloneDX 해석: %s %+v", f, in)
	}
	if d := dedupInputs(in); len(d) != 2 {
		t.Fatalf("중복 제거: %+v", d)
	}
	spdx := `{"spdxVersion":"SPDX-2.3","packages":[{"name":"c","versionInfo":"3","downloadLocation":"git+https://github.com/y/c.git",
	 "externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:pypi/c@3"}]}]}`
	in, f = parseUpInputs([]byte(spdx))
	if f != "SPDX 2.3" || len(in) != 1 || in[0].Purl != "pkg:pypi/c@3" || in[0].VCS == "" {
		t.Fatalf("SPDX 해석: %s %+v", f, in)
	}
}

// ---------- 모의 deps.dev · GitHub ----------

type upMocks struct {
	dd, gh   *httptest.Server
	ddCalls  atomic.Int32
	ghCalls  atomic.Int32
	ghLimit  atomic.Bool // true 면 모든 GitHub 호출에 한도 초과 응답
	ghRemain atomic.Int32
}

func newUpMocks(t *testing.T) *upMocks {
	m := &upMocks{}
	m.ghRemain.Store(50)
	now := time.Now().UTC()
	days := func(d int) string { return now.AddDate(0, 0, -d).Format(time.RFC3339) }
	ddResp := map[string]string{
		"/v3/systems/npm/packages/left-pad/versions/1.3.0": `{"isDeprecated":true,"advisoryKeys":[{"id":"GHSA-crit"}],
			"relatedProjects":[{"projectKey":{"id":"github.com/stevemao/left-pad"},"relationType":"SOURCE_REPO"}]}`,
		"/v3/systems/npm/packages/express/versions/4.18.2": `{"advisoryKeys":[{"id":"GHSA-high"}],
			"links":[{"label":"SOURCE_REPO","url":"git+https://github.com/expressjs/express.git"}],"relatedProjects":[]}`,
		"/v3/advisories/GHSA-crit":                      `{"cvss3Score":9.8}`,
		"/v3/advisories/GHSA-high":                      `{"cvss3Score":7.5}`,
		"/v3/projects/github.com%2Fstevemao%2Fleft-pad": `{"starsCount":1,"scorecard":{"date":"2026-11-01T00:00:00Z","overallScore":2.5,"checks":[{"name":"Maintained","score":0},{"name":"Packaging","score":-1}]}}`,
		"/v3/projects/github.com%2Fexpressjs%2Fexpress": `{"starsCount":69000,"scorecard":{"date":"2026-11-01T00:00:00Z","overallScore":8.5,"checks":[{"name":"Security-Policy","score":10},{"name":"Maintained","score":10}]}}`,
		"/v3/projects/github.com%2Fvendor%2Fapp":        `{"starsCount":3}`,
	}
	m.dd = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.ddCalls.Add(1)
		if b, ok := ddResp[r.URL.EscapedPath()]; ok {
			w.Write([]byte(b))
			return
		}
		http.NotFound(w, r)
	}))
	ghResp := map[string]string{
		"/repos/stevemao/left-pad":                       `{"html_url":"https://github.com/stevemao/left-pad","archived":true,"pushed_at":"` + days(2000) + `","license":{"spdx_id":"WTFPL"}}`,
		"/repos/expressjs/express":                       `{"html_url":"https://github.com/expressjs/express","pushed_at":"` + days(10) + `","license":{"spdx_id":"MIT"}}`,
		"/repos/expressjs/express/releases/latest":       `{"tag_name":"v5.3.0","published_at":"` + days(40) + `"}`,
		"/repos/expressjs/express/security-advisories":   `[{"severity":"medium","vulnerabilities":[{"patched_versions":"4.20.0"}]}]`,
		"/repos/foo/bar":                                 `{"html_url":"https://github.com/foo/bar","pushed_at":"` + days(400) + `"}`,
		"/repos/foo/bar/security-advisories":             `[{"severity":"critical","vulnerabilities":[{"patched_versions":null}]}]`,
		"/repos/vendor/app":                              `{"html_url":"https://github.com/vendor/app","pushed_at":"` + days(5) + `"}`,
		"/repos/vendor/app/contents/.github/SECURITY.md": `{}`,
		"/repos/vendor/app/dependency-graph/sbom": `{"sbom":{"spdxVersion":"SPDX-2.3","packages":[
			{"SPDXID":"SPDXRef-root","name":"com.github.vendor/app"},
			{"SPDXID":"p1","name":"lodash","versionInfo":"4.17.21","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/lodash@4.17.21"}]},
			{"SPDXID":"p2","name":"requests","versionInfo":"2.31.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:pypi/requests@2.31.0"}]}],
			"relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relatedSpdxElement":"SPDXRef-root","relationshipType":"DESCRIBES"}]}}`,
		"/rate_limit": `{"resources":{"core":{"limit":60,"remaining":42,"reset":1900000000}}}`,
	}
	m.gh = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.ghCalls.Add(1)
		if r.URL.Path == "/rate_limit" {
			if a := r.Header.Get("Authorization"); a != "" && a != "Bearer good-token-1234" {
				w.WriteHeader(401)
				return
			}
			w.Write([]byte(ghResp["/rate_limit"]))
			return
		}
		w.Header().Set("X-RateLimit-Limit", "60")
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(30*time.Minute).Unix(), 10))
		if m.ghLimit.Load() {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.WriteHeader(403)
			w.Write([]byte(`{"message":"API rate limit exceeded"}`))
			return
		}
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(int(m.ghRemain.Add(-1))))
		if b, ok := ghResp[r.URL.Path]; ok {
			w.Write([]byte(b))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(func() { m.dd.Close(); m.gh.Close() })
	setBases(t, m.dd.URL, m.gh.URL)
	return m
}

var upTestInputs = []upInput{
	{Name: "left-pad", Version: "1.3.0", Purl: "pkg:npm/left-pad@1.3.0"},
	{Name: "express", Version: "4.18.2", Purl: "pkg:npm/express@4.18.2"},
	{Name: "bar", Version: "v1.0.0", Purl: "pkg:golang/github.com/foo/bar@v1.0.0"},
	{Name: "openssl", Version: "3.0.11", Purl: "pkg:deb/debian/openssl@3.0.11"},
	{Name: "nopurl", Version: "1"},
}

func compByName(cs []upComp, n string) upComp {
	for _, c := range cs {
		if c.Name == n {
			return c
		}
	}
	return upComp{}
}

func TestUpstreamAnalyze(t *testing.T) {
	upTestEnv(t)
	m := newUpMocks(t)
	e := &upEngine{maxRepos: 10}
	comps, repos, notes := e.analyze(upTestInputs, func(string) {})
	if len(comps) != 5 || len(repos) != 3 || len(notes) != 0 {
		t.Fatalf("구성요소 %d 저장소 %d 알림 %v", len(comps), len(repos), notes)
	}
	lp := compByName(comps, "left-pad")
	if lp.Rating != "risk" || lp.Repo != "github.com/stevemao/left-pad" || lp.RepoSrc != "deps.dev" || !lp.Deprecated || lp.VulnCritical != 1 {
		t.Fatalf("left-pad: %+v", lp)
	}
	ex := compByName(comps, "express")
	if ex.Rating != "warn" || ex.Repo != "github.com/expressjs/express" || ex.VulnHigh != 1 {
		t.Fatalf("express: %+v", ex)
	}
	if r := repos["github.com/expressjs/express"]; r.GitHub != "ok" || r.Release != "v5.3.0" || r.SecPolicySrc != "scorecard" || *r.Advisories != 1 {
		t.Fatalf("express 저장소: %+v", r)
	}
	bar := compByName(comps, "bar")
	if bar.RepoSrc != "purl" || bar.Rating != "risk" { // 패치 없는 치명 권고
		t.Fatalf("bar: %+v", bar)
	}
	if r := repos["github.com/foo/bar"]; r.SecPolicy == nil || *r.SecPolicy || r.SecPolicySrc != "github" || r.DepsDev != "not-found" {
		t.Fatalf("bar 저장소: %+v", r)
	}
	if c := compByName(comps, "openssl"); c.Rating != "unknown" || !strings.Contains(c.Reasons[0], "deb") {
		t.Fatalf("openssl: %+v", c)
	}
	if c := compByName(comps, "nopurl"); c.Rating != "unknown" {
		t.Fatalf("nopurl: %+v", c)
	}
	rep := &upReport{Comps: comps, Repos: repos}
	summarize(rep, time.Now())
	if rep.Counts["risk"] != 2 || rep.Counts["warn"] != 1 || rep.Counts["unknown"] != 2 || len(rep.Top) != 2 || len(rep.Replace) != 1 {
		t.Fatalf("집계: %v top %d replace %+v", rep.Counts, len(rep.Top), rep.Replace)
	}
	// 두 번째 실행은 캐시 — 외부 호출 없음
	dd, gh := m.ddCalls.Load(), m.ghCalls.Load()
	comps2, repos2, _ := (&upEngine{maxRepos: 10}).analyze(upTestInputs, func(string) {})
	if m.ddCalls.Load() != dd || m.ghCalls.Load() != gh {
		t.Fatalf("캐시를 쓰지 않음: deps.dev %d→%d GitHub %d→%d", dd, m.ddCalls.Load(), gh, m.ghCalls.Load())
	}
	if !repos2["github.com/expressjs/express"].Cached || compByName(comps2, "left-pad").Rating != "risk" {
		t.Fatal("캐시 결과가 다름")
	}
}

func TestUpstreamRateLimit(t *testing.T) {
	upTestEnv(t)
	m := newUpMocks(t)
	m.ghLimit.Store(true)
	e := &upEngine{maxRepos: 10}
	_, repos, notes := e.analyze(upTestInputs, func(string) {})
	limited := 0
	for _, r := range repos {
		if r.GitHub == "rate-limited" {
			limited++
		}
	}
	if limited != 3 || !e.limitHit || len(notes) != 1 || !strings.Contains(notes[0], "한도") {
		t.Fatalf("한도 처리: limited=%d hit=%v notes=%v", limited, e.limitHit, notes)
	}
	// 한도에 걸린 뒤에는 GitHub 를 더 부르지 않는다(첫 응답 이후)
	if n := m.ghCalls.Load(); n > 3 {
		t.Fatalf("한도 이후에도 GitHub 호출 %d회", n)
	}
	// 불완전한 결과는 캐시하지 않는다
	var r upRepo
	if upCacheGet("repo|github.com/expressjs/express", upCacheTTL, &r) {
		t.Fatal("한도에 걸린 결과가 캐시됨")
	}
	// deps.dev 신호는 남아 있다
	if repos["github.com/expressjs/express"].Scorecard == nil {
		t.Fatal("deps.dev 신호 유실")
	}
}

func TestUpstreamMaxReposCap(t *testing.T) {
	upTestEnv(t)
	newUpMocks(t)
	e := &upEngine{maxRepos: 1}
	_, repos, notes := e.analyze(upTestInputs, func(string) {})
	skipped := 0
	for _, r := range repos {
		if r.GitHub == "skipped" {
			skipped++
		}
	}
	if skipped != 2 || len(notes) != 1 || !strings.Contains(notes[0], "상한") {
		t.Fatalf("상한: skipped=%d notes=%v", skipped, notes)
	}
}

func TestUpstreamConfigAPI(t *testing.T) {
	d := upTestEnv(t)
	newUpMocks(t)
	s := &Server{sor: newSoR(filepath.Join(d, "sor.jsonl"))}
	put := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.apiUpstreamConfigPut(w, httptest.NewRequest("PUT", "/api/upstream/config", strings.NewReader(body)))
		return w
	}
	if w := put(`{"githubToken":"bad-token-0000"}`); w.Code != 400 {
		t.Fatalf("잘못된 토큰이 저장됨: %d", w.Code)
	}
	w := put(`{"githubToken":"good-token-1234","maxRepos":50}`)
	if w.Code != 200 || strings.Contains(w.Body.String(), "good-token") || !strings.Contains(w.Body.String(), "…1234") {
		t.Fatalf("저장 응답: %d %s", w.Code, w.Body.String())
	}
	fi, err := os.Stat(upstreamConfigPath())
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("설정 파일 권한: %v %v", fi.Mode(), err)
	}
	if c := loadUpConfig(); c.GitHubToken != "good-token-1234" || c.maxRepos() != 50 {
		t.Fatalf("저장된 설정: %+v", c)
	}
	// 빈 토큰은 유지, clearToken 은 삭제
	put(`{"maxRepos":0}`)
	if c := loadUpConfig(); c.GitHubToken == "" || c.maxRepos() != 300 {
		t.Fatalf("토큰 유지: %+v", c)
	}
	put(`{"clearToken":true}`)
	if c := loadUpConfig(); c.GitHubToken != "" || c.maxRepos() != 12 {
		t.Fatalf("토큰 삭제: %+v", c)
	}
	g := httptest.NewRecorder()
	s.apiUpstreamConfigGet(g, httptest.NewRequest("GET", "/api/upstream/config", nil))
	if !strings.Contains(g.Body.String(), `"remaining":42`) {
		t.Fatalf("한도 조회: %s", g.Body.String())
	}
	sor, _ := os.ReadFile(filepath.Join(d, "sor.jsonl"))
	if strings.Contains(string(sor), "good-token") || !strings.Contains(string(sor), "upstream-config") {
		t.Fatalf("원장: %s", sor)
	}
}

func TestParseGitHubTarget(t *testing.T) {
	for in, want := range map[string]string{
		"https://github.com/Vendor/App":        "vendor/app",
		"github.com/vendor/app.git":            "vendor/app",
		"vendor/app":                           "vendor/app",
		"https://github.com/vendor/app/pull/1": "vendor/app",
		"https://gitlab.com/vendor/app":        "",
		"vendor":                               "",
		"../../etc":                            "",
	} {
		o, r, ok := parseGitHubTarget(in)
		got := ""
		if ok {
			got = o + "/" + r
		}
		if got != want {
			t.Errorf("parseGitHubTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

func waitUp(t *testing.T, s *Server, id string) upReport {
	t.Helper()
	for i := 0; i < 200; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/upstream/report/"+id, nil)
		req.SetPathValue("id", id)
		s.apiUpstreamGet(w, req)
		var rep upReport
		_ = json.Unmarshal(w.Body.Bytes(), &rep)
		if rep.State != "running" && rep.State != "" && fileExists(upReportPath(id)) {
			return rep
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("분석이 끝나지 않음")
	return upReport{}
}

func TestUpstreamRepoRun(t *testing.T) {
	d := upTestEnv(t)
	newUpMocks(t)
	s := &Server{sor: newSoR(filepath.Join(d, "sor.jsonl"))}
	w := httptest.NewRecorder()
	s.apiUpstreamRepo(w, httptest.NewRequest("POST", "/api/upstream/repo", strings.NewReader(`{"url":"https://github.com/vendor/app","ai":true}`)))
	if w.Code != 202 {
		t.Fatalf("시작: %d %s", w.Code, w.Body.String())
	}
	var st struct{ ID string }
	_ = json.Unmarshal(w.Body.Bytes(), &st)
	rep := waitUp(t, s, st.ID)
	r := rep.Repos["github.com/vendor/app"]
	if rep.State != "done" || r == nil || r.SecPolicy == nil || !*r.SecPolicy || r.Rating != "ok" {
		t.Fatalf("단건 분석: %+v / %+v", rep, r)
	}
	if rep.DepGraph == nil || rep.DepGraph.Packages != 2 || rep.DepGraph.Ecosystems["npm"] != 1 {
		t.Fatalf("의존성 그래프: %+v", rep.DepGraph)
	}
	if rep.Summary != nil || rep.AIError != "" {
		t.Fatal("AI 미설정인데 요약 시도")
	}
	// 목록·원장
	lw := httptest.NewRecorder()
	s.apiUpstreamList(lw, httptest.NewRequest("GET", "/api/upstream/reports", nil))
	if !strings.Contains(lw.Body.String(), st.ID) || !strings.Contains(lw.Body.String(), `"rating":"ok"`) {
		t.Fatalf("목록: %s", lw.Body.String())
	}
	sor, _ := os.ReadFile(filepath.Join(d, "sor.jsonl"))
	if !strings.Contains(string(sor), `"upstream-scan"`) {
		t.Fatalf("원장 기록 없음: %s", sor)
	}
	// 잘못된 주소·ID
	w = httptest.NewRecorder()
	s.apiUpstreamRepo(w, httptest.NewRequest("POST", "/api/upstream/repo", strings.NewReader(`{"url":"https://gitlab.com/a/b"}`)))
	if w.Code != 400 {
		t.Fatalf("gitlab 주소 거부: %d", w.Code)
	}
	gw := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/upstream/report/x", nil)
	req.SetPathValue("id", "../x")
	s.apiUpstreamGet(gw, req)
	if gw.Code != 400 {
		t.Fatalf("잘못된 ID: %d", gw.Code)
	}
}

func TestDepGraphAsync(t *testing.T) {
	upTestEnv(t)
	polls := 0
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/r/dependency-graph/sbom":
			w.WriteHeader(410)
		case "/repos/o/r/dependency-graph/sbom/generate-report":
			w.WriteHeader(201)
			w.Write([]byte(`{"sbom_url":"` + srv.URL + `/repos/o/r/dependency-graph/sbom/fetch-report/abc"}`))
		case "/repos/o/r/dependency-graph/sbom/fetch-report/abc":
			polls++
			w.Write([]byte(`{"spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"a","name":"x","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:cargo/x@1"}]}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	setBases(t, "http://127.0.0.1:1", srv.URL)
	g := ghDepGraph("", "o", "r")
	if g.Error != "" || g.Packages != 1 || g.Ecosystems["cargo"] != 1 || polls != 1 {
		t.Fatalf("비동기 SBOM: %+v polls=%d", g, polls)
	}
}
