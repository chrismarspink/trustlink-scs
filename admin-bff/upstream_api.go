package main

// 공개 저장소(상류) 분석 — 관리 API·설정·비동기 실행·AI 요약.
//  - 설정: /var/lib/trustlink/upstream-config.json (0600, UPSTREAM_CONFIG). GitHub 토큰은 응답에 내보내지 않는다(끝 4자리만).
//  - 보고서: /var/lib/trustlink/upstream/reports/ur-YYYYMMDD-HHMMSS.json (UPSTREAM_DIR). 캐시는 같은 곳 cache/.
//  - 실행은 한 번에 하나(수 분 소요) — 진행 상황은 GET /api/upstream/report/{id} 로 본다.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	upIDRe = regexp.MustCompile(`^ur-\d{8}-\d{6}(-\d{1,3})?$`)
	upMu   sync.Mutex
	upJobs = map[string]*upReport{} // 진행 중(끝나면 파일로 옮기고 지운다)
)

func upstreamConfigPath() string {
	return env("UPSTREAM_CONFIG", "/var/lib/trustlink/upstream-config.json")
}

// ---------- 설정 ----------

type upConfig struct {
	GitHubToken string `json:"githubToken,omitempty"` // 파일에만 저장
	MaxRepos    int    `json:"maxRepos,omitempty"`    // 실행당 GitHub 조회 저장소 상한(0 = 기본)
	UpdatedBy   string `json:"updatedBy,omitempty"`
	UpdatedAt   string `json:"updatedAt,omitempty"`
}

func loadUpConfig() upConfig {
	var c upConfig
	_ = readJSONFile(upstreamConfigPath(), &c)
	return c
}

func saveUpConfig(c upConfig) error {
	p := upstreamConfigPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// maxRepos: 토큰 없음 12개(저장소당 GitHub 3~6회 × 12 ≈ 시간당 60회 안), 토큰 있음 300개.
func (c upConfig) maxRepos() int {
	if c.MaxRepos > 0 {
		return c.MaxRepos
	}
	if c.GitHubToken != "" {
		return 300
	}
	return 12
}

type upConfigView struct {
	HasToken  bool   `json:"hasToken"`
	TokenHint string `json:"tokenHint,omitempty"`
	MaxRepos  int    `json:"maxRepos"`  // 저장된 값(0 = 기본)
	Effective int    `json:"effective"` // 실제 적용 상한
	UpdatedBy string `json:"updatedBy,omitempty"`
	UpdatedAt string `json:"updatedAt,omitempty"`
}

func viewUpConfig(c upConfig) upConfigView {
	v := upConfigView{HasToken: c.GitHubToken != "", MaxRepos: c.MaxRepos, Effective: c.maxRepos(), UpdatedBy: c.UpdatedBy, UpdatedAt: c.UpdatedAt}
	if n := len(c.GitHubToken); n >= 8 {
		v.TokenHint = "…" + c.GitHubToken[n-4:]
	}
	return v
}

// ghRateLimit: /rate_limit(한도에 포함되지 않음). 토큰 확인에도 쓴다. 401 이면 오류.
func ghRateLimit(token string) (*upRate, error) {
	var out struct {
		Resources struct {
			Core struct {
				Limit     int   `json:"limit"`
				Remaining int   `json:"remaining"`
				Reset     int64 `json:"reset"`
			} `json:"core"`
		} `json:"resources"`
	}
	ghRateMu.Lock()
	ghLimitedUntil = time.Time{} // /rate_limit 은 막히지 않는다 — 실제 값으로 다시 판단
	ghRateMu.Unlock()
	code, err := ghGet(token, "/rate_limit", &out)
	if err != nil {
		return nil, err
	}
	if code == 401 {
		return nil, errors.New("GitHub 토큰이 올바르지 않습니다(401)")
	}
	if code != 200 {
		return nil, fmt.Errorf("GitHub 응답 %d", code)
	}
	c := out.Resources.Core
	r := &upRate{Limit: c.Limit, Remaining: c.Remaining, Auth: token != ""}
	if c.Reset > 0 {
		r.Reset = time.Unix(c.Reset, 0).UTC().Format(time.RFC3339)
	}
	if c.Remaining == 0 && c.Reset > 0 {
		ghRateMu.Lock()
		ghLimitedUntil = time.Unix(c.Reset, 0)
		ghRateMu.Unlock()
	}
	return r, nil
}

// GET /api/upstream/config
func (s *Server) apiUpstreamConfigGet(w http.ResponseWriter, r *http.Request) {
	c := loadUpConfig()
	out := map[string]any{"config": viewUpConfig(c), "ai": aiEnabledFor("report")}
	if rt, err := ghRateLimit(c.GitHubToken); err == nil {
		out["rate"] = rt
	} else {
		out["rateError"] = err.Error()
	}
	writeJSON(w, 200, out)
}

// PUT /api/upstream/config {githubToken, clearToken, maxRepos}
func (s *Server) apiUpstreamConfigPut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		GitHubToken string `json:"githubToken"` // 빈 값이면 기존 토큰 유지
		ClearToken  bool   `json:"clearToken"`
		MaxRepos    int    `json:"maxRepos"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "잘못된 요청"})
		return
	}
	if in.MaxRepos < 0 || in.MaxRepos > 1000 {
		writeJSON(w, 400, map[string]string{"error": "GitHub 조회 상한은 0(기본)~1000"})
		return
	}
	c := loadUpConfig()
	c.MaxRepos = in.MaxRepos
	if t := strings.TrimSpace(in.GitHubToken); t != "" {
		if strings.ContainsAny(t, " \t\r\n") || len(t) > 256 {
			writeJSON(w, 400, map[string]string{"error": "토큰 형식이 올바르지 않습니다"})
			return
		}
		if _, err := ghRateLimit(t); err != nil {
			writeJSON(w, 400, map[string]string{"error": redactKey(err.Error(), t)})
			return
		}
		c.GitHubToken = t
	}
	if in.ClearToken {
		c.GitHubToken = ""
	}
	c.UpdatedBy, c.UpdatedAt = w.Header().Get("X-User"), time.Now().UTC().Format(time.RFC3339)
	if err := saveUpConfig(c); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_ = s.sor.append(SoREvent{Actor: c.UpdatedBy, Action: "upstream-config", Status: map[bool]string{true: "token", false: "no-token"}[c.GitHubToken != ""],
		Detail: map[string]any{"hasToken": c.GitHubToken != "", "maxRepos": c.MaxRepos}})
	writeJSON(w, 200, map[string]any{"config": viewUpConfig(c)})
}

// ---------- 제품 SBOM ----------

// upstreamSBOM: repo:tag 에 붙은 가장 최근 SBOM(CycloneDX·SPDX) 원문.
func (s *Server) upstreamSBOM(repo, tag string) []byte {
	mr, err := s.zotGetSvc("/v2/"+repo+"/manifests/"+tag, acceptManifest)
	if err != nil {
		return nil
	}
	dig := mr.Header.Get("Docker-Content-Digest")
	mr.Body.Close()
	if dig == "" {
		return nil
	}
	rr, err := s.zotGetSvc("/v2/"+repo+"/referrers/"+dig, "")
	if err != nil {
		return nil
	}
	var idx ociIndex
	_ = json.NewDecoder(rr.Body).Decode(&idx)
	rr.Body.Close()
	best, at := "", ""
	for _, d := range idx.Manifests {
		if kindDir(d.ArtifactType, "") != "sbom" {
			continue
		}
		if c := d.Annotations["org.opencontainers.image.created"]; best == "" || c > at {
			best, at = d.Digest, c
		}
	}
	if best == "" {
		return nil
	}
	return s.svcReferrerBlob(repo, best)
}

// ---------- GitHub 의존성 그래프 SBOM(단건 분석) ----------

// ghDepGraph: GET …/dependency-graph/sbom(동기). 없어졌으면(404·410 외) 비동기 generate-report → fetch-report 로.
func ghDepGraph(token, owner, name string) *upDepGraph {
	base := "/repos/" + owner + "/" + name + "/dependency-graph/sbom"
	var doc struct {
		SBOM json.RawMessage `json:"sbom"`
	}
	code, err := ghGet(token, base, &doc)
	if err != nil {
		return &upDepGraph{Error: err.Error()}
	}
	raw := []byte(doc.SBOM)
	if code != 200 {
		var gen struct {
			URL string `json:"sbom_url"`
		}
		if c2, err := ghGet(token, base+"/generate-report", &gen); err != nil || gen.URL == "" {
			msg := fmt.Sprintf("의존성 그래프 SBOM 을 받지 못했습니다(GitHub %d) — 의존성 그래프가 꺼져 있거나 권한이 없습니다", code)
			if err != nil {
				msg = err.Error()
			} else if c2 != 0 && c2 != 200 && c2 != 201 {
				msg = fmt.Sprintf("의존성 그래프 SBOM 을 받지 못했습니다(GitHub %d/%d)", code, c2)
			}
			return &upDepGraph{Error: msg}
		}
		if !strings.HasPrefix(gen.URL, githubAPIBase+"/") {
			return &upDepGraph{Error: "예상과 다른 SBOM 주소"}
		}
		raw = nil
		for i := 0; i < 8 && raw == nil; i++ { // 생성 대기(202) — 최대 약 40초
			var body json.RawMessage
			c3, err := ghGet(token, gen.URL, &body)
			if err != nil {
				return &upDepGraph{Error: err.Error()}
			}
			if c3 == 200 && len(body) > 2 {
				raw = body
				var wrap struct {
					SBOM json.RawMessage `json:"sbom"`
				}
				if json.Unmarshal(body, &wrap) == nil && len(wrap.SBOM) > 0 {
					raw = wrap.SBOM
				}
				break
			}
			time.Sleep(5 * time.Second)
		}
		if raw == nil {
			return &upDepGraph{Error: "의존성 그래프 SBOM 생성이 끝나지 않았습니다 — 잠시 후 다시 실행하세요"}
		}
	}
	return depGraphSummary(raw)
}

func depGraphSummary(raw []byte) *upDepGraph {
	var sp struct {
		Packages []struct {
			SPDXID       string `json:"SPDXID"`
			Name         string `json:"name"`
			Version      string `json:"versionInfo"`
			ExternalRefs []struct {
				Type    string `json:"referenceType"`
				Locator string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
		Relationships []struct {
			From string `json:"spdxElementId"`
			To   string `json:"relatedSpdxElement"`
			Type string `json:"relationshipType"`
		} `json:"relationships"`
	}
	if err := json.Unmarshal(raw, &sp); err != nil {
		return &upDepGraph{Error: "SPDX 형식 오류"}
	}
	root := map[string]bool{} // 문서가 설명하는 저장소 자신(DESCRIBES)은 세지 않는다
	for _, r := range sp.Relationships {
		if r.Type == "DESCRIBES" {
			root[r.To] = true
		}
	}
	g := &upDepGraph{Ecosystems: map[string]int{}}
	for _, p := range sp.Packages {
		if root[p.SPDXID] {
			continue
		}
		eco := "기타"
		for _, e := range p.ExternalRefs {
			if pp, ok := parsePurl(e.Locator); ok && e.Type == "purl" {
				eco = pp.Type
			}
		}
		g.Packages++
		g.Ecosystems[eco]++
		if len(g.Sample) < 30 {
			g.Sample = append(g.Sample, strings.TrimSpace(p.Name+" "+p.Version))
		}
	}
	return g
}

// ---------- 실행 ----------

func newUpID() string {
	id := "ur-" + time.Now().UTC().Format("20060102-150405")
	for i := 2; ; i++ {
		upMu.Lock()
		_, busy := upJobs[id]
		upMu.Unlock()
		if !busy && !fileExists(upReportPath(id)) {
			return id
		}
		id = "ur-" + time.Now().UTC().Format("20060102-150405") + "-" + itoa(i)
	}
}

func upReportPath(id string) string { return filepath.Join(upstreamDir(), "reports", id+".json") }

// startUp: 진행 중 작업이 없으면 새 보고서를 등록한다.
func startUp(rep *upReport) error {
	upMu.Lock()
	defer upMu.Unlock()
	for _, j := range upJobs {
		if j.State == "running" {
			return errors.New("다른 상류 분석이 진행 중입니다 (" + j.ID + ")")
		}
	}
	upJobs[rep.ID] = rep
	return nil
}

func upSet(rep *upReport, f func()) {
	upMu.Lock()
	f()
	upMu.Unlock()
}

// finishUp: 등급 집계 → (AI 요약) → 파일 저장 → 원장.
func (s *Server) finishUp(rep *upReport, useAI bool) {
	if useAI && rep.State == "running" {
		upSet(rep, func() { rep.Progress = "AI 요약 작성 중" })
		sum, meta, err := s.upstreamAI(rep)
		upSet(rep, func() {
			if err != nil {
				rep.AIError = err.Error()
			} else {
				rep.Summary, rep.AIMeta = sum, meta
			}
		})
	}
	upSet(rep, func() {
		if rep.State == "running" {
			rep.State = "done"
		}
		rep.Progress, rep.Finished = "", time.Now().UTC().Format(time.RFC3339)
	})
	_ = s.sor.append(SoREvent{Actor: rep.CreatedBy, Action: "upstream-scan", Status: rep.State, Repo: rep.Repo, Tag: rep.Tag,
		Detail: map[string]any{"id": rep.ID, "kind": rep.Kind, "target": rep.Target, "components": len(rep.Comps), "repos": len(rep.Repos),
			"counts": rep.Counts, "replace": len(rep.Replace), "rateLimited": rep.Rate != nil && rep.Rate.Hit, "ai": rep.AIMeta != nil, "error": rep.Error}})
	upSet(rep, func() {
		_ = os.MkdirAll(filepath.Dir(upReportPath(rep.ID)), 0o750)
		if err := writeJSONFile(upReportPath(rep.ID), rep); err != nil {
			rep.State, rep.Error = "error", "보고서 저장 실패: "+err.Error()
			return
		}
		delete(upJobs, rep.ID)
	})
}

func (s *Server) runUpstreamProduct(rep *upReport, useAI bool) {
	defer func() {
		if e := recover(); e != nil {
			upSet(rep, func() { rep.State, rep.Error = "error", fmt.Sprint(e) })
			s.finishUp(rep, false)
		}
	}()
	cfg := loadUpConfig()
	upSet(rep, func() { rep.Progress = "SBOM 읽는 중" })
	inputs, format := parseUpInputs(s.upstreamSBOM(rep.Repo, rep.Tag))
	if format == "" {
		upSet(rep, func() {
			rep.State, rep.Error = "error", "이 버전에 SBOM(CycloneDX·SPDX)이 없습니다 — 제품 화면에서 SBOM 을 먼저 생성·첨부하세요"
		})
		s.finishUp(rep, false)
		return
	}
	upSet(rep, func() { rep.SBOM = fmt.Sprintf("%s · 구성요소 %d개", format, len(inputs)) })
	e := &upEngine{token: cfg.GitHubToken, maxRepos: cfg.maxRepos()}
	comps, repos, notes := e.analyze(inputs, func(m string) { upSet(rep, func() { rep.Progress = m }) })
	rt := ghRateNow()
	rt.Hit, rt.Auth = e.limitHit, cfg.GitHubToken != ""
	upSet(rep, func() {
		rep.Comps, rep.Repos, rep.Notes, rep.Rate = comps, repos, append(rep.Notes, notes...), &rt
		summarize(rep, time.Now())
	})
	s.finishUp(rep, useAI)
}

// parseGitHubTarget: https://github.com/o/r(.git)(/…), github.com/o/r, o/r → owner, repo.
func parseGitHubTarget(s string) (string, string, bool) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "github.com") {
		if strings.Count(s, "/") != 1 {
			return "", "", false
		}
		s = "github.com/" + s
	}
	id := repoFromURL(s)
	if !strings.HasPrefix(id, "github.com/") {
		return "", "", false
	}
	o, r, _ := strings.Cut(strings.TrimPrefix(id, "github.com/"), "/")
	return o, r, true
}

func (s *Server) runUpstreamRepo(rep *upReport, owner, name string, useAI bool) {
	defer func() {
		if e := recover(); e != nil {
			upSet(rep, func() { rep.State, rep.Error = "error", fmt.Sprint(e) })
			s.finishUp(rep, false)
		}
	}()
	cfg := loadUpConfig()
	e := &upEngine{token: cfg.GitHubToken, maxRepos: 1}
	id := "github.com/" + owner + "/" + name
	upSet(rep, func() { rep.Progress = "저장소 신호 조회 중" })
	r := e.fetchRepo(id)
	upSet(rep, func() { rep.Progress = "의존성 그래프 SBOM 받는 중" })
	var dg *upDepGraph
	if r.GitHub == "ok" {
		dg = ghDepGraph(cfg.GitHubToken, owner, name)
		if strings.Contains(dg.Error, errGHLimit.Error()) {
			e.limitHit = true
		}
	}
	rt := ghRateNow()
	rt.Hit, rt.Auth = e.limitHit, cfg.GitHubToken != ""
	upSet(rep, func() {
		rep.Repos, rep.DepGraph, rep.Rate = map[string]*upRepo{id: r}, dg, &rt
		switch r.GitHub {
		case "not-found":
			rep.State, rep.Error = "error", "GitHub 저장소를 찾을 수 없습니다(비공개이거나 주소 오류)"
		case "rate-limited":
			rep.Notes = append(rep.Notes, "GitHub API 요청 한도에 걸려 GitHub 신호를 받지 못했습니다(재설정 "+firstNonEmpty(rt.Reset, "—")+"). 토큰을 등록하세요.")
		}
		summarize(rep, time.Now())
	})
	s.finishUp(rep, useAI)
}

// POST /api/upstream/run {repo, tag, ai}
func (s *Server) apiUpstreamRun(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Repo string `json:"repo"`
		Tag  string `json:"tag"`
		AI   bool   `json:"ai"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&in); err != nil || in.Repo == "" || in.Tag == "" ||
		strings.Contains(in.Repo, "..") || strings.ContainsAny(in.Tag, "/\\") {
		writeJSON(w, 400, map[string]string{"error": "repo, tag 필수"})
		return
	}
	rep := &upReport{ID: newUpID(), Kind: "product", Repo: in.Repo, Tag: in.Tag, Created: time.Now().UTC().Format(time.RFC3339),
		CreatedBy: w.Header().Get("X-User"), State: "running", Progress: "시작", Comps: []upComp{}, Repos: map[string]*upRepo{}, Disclaimer: upDisclaimer}
	if err := startUp(rep); err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	go s.runUpstreamProduct(rep, in.AI && aiEnabledFor("report"))
	writeJSON(w, 202, map[string]string{"id": rep.ID})
}

// POST /api/upstream/repo {url, ai} — 공개 GitHub 저장소 하나(예: 협력사 공개 저장소)
func (s *Server) apiUpstreamRepo(w http.ResponseWriter, r *http.Request) {
	var in struct {
		URL string `json:"url"`
		AI  bool   `json:"ai"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "잘못된 요청"})
		return
	}
	owner, name, ok := parseGitHubTarget(in.URL)
	if !ok {
		writeJSON(w, 400, map[string]string{"error": "GitHub 저장소 주소를 넣으세요 (예: https://github.com/owner/repo)"})
		return
	}
	rep := &upReport{ID: newUpID(), Kind: "repo", Target: "https://github.com/" + owner + "/" + name, Created: time.Now().UTC().Format(time.RFC3339),
		CreatedBy: w.Header().Get("X-User"), State: "running", Progress: "시작", Comps: []upComp{}, Repos: map[string]*upRepo{}, Disclaimer: upDisclaimer}
	if err := startUp(rep); err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	go s.runUpstreamRepo(rep, owner, name, in.AI && aiEnabledFor("report"))
	writeJSON(w, 202, map[string]string{"id": rep.ID})
}

// GET /api/upstream/report/{id}
func (s *Server) apiUpstreamGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !upIDRe.MatchString(id) {
		writeJSON(w, 400, map[string]string{"error": "잘못된 보고서 ID"})
		return
	}
	upMu.Lock()
	if j, ok := upJobs[id]; ok {
		b, _ := json.Marshal(j)
		upMu.Unlock()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write(b)
		return
	}
	upMu.Unlock()
	var rep upReport
	if err := readJSONFile(upReportPath(id), &rep); err != nil {
		writeJSON(w, 404, map[string]string{"error": "보고서 없음"})
		return
	}
	writeJSON(w, 200, rep)
}

type upListItem struct {
	ID        string         `json:"id"`
	Kind      string         `json:"kind"`
	Repo      string         `json:"repo,omitempty"`
	Tag       string         `json:"tag,omitempty"`
	Target    string         `json:"target,omitempty"`
	Created   string         `json:"created"`
	CreatedBy string         `json:"createdBy"`
	State     string         `json:"state"`
	Progress  string         `json:"progress,omitempty"`
	Comps     int            `json:"comps"`
	Repos     int            `json:"repos"`
	Counts    map[string]int `json:"counts,omitempty"`
	Rating    string         `json:"rating,omitempty"` // 단건 분석 저장소 등급
	Summary   bool           `json:"summary"`
}

func upItem(r *upReport) upListItem {
	it := upListItem{ID: r.ID, Kind: r.Kind, Repo: r.Repo, Tag: r.Tag, Target: r.Target, Created: r.Created, CreatedBy: r.CreatedBy,
		State: r.State, Progress: r.Progress, Comps: len(r.Comps), Repos: len(r.Repos), Counts: r.Counts, Summary: r.Summary != nil}
	if r.Kind == "repo" {
		for _, x := range r.Repos {
			it.Rating = x.Rating
		}
	}
	return it
}

// GET /api/upstream/reports → 최근 보고서(진행 중 포함)
func (s *Server) apiUpstreamList(w http.ResponseWriter, r *http.Request) {
	out := []upListItem{}
	upMu.Lock()
	for _, j := range upJobs {
		out = append(out, upItem(j))
	}
	upMu.Unlock()
	files, _ := filepath.Glob(filepath.Join(upstreamDir(), "reports", "ur-*.json"))
	sort.Sort(sort.Reverse(sort.StringSlice(files)))
	for i, f := range files {
		if i >= 200 {
			break
		}
		var rep upReport
		if readJSONFile(f, &rep) == nil {
			out = append(out, upItem(&rep))
		}
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].ID > out[b].ID })
	writeJSON(w, 200, out)
}

// ---------- AI 요약 ----------

var upSummarySchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"headline":  map[string]any{"type": "string", "maxLength": 200},
		"points":    map[string]any{"type": "array", "items": map[string]any{"type": "string", "maxLength": 220}, "maxItems": 5},
		"actions":   map[string]any{"type": "array", "items": map[string]any{"type": "string", "maxLength": 220}, "maxItems": 5},
		"citations": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "maxItems": 15},
	},
	"required": []string{"headline", "points", "actions", "citations"},
}

var upRatingKo = map[string]string{"risk": "위험", "warn": "주의", "ok": "양호", "unknown": "미확인"}

// upFacts: 규칙 판정 결과만 사실로 쓴다(저장소 설명 등 외부 원문은 넣지 않는다).
func upFacts(rep *upReport) []aiFact {
	facts := []aiFact{}
	if rep.Kind == "repo" {
		for _, r := range rep.Repos {
			t := r.ID + " — 등급 " + upRatingKo[r.Rating]
			if r.Scorecard != nil {
				t += fmt.Sprintf("; Scorecard %.1f", *r.Scorecard)
			}
			if r.PushedAt != "" {
				t += "; 마지막 push " + r.PushedAt[:min(10, len(r.PushedAt))]
			}
			if r.Release != "" {
				t += "; 최근 릴리스 " + r.Release + " " + r.ReleaseAt[:min(10, len(r.ReleaseAt))]
			}
			if r.Advisories != nil {
				t += fmt.Sprintf("; 공개 보안 권고 %d건(치명 %d·높음 %d)", *r.Advisories, r.AdvCritical, r.AdvHigh)
			}
			facts = append(facts, aiFact{ID: "R1", Text: t})
			for i, x := range r.Reasons {
				facts = append(facts, aiFact{ID: "R1-" + itoa(i+1), Text: x})
			}
		}
		if g := rep.DepGraph; g != nil && g.Error == "" {
			eco := []string{}
			for k, v := range g.Ecosystems {
				eco = append(eco, fmt.Sprintf("%s %d", k, v))
			}
			sort.Strings(eco)
			facts = append(facts, aiFact{ID: "D1", Text: fmt.Sprintf("GitHub 의존성 그래프 패키지 %d개 (%s)", g.Packages, strings.Join(eco, ", "))})
		}
		return facts
	}
	c := rep.Counts
	facts = append(facts, aiFact{ID: "S1", Text: fmt.Sprintf("제품 %s:%s 구성요소 %d개, 상류 저장소 %d개 — 위험 %d, 주의 %d, 양호 %d, 미확인 %d; 교체·포크 검토 대상 %d개",
		rep.Repo, rep.Tag, len(rep.Comps), len(rep.Repos), c["risk"], c["warn"], c["ok"], c["unknown"], len(rep.Replace))})
	n := 0
	add := func(f upFlag, tag string) {
		n++
		facts = append(facts, aiFact{ID: "C" + itoa(n), Text: fmt.Sprintf("%s %s (%s) — %s%s; 사유: %s", f.Name, f.Version, firstNonEmpty(f.Repo, "저장소 미확인"),
			upRatingKo[f.Rating], tag, truncate(strings.Join(f.Reasons, " / "), 240))})
	}
	for i, f := range rep.Top {
		if i < 12 {
			add(f, "")
		}
	}
	for i, f := range rep.Replace {
		if i < 8 {
			add(f, ", 교체·포크 검토 대상")
		}
	}
	return facts
}

func (s *Server) upstreamAI(rep *upReport) (*upSummary, *aiMeta, error) {
	upMu.Lock()
	facts := upFacts(rep)
	upMu.Unlock()
	task := "위 사실은 제3자 구성요소(오픈소스 상류 저장소) 건강도 점검 결과다. CRA 실사(due diligence) 기록의 첫 쪽 요약을 쓴다.\n" +
		"- headline: 한 문장 결론, 90자 이내.\n- points: 핵심 관찰 3~5개, 각 80자 이내.\n" +
		"- actions: 먼저 할 일 3~5개(교체·포크 검토, 업그레이드, 공급자 문의 등), 각 80자 이내.\n" +
		"- 각 문장 끝에 근거 사실 ID 를 [C1] 처럼 붙이고 citations 에도 넣는다. 사실에 없는 저장소·수치·날짜를 쓰지 않는다."
	if rep.Kind == "repo" {
		task = "위 사실은 공개 GitHub 저장소 하나(협력사·상류 저장소)의 건강도 점검 결과다. 공급자 실사 기록용 요약을 쓴다.\n" +
			"- headline: 한 문장 결론, 90자 이내.\n- points: 핵심 관찰 2~5개, 각 80자 이내.\n- actions: 확인·요청할 일 2~5개, 각 80자 이내.\n" +
			"- 각 문장 끝에 근거 사실 ID 를 [R1] 처럼 붙이고 citations 에도 넣는다. 사실에 없는 수치·날짜를 쓰지 않는다."
	}
	var sum upSummary
	meta, err := s.aiDraftFor("report", "ko", facts, task, upSummarySchema, 1200, &sum)
	if err != nil {
		return nil, nil, err
	}
	if len(sum.Points) > 5 {
		sum.Points = sum.Points[:5]
	}
	if len(sum.Actions) > 5 {
		sum.Actions = sum.Actions[:5]
	}
	sum.Citations = validCitations(sum.Citations, facts)
	return &sum, &meta, nil
}
