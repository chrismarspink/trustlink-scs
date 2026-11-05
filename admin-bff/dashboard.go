package main

// dashboard.go: 관리 대시보드 집계(GET /api/dashboard, admins).
//   ① 할 일   — 판단 대기 취약점, 오래된 미판단, 동기화·메일 실패, 만료 임박(자동화 계정·HTTPS 인증서), 연락처 누락
//   ② 보안 현황 — DT 포트폴리오 추이, 제품별 미판단, 판단 대기 기간 분포, VEX 처리율, 평균 대응 시간, 최근 새 취약점
//   ③ 공급망 품질 — SBOM·VEX 보유율, SBOM 출처(공급자/syft), 누락 항목, 라이선스, 많이 쓰는 구성요소와 영향 범위
//   ④ 고객·배포 — 고객사별 다운로드, 최근 다운로드, 최신이 아닌 버전을 받는 고객, 고객 통보
//   ⑤ 운영    — 일별 업로드·다운로드, 활동 상위 계정, 메일 성공률
// 데이터: zot(레지스트리·접근 로그), DT, 통보 상태, 감사 기록(sor), 접근 정책, Keycloak. 계산이 무거워 5분 캐시.

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	dashCacheTTL    = 5 * time.Minute
	dashDays        = 30 // 추이·집계 기간
	dashTagsPerRepo = 50 // 제품마다 최근 버전만 훑는다(개발 빌드가 많은 저장소 대비)
	dashAgingDays   = 7  // 이 기간 넘게 판단되지 않은 취약점은 할 일에 올린다
	dashExpireDays  = 30 // 만료 임박 기준
)

type dashCount struct {
	Label string `json:"label"`
	Value int    `json:"value"`
}

type dashTodo struct {
	Kind  string `json:"kind"` // vuln | aging | sync | mail | robot | cert | email | contact
	Tone  string `json:"tone"` // crit | warn
	Text  string `json:"text"`
	Count int    `json:"count"`
	Link  string `json:"link,omitempty"`
}

type dashProductVuln struct {
	Repo     string `json:"repo"`
	Tag      string `json:"tag"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Total    int    `json:"total"`
	Pending  int    `json:"pending"`
}

type dashRecent struct {
	Time  string `json:"time"`
	Repo  string `json:"repo"`
	Tag   string `json:"tag"`
	Title string `json:"title"`
}

type dashDay struct {
	Date      string `json:"date"`
	Critical  int    `json:"critical,omitempty"`
	High      int    `json:"high,omitempty"`
	Medium    int    `json:"medium,omitempty"`
	Low       int    `json:"low,omitempty"`
	Unaudited int    `json:"unaudited,omitempty"`
	Uploads   int    `json:"uploads,omitempty"`
	Downloads int    `json:"downloads,omitempty"`
}

type dashComponent struct {
	Name     string `json:"name"`
	Products int    `json:"products"`
	Versions int    `json:"versions"`
	Vulns    int    `json:"vulns"`
}

type dashDownload struct {
	Time   string `json:"time"`
	User   string `json:"user"`
	Org    string `json:"org,omitempty"`
	Repo   string `json:"repo"`
	Tag    string `json:"tag"`
	Latest string `json:"latest,omitempty"` // 받은 버전이 최신이 아니면 그 제품의 최신 버전
}

type Dashboard struct {
	Generated string     `json:"generated"`
	DT        bool       `json:"dt"`
	Todo      []dashTodo `json:"todo"`
	Security  struct {
		Pending     map[string]int    `json:"pending"` // 심각도 → 판단 대기 수
		Total       int               `json:"total"`
		Analyzed    int               `json:"analyzed"`
		Aging       []dashCount       `json:"aging"` // 판단 대기 기간 분포
		Trend       []dashDay         `json:"trend"`
		Products    []dashProductVuln `json:"products"`
		MTTRHours   float64           `json:"mttrHours"` // 새 취약점 통보 → VEX 발행 평균(시간)
		MTTRSamples int               `json:"mttrSamples"`
		Recent      []dashRecent      `json:"recent"`
	} `json:"security"`
	Quality struct {
		Versions     int             `json:"versions"`
		WithSBOM     int             `json:"withSbom"`
		SBOMSupplier int             `json:"sbomSupplier"` // 공급자가 올린 SBOM
		SBOMSyft     int             `json:"sbomSyft"`     // TrustLink 가 syft 로 생성
		WithVEX      int             `json:"withVex"`
		Components   int             `json:"components"`
		NoVersion    int             `json:"noVersion"`
		NoPurl       int             `json:"noPurl"`
		NoLicense    int             `json:"noLicense"`
		Copyleft     int             `json:"copyleft"`
		Licenses     []dashCount     `json:"licenses"`
		Top          []dashComponent `json:"top"`
	} `json:"quality"`
	Customers struct {
		Orgs     []dashCount    `json:"orgs"` // 고객사별 다운로드 수
		Recent   []dashDownload `json:"recent"`
		Outdated []dashDownload `json:"outdated"` // 최신이 아닌 버전을 받은 고객(최근순)
		Notices  int            `json:"notices"`  // 고객에게 보낸 통보(기간 내)
	} `json:"customers"`
	Ops struct {
		Daily       []dashDay   `json:"daily"`
		Actors      []dashCount `json:"actors"`
		Mailed      int         `json:"mailed"`
		MailFailed  int         `json:"mailFailed"`
		LastSync    string      `json:"lastSync"`
		LastSyncMsg string      `json:"lastSyncMsg"`
		CertDays    int         `json:"certDays"` // HTTPS 인증서 남은 날(-1: http 이거나 확인 불가)
	} `json:"ops"`
}

var dashCache struct {
	sync.Mutex
	at   time.Time
	data *Dashboard
}

func (s *Server) apiDashboard(w http.ResponseWriter, r *http.Request) {
	dashCache.Lock()
	defer dashCache.Unlock()
	if dashCache.data == nil || time.Since(dashCache.at) > dashCacheTTL || r.URL.Query().Get("refresh") == "1" {
		dashCache.data, dashCache.at = s.buildDashboard(time.Now()), time.Now()
	}
	writeJSON(w, 200, dashCache.data)
}

func (s *Server) buildDashboard(now time.Time) *Dashboard {
	d := &Dashboard{Generated: now.UTC().Format(time.RFC3339), Todo: []dashTodo{}}
	d.Security.Pending = map[string]int{}
	since := now.AddDate(0, 0, -dashDays)

	latest := s.dashInventory(d)
	s.dashSecurity(d, now)
	orgOf, orgTodo := s.dashOrgs()
	s.dashLog(d, now, since, latest, orgOf)
	s.dashNotices(d, now, since)
	d.Todo = append(d.Todo, orgTodo...)
	d.Todo = append(d.Todo, s.dashExpiring(now)...)
	if days := certDaysLeft(s.cfg.RedirectURI, now); days >= 0 {
		d.Ops.CertDays = days
		if days <= dashExpireDays {
			d.Todo = append(d.Todo, dashTodo{Kind: "cert", Tone: "crit", Count: days, Text: "HTTPS 인증서 만료 임박(자동 갱신 확인)"})
		}
	} else {
		d.Ops.CertDays = -1
	}
	sort.SliceStable(d.Todo, func(i, j int) bool { return d.Todo[i].Tone == "crit" && d.Todo[j].Tone != "crit" })
	return d
}

// ---------- ③ 공급망 품질: zot 레지스트리 훑기 ----------

// dashInventory: 제품·버전마다 SBOM·VEX 첨부와 SBOM 출처를 센다. 반환: 제품 → 최신 버전.
func (s *Server) dashInventory(d *Dashboard) map[string]string {
	caller := s.svcCaller()
	latest := map[string]string{}
	for _, repo := range s.svcCatalog() {
		tags := sortedVersions(s.svcTags(repo))
		if len(tags) == 0 {
			continue
		}
		latest[repo] = tags[len(tags)-1]
		if len(tags) > dashTagsPerRepo {
			tags = tags[len(tags)-dashTagsPerRepo:]
		}
		for _, tag := range tags {
			_, subj, err := s.fetchManifest(caller, repo, tag)
			if err != nil {
				continue
			}
			d.Quality.Versions++
			hasSBOM, syft, hasVEX := false, false, false
			for _, ref := range s.fetchReferrers(caller, repo, subj) {
				switch {
				case isSBOM(ref.ArtifactType):
					hasSBOM = true
					if ref.Annotations["com.trustlink.sbom.provenance"] == "trustlink-analyzed" {
						syft = true
					}
				case strings.Contains(ref.ArtifactType, "vex"):
					hasVEX = true
				}
			}
			if hasSBOM {
				d.Quality.WithSBOM++
				if syft {
					d.Quality.SBOMSyft++
				} else {
					d.Quality.SBOMSupplier++
				}
			}
			if hasVEX {
				d.Quality.WithVEX++
			}
		}
	}
	return latest
}

// ---------- ② 보안 현황 + ③ 구성요소: DT ----------

type dtFinding struct {
	Component struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"component"`
	Vulnerability struct {
		VulnID   string `json:"vulnId"`
		Severity string `json:"severity"`
	} `json:"vulnerability"`
	Analysis struct {
		State        string `json:"state"`
		IsSuppressed bool   `json:"isSuppressed"`
	} `json:"analysis"`
	Attribution struct {
		AttributedOn int64 `json:"attributedOn"` // epoch ms
	} `json:"attribution"`
}

type dtComponent struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	Purl            string `json:"purl"`
	License         string `json:"license"`
	ResolvedLicense *struct {
		LicenseID string `json:"licenseId"`
		Name      string `json:"name"`
	} `json:"resolvedLicense"`
}

// pendingState: 아직 판단이 끝나지 않은 분석 상태(조사 중 포함).
func pendingState(st string) bool {
	return st == "" || st == "NOT_SET" || st == "IN_TRIAGE"
}

var agingBuckets = []struct {
	label string
	max   time.Duration
}{{"1일 이내", 24 * time.Hour}, {"1~7일", 7 * 24 * time.Hour}, {"7~30일", 30 * 24 * time.Hour}, {"30일 초과", 1 << 62}}

func agingBucket(age time.Duration) int {
	for i, b := range agingBuckets {
		if age <= b.max {
			return i
		}
	}
	return len(agingBuckets) - 1
}

// copyleft 계열 라이선스(배포 시 소스 공개 의무가 생길 수 있는 것) — SPDX ID 앞부분으로 판정.
var copyleftPrefix = []string{"GPL", "AGPL", "LGPL", "MPL", "EPL", "CDDL", "EUPL", "OSL", "CC-BY-SA"}

func isCopyleft(id string) bool {
	u := strings.ToUpper(id)
	for _, p := range copyleftPrefix {
		if strings.HasPrefix(u, p) {
			return true
		}
	}
	return false
}

func (s *Server) dashSecurity(d *Dashboard, now time.Time) {
	if !s.dtEnabled() {
		return
	}
	d.DT = true
	n := s.notify
	n.mu.Lock()
	projects := map[string]string{}
	for k, v := range n.st.Projects {
		projects[k] = v
	}
	n.mu.Unlock()

	aging := make([]int, len(agingBuckets))
	licenses := map[string]int{}
	type compAgg struct {
		products map[string]bool
		versions int
		vulns    int
	}
	comps := map[string]*compAgg{}
	for key, repo := range projects {
		name, tag, ok := strings.Cut(key, "@")
		if !ok {
			continue
		}
		uuid, err := s.dtLookupProject(name, tag)
		if err != nil || uuid == "" {
			continue
		}
		pv := dashProductVuln{Repo: repo, Tag: tag}
		var fs []dtFinding
		if b, err := s.dtFindings(uuid); err == nil {
			_ = json.Unmarshal(b, &fs)
		}
		vulnsByComp := map[string]int{}
		for _, f := range fs {
			if f.Analysis.IsSuppressed {
				continue
			}
			sev := strings.ToUpper(f.Vulnerability.Severity)
			pv.Total++
			d.Security.Total++
			vulnsByComp[f.Component.Name]++
			switch sev {
			case "CRITICAL":
				pv.Critical++
			case "HIGH":
				pv.High++
			}
			if !pendingState(f.Analysis.State) {
				d.Security.Analyzed++
				continue
			}
			pv.Pending++
			d.Security.Pending[sev]++
			if f.Attribution.AttributedOn > 0 {
				age := now.Sub(time.UnixMilli(f.Attribution.AttributedOn))
				aging[agingBucket(age)]++
			}
		}
		if pv.Total > 0 {
			d.Security.Products = append(d.Security.Products, pv)
		}
		for _, c := range s.dtComponents(uuid) {
			d.Quality.Components++
			if c.Version == "" {
				d.Quality.NoVersion++
			}
			if c.Purl == "" {
				d.Quality.NoPurl++
			}
			lic := c.License
			if c.ResolvedLicense != nil && c.ResolvedLicense.LicenseID != "" {
				lic = c.ResolvedLicense.LicenseID
			}
			if lic == "" {
				d.Quality.NoLicense++
			} else {
				licenses[lic]++
				if isCopyleft(lic) {
					d.Quality.Copyleft++
				}
			}
			a := comps[c.Name]
			if a == nil {
				a = &compAgg{products: map[string]bool{}}
				comps[c.Name] = a
			}
			a.products[repo] = true
			a.versions++
			a.vulns += vulnsByComp[c.Name]
		}
	}
	for i, b := range agingBuckets {
		d.Security.Aging = append(d.Security.Aging, dashCount{Label: b.label, Value: aging[i]})
	}
	sort.Slice(d.Security.Products, func(i, j int) bool {
		a, b := d.Security.Products[i], d.Security.Products[j]
		if a.Critical != b.Critical {
			return a.Critical > b.Critical
		}
		if a.High != b.High {
			return a.High > b.High
		}
		return a.Pending > b.Pending
	})
	d.Quality.Licenses = topCounts(licenses, 10)
	for name, a := range comps {
		d.Quality.Top = append(d.Quality.Top, dashComponent{Name: name, Products: len(a.products), Versions: a.versions, Vulns: a.vulns})
	}
	sort.Slice(d.Quality.Top, func(i, j int) bool {
		a, b := d.Quality.Top[i], d.Quality.Top[j]
		if a.Vulns != b.Vulns {
			return a.Vulns > b.Vulns
		}
		if a.Products != b.Products {
			return a.Products > b.Products
		}
		return a.Name < b.Name
	})
	if len(d.Quality.Top) > 15 {
		d.Quality.Top = d.Quality.Top[:15]
	}
	d.Security.Trend = s.dtPortfolioTrend()

	// 할 일: 판단 대기(심각도 높은 것), 오래된 미판단, 동기화 실패
	if c, h := d.Security.Pending["CRITICAL"], d.Security.Pending["HIGH"]; c+h > 0 {
		link := ""
		if len(d.Security.Products) > 0 {
			p := d.Security.Products[0]
			link = "/artifact/" + url.PathEscape(p.Repo) + "/" + url.PathEscape(p.Tag)
		}
		tone := "warn"
		if c > 0 {
			tone = "crit"
		}
		d.Todo = append(d.Todo, dashTodo{Kind: "vuln", Tone: tone, Count: c + h, Link: link,
			Text: "판단 대기 CRITICAL " + strconv.Itoa(c) + " · HIGH " + strconv.Itoa(h)})
	}
	if old := aging[2] + aging[3]; old > 0 {
		d.Todo = append(d.Todo, dashTodo{Kind: "aging", Tone: "warn", Count: old, Text: strconv.Itoa(dashAgingDays) + "일 넘게 판단되지 않은 취약점"})
	}
}

func (s *Server) dtComponents(uuid string) []dtComponent {
	resp, err := s.dtReq("GET", "/api/v1/component/project/"+url.PathEscape(uuid)+"?pageSize=2000&pageNumber=1", nil)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	var cs []dtComponent
	_ = json.NewDecoder(resp.Body).Decode(&cs)
	return cs
}

// dtPortfolioTrend: DT 포트폴리오 지표 이력(일별) — 같은 날 여러 건이면 마지막 값.
func (s *Server) dtPortfolioTrend() []dashDay {
	resp, err := s.dtReq("GET", "/api/v1/metrics/portfolio/"+strconv.Itoa(dashDays)+"/days", nil)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	var ms []struct {
		Critical          int   `json:"critical"`
		High              int   `json:"high"`
		Medium            int   `json:"medium"`
		Low               int   `json:"low"`
		FindingsUnaudited int   `json:"findingsUnaudited"`
		LastOccurrence    int64 `json:"lastOccurrence"`
	}
	if json.NewDecoder(resp.Body).Decode(&ms) != nil {
		return nil
	}
	byDay := map[string]dashDay{}
	for _, m := range ms {
		day := time.UnixMilli(m.LastOccurrence).UTC().Format("2006-01-02")
		byDay[day] = dashDay{Date: day, Critical: m.Critical, High: m.High, Medium: m.Medium, Low: m.Low, Unaudited: m.FindingsUnaudited}
	}
	out := make([]dashDay, 0, len(byDay))
	for _, v := range byDay {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Date < out[j].Date })
	return out
}

// ---------- ④ 고객·배포 + ⑤ 운영: zot 접근 로그 ----------

type zotLogLine struct {
	Time       string `json:"time"`
	Message    string `json:"message"`
	Username   string `json:"username"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	StatusCode int    `json:"statusCode"`
}

var manifestPath = regexp.MustCompile(`^/v2/(.+)/manifests/([^/]+)$`)

// 다운로드 집계에서 빼는 내부 서비스 계정
var dashServiceUsers = map[string]bool{"": true, "svc-bff": true}

// parseZotAccess: 접근 로그 한 줄 → (업로드|다운로드, 사용자, 제품, 버전, 시각). 해당 없으면 kind="".
// 업로드 = 태그로 매니페스트 PUT(201), 다운로드 = 태그로 매니페스트 GET(200). digest 참조(첨부·내부 조회)는 제외.
func parseZotAccess(line []byte) (kind, user, repo, tag string, t time.Time) {
	var l zotLogLine
	if json.Unmarshal(line, &l) != nil || l.Message != "HTTP API" {
		return
	}
	m := manifestPath.FindStringSubmatch(l.Path)
	if m == nil || strings.HasPrefix(m[2], "sha256:") {
		return
	}
	tt, err := time.Parse(time.RFC3339Nano, l.Time)
	if err != nil {
		return
	}
	switch {
	case l.Method == "PUT" && l.StatusCode == 201:
		kind = "upload"
	case l.Method == "GET" && l.StatusCode == 200 && !dashServiceUsers[l.Username]:
		kind = "download"
	default:
		return
	}
	return kind, l.Username, m[1], m[2], tt
}

func (s *Server) dashLog(d *Dashboard, now, since time.Time, latest map[string]string, orgOf map[string]string) {
	days := map[string]*dashDay{}
	for i := 0; i < dashDays; i++ {
		day := since.AddDate(0, 0, i+1).UTC().Format("2006-01-02")
		days[day] = &dashDay{Date: day}
	}
	actors := map[string]int{}
	byOrg := map[string]int{}
	seen := map[string]bool{} // 같은 사용자·버전을 1분 안에 여러 번 조회하면 한 번으로
	var downloads []dashDownload
	if f, err := os.Open(s.cfg.LogFile); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			kind, user, repo, tag, t := parseZotAccess(sc.Bytes())
			if kind == "" || t.Before(since) {
				continue
			}
			key := kind + "|" + user + "|" + repo + "|" + tag + "|" + t.UTC().Format("2006-01-02T15:04")
			if seen[key] {
				continue
			}
			seen[key] = true
			day := days[t.UTC().Format("2006-01-02")]
			if kind == "upload" {
				if day != nil {
					day.Uploads++
				}
				if user != "" {
					actors[user]++
				}
				continue
			}
			if day != nil {
				day.Downloads++
			}
			actors[user]++
			dl := dashDownload{Time: t.UTC().Format(time.RFC3339), User: user, Org: orgOf[user], Repo: repo, Tag: tag}
			if lt := latest[repo]; lt != "" && lt != tag && tag != "latest" && cmpVersion(tag, lt) < 0 {
				dl.Latest = lt
			}
			if dl.Org != "" {
				byOrg[dl.Org]++
			}
			downloads = append(downloads, dl)
		}
		f.Close()
	}
	for _, v := range days {
		d.Ops.Daily = append(d.Ops.Daily, *v)
	}
	sort.Slice(d.Ops.Daily, func(i, j int) bool { return d.Ops.Daily[i].Date < d.Ops.Daily[j].Date })
	d.Ops.Actors = topCounts(actors, 10)
	d.Customers.Orgs = topCounts(byOrg, 20)
	// 최근순
	for i := len(downloads) - 1; i >= 0; i-- {
		dl := downloads[i]
		if len(d.Customers.Recent) < 20 {
			d.Customers.Recent = append(d.Customers.Recent, dl)
		}
		if dl.Org != "" && dl.Latest != "" && len(d.Customers.Outdated) < 20 {
			d.Customers.Outdated = append(d.Customers.Outdated, dl)
		}
	}
}

// dashOrgs: 사용자·자동화 계정 → 고객사, 그리고 연락처 누락 할 일(이메일 없는 고객 사용자, 통보 주소 없는 고객사).
func (s *Server) dashOrgs() (map[string]string, []dashTodo) {
	orgOf := map[string]string{}
	var todo []dashTodo
	gs, err := s.listGroups()
	if err != nil {
		return orgOf, nil
	}
	noEmail, noContact := 0, 0
	orgs := map[string]bool{}
	for _, g := range gs {
		if !strings.HasPrefix(g.Name, orgPrefix) {
			continue
		}
		org := strings.TrimPrefix(g.Name, orgPrefix)
		orgs[org] = true
		if len(orgContacts(g)) == 0 {
			noContact++
		}
		for _, u := range s.groupUsers(g.ID) {
			orgOf[u.Username] = org
			if u.Email == "" {
				noEmail++
			}
		}
	}
	// 다운로드용 자동화 계정은 이름 규칙(robot-<고객사>)으로 고객사를 붙인다
	if s.access != nil {
		for _, r := range s.access.snapshot().Robots {
			if org := strings.TrimPrefix(r.Name, "robot-"); org != r.Name && orgs[org] {
				orgOf[r.Name] = org
			}
		}
	}
	if noEmail > 0 {
		todo = append(todo, dashTodo{Kind: "email", Tone: "warn", Count: noEmail, Link: "/admin/users", Text: "이메일이 없는 고객 사용자(보안 통보를 받지 못함)"})
	}
	if noContact > 0 {
		todo = append(todo, dashTodo{Kind: "contact", Tone: "warn", Count: noContact, Link: "/admin/orgs", Text: "보안 통보 주소가 없는 고객사"})
	}
	return orgOf, todo
}

// ---------- 통보 기록·감사 기록 ----------

func (s *Server) dashNotices(d *Dashboard, now, since time.Time) {
	n := s.notify
	n.mu.Lock()
	notices := append([]Notice(nil), n.st.Notices...)
	d.Ops.LastSync, d.Ops.LastSyncMsg = n.st.LastSync, n.st.LastSyncMsg
	n.mu.Unlock()
	if strings.Contains(d.Ops.LastSyncMsg, "실패") && !strings.Contains(d.Ops.LastSyncMsg, "실패 0건") {
		d.Todo = append(d.Todo, dashTodo{Kind: "sync", Tone: "warn", Count: 1, Link: "/admin/notify", Text: "취약점 감시 동기화 실패: " + d.Ops.LastSyncMsg})
	}
	firstNew := map[string]time.Time{} // repo|tag → 첫 새 취약점 통보
	failed := 0
	for _, nt := range notices {
		t, err := time.Parse(time.RFC3339, nt.Time)
		if err != nil {
			continue
		}
		key := nt.Repo + "|" + nt.Tag
		if nt.Kind == "vuln-new" {
			if f, ok := firstNew[key]; !ok || t.Before(f) {
				firstNew[key] = t
			}
		}
		if t.Before(since) {
			continue
		}
		d.Ops.Mailed += len(nt.Mailed)
		if nt.MailErr != "" {
			failed++
		}
		if nt.Audience == "customer" {
			d.Customers.Notices++
		}
	}
	d.Ops.MailFailed = failed
	if failed > 0 {
		d.Todo = append(d.Todo, dashTodo{Kind: "mail", Tone: "warn", Count: failed, Link: "/admin/notify", Text: "메일 발송 실패(최근 " + strconv.Itoa(dashDays) + "일)"})
	}
	// 최근 새 취약점 통보(최근순 10건)
	for i := len(notices) - 1; i >= 0 && len(d.Security.Recent) < 10; i-- {
		if nt := notices[i]; nt.Kind == "vuln-new" {
			d.Security.Recent = append(d.Security.Recent, dashRecent{Time: nt.Time, Repo: nt.Repo, Tag: nt.Tag,
				Title: strings.TrimPrefix(nt.Title, "[TrustLink] ")})
		}
	}
	// 평균 대응 시간: 첫 새 취약점 통보 → 그 버전의 첫 VEX 발행(감사 기록)
	evs, _ := s.sor.list()
	d.Security.MTTRHours, d.Security.MTTRSamples = mttr(firstNew, evs)
}

// mttr: 버전마다 (첫 새 취약점 통보 → 그 뒤 첫 VEX 발행) 시간의 평균(시간 단위)과 표본 수.
func mttr(firstNew map[string]time.Time, evs []SoREvent) (float64, int) {
	done := map[string]bool{}
	var sum float64
	cnt := 0
	for _, ev := range evs {
		if ev.Action != "vex-publish" {
			continue
		}
		key := ev.Repo + "|" + ev.Tag
		start, ok := firstNew[key]
		t, err := time.Parse(time.RFC3339, ev.Time)
		if !ok || done[key] || err != nil || t.Before(start) {
			continue
		}
		done[key] = true
		sum += t.Sub(start).Hours()
		cnt++
	}
	if cnt == 0 {
		return 0, 0
	}
	return float64(int(sum/float64(cnt)*10)) / 10, cnt
}

// dashExpiring: 만료됐거나 곧 만료되는 자동화 계정.
func (s *Server) dashExpiring(now time.Time) []dashTodo {
	if s.access == nil {
		return nil
	}
	soon, expired := 0, 0
	for _, r := range s.access.snapshot().Robots {
		t, err := time.Parse(time.RFC3339, r.Expires)
		if err != nil {
			continue
		}
		switch {
		case t.Before(now):
			expired++
		case t.Before(now.AddDate(0, 0, dashExpireDays)):
			soon++
		}
	}
	var out []dashTodo
	if expired > 0 {
		out = append(out, dashTodo{Kind: "robot", Tone: "crit", Count: expired, Link: "/admin/robots", Text: "만료된 자동화 계정(연결된 시스템 업로드·다운로드 중단)"})
	}
	if soon > 0 {
		out = append(out, dashTodo{Kind: "robot", Tone: "warn", Count: soon, Link: "/admin/robots", Text: strconv.Itoa(dashExpireDays) + "일 안에 만료되는 자동화 계정"})
	}
	return out
}

// certDaysLeft: 공개 주소가 https 면 서버 인증서의 남은 날 수, 아니면 -1.
func certDaysLeft(redirectURI string, now time.Time) int {
	u, err := url.Parse(redirectURI)
	if err != nil || u.Scheme != "https" {
		return -1
	}
	host := u.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host += ":443"
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", host, &tls.Config{ServerName: u.Hostname()})
	if err != nil {
		return -1
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return -1
	}
	return int(certs[0].NotAfter.Sub(now).Hours() / 24)
}

func topCounts(m map[string]int, n int) []dashCount {
	out := make([]dashCount, 0, len(m))
	for k, v := range m {
		out = append(out, dashCount{Label: k, Value: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Value != out[j].Value {
			return out[i].Value > out[j].Value
		}
		return out[i].Label < out[j].Label
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}
