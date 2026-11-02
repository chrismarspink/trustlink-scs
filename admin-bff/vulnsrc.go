package main

// vulnsrc.go: Dependency-Track 취약점 DB 설정(관리 › 설정·스토리지 › 취약점 DB).
//   NVD 는 기본 사용. OSV(생태계 선택, 키 불필요)와 GitHub Advisories(토큰 필요)를 켜고 끈다.
//   출처를 늘리면 기존 버전에서 기존 취약점이 한꺼번에 새로 잡히므로, DT 가 새 출처를 다 내려받을 때까지
//   변경 전부터 감시하던 버전의 통보를 보류하고, 내려받기가 끝나면 모두 재분석한 뒤 보류를 푼다.

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
)

const (
	vsGroup        = "vuln-source"
	vsOSV          = "google.osv.enabled" // 켠 생태계 목록, ';' 구분
	vsGitHub       = "github.advisories.enabled"
	vsGitHubToken  = "github.advisories.access.token"
	vsQuietMax     = 72 * time.Hour                       // 출처 데이터가 끝내 안 들어와도 이 시간이 지나면 보류 해제
	vsQuietTail    = time.Hour                            // 재분석 요청 뒤 늦게 오는 알림까지 보류
	dtHiddenSecret = "HiddenDecryptedPropertyPlaceholder" // DT 가 비밀값 대신 돌려주는 표시
)

// DT 는 설정을 바꿔도 바로 내려받지 않고 정기 작업(OSV·GitHub 미러, 기본 24시간 주기)에서 받는다.
// 그래서 시간이 아니라 출처별 취약점 수가 늘고 안정되면(= 내려받기 완료) 재분석한다.
var vsWatchEvery = 10 * time.Minute

type vulnSources struct {
	OSV            []string `json:"osv"`
	Ecosystems     []string `json:"ecosystems"`
	GitHub         bool     `json:"github"`
	GitHubTokenSet bool     `json:"githubTokenSet"`
	QuietUntil     string   `json:"quietUntil"`
	Waiting        []string `json:"waiting"` // 내려받기를 기다리는 출처
}

func (s *Server) dtConfig(call func(string, string, string) (int, []byte, error)) (map[string]string, error) {
	code, b, err := call("GET", "/api/v1/configProperty", "")
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("DT 설정 조회 실패(%d)", code)
	}
	var ps []struct{ GroupName, PropertyName, PropertyValue string }
	_ = json.Unmarshal(b, &ps)
	out := map[string]string{}
	for _, p := range ps {
		if p.GroupName == vsGroup {
			out[p.PropertyName] = p.PropertyValue
		}
	}
	return out, nil
}

func splitEco(v string) []string {
	out := []string{}
	for _, e := range strings.Split(v, ";") {
		if e = strings.TrimSpace(e); e != "" {
			out = append(out, e)
		}
	}
	return out
}

// GET /api/vulnsources
func (s *Server) apiVulnSources(w http.ResponseWriter, r *http.Request) {
	call, err := s.dtAdminCaller()
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	cfg, err := s.dtConfig(call)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	eco := []string{}
	if _, b, err := call("GET", "/api/v1/integration/osv/ecosystem", ""); err == nil {
		_ = json.Unmarshal(b, &eco)
	}
	clean := eco[:0]
	for _, e := range eco {
		if e != "[EMPTY]" {
			clean = append(clean, e)
		}
	}
	tok := cfg[vsGitHubToken]
	s.notify.mu.Lock()
	quiet := s.notify.st.QuietUntil
	waiting := []string{}
	if rb := s.notify.st.Rebase; rb != nil {
		for src := range rb.Start {
			waiting = append(waiting, src)
		}
	}
	s.notify.mu.Unlock()
	writeJSON(w, 200, vulnSources{OSV: splitEco(cfg[vsOSV]), Ecosystems: clean, GitHub: cfg[vsGitHub] == "true",
		GitHubTokenSet: tok != "" && tok != "null", QuietUntil: quiet, Waiting: waiting})
}

// PUT /api/vulnsources {osv:[...], github:bool, githubToken?:string}
func (s *Server) apiVulnSourcesPut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		OSV         []string `json:"osv"`
		GitHub      bool     `json:"github"`
		GitHubToken string   `json:"githubToken"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	call, err := s.dtAdminCaller()
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	cfg, err := s.dtConfig(call)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	tokenSet := cfg[vsGitHubToken] != "" && cfg[vsGitHubToken] != "null"
	if in.GitHub && !tokenSet && in.GitHubToken == "" {
		writeJSON(w, 400, map[string]string{"error": "GitHub Advisories 를 켜려면 토큰이 필요합니다"})
		return
	}
	sort.Strings(in.OSV)
	want := map[string]string{vsOSV: strings.Join(in.OSV, ";"), vsGitHub: fmt.Sprint(in.GitHub)}
	if in.GitHubToken != "" {
		want[vsGitHubToken] = in.GitHubToken
	}
	cur := splitEco(cfg[vsOSV])
	sort.Strings(cur)
	changed := []string{}
	for k, v := range want {
		old := cfg[k]
		if k == vsOSV {
			old = strings.Join(cur, ";")
		}
		if k != vsGitHubToken && old == v {
			continue
		}
		var val any = v
		if v == "" {
			val = nil // DT 는 빈 문자열을 거부("control characters") — 비울 때는 null
		}
		body, _ := json.Marshal(map[string]any{"groupName": vsGroup, "propertyName": k, "propertyValue": val})
		code, b, err := call("POST", "/api/v1/configProperty", string(body))
		if err != nil || code != 200 {
			writeJSON(w, 502, map[string]string{"error": fmt.Sprintf("DT 설정 저장 실패(%s %d): %v %s", k, code, err, b)})
			return
		}
		changed = append(changed, k)
	}
	// 출처가 늘어나면(새로 켠 생태계·GitHub) 기존 취약점이 한꺼번에 나오므로 통보 보류 + 자동 재분석
	added := in.GitHub && cfg[vsGitHub] != "true"
	for _, e := range in.OSV {
		if !contains(cur, e) {
			added = true
		}
	}
	quiet := ""
	if added {
		srcs := []string{}
		if in.GitHub && cfg[vsGitHub] != "true" {
			srcs = append(srcs, "GITHUB")
		}
		if len(in.OSV) > len(cur) || !sameSet(in.OSV, cur) {
			srcs = append(srcs, "OSV")
		}
		quiet = s.startRebase(srcs)
	}
	_ = s.sor.append(SoREvent{Actor: w.Header().Get("X-User"), Action: "vuln-sources", Status: "updated",
		Detail: map[string]any{"osv": in.OSV, "github": in.GitHub, "changed": changed, "quietUntil": quiet}})
	writeJSON(w, 200, map[string]any{"status": "ok", "changed": len(changed), "quietUntil": quiet})
}

// POST /api/vulnsources/reanalyze — 감시 중인 모든 버전 즉시 재분석.
func (s *Server) apiVulnReanalyze(w http.ResponseWriter, r *http.Request) {
	n, failed := s.reanalyzeTracked()
	writeJSON(w, 200, map[string]any{"status": "ok", "requested": n, "failed": failed})
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		if !contains(b, x) {
			return false
		}
	}
	return true
}

// startRebase: 통보 보류를 걸고(최대 vsQuietMax, 이 시각 전부터 감시하던 버전만) 출처별 취약점 수를 기록한 뒤 감시 시작.
func (s *Server) startRebase(srcs []string) string {
	now := time.Now().UTC()
	rb := &rebaseState{Since: now.Format(time.RFC3339), Start: map[string]int{}, Last: map[string]int{}}
	for _, src := range srcs {
		c, _ := s.dtSourceCount(src)
		rb.Start[src], rb.Last[src] = c, c
	}
	until := now.Add(vsQuietMax).Format(time.RFC3339)
	n := s.notify
	n.mu.Lock()
	running := n.st.Rebase != nil
	n.st.Rebase = rb
	n.st.QuietSince = rb.Since
	n.st.QuietUntil = until
	n.saveLocked()
	n.mu.Unlock()
	if !running {
		go s.watchRebase()
	}
	return until
}

// watchRebase: 새 출처의 취약점 수가 늘고 두 번 연속 같으면(내려받기 완료) 재분석 → 1시간 뒤 보류 해제.
func (s *Server) watchRebase() {
	n := s.notify
	for {
		n.mu.Lock()
		rb := n.st.Rebase
		until, _ := time.Parse(time.RFC3339, n.st.QuietUntil)
		n.mu.Unlock()
		if rb == nil {
			return
		}
		if time.Now().After(until) {
			log.Printf("취약점 DB 변경: 내려받기 완료를 확인하지 못한 채 보류 기한 경과 — 보류 해제")
			n.mu.Lock()
			n.st.Rebase = nil
			n.saveLocked()
			n.mu.Unlock()
			return
		}
		ready := true
		cur := map[string]int{}
		for src, start := range rb.Start {
			c, err := s.dtSourceCount(src)
			cur[src] = c
			if err != nil || c <= start || c != rb.Last[src] {
				ready = false
			}
		}
		n.mu.Lock()
		if n.st.Rebase != nil {
			n.st.Rebase.Last = cur
		}
		n.saveLocked()
		n.mu.Unlock()
		if ready {
			req, failed := s.reanalyzeTracked()
			log.Printf("취약점 DB 변경: 새 출처 내려받기 완료(%v) → 재분석 요청 %d건, 실패 %d건, %s 뒤 보류 해제", cur, req, failed, vsQuietTail)
			n.mu.Lock()
			n.st.Rebase = nil
			n.st.QuietUntil = time.Now().Add(vsQuietTail).UTC().Format(time.RFC3339)
			n.saveLocked()
			n.mu.Unlock()
			return
		}
		time.Sleep(vsWatchEvery)
	}
}

// dtSourceCount: DT 에 들어 있는 출처별 취약점 수(OSV, GITHUB, NVD …).
func (s *Server) dtSourceCount(src string) (int, error) {
	resp, err := s.dtReq("GET", "/api/v1/vulnerability/source/"+url.PathEscape(src)+"?pageSize=1&pageNumber=1", nil)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("DT 취약점 수 조회 실패(%d)", resp.StatusCode)
	}
	var c int
	_, err = fmt.Sscan(resp.Header.Get("X-Total-Count"), &c)
	return c, err
}

// reanalyzeTracked: 통보 동기화가 DT 에 올린 모든 버전을 DT 에서 다시 분석시킨다.
func (s *Server) reanalyzeTracked() (int, int) {
	s.notify.mu.Lock()
	keys := make([]string, 0, len(s.notify.st.SBOM))
	for k := range s.notify.st.SBOM {
		keys = append(keys, k)
	}
	s.notify.mu.Unlock()
	n, failed := 0, 0
	for _, k := range keys {
		repo, tag, _ := strings.Cut(k, "|")
		uuid, err := s.dtLookupProject(path.Base(repo), tag)
		if err != nil || uuid == "" {
			failed++
			continue
		}
		resp, err := s.dtReq("POST", "/api/v1/finding/project/"+url.PathEscape(uuid)+"/analyze", nil)
		if err != nil {
			failed++
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			failed++
			continue
		}
		n++
	}
	return n, failed
}
