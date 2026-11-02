package main

// vulnsrc.go: Dependency-Track 취약점 DB 설정(관리 › 설정·스토리지 › 취약점 DB).
//   NVD 는 기본 사용. OSV(생태계 선택, 키 불필요)와 GitHub Advisories(토큰 필요)를 켜고 끈다.
//   출처를 바꾸면 기존 버전에서 새로 잡히는 취약점이 한꺼번에 나오므로 24시간 통보를 보류(기준선)하고,
//   DT 가 새 DB 를 내려받을 시간을 둔 뒤 감시 중인 모든 버전을 자동 재분석한다.

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
	vsQuietAfter   = 24 * time.Hour
	dtHiddenSecret = "HiddenDecryptedPropertyPlaceholder" // DT 가 비밀값 대신 돌려주는 표시
)

// 재분석 시점: DT 가 OSV 생태계를 내려받는 데 수 분~수십 분 걸린다.
var vsReanalyzeAfter = []time.Duration{20 * time.Minute, 2 * time.Hour}

type vulnSources struct {
	OSV            []string `json:"osv"`
	Ecosystems     []string `json:"ecosystems"`
	GitHub         bool     `json:"github"`
	GitHubTokenSet bool     `json:"githubTokenSet"`
	QuietUntil     string   `json:"quietUntil"`
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
	s.notify.mu.Unlock()
	writeJSON(w, 200, vulnSources{OSV: splitEco(cfg[vsOSV]), Ecosystems: clean, GitHub: cfg[vsGitHub] == "true",
		GitHubTokenSet: tok != "" && tok != "null", QuietUntil: quiet})
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
		body, _ := json.Marshal(map[string]string{"groupName": vsGroup, "propertyName": k, "propertyValue": v})
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
		quiet = s.notifyQuiet(vsQuietAfter)
		go s.scheduleReanalyze()
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

// notifyQuiet: 지금부터 d 동안 DT 새 취약점 알림을 통보하지 않고 기준선으로만 기록.
func (s *Server) notifyQuiet(d time.Duration) string {
	until := time.Now().Add(d).UTC().Format(time.RFC3339)
	s.notify.mu.Lock()
	s.notify.st.QuietUntil = until
	s.notify.saveLocked()
	s.notify.mu.Unlock()
	return until
}

func (s *Server) scheduleReanalyze() {
	start := time.Now()
	for _, d := range vsReanalyzeAfter {
		time.Sleep(time.Until(start.Add(d)))
		n, failed := s.reanalyzeTracked()
		log.Printf("취약점 DB 변경 후 재분석: 요청 %d건, 실패 %d건", n, failed)
	}
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
