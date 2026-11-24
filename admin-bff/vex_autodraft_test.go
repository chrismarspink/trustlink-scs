package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const autoProj = "33333333-3333-3333-3333-333333333333"

// 자동 초안 시험 환경: 가짜 DT(조회·findings) + 가짜 LLM + KEV 사본(미러) + 원장.
func autoDraftEnv(t *testing.T, findings string) (*Server, *int32) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AI_VEX_DIR", filepath.Join(dir, "ai-vex"))
	t.Setenv("MIRROR_DIR", dir)
	t.Setenv("AI_CONFIG", filepath.Join(dir, "없음.json"))
	kev := filepath.Join(dir, "data/www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
	os.MkdirAll(filepath.Dir(kev), 0o755)
	os.WriteFile(kev, []byte(`{"vulnerabilities":[{"cveID":"CVE-2026-109618","dateAdded":"2026-10-26","dueDate":"2026-10-29"}]}`), 0o644)
	var calls int32
	llm := fakeLLM(t, `{"status":"affected","justification":"","response":"update","detail":"영향 있음 [V1]","plan":["업데이트 [V1]"],"workaround":"","citations":["V1"],"missing":[],"confidence":"medium"}`, nil)
	t.Cleanup(llm.Close)
	t.Setenv("AI_URL", llm.URL)
	dt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v1/project/lookup"):
			if r.URL.Query().Get("name") == "innopouch" && r.URL.Query().Get("version") == "11.0" {
				json.NewEncoder(w).Encode(map[string]string{"uuid": autoProj})
				return
			}
			http.NotFound(w, r)
		case r.URL.Path == "/api/v1/finding/project/"+autoProj:
			atomic.AddInt32(&calls, 1)
			w.Write([]byte(findings))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(dt.Close)
	s := &Server{cfg: Config{DTBaseURL: dt.URL, DTApiKey: "k"}, http: &http.Client{Timeout: 5 * time.Second}}
	s.dtKey.Store("k")
	s.sor = newSoR(filepath.Join(dir, "sor.jsonl"))
	t.Cleanup(func() {
		vexBatchMu.Lock()
		delete(vexBatches, autoProj)
		vexBatchMu.Unlock()
	})
	return s, &calls
}

func finding(comp, vuln, id, sev, state string) string {
	return `{"component":{"uuid":"` + comp + `","name":"php","version":"8.3.7","purl":"pkg:generic/php@8.3.7"},` +
		`"vulnerability":{"uuid":"` + vuln + `","vulnId":"` + id + `","source":"NVD","severity":"` + sev + `"},"analysis":{"state":"` + state + `"}}`
}

var autoFindings = "[" + strings.Join([]string{
	finding("c1", "v1", "CVE-2026-7261", "CRITICAL", "NOT_SET"),
	finding("c1", "v2", "CVE-2026-109618", "CRITICAL", ""),          // KEV — 맨 앞
	finding("c1", "v3", "CVE-2026-14355", "MEDIUM", "NOT_SET"),      // 제외(치명·KEV 아님)
	finding("c1", "v4", "CVE-2026-6722", "CRITICAL", "EXPLOITABLE"), // 제외(이미 판단)
	finding("c1", "v5", "CVE-2026-17543", "CRITICAL", "NOT_SET"),
}, ",") + "]"

func waitBatch(t *testing.T, project string) *vexBatch {
	t.Helper()
	for i := 0; i < 200; i++ {
		vexBatchMu.Lock()
		b := vexBatches[project]
		st := ""
		if b != nil {
			st = b.State
		}
		vexBatchMu.Unlock()
		if b != nil && st != "running" {
			return b
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("일괄 판정이 끝나지 않음")
	return nil
}

func sorActions(t *testing.T, s *Server) []SoREvent {
	b, _ := os.ReadFile(s.sor.path)
	var out []SoREvent
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var e SoREvent
		if json.Unmarshal([]byte(l), &e) == nil {
			out = append(out, e)
		}
	}
	return out
}

func TestAutoDraftPick(t *testing.T) {
	autoDraftEnv(t, "[]")
	var fs []dtFindingFull
	json.Unmarshal([]byte(autoFindings), &fs)
	picks, kev, crit := autoDraftPick(fs, 10, nil)
	if len(picks) != 3 || kev != 1 || crit != 2 || picks[0].Vulnerability.VulnID != "CVE-2026-109618" {
		t.Fatalf("KEV 먼저, 미분석 KEV·치명만: %d kev=%d crit=%d %+v", len(picks), kev, crit, picks)
	}
	if p, _, _ := autoDraftPick(fs, 2, nil); len(p) != 2 {
		t.Fatalf("최대 개수: %d", len(p))
	}
	if p, _, _ := autoDraftPick(fs, 10, map[string]*vexDraftResult{"c1|v2": {}}); len(p) != 2 || p[0].Vulnerability.VulnID == "CVE-2026-109618" {
		t.Fatalf("이미 초안이 있는 항목은 건너뜀: %+v", p)
	}
}

func TestAutoDraftStartsBatch(t *testing.T) {
	s, _ := autoDraftEnv(t, autoFindings)
	t.Setenv("AI_AUTODRAFT_MAX", "2")
	if st := s.autoDraft("products/innopouch", "11.0"); st != "started" {
		t.Fatalf("자동 초안 시작: %s", st)
	}
	b := waitBatch(t, autoProj)
	if b.Trigger != "auto" || b.Actor != autoDraftActor || b.Total != 2 || len(b.Results) != 2 || b.State != "done" {
		t.Fatalf("배치: trigger=%q actor=%q total=%d results=%d state=%s", b.Trigger, b.Actor, b.Total, len(b.Results), b.State)
	}
	for k, r := range b.Results {
		if !r.Auto {
			t.Fatalf("자동 초안 표시 누락: %s", k)
		}
	}
	if b.Results["c1|v2"] == nil || !b.Results["c1|v2"].KEV {
		t.Fatal("KEV 항목이 먼저 초안이 되어야 함")
	}
	var ev *SoREvent
	for _, e := range sorActions(t, s) {
		if e.Action == "ai-autodraft" {
			e := e
			ev = &e
		}
	}
	if ev == nil || ev.Repo != "products/innopouch" || ev.Tag != "11.0" || ev.Detail["kev"].(float64) != 1 || ev.Detail["total"].(float64) != 2 {
		t.Fatalf("원장 ai-autodraft: %+v", ev)
	}
	// 두 번째: 남은 치명 1건만, 이전 초안 2건은 유지
	if st := s.autoDraft("products/innopouch", "11.0"); st != "started" {
		t.Fatalf("두 번째 자동 초안: %s", st)
	}
	b = waitBatch(t, autoProj)
	if b.Total != 1 || len(b.Results) != 3 {
		t.Fatalf("이어 붙이기: total=%d results=%d", b.Total, len(b.Results))
	}
	if st := s.autoDraft("products/innopouch", "11.0"); st != "none" {
		t.Fatalf("다 만든 뒤에는 none: %s", st)
	}
	// 저장본에도 trigger·auto 가 남는다(재시작 후 화면 표시)
	var saved vexBatch
	if err := readJSONFile(vexBatchPath(autoProj), &saved); err != nil || saved.Trigger != "auto" || !saved.Results["c1|v1"].Auto {
		t.Fatalf("저장본: %v %+v", err, saved.Trigger)
	}
}

func TestAutoDraftSkips(t *testing.T) {
	s, calls := autoDraftEnv(t, autoFindings)
	t.Setenv("AI_AUTODRAFT", "off")
	if st := s.autoDraft("products/innopouch", "11.0"); st != "off" {
		t.Fatalf("끄기: %s", st)
	}
	t.Setenv("AI_AUTODRAFT", "on")
	if st := s.autoDraft("products/innopouch", "9.9"); st != "no-project" {
		t.Fatalf("DT 프로젝트 없음: %s", st)
	}
	vexBatchMu.Lock()
	vexBatches[autoProj] = &vexBatch{Project: autoProj, State: "running", Results: map[string]*vexDraftResult{}}
	vexBatchMu.Unlock()
	if st := s.autoDraft("products/innopouch", "11.0"); st != "running" {
		t.Fatalf("진행 중이면 걸지 않음: %s", st)
	}
	if atomic.LoadInt32(calls) != 0 {
		t.Fatal("진행 중이면 findings 도 읽지 않아야 함")
	}
	t.Setenv("AI_URL", "")
	if st := s.autoDraft("products/innopouch", "11.0"); st != "ai-off" {
		t.Fatalf("AI 꺼짐: %s", st)
	}
	for _, e := range sorActions(t, s) {
		if e.Action == "ai-autodraft" {
			t.Fatal("건너뛴 경우 원장에 남기지 않음")
		}
	}
}

func TestAutoDraftMaxEnv(t *testing.T) {
	for v, want := range map[string]int{"": 10, "3": 3, "0": 10, "x": 10, "99": 50} {
		t.Setenv("AI_AUTODRAFT_MAX", v)
		if got := autoDraftMax(); got != want {
			t.Errorf("AI_AUTODRAFT_MAX=%q → %d (want %d)", v, got, want)
		}
	}
}

// 통보 경로: 새 취약점 통보가 나가면 자동 초안이 걸린다.
func TestNotifyTriggersAutoDraft(t *testing.T) {
	s, _ := autoDraftEnv(t, autoFindings)
	s.cfg.KCInternal, s.cfg.RedirectURI, s.mail = "http://127.0.0.1:1", "http://tl.example/admin/callback", &Mailer{}
	s.http.Timeout = time.Second
	s.notify = newNotifier(filepath.Join(t.TempDir(), "notify.json"))
	s.notify.st.Projects["innopouch@11.0"] = "products/innopouch"
	s.queueVulnNotice(dtVuln("CVE-2026-109618", "critical", "innopouch", "11.0"))
	s.flushBatches(true)
	for i := 0; i < 200; i++ {
		vexBatchMu.Lock()
		b := vexBatches[autoProj]
		vexBatchMu.Unlock()
		if b != nil {
			waitBatch(t, autoProj)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("통보 뒤 자동 초안이 걸리지 않음")
}
