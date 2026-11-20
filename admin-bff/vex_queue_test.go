package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 대기열: 제품·버전별 미판단 집계, 급한 순 정렬, AI 일괄 판정 상태(파일) 반영.
func TestVexQueue(t *testing.T) {
	t.Setenv("AI_VEX_DIR", t.TempDir())
	uuids := map[string]string{"products/a@1.0": "11111111-1111-1111-1111-111111111111", "products/b@2.0": "22222222-2222-2222-2222-222222222222"}
	finds := map[string]string{
		uuids["products/a@1.0"]: `[{"vulnerability":{"vulnId":"CVE-1","severity":"HIGH"},"analysis":{"state":"NOT_SET"}},
			{"vulnerability":{"vulnId":"CVE-2","severity":"LOW"},"analysis":{"state":"NOT_AFFECTED"}}]`,
		uuids["products/b@2.0"]: `[{"vulnerability":{"vulnId":"CVE-3","severity":"CRITICAL"},"analysis":{}},
			{"vulnerability":{"vulnId":"CVE-4","severity":"HIGH"},"analysis":{"state":"EXPLOITABLE"}},
			{"vulnerability":{"vulnId":"CVE-5","severity":"HIGH"},"analysis":{"state":"NOT_SET","isSuppressed":true}}]`,
	}
	dt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/project/lookup") {
			json.NewEncoder(w).Encode(map[string]string{"uuid": uuids[r.URL.Query().Get("name")+"@"+r.URL.Query().Get("version")]})
			return
		}
		w.Write([]byte(finds[strings.TrimPrefix(r.URL.Path, "/api/v1/finding/project/")]))
	}))
	defer dt.Close()
	s := &Server{cfg: Config{DTBaseURL: dt.URL, DTApiKey: "k"}, http: &http.Client{Timeout: 5 * time.Second},
		store: newStore(filepath.Join(t.TempDir(), "s.json"))}
	s.dtKey.Store("k")
	s.notify = newNotifier(filepath.Join(t.TempDir(), "n.json"))
	s.notify.st.Projects = map[string]string{"products/a@1.0": "products/a", "products/b@2.0": "products/b"}
	(&vexBatch{Project: uuids["products/a@1.0"], State: "done", Total: 1, Done: 1, Finished: "2026-11-19T00:00:00Z",
		Results: map[string]*vexDraftResult{"c|v": {}}}).save()

	sid := s.store.put(Session{Username: "dev1", Groups: []string{"developers"}, Expiry: time.Now().Add(time.Hour)})
	req := httptest.NewRequest("GET", "/api/vex/queue?refresh=1", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: sid})
	rec := httptest.NewRecorder()
	s.apiVexQueue(rec, req)
	var out struct {
		Rows    []vexQueueRow  `json:"rows"`
		Summary map[string]int `json:"summary"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.Rows) != 2 || out.Rows[0].Repo != "products/b" {
		t.Fatalf("치명 미판단이 있는 제품이 먼저: %+v", out.Rows)
	}
	b, a := out.Rows[0], out.Rows[1]
	if b.Total != 2 || b.Pending != 1 || b.PendCrit != 1 || b.Affected != 1 {
		t.Fatalf("숨김 제외·영향 있음 집계: %+v", b)
	}
	if a.Pending != 1 || a.PendHigh != 1 || a.Analyzed != 1 || a.BatchState != "done" || a.BatchDrafts != 1 {
		t.Fatalf("일괄 판정 상태: %+v", a)
	}
	if out.Summary["pending"] != 2 || out.Summary["drafts"] != 1 {
		t.Fatalf("합계: %v", out.Summary)
	}
}
