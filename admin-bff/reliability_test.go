package main

import (
	"crypto/tls"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// 저장·감사 기록이 실패하면 호출한 쪽이 오류를 버려도 세어 두고, 관리자 제안과 건강 점검에 드러난다.
func TestReliabilitySurfacesFailures(t *testing.T) {
	relStat.Lock()
	relStat.StoreFails, relStat.SorFails = 0, 0
	relStat.Unlock()
	bad := filepath.Join(t.TempDir(), "file-not-dir")
	if err := writeJSONFile(bad, 1); err != nil {
		t.Fatal(err)
	}
	_ = writeJSONFile(filepath.Join(bad, "x.json"), 1) // 파일 아래에는 쓸 수 없다
	_ = (&SoR{path: filepath.Join(bad, "sor.jsonl")}).append(SoREvent{Action: "x"})
	s := agentServer(t)
	found := false
	for _, x := range s.agentTasks(Session{Username: "admin1", Groups: []string{"admins"}}) {
		if x.ID == "rel:fails" && x.Urgent && strings.Contains(x.Title, "저장 실패 1건 · 감사 기록 실패 1건") {
			found = true
		}
	}
	if !found {
		t.Errorf("관리자 제안에 저장 실패가 없음")
	}
	for _, x := range s.agentTasks(Session{Username: "dev1", Groups: []string{"developers"}}) {
		if x.Kind == "rel" {
			t.Errorf("운영 문제가 관리자가 아닌 사람에게 보임")
		}
	}
	out := map[string]any{}
	s.relHealth(out)
	if out["storeFails"] != 1 || out["sorFails"] != 1 || out["lastFail"] == "" {
		t.Errorf("건강 점검: %+v", out)
	}
	relStat.Lock()
	relStat.StoreFails, relStat.SorFails = 0, 0
	relStat.Unlock()
}

func TestUICacheHeader(t *testing.T) {
	w := httptest.NewRecorder()
	uiCacheHeader(w, true)
	if !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Errorf("해시 파일: %q", w.Header().Get("Cache-Control"))
	}
	w = httptest.NewRecorder()
	uiCacheHeader(w, false)
	if w.Header().Get("Cache-Control") != "no-cache" {
		t.Errorf("첫 문서: %q", w.Header().Get("Cache-Control"))
	}
}

func TestReqHTTPS(t *testing.T) {
	cases := []struct {
		tls  bool
		xfp  string
		want bool
	}{
		{false, "", false},
		{false, "http", false},
		{false, "https", true},
		{false, "https, http", true},
		{false, "HTTPS", true},
		{true, "", true},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		if c.xfp != "" {
			r.Header.Set("X-Forwarded-Proto", c.xfp)
		}
		if c.tls {
			r.TLS = &tls.ConnectionState{}
		}
		if got := reqHTTPS(r); got != c.want {
			t.Errorf("tls=%v xfp=%q → %v, want %v", c.tls, c.xfp, got, c.want)
		}
	}
}
