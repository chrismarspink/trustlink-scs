package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMirrorWindow(t *testing.T) {
	p := mirrorPolicy{WindowStart: "02:00", WindowEnd: "06:00"}
	at := func(h, m int) time.Time { return time.Date(2026, 11, 17, h, m, 0, 0, kst) }
	if !inWindow(p, at(3, 0)) || inWindow(p, at(6, 0)) || inWindow(p, at(1, 59)) {
		t.Fatal("일반 창 판정 오류")
	}
	if got := nextWindowAt(p, at(7, 0)); !got.Equal(at(2, 0).AddDate(0, 0, 1)) {
		t.Fatalf("다음 창 = %v", got)
	}
	if got := nextWindowAt(p, at(1, 0)); !got.Equal(at(2, 0)) {
		t.Fatalf("오늘 창 = %v", got)
	}
	night := mirrorPolicy{WindowStart: "23:00", WindowEnd: "01:00"}
	if !inWindow(night, at(23, 30)) || !inWindow(night, at(0, 30)) || inWindow(night, at(12, 0)) {
		t.Fatal("자정 넘는 창 판정 오류")
	}
}

func TestLocalPathRejectsTraversal(t *testing.T) {
	if p, err := localPath("https://a.example/x/../../etc/passwd"); err == nil && strings.Contains(p, "..") {
		t.Fatal(p)
	}
	if _, err := localPath("https://a.example/x?q=1"); err == nil {
		t.Fatal("쿼리 허용됨")
	}
	if p, _ := localPath("https://a.example/feeds/a.gz"); p != "a.example/feeds/a.gz" {
		t.Fatal(p)
	}
}

// 원본 → 미러(조건부 GET·해시·정리) → 하위 미러(연쇄) 전 과정.
func TestMirrorFetchConditionalPruneAndChain(t *testing.T) {
	hits := map[string]int{}
	body := map[string]string{"/v1.txt": "one", "/v2.txt": "two"}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits[r.URL.Path]++
		if r.Header.Get("If-None-Match") == `"e`+r.URL.Path+`"` {
			w.WriteHeader(304)
			return
		}
		b, ok := body[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("ETag", `"e`+r.URL.Path+`"`)
		fmt.Fprint(w, b)
	}))
	defer origin.Close()
	host := strings.TrimPrefix(origin.URL, "http://")
	want := []string{"/v1.txt"}
	mirrorCatalog = append(mirrorCatalog, mirrorSource{ID: "t", Hosts: []string{host}, IntervalH: 24, run: func(r *runCtx) error {
		for _, p := range want {
			if err := r.get(origin.URL + p); err != nil {
				return err
			}
		}
		return r.tryGet(origin.URL + "/missing.txt")
	}})
	defer func() { mirrorCatalog = mirrorCatalog[:len(mirrorCatalog)-1] }()

	m := &mirror{dir: t.TempDir(), client: http.DefaultClient}
	if err := m.load(); err != nil {
		t.Fatal(err)
	}
	m.policy.Mode, m.policy.MinFreeGB = "scheduled", 1
	m.runSource("t", "manual")
	if st := m.states["t"]; st.Status != "ok" {
		t.Fatalf("1차 실행: %+v", st)
	}
	snap1, _, n := m.snapshotLocked()
	if n != 1 || m.files[host+"/v1.txt"].SHA256 == "" {
		t.Fatalf("매니페스트: %d", n)
	}
	m.runSource("t", "manual") // 같은 내용 → 304, 스냅샷 동일
	if snap2, _, _ := m.snapshotLocked(); snap2 != snap1 || m.states["t"].Changed != 0 {
		t.Fatal("변경 없음인데 스냅샷이 바뀜")
	}
	want = []string{"/v2.txt"} // 원본 묶음이 바뀜 → 이전 파일 정리
	m.runSource("t", "manual")
	if _, err := os.Stat(filepath.Join(m.dataDir(), host, "v1.txt")); !os.IsNotExist(err) {
		t.Fatal("이전 파일이 남음")
	}
	// 하위 미러: 원본 대신 상위 미러에서 받는다
	up := httptest.NewServer(m.handler())
	defer up.Close()
	child := &mirror{dir: t.TempDir(), client: http.DefaultClient}
	if err := child.load(); err != nil {
		t.Fatal(err)
	}
	child.policy.Mode, child.policy.MinFreeGB, child.policy.Upstream = "scheduled", 1, up.URL
	before := hits["/v2.txt"]
	child.runSource("t", "manual")
	b, err := os.ReadFile(filepath.Join(child.dataDir(), host, "v2.txt"))
	if err != nil || string(b) != "two" || hits["/v2.txt"] != before {
		t.Fatalf("연쇄 미러 실패: %q %v (원본 접속 %d→%d)", b, err, before, hits["/v2.txt"])
	}
	// 폐쇄망 모드: 받지 않음
	child.policy.Mode = "offline"
	child.states["t"].LastSuccess = ""
	child.runSource("t", "manual")
	if child.states["t"].LastSuccess != "" {
		t.Fatal("폐쇄망 모드에서 접속함")
	}
	// 쓰기 API 는 키가 있어야 한다
	req := httptest.NewRequest("POST", "/_api/sync/t", nil)
	rec := httptest.NewRecorder()
	m.handler().ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("키 없이 %d", rec.Code)
	}
}
