package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 허브 → 받는 쪽: 구독 키, 서명·해시 검증, 변조 거부, 되돌리기 거부, 오프라인 번들.
func TestFeedHub(t *testing.T) {
	body := map[string]string{"/a.txt": "alpha", "/b.txt": "beta"}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := body[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, b)
	}))
	defer origin.Close()
	host := strings.TrimPrefix(origin.URL, "http://")
	mirrorCatalog = append(mirrorCatalog, mirrorSource{ID: "h", Hosts: []string{host}, IntervalH: 24, run: func(r *runCtx) error {
		return each(r, origin.URL+"/a.txt", origin.URL+"/b.txt")
	}})
	defer func() { mirrorCatalog = mirrorCatalog[:len(mirrorCatalog)-1] }()
	newMirror := func() *mirror {
		m := &mirror{dir: t.TempDir(), client: http.DefaultClient}
		if err := m.load(); err != nil {
			t.Fatal(err)
		}
		m.policy.Mode, m.policy.MinFreeGB = "scheduled", 1
		return m
	}

	hub := newMirror()
	hub.hub = true
	if err := hub.loadSignKey(true); err != nil {
		t.Fatal(err)
	}
	hub.runSource("h", "manual")
	if hub.states["h"].Status != "ok" {
		t.Fatalf("허브 수집: %+v", hub.states["h"])
	}
	pub := base64.StdEncoding.EncodeToString(hub.pubKey())
	// 구독 키 발급(명령줄과 같은 경로)
	if err := mirrorCLI(hub, []string{"sub", "add", "site-a"}); err != nil {
		t.Fatal(err)
	}
	key := "tlsub_test"
	sha256Hex := func(k string) string { h := sha256.Sum256([]byte(k)); return hex.EncodeToString(h[:]) }
	srv := httptest.NewServer(hub.handler())
	defer srv.Close()

	get := func(p, k string) int {
		req, _ := http.NewRequest("GET", srv.URL+p, nil)
		if k != "" {
			req.Header.Set(subHeader, k)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if get("/"+host+"/a.txt", "") != 401 || get("/_api/snapshot", "wrong") != 401 || get("/_api/healthz", "") != 200 {
		t.Fatal("허브가 키 없이 읽기를 허용하거나 healthz 를 막음")
	}
	// 테스트용으로 아는 키를 등록한다
	writeSub := func(name, k string) {
		subs := append(hub.readSubs(), subscriber{Name: name, Hash: sha256Hex(k), Created: "2026-01-01T00:00:00Z"})
		if err := writeJSONFile(hub.statePath("subscribers.json"), subs); err != nil {
			t.Fatal(err)
		}
		hub.subMod = hub.subMod.Add(-1) // 같은 시각에 쓴 파일도 다시 읽게
	}
	writeSub("site-b", key)
	if get("/"+host+"/a.txt", key) != 200 {
		t.Fatal("맞는 구독 키인데 거부")
	}

	child := func(pubKey, k string) *mirror {
		c := newMirror()
		c.policy.Upstream, c.policy.UpstreamPubKey = srv.URL, pubKey
		if k != "" {
			_ = os.WriteFile(c.statePath("upstream.key"), []byte(k), 0o600)
		}
		return c
	}
	// 정상: 키 + 공개키
	c := child(pub, key)
	c.runSource("h", "manual")
	if b, err := os.ReadFile(filepath.Join(c.dataDir(), host, "a.txt")); c.states["h"].Status != "ok" || err != nil || string(b) != "alpha" {
		t.Fatalf("검증 동기화 실패: %+v %v", c.states["h"], err)
	}
	if hs, _, _ := hub.snapshotLocked(); c.lastUpstream() == nil || c.lastUpstream().Snapshot != hs {
		t.Fatal("받아들인 스냅샷 기록이 허브와 다름")
	}
	if cs, _, _ := c.snapshotLocked(); cs != c.lastUpstream().Snapshot {
		t.Fatal("받는 쪽 스냅샷 ID 가 허브와 다름")
	}
	// 키 없음 / 다른 공개키 → 받지 않는다
	if x := child(pub, ""); true {
		x.runSource("h", "manual")
		if x.states["h"].Status != "error" || len(x.files) != 0 {
			t.Fatalf("구독 키 없이 받음: %+v", x.states["h"])
		}
	}
	other := newMirror()
	_ = other.loadSignKey(true)
	if x := child(base64.StdEncoding.EncodeToString(other.pubKey()), key); true {
		x.runSource("h", "manual")
		if x.states["h"].Status != "error" || len(x.files) != 0 || !strings.Contains(x.states["h"].Error, "서명") {
			t.Fatalf("다른 공개키인데 받음: %+v", x.states["h"])
		}
	}
	// 허브 디스크의 파일이 바뀜(매니페스트와 불일치) → 받는 쪽은 교체하지 않는다
	if err := os.WriteFile(filepath.Join(hub.dataDir(), host, "b.txt"), []byte("EVIL"), 0o644); err != nil {
		t.Fatal(err)
	}
	if x := child(pub, key); true {
		x.runSource("h", "manual")
		if _, err := os.Stat(filepath.Join(x.dataDir(), host, "b.txt")); x.states["h"].Status != "error" || !os.IsNotExist(err) {
			t.Fatalf("변조된 파일을 받아들임: %+v", x.states["h"])
		}
	}
	_ = os.WriteFile(filepath.Join(hub.dataDir(), host, "b.txt"), []byte("beta"), 0o644)

	// 오프라인 번들: 내보내기 → 폐쇄망 미러에 들여오기
	tarPath := filepath.Join(t.TempDir(), "bundle.tar")
	if err := hub.exportBundle(tarPath); err != nil {
		t.Fatal(err)
	}
	off := newMirror()
	off.policy.Mode = "offline"
	if err := off.importBundle(tarPath, ""); err == nil {
		t.Fatal("공개키 없이 들여옴")
	}
	if err := off.importBundle(tarPath, base64.StdEncoding.EncodeToString(other.pubKey())); err == nil {
		t.Fatal("다른 공개키로 들여옴")
	}
	if err := off.importBundle(tarPath, pub); err != nil {
		t.Fatal(err)
	}
	hs, _, _ := hub.snapshotLocked()
	if os2, _, n := off.snapshotLocked(); os2 != hs || n != 2 || off.states["h"].Status != "ok" {
		t.Fatalf("들여온 스냅샷이 허브와 다름: %s %d", os2, n)
	}
	// 변조된 번들(내용 한 글자) → 거부, 기존 사본 유지
	raw, _ := os.ReadFile(tarPath)
	bad := filepath.Join(t.TempDir(), "bad.tar")
	_ = os.WriteFile(bad, bytes.Replace(raw, []byte("alpha"), []byte("alphX"), 1), 0o644)
	fresh := newMirror()
	if err := fresh.importBundle(bad, pub); err == nil || len(fresh.files) != 0 {
		t.Fatalf("변조된 번들을 들여옴: %v", err)
	}
	// 되돌리기: 더 오래된 스냅샷은 거부
	var env snapEnvelope
	resp, _ := http.NewRequest("GET", srv.URL+"/_api/snapshot", nil)
	resp.Header.Set(subHeader, key)
	r2, err := http.DefaultClient.Do(resp)
	if err != nil {
		t.Fatal(err)
	}
	_ = json.NewDecoder(r2.Body).Decode(&env)
	r2.Body.Close()
	p, _, err := openEnvelope(&env, pub)
	if err != nil {
		t.Fatal(err)
	}
	off.acceptUpstream(env.KeyID, &snapPayload{Generated: "2099-01-01T00:00:00Z", Snapshot: "x"}, "sync")
	if err := off.checkRollback(env.KeyID, p); err == nil {
		t.Fatal("오래된 스냅샷을 거부하지 않음")
	}
	// 구독 키는 정책 파일·상태 응답에 남지 않는다
	if st, _ := json.Marshal(c.status()); bytes.Contains(st, []byte(key)) || !c.status().Policy.UpstreamKeySet {
		t.Fatal("상태 응답에 구독 키가 보이거나 설정 표시가 없음")
	}
}
