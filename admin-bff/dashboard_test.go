package main

import (
	"testing"
	"time"
)

func TestParseZotAccess(t *testing.T) {
	cases := []struct {
		line, kind, user, repo, tag string
	}{
		{`{"time":"2026-11-05T13:20:56.7Z","message":"HTTP API","username":"acme1","method":"GET","path":"/v2/products/innopouch/manifests/9.0","statusCode":200}`,
			"download", "acme1", "products/innopouch", "9.0"},
		{`{"time":"2026-11-05T13:20:56.7Z","message":"HTTP API","username":"ci-innopouch","method":"PUT","path":"/v2/products/innopouch/manifests/11.0","statusCode":201}`,
			"upload", "ci-innopouch", "products/innopouch", "11.0"},
		// 내부 서비스 계정·digest 참조·실패 응답·다른 경로는 제외
		{`{"time":"2026-11-05T13:20:56.7Z","message":"HTTP API","username":"svc-bff","method":"GET","path":"/v2/products/webapp/manifests/latest","statusCode":200}`, "", "", "", ""},
		{`{"time":"2026-11-05T13:20:56.7Z","message":"HTTP API","username":"acme1","method":"GET","path":"/v2/products/innopouch/manifests/sha256:abc","statusCode":200}`, "", "", "", ""},
		{`{"time":"2026-11-05T13:20:56.7Z","message":"HTTP API","username":"acme1","method":"GET","path":"/v2/products/innopouch/manifests/9.0","statusCode":401}`, "", "", "", ""},
		{`{"time":"2026-11-05T13:20:56.7Z","message":"HTTP API","username":"acme1","method":"GET","path":"/v2/products/innopouch/blobs/sha256:abc","statusCode":200}`, "", "", "", ""},
		{`not json`, "", "", "", ""},
	}
	for _, c := range cases {
		kind, user, repo, tag, _ := parseZotAccess([]byte(c.line))
		if kind != c.kind || user != c.user || repo != c.repo || tag != c.tag {
			t.Errorf("%s\n → %q %q %q %q", c.line, kind, user, repo, tag)
		}
	}
}

func TestAgingBucketAndCopyleft(t *testing.T) {
	if agingBucket(2*time.Hour) != 0 || agingBucket(3*24*time.Hour) != 1 || agingBucket(10*24*time.Hour) != 2 || agingBucket(90*24*time.Hour) != 3 {
		t.Error("판단 대기 기간 구간이 잘못됨")
	}
	for id, want := range map[string]bool{"GPL-2.0-only": true, "LGPL-2.1": true, "MPL-2.0": true, "Apache-2.0": false, "MIT": false, "": false} {
		if isCopyleft(id) != want {
			t.Errorf("isCopyleft(%q) != %v", id, want)
		}
	}
	if !pendingState("") || !pendingState("IN_TRIAGE") || pendingState("NOT_AFFECTED") || pendingState("EXPLOITABLE") {
		t.Error("판단 대기 상태 판정이 잘못됨")
	}
}

func TestMTTR(t *testing.T) {
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	first := map[string]time.Time{"products/a|1.0": t0, "products/b|2.0": t0}
	evs := []SoREvent{
		{Time: t0.Add(-time.Hour).Format(time.RFC3339), Action: "vex-publish", Repo: "products/a", Tag: "1.0"}, // 통보 전 발행은 제외
		{Time: t0.Add(10 * time.Hour).Format(time.RFC3339), Action: "vex-publish", Repo: "products/a", Tag: "1.0"},
		{Time: t0.Add(20 * time.Hour).Format(time.RFC3339), Action: "vex-publish", Repo: "products/a", Tag: "1.0"}, // 첫 발행만
		{Time: t0.Add(30 * time.Hour).Format(time.RFC3339), Action: "vex-publish", Repo: "products/b", Tag: "2.0"},
		{Time: t0.Add(5 * time.Hour).Format(time.RFC3339), Action: "user-create"},
	}
	if h, n := mttr(first, evs); h != 20 || n != 2 {
		t.Errorf("mttr = %v 시간, %d 건 (20, 2 이어야 함)", h, n)
	}
}

func TestTopCounts(t *testing.T) {
	got := topCounts(map[string]int{"b": 2, "a": 2, "c": 5, "d": 1}, 3)
	if len(got) != 3 || got[0].Label != "c" || got[1].Label != "a" || got[2].Label != "b" {
		t.Errorf("got %+v", got)
	}
}
