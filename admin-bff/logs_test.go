package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 3일치 로그: 하루 3000줄(그중 2/3 은 svc-bff 내부 호출), 사이사이 업로드·인증 실패·오류.
func writeTestLog(t *testing.T) (string, int) {
	p := filepath.Join(t.TempDir(), "zot.log")
	var b strings.Builder
	start := time.Date(2026, 11, 20, 15, 0, 0, 0, time.UTC) // KST 11-21 00:00
	real := 0
	for i := 0; i < 9000; i++ {
		ts := start.Add(time.Duration(i) * 28800 * time.Millisecond).Format(time.RFC3339Nano)
		switch {
		case i%3 != 0:
			fmt.Fprintf(&b, `{"time":"%s","level":"info","message":"HTTP API","username":"svc-bff","method":"GET","path":"/v2/_catalog","statusCode":200}`+"\n", ts)
		case i%30 == 0:
			fmt.Fprintf(&b, `{"time":"%s","level":"info","message":"HTTP API","username":"ci","method":"PUT","path":"/v2/products/a/manifests/1.%d","statusCode":201}`+"\n", ts, i)
			real++
		case i%99 == 0:
			fmt.Fprintf(&b, `{"time":"%s","level":"error","message":"failed to parse authorization header","error":"bad"}`+"\n", ts)
			real++
		default:
			fmt.Fprintf(&b, `{"time":"%s","level":"info","message":"HTTP API","username":"acme1","method":"GET","path":"/v2/products/a/manifests/1.0","statusCode":200,"n":%d}`+"\n", ts, i)
			real++
		}
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p, real
}

type logsResp struct {
	Entries        []logEntry     `json:"entries"`
	Next           int64          `json:"next"`
	More           bool           `json:"more"`
	ByEvent        map[string]int `json:"byEvent"`
	CountsComplete bool           `json:"countsComplete"`
	FirstTime      string         `json:"firstTime"`
	LastTime       string         `json:"lastTime"`
}

func getLogs(t *testing.T, s *Server, qs string) logsResp {
	w := httptest.NewRecorder()
	s.apiLogs(w, httptest.NewRequest("GET", "/api/logs?"+qs, nil))
	var r logsResp
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatal(err, w.Body.String())
	}
	return r
}

func TestLogsPagingNoGapNoDup(t *testing.T) {
	p, real := writeTestLog(t)
	s := &Server{cfg: Config{LogFile: p}}
	seen := map[int64]bool{}
	cur, pages, prev := "", 0, "9999"
	for {
		r := getLogs(t, s, "limit=77"+cur)
		for _, e := range r.Entries {
			if seen[e.Off] {
				t.Fatalf("중복 %d", e.Off)
			}
			if e.Time > prev {
				t.Fatalf("최신순이 아님 %s > %s", e.Time, prev)
			}
			prev = e.Time
			seen[e.Off] = true
			if e.User == "svc-bff" {
				t.Fatal("내부 호출은 숨김")
			}
		}
		pages++
		if !r.More {
			break
		}
		cur = fmt.Sprintf("&cursor=%d", r.Next)
	}
	if len(seen) != real {
		t.Fatalf("빠짐: %d / %d (쪽 %d)", len(seen), real, pages)
	}
}

func TestLogsDateAndEvent(t *testing.T) {
	p, _ := writeTestLog(t)
	s := &Server{cfg: Config{LogFile: p}}
	r := getLogs(t, s, "from=2026-11-22&to=2026-11-22&limit=500")
	if len(r.Entries) == 0 || !r.CountsComplete {
		t.Fatalf("하루 범위: %d complete=%v", len(r.Entries), r.CountsComplete)
	}
	for _, e := range r.Entries {
		d := mustT(e.Time).In(kst).Format("2006-01-02")
		if d != "2026-11-22" {
			t.Fatalf("다른 날 %s", e.Time)
		}
	}
	up := getLogs(t, s, "event=upload&limit=500")
	if len(up.Entries) != 300 {
		t.Fatalf("업로드 %d", len(up.Entries))
	}
	af := getLogs(t, s, "event=authfail&levels=error")
	if len(af.Entries) == 0 || af.Entries[0].Event != "authfail" {
		t.Fatalf("인증 실패 %+v", af.Entries)
	}
	for msg, want := range map[string]string{"applied policy": "cleanup", "garbage collected blobs": "cleanup", "user profile successfully set": "login"} {
		if got := classifyLog(&logEntry{Msg: msg, Level: "info"}); got != want {
			t.Fatalf("%s → %s, want %s", msg, got, want)
		}
	}
	if r.FirstTime == "" || r.LastTime <= r.FirstTime {
		t.Fatalf("범위 %s ~ %s", r.FirstTime, r.LastTime)
	}
}

func mustT(s string) time.Time { t, _ := time.Parse(time.RFC3339Nano, s); return t }
