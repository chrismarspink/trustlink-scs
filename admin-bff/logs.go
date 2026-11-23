package main

// logs.go: 관리 › 로그 — zot 로그(JSON 한 줄씩)를 빠르게 보여 준다.
//   - 파일 전체를 읽지 않는다: 끝에서부터 1MB 씩 거꾸로 읽어 한 쪽(limit)만 채우면 멈춘다.
//   - 쪽 넘김은 바이트 위치(cursor) — "더 오래된 로그"는 그 위치부터 이어서 읽는다.
//   - 날짜는 시간순으로 쌓인 파일을 이분 탐색해 바로 그 날로 간다.
//   - 이벤트(업로드·다운로드·삭제·인증 실패·오류 등)·레벨·사용자·검색어로 거른다.
//   - 내부 호출(svc-bff 의 주기 조회)은 기본으로 숨긴다(전체의 대부분).

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type logEntry struct {
	Off     int64  `json:"off"`
	Time    string `json:"time"`
	Level   string `json:"level"`
	Msg     string `json:"msg"`
	Event   string `json:"event"`
	User    string `json:"user,omitempty"`
	Method  string `json:"method,omitempty"`
	Path    string `json:"path,omitempty"`
	Status  int    `json:"status,omitempty"`
	Latency string `json:"latency,omitempty"`
	IP      string `json:"ip,omitempty"`
	Err     string `json:"err,omitempty"`
	Raw     string `json:"raw"`
}

// 이벤트 종류(화면 선택지와 같음)
var logEvents = []struct{ Key, Label string }{
	{"upload", "업로드"}, {"download", "다운로드"}, {"delete", "삭제"}, {"authfail", "인증·권한 실패"},
	{"error", "오류"}, {"request", "기타 요청"}, {"system", "시작·설정"}, {"other", "기타"},
}

var logAuthMsgs = []string{"authorization header", "api token", "bcrypt compare failed", "unauthorized", "authentication failed"}

func classifyLog(e *logEntry) string {
	low := strings.ToLower(e.Msg + " " + e.Err)
	switch {
	case e.Status == 401 || e.Status == 403 || containsAny(low, logAuthMsgs):
		return "authfail"
	case e.Level == "error" || e.Level == "fatal" || e.Level == "panic" || e.Status >= 500:
		return "error"
	case e.Method == "DELETE" && e.Status < 300:
		return "delete"
	case e.Method == "PUT" && e.Status == 201 && manifestPath.MatchString(e.Path):
		return "upload"
	case e.Method == "GET" && e.Status == 200 && manifestPath.MatchString(e.Path) && !strings.Contains(e.Path, "/manifests/sha256:"):
		return "download"
	case e.Msg == "HTTP API":
		return "request"
	case e.Level == "warn" || strings.Contains(low, "start") || strings.Contains(low, "config") || strings.Contains(low, "loaded"):
		return "system"
	}
	return "other"
}

func containsAny(s string, subs []string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

func parseLogLine(off int64, line []byte) logEntry {
	var l struct {
		Time       string `json:"time"`
		Level      string `json:"level"`
		Message    string `json:"message"`
		Username   string `json:"username"`
		Identity   string `json:"identity"`
		Method     string `json:"method"`
		Path       string `json:"path"`
		StatusCode int    `json:"statusCode"`
		Latency    string `json:"latency"`
		ClientIP   string `json:"clientIP"`
		Error      string `json:"error"`
	}
	e := logEntry{Off: off, Raw: string(line)}
	if json.Unmarshal(line, &l) != nil {
		e.Msg, e.Level, e.Event = truncate(string(line), 300), "", "other"
		return e
	}
	e.Time, e.Level, e.Msg = l.Time, l.Level, l.Message
	e.User, e.Method, e.Path, e.Status, e.Latency, e.IP, e.Err = firstNonEmpty(l.Username, l.Identity), l.Method, l.Path, l.StatusCode, l.Latency, l.ClientIP, l.Error
	e.Event = classifyLog(&e)
	return e
}

// logTime: 줄 앞의 "time":"…" 만 빠르게 꺼낸다(JSON 전체를 풀지 않고).
func logTime(line []byte) string {
	i := bytes.Index(line, []byte(`"time":"`))
	if i < 0 || i > 40 {
		return ""
	}
	rest := line[i+8:]
	j := bytes.IndexByte(rest, '"')
	if j < 0 {
		return ""
	}
	return string(rest[:j])
}

// 내부 호출·반복 메시지(숨기기 대상)
var logNoise = [][]byte{[]byte(`"svc-bff"`), []byte(`"message":"getting manifest"`)}

func isLogNoise(line []byte) bool {
	for _, n := range logNoise {
		if bytes.Contains(line, n) {
			return true
		}
	}
	return false
}

// scanBack: [0,end) 를 끝에서부터 한 줄씩 fn 에 준다. fn 이 false 를 주면 그 줄 시작 위치를 돌려주고 멈춘다.
// budget 바이트를 넘게 읽으면 거기서 멈추고 아직 안 본 끝 위치를 돌려준다. 처음까지 다 보면 0.
func scanBack(f *os.File, end, budget int64, fn func(off int64, line []byte) bool) int64 {
	const chunk = 1 << 20
	pos := end
	var rest []byte
	var read int64
	for pos > 0 {
		if read >= budget {
			return pos + int64(len(rest))
		}
		n := min(int64(chunk), pos)
		pos -= n
		buf := make([]byte, int(n)+len(rest))
		if _, err := f.ReadAt(buf[:n], pos); err != nil {
			return 0
		}
		copy(buf[n:], rest)
		read += n
		e := len(buf)
		for {
			i := bytes.LastIndexByte(buf[:e], '\n')
			if i < 0 {
				break
			}
			if line := buf[i+1 : e]; len(line) > 0 && !fn(pos+int64(i+1), line) {
				return pos + int64(i+1)
			}
			e = i
		}
		rest = append([]byte(nil), buf[:e]...)
	}
	if len(rest) > 0 && !fn(0, rest) {
		return 0
	}
	return 0
}

// offsetAt: 시각 t(UTC RFC3339 문자열) 이상인 첫 줄의 시작 위치(이분 탐색, 파일은 시간순).
func offsetAt(f *os.File, size int64, t string) int64 {
	lineAfter := func(p int64) (int64, string) { // p 다음 줄의 시작과 시각
		buf := make([]byte, 64<<10)
		n, _ := f.ReadAt(buf, p)
		buf = buf[:n]
		s := 0
		if p > 0 {
			i := bytes.IndexByte(buf, '\n')
			if i < 0 {
				return size, ""
			}
			s = i + 1
		}
		e := bytes.IndexByte(buf[s:], '\n')
		if e < 0 {
			e = len(buf) - s
		}
		return p + int64(s), logTime(buf[s : s+e])
	}
	lo, hi := int64(0), size
	for hi-lo > 64<<10 {
		mid := (lo + hi) / 2
		_, tm := lineAfter(mid)
		if tm != "" && tm < t {
			lo = mid
		} else {
			hi = mid
		}
	}
	// lo..hi 사이를 앞으로 훑어 정확한 줄을 찾는다
	p := lo
	for p < size {
		off, tm := lineAfter(p)
		if off >= size || (tm != "" && tm >= t) {
			return off
		}
		next := bytes.IndexByte(mustRead(f, off, 64<<10), '\n')
		if next < 0 {
			return size
		}
		p = off + int64(next) // 다음 반복에서 이 줄 끝 다음 줄을 본다
	}
	return size
}

func mustRead(f *os.File, off int64, n int) []byte {
	b := make([]byte, n)
	m, _ := f.ReadAt(b, off)
	return b[:m]
}

// kstDay: "2026-11-23" → 그 날 0시(KST)의 UTC 문자열. add 일 더한다.
func kstDay(d string, add int) (string, bool) {
	t, err := time.ParseInLocation("2006-01-02", d, kst)
	if err != nil {
		return "", false
	}
	return t.AddDate(0, 0, add).UTC().Format("2006-01-02T15:04:05"), true
}

// GET /api/logs?cursor=&limit=&q=&levels=info,warn&event=&user=&from=YYYY-MM-DD&to=YYYY-MM-DD&all=1
func (s *Server) apiLogs(w http.ResponseWriter, r *http.Request) {
	t0 := time.Now()
	qv := r.URL.Query()
	limit := atoiDefault(qv.Get("limit"), 100)
	if limit < 1 || limit > 500 {
		limit = 100
	}
	q := []byte(strings.ToLower(strings.TrimSpace(qv.Get("q"))))
	user := strings.TrimSpace(qv.Get("user"))
	event := qv.Get("event")
	levels := map[string]bool{}
	for _, l := range strings.Split(qv.Get("levels"), ",") {
		if l = strings.TrimSpace(strings.ToLower(l)); l != "" {
			levels[l] = true
		}
	}
	hideNoise := qv.Get("all") != "1"

	f, err := os.Open(s.cfg.LogFile)
	if err != nil {
		writeJSON(w, 200, map[string]any{"entries": []any{}, "error": "로그 파일을 읽을 수 없음: " + err.Error(), "events": logEvents})
		return
	}
	defer f.Close()
	st, _ := f.Stat()
	size := st.Size()

	// 파일의 처음·마지막 시각(날짜 선택 범위)
	firstTime := logTime(bytes.SplitN(mustRead(f, 0, 4096), []byte("\n"), 2)[0])
	lastTime := ""
	scanBack(f, size, 1<<20, func(_ int64, line []byte) bool { lastTime = logTime(line); return lastTime == "" })

	end := size
	if c := qv.Get("cursor"); c != "" {
		if n, err := strconv.ParseInt(c, 10, 64); err == nil && n >= 0 && n <= size {
			end = n
		}
	}
	fromS := ""
	if d := qv.Get("from"); d != "" {
		fromS, _ = kstDay(d, 0)
	}
	if d := qv.Get("to"); d != "" && qv.Get("cursor") == "" {
		if toS, ok := kstDay(d, 1); ok {
			end = min(end, offsetAt(f, size, toS))
		}
	}

	// 날짜를 골랐으면 그 기간을 끝까지 세어 요약을 정확히(최대 96MB), 아니면 한 쪽 찾는 동안만(최대 48MB).
	budget := int64(48 << 20)
	if fromS != "" {
		budget = 96 << 20
	}
	match := func(e *logEntry, line []byte) bool {
		return (len(levels) == 0 || levels[e.Level]) && (event == "" || e.Event == event) &&
			(user == "" || strings.EqualFold(e.User, user)) && (len(q) == 0 || bytes.Contains(bytes.ToLower(line), q))
	}
	entries := []logEntry{}
	byLevel, byEvent := map[string]int{}, map[string]int{}
	var scope, seen int
	next := int64(-1)
	reachedFrom, extra := false, false
	stop := scanBack(f, end, budget, func(off int64, line []byte) bool {
		if fromS != "" {
			if tm := logTime(line); tm != "" && tm < fromS {
				reachedFrom = true
				return false
			}
		}
		seen++
		if hideNoise && isLogNoise(line) {
			return true
		}
		if len(entries) >= limit && fromS == "" { // 날짜 범위가 없으면 한 쪽을 채우는 즉시 멈춘다
			next, extra = off+int64(len(line)), true
			return false
		}
		e := parseLogLine(off, line)
		scope++
		byLevel[e.Level]++
		byEvent[e.Event]++
		if !match(&e, line) {
			return true
		}
		if len(entries) >= limit { // 날짜 범위 요약을 위해 계속 세는 중 — 더 있다는 것만 기록
			extra = true
			return true
		}
		entries = append(entries, e)
		if len(entries) == limit {
			next = off // 다음 쪽은 이 줄 앞부터
		}
		return true
	})
	more := true
	switch {
	case next >= 0:
		more = extra || (!reachedFrom && stop != 0 && fromS != "")
	case reachedFrom || stop == 0:
		more, next = false, 0
	default: // 읽을 양을 다 씀 — 이어서 찾기
		next = stop
	}
	if !more {
		next = 0
	}
	writeJSON(w, 200, map[string]any{
		"entries": entries, "next": next, "more": more,
		"partial": more && len(entries) < limit, // 다 찾기 전에 읽을 양이 끝남
		"scanned": seen, "scope": scope, "byLevel": byLevel, "byEvent": byEvent,
		"countsComplete": fromS != "" && (reachedFrom || stop == 0),
		"fileSize":       size, "firstTime": firstTime, "lastTime": lastTime, "events": logEvents,
		"ms": time.Since(t0).Milliseconds(),
	})
}
