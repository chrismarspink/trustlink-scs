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

func mcpServer(t *testing.T) *Server {
	s := askServer(t)
	t.Setenv("MCP_STORE", filepath.Join(t.TempDir(), "mcp-tokens.json"))
	return s
}

// 화면 로그인으로 토큰을 만든다 → 토큰 원문
func mcpNewToken(t *testing.T, s *Server, sess Session) (string, string) {
	sid := s.store.put(Session{Username: sess.Username, Groups: sess.Groups, Expiry: time.Now().Add(time.Hour)})
	r := httptest.NewRequest("POST", "/api/mcp/tokens", strings.NewReader(`{"name":"시험","days":30}`))
	r.AddCookie(&http.Cookie{Name: cookieName, Value: sid})
	w := httptest.NewRecorder()
	s.apiMcpTokenCreate(w, r)
	var out struct{ ID, Token, URL string }
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != 200 || !strings.HasPrefix(out.Token, mcpPrefix) || !strings.HasSuffix(out.URL, "/api/mcp") {
		t.Fatalf("토큰 만들기: %d %s", w.Code, w.Body.String())
	}
	return out.Token, out.ID
}

func mcpDo(s *Server, token, body string) (int, string) {
	r := httptest.NewRequest("POST", "/api/mcp", strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.apiMcp(w, r)
	return w.Code, w.Body.String()
}

func mcpCallReq(name, args string) string {
	return `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"` + name + `","arguments":` + args + `}}`
}

// 규격의 기본 흐름: initialize → initialized 알림 → tools/list → tools/call
func TestMcpProtocol(t *testing.T) {
	s := mcpServer(t)
	tok, _ := mcpNewToken(t, s, askAdmin)
	code, body := mcpDo(s, tok, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`)
	if code != 200 || !strings.Contains(body, `"protocolVersion":"2025-03-26"`) || !strings.Contains(body, `"tools"`) || !strings.Contains(body, `"id":1`) {
		t.Fatalf("initialize: %d %s", code, body)
	}
	if code, body := mcpDo(s, tok, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); code != 202 || body != "" {
		t.Errorf("알림: %d %q", code, body)
	}
	_, body = mcpDo(s, tok, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	for _, want := range []string{"trustlink_ask", "trustlink_vulnerability", "trustlink_component", "trustlink_status", "trustlink_urgent", `"readOnlyHint":true`, `"inputSchema"`} {
		if !strings.Contains(body, want) {
			t.Errorf("tools/list 에 %s 없음", want)
		}
	}
	_, body = mcpDo(s, tok, mcpCallReq("trustlink_vulnerability", `{"id":"cve-2026-0004"}`))
	for _, want := range []string{"CVE-2026-0004", "products/prod", "알파은행", `"isError":false`, "http"} {
		if !strings.Contains(body, want) {
			t.Errorf("취약점 조회에 %s 없음: %s", want, body)
		}
	}
	if _, body := mcpDo(s, tok, mcpCallReq("trustlink_status", `{}`)); !strings.Contains(body, "감시하고 있습니다") {
		t.Errorf("현황: %s", body)
	}
	if _, body := mcpDo(s, tok, mcpCallReq("trustlink_vulnerability", `{"id":"없음"}`)); !strings.Contains(body, `"isError":true`) {
		t.Errorf("잘못된 번호: %s", body)
	}
	if _, body := mcpDo(s, tok, mcpCallReq("nope", `{}`)); !strings.Contains(body, `-32602`) {
		t.Errorf("없는 도구: %s", body)
	}
	if _, body := mcpDo(s, tok, `{"jsonrpc":"2.0","id":9,"method":"resources/list"}`); !strings.Contains(body, `-32601`) {
		t.Errorf("없는 요청: %s", body)
	}
}

// 조회만: 일을 시키는 말을 해도 초안·양식·대기 작업을 만들지 않는다.
func TestMcpReadOnly(t *testing.T) {
	s := mcpServer(t)
	a := s.askQuery(askAdmin, "CVE-2026-0004 고객 통지 초안 만들어 줘")
	if a.pending != nil || a.notice != nil || a.UI != nil || a.Intent != "vuln" {
		t.Errorf("조회 경로에서 행동이 만들어짐: %s %+v", a.Intent, a.pending)
	}
	if b := s.askAnswer(askAdmin, "CVE-2026-0004 고객 통지 초안 만들어 줘"); b.pending == nil {
		t.Errorf("화면 경로의 행동은 그대로여야 한다: %s", b.Intent)
	}
}

// 인증과 범위: 토큰 없음·틀림·끊김은 401, 고객 토큰은 자기 제품만.
func TestMcpAuthScope(t *testing.T) {
	s := mcpServer(t)
	list := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	if code, _ := mcpDo(s, "", list); code != 401 {
		t.Errorf("토큰 없음: %d", code)
	}
	if code, _ := mcpDo(s, mcpPrefix+"deadbeef", list); code != 401 {
		t.Errorf("틀린 토큰: %d", code)
	}
	cust, _ := mcpNewToken(t, s, Session{Username: "u", Groups: []string{"org-alpha"}})
	for _, call := range []string{mcpCallReq("trustlink_status", `{}`), mcpCallReq("trustlink_urgent", `{}`), mcpCallReq("trustlink_component", `{"name":"lib"}`),
		mcpCallReq("trustlink_ask", `{"question":"고객 목록"}`), mcpCallReq("trustlink_vulnerability", `{"id":"CVE-2026-0004"}`)} {
		_, body := mcpDo(s, cust, call)
		for _, leak := range []string{"Beta Corp", "감마공사", "/admin/", "/artifact/"} {
			if strings.Contains(body, leak) {
				t.Errorf("고객 토큰 답에 %s: %s", leak, body)
			}
		}
	}
	// 토큰 원문은 저장하지 않는다
	mcpStore.Lock()
	for _, x := range mcpStore.tokens {
		if strings.Contains(x.Hash, mcpPrefix) || len(x.Hash) != 64 {
			t.Errorf("토큰이 해시가 아님: %q", x.Hash)
		}
	}
	mcpStore.Unlock()
	// 끊으면 바로 막힌다 — 남의 토큰은 끊지 못한다
	tok, id := mcpNewToken(t, s, Session{Username: "dev1", Groups: []string{"developers"}})
	del := func(sess Session) int {
		sid := s.store.put(Session{Username: sess.Username, Groups: sess.Groups, Expiry: time.Now().Add(time.Hour)})
		r := httptest.NewRequest("DELETE", "/api/mcp/tokens/"+id, nil)
		r.SetPathValue("id", id)
		r.AddCookie(&http.Cookie{Name: cookieName, Value: sid})
		w := httptest.NewRecorder()
		s.apiMcpTokenDelete(w, r)
		return w.Code
	}
	if c := del(Session{Username: "other", Groups: []string{"developers"}}); c != 404 {
		t.Errorf("남의 토큰 끊기: %d", c)
	}
	if code, _ := mcpDo(s, tok, list); code != 200 {
		t.Errorf("끊기 전: %d", code)
	}
	if c := del(Session{Username: "dev1", Groups: []string{"developers"}}); c != 200 {
		t.Errorf("내 토큰 끊기: %d", c)
	}
	if code, _ := mcpDo(s, tok, list); code != 401 {
		t.Errorf("끊은 뒤: %d", code)
	}
	// 기한이 지난 토큰
	old, _ := mcpNewToken(t, s, askAdmin)
	mcpStore.Lock()
	mcpStore.tokens[len(mcpStore.tokens)-1].Expires = "2020-01-01T00:00:00Z"
	mcpStore.Unlock()
	if code, _ := mcpDo(s, old, list); code != 401 {
		t.Errorf("기한 지난 토큰: %d", code)
	}
}

// 묻고 찾기에 설정을 물으면 순서를 답한다.
func TestAskMcpHelp(t *testing.T) {
	s := mcpServer(t)
	a := s.askAnswer(Session{Username: "dev1", Groups: []string{"developers"}}, "클로드에 MCP 설정 도와줘")
	if a.Intent != "howto" || len(a.Rows) < 4 || a.Rows[0].Link != "/mcp" {
		t.Errorf("MCP 안내: %s %+v", a.Intent, a.Rows)
	}
}
