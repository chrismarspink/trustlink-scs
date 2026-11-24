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

func askPost(t *testing.T, s *Server, sess Session, q string) *askAnswer {
	t.Helper()
	sid := s.store.put(Session{Username: sess.Username, Groups: sess.Groups, Expiry: time.Now().Add(time.Hour)})
	r := httptest.NewRequest("POST", "/api/ask", strings.NewReader(`{"q":`+jsonStr(q)+`}`))
	r.AddCookie(&http.Cookie{Name: cookieName, Value: sid})
	w := httptest.NewRecorder()
	s.apiAsk(w, r)
	var raw struct {
		ID string `json:"id"`
		UI []a2   `json:"ui"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &raw)
	askStore.Lock()
	a := askStore.m[raw.ID]
	askStore.Unlock()
	if a == nil {
		t.Fatalf("답이 저장되지 않음: %s", w.Body.String())
	}
	return a
}

func jsonStr(s string) string { b, _ := json.Marshal(s); return string(b) }

func askDo(s *Server, sess Session, surface, name string, ctx map[string]any) (int, map[string]any) {
	sid := s.store.put(Session{Username: sess.Username, Groups: sess.Groups, Expiry: time.Now().Add(time.Hour)})
	body, _ := json.Marshal(map[string]any{"version": a2uiVersion, "action": map[string]any{"name": name, "surfaceId": surface, "context": ctx}})
	r := httptest.NewRequest("POST", "/api/ask/action", strings.NewReader(string(body)))
	r.AddCookie(&http.Cookie{Name: cookieName, Value: sid})
	w := httptest.NewRecorder()
	s.apiAskAction(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// A2UI 메시지 모양: createSurface → updateComponents(root 포함) → updateDataModel
func checkA2UI(t *testing.T, ui []a2, surface string, wantComps ...string) {
	t.Helper()
	b, _ := json.Marshal(ui)
	txt := string(b)
	for _, want := range append([]string{`"version":"v0.9.1"`, `"surfaceId":"` + surface + `"`, `"id":"root"`}, wantComps...) {
		if !strings.Contains(txt, want) {
			t.Errorf("A2UI 에 %s 없음", want)
		}
	}
}

var askAdmin = Session{Username: "admin1", Groups: []string{"admins"}}

// 고객 통지: 초안 → 양식 → 단추를 눌러야 발송함으로. "고객에게 보내"는 바로 보내지 않고 양식을 다시 띄운다.
func TestAskNoticeFlow(t *testing.T) {
	s := askServer(t)
	a := askPost(t, s, askAdmin, "CVE-2026-0001 고객 통지 초안 만들어 줘")
	if a.pending == nil || a.pending.Kind != "notice" || len(a.UI) != 3 {
		t.Fatalf("통지 초안: %q %+v", a.Lead, a.pending)
	}
	checkA2UI(t, a.UI, a.ID, `"component":"ChoicePicker"`, `"name":"notice.send"`, `"createSurface"`, `"call":"openUrl"`)
	if n, ok := s.cust().notice(a.pending.NoticeID); !ok || n.Status != "draft" {
		t.Fatalf("초안이 저장되지 않음")
	}
	b := askPost(t, s, askAdmin, "고객에게 보내")
	if b.pending == nil || b.pending.NoticeID != a.pending.NoticeID || !strings.Contains(b.Lead, "누르기 전에는") {
		t.Errorf("'고객에게 보내'는 양식을 다시 띄워야 함: %q", b.Lead)
	}
	if n, _ := s.cust().notice(a.pending.NoticeID); n.Status != "draft" {
		t.Errorf("단추를 누르기 전에 상태가 바뀜: %s", n.Status)
	}
	// 남의 양식·권한 없는 사람
	if code, _ := askDo(s, Session{Username: "dev1", Groups: []string{"developers"}}, a.ID, "notice.send", map[string]any{"targets": a.pending.Keys}); code != 404 {
		t.Errorf("남의 양식: %d", code)
	}
	// 양식에 없던 대상은 무시된다
	if code, _ := askDo(s, askAdmin, a.ID, "notice.send", map[string]any{"targets": []string{"없는|키"}, "delay": []string{"30"}}); code != 400 {
		t.Errorf("없는 대상: %d", code)
	}
	code, out := askDo(s, askAdmin, a.ID, "notice.send", map[string]any{"targets": a.pending.Keys, "delay": []string{"60"}})
	if code != 200 || out["ui"] == nil {
		t.Fatalf("발송: %d %v", code, out)
	}
	if code, _ := askDo(s, askAdmin, a.ID, "notice.send", map[string]any{"targets": a.pending.Keys}); code != 409 {
		t.Errorf("두 번 누름: %d", code)
	}
	// 고객 통지는 관리자만
	if c := askPost(t, s, Session{Username: "dev1", Groups: []string{"developers"}}, "CVE-2026-0001 고객 통지 초안 만들어 줘"); c.pending != nil || !strings.Contains(c.Lead, "관리자만") {
		t.Errorf("개발자에게 통지 양식이 나옴: %q", c.Lead)
	}
	// "알려 줘"는 묻는 말 — 통지 초안을 만들지 않는다
	if d := askPost(t, s, askAdmin, "CVE-2026-0004 어디에 있는지 알려줘"); d.Intent != "vuln" {
		t.Errorf("묻는 말이 행동으로 처리됨: %s", d.Intent)
	}
}

// VEX: 버전 고르기 → 규칙 초안 양식 → 저장. '영향 없음'은 근거가 있어야 저장된다.
func TestAskVexFlow(t *testing.T) {
	s := askServer(t)
	dev := Session{Username: "dev1", Groups: []string{"developers"}}
	a := askPost(t, s, dev, "CVE-2026-0004 VEX 판정 초안")
	if a.pending == nil || a.pending.Kind != "vexpick" || len(a.pending.Hits) != 4 {
		t.Fatalf("버전 고르기: %q %+v", a.Lead, a.pending)
	}
	checkA2UI(t, a.UI, a.ID, `"name":"vex.pick"`)
	code, out := askDo(s, dev, a.ID, "vex.pick", map[string]any{"target": []string{"0"}})
	if code != 200 || a.pending.Kind != "vex" {
		t.Fatalf("초안: %d %v", code, out)
	}
	b, _ := json.Marshal(out["ui"])
	for _, want := range []string{`"name":"vex.save"`, `"component":"TextField"`, `"updateComponents"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("VEX 양식에 %s 없음", want)
		}
	}
	if strings.Contains(string(b), "createSurface") {
		t.Errorf("같은 화면을 갱신해야 함(createSurface 가 다시 나옴)")
	}
	if code, _ := askDo(s, dev, a.ID, "vex.save", map[string]any{"status": []string{"not_affected"}, "justification": []string{"none"}, "detail": "x"}); code != 400 {
		t.Errorf("근거 없는 영향 없음: %d", code)
	}
	custFakeAnalysis = nil
	code, _ = askDo(s, dev, a.ID, "vex.save", map[string]any{"status": []string{"not_affected"}, "justification": []string{"vulnerable_code_not_in_execute_path"}, "detail": "기능을 끔"})
	if code != 200 || custFakeAnalysis == nil || custFakeAnalysis["analysisState"] != "NOT_AFFECTED" || custFakeAnalysis["analysisDetails"] != "기능을 끔" {
		t.Fatalf("저장: %d %v", code, custFakeAnalysis)
	}
	// 고객 계정은 판정할 수 없다
	if c := askPost(t, s, Session{Username: "u", Groups: []string{"org-alpha"}}, "CVE-2026-0001 VEX 판정"); c.pending != nil {
		t.Errorf("고객에게 VEX 양식이 나옴")
	}
}

// 규제 보고서: 양식 → 만들기 → 내려받기 단추
func TestAskReportFlow(t *testing.T) {
	s := askServer(t)
	t.Setenv("REG_DIR", filepath.Join(t.TempDir(), "regs"))
	a := askPost(t, s, askAdmin, "prod 제품 미국 수출 규제 리포트 만들어 줘")
	if a.pending == nil || a.pending.Kind != "report" || a.report["regions"][0] != "US" || a.report["product"][0] == "none" {
		t.Fatalf("보고서 양식: %q %+v %+v", a.Lead, a.pending, a.report)
	}
	checkA2UI(t, a.UI, a.ID, `"name":"report.make"`)
	code, out := askDo(s, askAdmin, a.ID, "report.make", map[string]any{"regions": []string{"US"}, "audience": []string{"sales"}, "product": a.report["product"], "lang": []string{"ko"}})
	b, _ := json.Marshal(out["ui"])
	if code != 200 || !strings.Contains(string(b), "/api/regs-report/rr-") || !strings.Contains(string(b), "PDF 내려받기") {
		t.Fatalf("보고서 만들기: %d %s", code, b)
	}
	if c := askPost(t, s, Session{Username: "dev1", Groups: []string{"developers"}}, "미국 규제 보고서 만들어 줘"); c.pending != nil {
		t.Errorf("개발자에게 보고서 양식이 나옴")
	}
}
