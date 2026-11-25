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

func agentCall(t *testing.T, s *Server, sess Session, h func(http.ResponseWriter, *http.Request), method, id, body string) (int, string) {
	t.Helper()
	sid := s.store.put(Session{Username: sess.Username, Groups: sess.Groups, Expiry: time.Now().Add(time.Hour)})
	r := httptest.NewRequest(method, "/api/agent", strings.NewReader(body))
	r.AddCookie(&http.Cookie{Name: cookieName, Value: sid})
	r.SetPathValue("id", id)
	w := httptest.NewRecorder()
	h(w, r)
	return w.Code, w.Body.String()
}

func agentServer(t *testing.T) *Server {
	t.Setenv("AI_CONFIG", filepath.Join(t.TempDir(), "ai-config.json"))
	s := askServer(t)
	s.notify.st.Notices = []Notice{
		{ID: "n1", Title: "새 취약점", To: []string{"dev1", "u-alpha"}},
		{ID: "n2", Title: "VEX 발행", To: []string{"dev1"}, Read: map[string]bool{"dev1": true}},
	}
	return s
}

// 권한에 따라 보이는 것이 다르다: 관리자는 승인할 메일, 고객은 자기 제품, 예약 종류는 권한이 있는 것만.
func TestAgentByRole(t *testing.T) {
	s := agentServer(t)
	admin := Session{Username: "admin1", Groups: []string{"admins"}}
	alpha := Session{Username: "u-alpha", Groups: []string{"org-alpha"}}
	h := s.holdMail("vex", "VEX 발행 통보 · prod 1.0", "products/prod:1.0", []string{"u@alpha.example.com"}, "제목", mailContent{Text: "본문"})

	var got struct {
		Role    string
		Tasks   []agentTask
		Recipes []agentRecipe
	}
	_, body := agentCall(t, s, admin, s.apiAgent, "GET", "", "")
	_ = json.Unmarshal([]byte(body), &got)
	hold := false
	for _, x := range got.Tasks {
		hold = hold || (x.ID == "hold:"+h.ID && x.Grade == "approve")
	}
	if got.Role != "admin" || !hold || len(got.Recipes) != 3 {
		t.Fatalf("관리자: %s 승인 메일 %v 예약 종류 %d\n%s", got.Role, hold, len(got.Recipes), body)
	}
	// 승인이 필요한 것은 에이전트가 대신 실행하지 않는다
	if _, body := agentCall(t, s, admin, s.apiAgentRun, "POST", "", `{"ids":["hold:`+h.ID+`"]}`); !strings.Contains(body, `"ok":false`) || len(holdWaiting()) != 1 {
		t.Errorf("승인 필요 작업이 실행됨: %s", body)
	}

	_, body = agentCall(t, s, alpha, s.apiAgent, "GET", "", "")
	got.Tasks, got.Recipes = nil, nil
	_ = json.Unmarshal([]byte(body), &got)
	if got.Role != "customer" || len(got.Recipes) != 0 || strings.Contains(body, "hold:") || strings.Contains(body, "Beta") {
		t.Fatalf("고객: %s\n%s", got.Role, body)
	}
	mine := 0
	for _, x := range got.Tasks {
		if x.Kind == "my" && x.Grade == "go" && x.Link == "/my" {
			mine++
		}
	}
	if mine == 0 {
		t.Errorf("고객에게 자기 제품의 조치할 것이 없음: %s", body)
	}
	if code, _ := agentCall(t, s, alpha, s.apiAgentScheduleAdd, "POST", "", `{"recipe":"expiry-check","repeat":"daily","time":"08:30"}`); code != 403 {
		t.Errorf("고객이 예약을 만듦: %d", code)
	}
}

// 실행 → 기록 → 되돌리기. 남의 기록은 되돌릴 수 없다.
func TestAgentRunUndo(t *testing.T) {
	s := agentServer(t)
	dev := Session{Username: "dev1", Groups: []string{"developers"}}
	code, body := agentCall(t, s, dev, s.apiAgentRun, "POST", "", `{"ids":["notif:all"]}`)
	var out struct{ Results []agentLog }
	_ = json.Unmarshal([]byte(body), &out)
	if code != 200 || len(out.Results) != 1 || !out.Results[0].OK || out.Results[0].Undo == nil || len(s.agentUnread("dev1")) != 0 {
		t.Fatalf("실행: %d %s", code, body)
	}
	if len(s.agentUnread("u-alpha")) != 1 {
		t.Errorf("다른 사람의 알림까지 읽음 처리됨")
	}
	id := out.Results[0].ID
	if code, _ := agentCall(t, s, Session{Username: "other", Groups: []string{"developers"}}, s.apiAgentUndo, "POST", "", `{"id":"`+id+`"}`); code != 403 {
		t.Errorf("남의 기록 되돌리기: %d", code)
	}
	if code, body := agentCall(t, s, dev, s.apiAgentUndo, "POST", "", `{"id":"`+id+`"}`); code != 200 || len(s.agentUnread("dev1")) != 1 {
		t.Fatalf("되돌리기: %d %s", code, body)
	}
	if code, _ := agentCall(t, s, dev, s.apiAgentUndo, "POST", "", `{"id":"`+id+`"}`); code != 409 {
		t.Errorf("두 번 되돌리기: %d", code)
	}
	if _, body := agentCall(t, s, dev, s.apiAgent, "GET", "", ""); !strings.Contains(body, `"undone"`) || !strings.Contains(body, `"role":"vex"`) {
		t.Errorf("기록에 되돌림 표시 없음: %s", body)
	}
}

// 예약: 권한이 있는 종류만, 시각 형식 확인, 켜기·끄기·삭제, 다음 실행 시각(한국 시간).
func TestAgentSchedule(t *testing.T) {
	s := agentServer(t)
	dev := Session{Username: "dev1", Groups: []string{"developers"}}
	if code, _ := agentCall(t, s, dev, s.apiAgentScheduleAdd, "POST", "", `{"recipe":"reg-discover","repeat":"daily","time":"08:30"}`); code != 403 {
		t.Errorf("관리자 전용 예약: %d", code)
	}
	if code, _ := agentCall(t, s, dev, s.apiAgentScheduleAdd, "POST", "", `{"recipe":"vex-draft","repeat":"daily","time":"25:00"}`); code != 400 {
		t.Errorf("잘못된 시각: %d", code)
	}
	code, body := agentCall(t, s, dev, s.apiAgentScheduleAdd, "POST", "", `{"recipe":"vex-draft","repeat":"daily","time":"08:30"}`)
	var sc agentSchedule
	_ = json.Unmarshal([]byte(body), &sc)
	if code != 200 || !sc.On || sc.Next == "" || sc.Owner != "dev1" {
		t.Fatalf("예약 추가: %d %s", code, body)
	}
	if code, _ := agentCall(t, s, Session{Username: "other", Groups: []string{"developers"}}, s.apiAgentSchedule, "DELETE", sc.ID, ""); code != 404 {
		t.Errorf("남의 예약 삭제: %d", code)
	}
	if code, body := agentCall(t, s, dev, s.apiAgentSchedule, "POST", sc.ID, `{"on":false}`); code != 200 || !strings.Contains(body, "off") {
		t.Errorf("끄기: %d %s", code, body)
	}
	if code, _ := agentCall(t, s, dev, s.apiAgentSchedule, "DELETE", sc.ID, ""); code != 200 {
		t.Errorf("삭제: %d", code)
	}

	at := time.Date(2026, 11, 26, 1, 0, 0, 0, time.UTC) // 한국 시간 목요일 10:00
	if n := agentNext(agentSchedule{Repeat: "daily", Time: "08:30"}, at).In(agentKST).Format("01-02 15:04"); n != "11-27 08:30" {
		t.Errorf("매일: %s", n)
	}
	if n := agentNext(agentSchedule{Repeat: "once", Time: "14:00"}, at).In(agentKST).Format("01-02 15:04"); n != "11-26 14:00" {
		t.Errorf("한 번: %s", n)
	}
	if n := agentNext(agentSchedule{Repeat: "weekly", Weekday: 1, Time: "09:00"}, at).In(agentKST).Format("01-02 15:04"); n != "11-30 09:00" {
		t.Errorf("매주 월요일: %s", n)
	}
}
