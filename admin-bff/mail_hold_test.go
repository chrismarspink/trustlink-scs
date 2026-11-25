package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func holdCall(s *Server, h func(http.ResponseWriter, *http.Request), method, id, body string) (int, string) {
	r := httptest.NewRequest(method, "/api/mail/hold/"+id, strings.NewReader(body))
	r.SetPathValue("id", id)
	w := httptest.NewRecorder()
	w.Header().Set("X-User", "admin1")
	h(w, r)
	return w.Code, w.Body.String()
}

// 고객에게 갈 자동 메일: 승인 전에는 나가지 않고, 승인하면 발송함으로, 반려하면 사라진다.
func TestMailHold(t *testing.T) {
	s := askServer(t)
	s.mail = &Mailer{Host: "smtp.invalid", Port: "587", From: "tl@example.com", Allow: map[string]bool{"allowed@example.com": true}}
	c := mailContent{Text: "본문", HTML: "<p>본문 <b>VEX</b></p>"}
	a := s.holdMail("vex", "VEX 발행 통보 · prod 1.0", "products/prod:1.0", []string{"u@alpha.example.com"}, "[TrustLink] prod 1.0 보안 판단(VEX) 갱신", c)
	b := s.holdMail("expiry", "알파은행 · 만료 안내", "c1", []string{"buy@alpha.example.com"}, "[안내] 계약·지원 만료 예정", c)
	if n := len(holdWaiting()); n != 2 {
		t.Fatalf("승인 대기 %d건", n)
	}
	groups, total := s.inboxGroups()
	found := false
	for _, g := range groups {
		if g.Key == "hold" && g.Count == 2 {
			found = true
		}
	}
	if !found || total < 2 {
		t.Errorf("승인 대기함에 고객 메일 묶음이 없음: %+v", groups)
	}
	if code, body := holdCall(s, s.apiMailHoldPreview, "GET", a.ID, ""); code != 200 || !strings.Contains(body, "<b>VEX</b>") {
		t.Errorf("미리보기: %d %s", code, body)
	}
	// 승인 → 발송함에 대기로 들어간다(바로 나가지 않음)
	code, body := holdCall(s, s.apiMailHoldApprove, "POST", a.ID, `{"delay":120}`)
	if code != 200 || !strings.Contains(body, `"status":"pending"`) || !strings.Contains(body, `"kind":"notify"`) || !strings.Contains(body, `"createdBy":"admin1"`) {
		t.Fatalf("승인: %d %s", code, body)
	}
	if code, _ := holdCall(s, s.apiMailHoldApprove, "POST", a.ID, `{}`); code != 409 {
		t.Errorf("두 번 승인: %d", code)
	}
	outbox.Lock()
	for id, j := range outbox.jobs { // 시험이 끝난 뒤 실제 발송을 시도하지 않게
		j.timer.Stop()
		delete(outbox.jobs, id)
	}
	outbox.Unlock()
	// 반려 → 사유를 남기고 내용은 지운다
	if code, body := holdCall(s, s.apiMailHoldReject, "POST", b.ID, `{"reason":"갱신 협의 중"}`); code != 200 || !strings.Contains(body, "갱신 협의 중") {
		t.Errorf("반려: %d %s", code, body)
	}
	if _, ok := holdContent(b.ID); ok {
		t.Error("반려한 메일의 내용이 남아 있음")
	}
	if n := len(holdWaiting()); n != 0 {
		t.Errorf("처리 뒤 승인 대기 %d건", n)
	}
}
