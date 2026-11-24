package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 실패한 메일은 보관해 둔 내용으로 다시 보낼 수 있다(발송함을 거쳐, 한 번만).
func TestOutboxResend(t *testing.T) {
	s := testCustServer(t)
	s.mail = &Mailer{Host: "127.0.0.1", Port: "1", From: "tl@example.com", Allow: map[string]bool{"a@example.com": true}}
	done := make(chan outboxItem, 1)
	it := s.enqueueMail("digest", "현황", "", "admin", []string{"a@example.com"}, "제목", mailContent{Text: "본문", HTML: "<b>본문</b>"}, 0, func(x outboxItem) { done <- x })
	select {
	case x := <-done:
		if x.Status != "failed" {
			t.Fatalf("실패여야 함: %+v", x)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("발송 시도가 끝나지 않음")
	}
	call := func(id string) (int, outboxItem) {
		r := httptest.NewRequest("POST", "/api/mail/outbox/"+id+"/resend", strings.NewReader(`{"delay":120}`))
		r.SetPathValue("id", id)
		w := httptest.NewRecorder()
		s.apiMailOutboxResend(w, r)
		var o outboxItem
		_ = json.Unmarshal(w.Body.Bytes(), &o)
		return w.Code, o
	}
	code, n := call(it.ID)
	if code != 202 || n.Status != "pending" || n.ResendOf != it.ID || n.Subject != "제목" {
		t.Fatalf("다시 보내기: %d %+v", code, n)
	}
	outbox.Lock()
	job := outbox.jobs[n.ID]
	outbox.Unlock()
	if job == nil || job.content.HTML != "<b>본문</b>" {
		t.Fatalf("보관한 내용이 아님: %+v", job)
	}
	job.timer.Stop()
	if code, _ := call(it.ID); code != 409 { // 같은 메일을 두 번 다시 보내지 않는다
		t.Errorf("두 번째 다시 보내기: %d", code)
	}
	if code, _ := call(n.ID); code != 409 { // 기다리는 메일은 대상이 아님
		t.Errorf("대기 메일 다시 보내기: %d", code)
	}
	if code, _ := call("../x"); code != 404 {
		t.Errorf("잘못된 ID: %d", code)
	}
}
