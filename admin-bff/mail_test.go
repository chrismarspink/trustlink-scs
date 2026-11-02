package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestMailAllowlist(t *testing.T) {
	m := &Mailer{Allow: map[string]bool{"dev@example.com": true}}
	ok, dropped := m.filter([]string{"Dev@Example.com", "acme1@innotium.local"})
	if len(ok) != 1 || len(dropped) != 1 || dropped[0] != "acme1@innotium.local" {
		t.Fatalf("ok=%v dropped=%v", ok, dropped)
	}
	if ok, _ := (&Mailer{}).filter([]string{"a@b.c"}); len(ok) != 1 {
		t.Fatal("빈 허용 목록은 제한 없음이어야 함")
	}
}

func TestBuildMessageKorean(t *testing.T) {
	msg := string(buildMessage("trustlink@innotium.com", []string{"a@b.c"}, "[TrustLink] 시험", "본문", time.Unix(0, 0)))
	for _, want := range []string{`From: "TrustLink" <trustlink@innotium.com>`, "Subject: =?UTF-8?b?", "Content-Transfer-Encoding: base64", "\r\n\r\n67O466y4\r\n"} {
		if !strings.Contains(msg, want) {
			t.Errorf("메시지에 %q 없음:\n%s", want, msg)
		}
	}
}

// 실제 발송(opt-in): MAIL_TEST_TO 와 SMTP_* 환경 변수가 있을 때만.
func TestMailSendIntegration(t *testing.T) {
	to := os.Getenv("MAIL_TEST_TO")
	if to == "" {
		t.Skip("MAIL_TEST_TO 미설정")
	}
	sent, dropped, err := newMailer().Send([]string{to}, "[TrustLink] 메일 발송 시험(통합 시험)", "TrustLink BFF mail.go 통합 시험 메일입니다.")
	if err != nil || len(sent) != 1 {
		t.Fatalf("sent=%v dropped=%v err=%v", sent, dropped, err)
	}
}
