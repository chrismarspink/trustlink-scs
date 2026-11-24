package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRenderMailAndInlineLogo(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AI_CONFIG", filepath.Join(dir, "a.json"))
	t.Setenv("MAIL_ORG_NAME", "ACME")
	s := &Server{}
	c := mailCard{Module: "자동 대응", Purpose: "결정 요청", Tone: "decide", Title: "고객 보안 권고 발송 승인 요청", Product: "app", Version: "1.0",
		Lead: "a <b> c", Facts: []mailFact{{K: "취약점", V: "CVE-1", Chips: []string{"CRITICAL", "KEV"}}},
		AI: &mailAI{Label: "AI 분석 — 조사 필요", Text: "요약", Model: "gemma"}, Action: "열기", URL: "https://x/admin", Ref: "r1"}
	mc := s.renderMail(c)
	for _, want := range []string{"결정 요청", "자동 대응", "AI 생성 · gemma", "a &lt;b&gt; c", "ACME", "참조 r1", "CRITICAL"} {
		if !strings.Contains(mc.HTML, want) {
			t.Errorf("HTML 에 %q 없음", want)
		}
	}
	if !strings.Contains(mc.Text, "AI 생성 · gemma") || !strings.Contains(mc.Text, "[CRITICAL·KEV] CVE-1") || len(mc.Inline) != 0 {
		t.Errorf("평문/로고: %q", mc.Text)
	}
	// 로고를 올려 두면 메일 안에 넣어 보낸다(multipart/related + Content-ID)
	png := []byte("\x89PNG\r\n\x1a\n0000")
	if err := os.WriteFile(filepath.Join(dir, "mail-logo.png"), png, 0o600); err != nil {
		t.Fatal(err)
	}
	mc = s.renderMail(c)
	if len(mc.Inline) != 1 || !strings.Contains(mc.HTML, "cid:"+mailLogoCID) {
		t.Fatalf("로고가 본문에 없음")
	}
	raw := string(buildMessageRich("tl@x.com", []string{"a@b.c"}, "제목", mc, time.Now(), "B"))
	for _, want := range []string{`multipart/alternative; boundary="B-alt"`, `multipart/related; boundary="B-rel"`, "Content-ID: <" + mailLogoCID + ">", "--B-rel--", "--B-alt--"} {
		if !strings.Contains(raw, want) {
			t.Errorf("메시지에 %q 없음", want)
		}
	}
}
