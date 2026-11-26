package main

import (
	"strings"
	"testing"
)

// 내부 검증(pilot) 고객은 대상에 ring=pilot 로 표시된다.
func TestBuildNoticeRingPilot(t *testing.T) {
	s := testCustServer(t)
	c := s.cust()
	c.mu.Lock()
	for i := range c.d.Customers {
		if c.d.Customers[i].ID == "alpha" {
			c.d.Customers[i].Pilot = true
		}
	}
	c.mu.Unlock()
	n, err := s.buildNotice("patch", "products/prod", "CVE-2026-0001", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Targets) != 1 || n.Targets[0].Ring != "pilot" {
		t.Fatalf("pilot 고객 대상은 ring=pilot 여야 한다: %+v", n.Targets)
	}
}

// 발송 게이트: 내부 검증 고객을 먼저 보낸 뒤에야 외부로. pilot 이 없으면 기존과 동일.
func TestPilotGate(t *testing.T) {
	n := &CustNotice{Targets: []CustTarget{
		{Key: "ext|u|ko", Customer: "알파은행"},
		{Key: "pilot|u|ko", Customer: "내부QA", Ring: "pilot"},
	}}
	if msg := pilotGate(n, []string{"ext|u|ko"}); msg == "" || !strings.Contains(msg, "내부QA") {
		t.Fatalf("내부 먼저 — 외부 발송은 막혀야 한다: %q", msg)
	}
	if msg := pilotGate(n, []string{"pilot|u|ko"}); msg != "" {
		t.Fatalf("내부 발송은 허용해야 한다: %q", msg)
	}
	if msg := pilotGate(n, []string{"ext|u|ko", "pilot|u|ko"}); msg == "" {
		t.Fatal("한 번에 내부+외부도 막아 2단계를 강제해야 한다")
	}
	n.Targets[1].Result = &custSendResult{At: "t"} // 내부를 보낸(시도한) 뒤
	if msg := pilotGate(n, []string{"ext|u|ko"}); msg != "" {
		t.Fatalf("내부를 보낸 뒤에는 외부 허용: %q", msg)
	}
	plain := &CustNotice{Targets: []CustTarget{{Key: "ext|u|ko", Customer: "알파"}}}
	if msg := pilotGate(plain, []string{"ext|u|ko"}); msg != "" {
		t.Fatalf("pilot 고객이 없으면 변화 없음(차단 안 함): %q", msg)
	}
}
