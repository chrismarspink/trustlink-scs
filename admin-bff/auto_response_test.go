package main

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// 패치 있음 → 고객 통지 초안 + 관리자 승인 대기 → 승인하면 발송함(취소 가능)
// 패치 없음 → 개발자 통보(고객에게는 아무것도 나가지 않음)
func TestAutoResponseFlow(t *testing.T) {
	s := testCustServer(t)
	s.notify = newNotifier(filepath.Join(t.TempDir(), "notify.json"))
	autoRes.Lock()
	autoRes.loaded, autoRes.Runs, autoRes.Settings = true, nil, autoSettings{Mode: "on", MaxPerVer: 3}
	autoRes.Unlock()

	r := s.runAutoResponse(newAutoRun("manual", "admin", "products/prod", "1.0", "CVE-2026-0001"))
	if r.State != "waiting" || r.Outcome != "approval" || r.FixTag != "2.0" || r.NoticeID == "" || len(r.Customers) != 1 || r.Customers[0] != "알파은행" {
		t.Fatalf("패치 있음 → 승인 대기: %+v", r)
	}
	for _, st := range r.Stages {
		if st.Key == "notify" && st.State != "todo" {
			t.Fatalf("승인 전에는 고객 통지 안 함: %+v", st)
		}
	}
	n, _ := s.cust().notice(r.NoticeID)
	if n.Status != "draft" || n.AutoRun != r.ID || n.Targets[0].Result != nil {
		t.Fatalf("통지는 초안: %+v", n)
	}
	// 관리자 승인 → 발송함(허용 목록 주소만 대기열로)
	s.mail = &Mailer{Host: "smtp.invalid", Port: "587", From: "tl@example.com", Allow: map[string]bool{"sec@alpha.example.com": true}}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/auto-response/"+r.ID+"/approve", strings.NewReader(`{"delay":120}`))
	req.SetPathValue("id", r.ID)
	s.apiAutoResponseDecide(w, req)
	if w.Code != 200 {
		t.Fatalf("승인: %d %s", w.Code, w.Body.String())
	}
	n, _ = s.cust().notice(r.NoticeID)
	if n.Status != "queued" || !n.Targets[0].Result.Pending {
		t.Fatalf("승인 후 발송함 대기: %s %+v", n.Status, n.Targets[0].Result)
	}
	// 정리: 발송함 대기 취소(테스트가 실제 SMTP 로 보내지 않게)
	cw := httptest.NewRecorder()
	cr := httptest.NewRequest("DELETE", "/", nil)
	cr.SetPathValue("id", n.Targets[0].Result.Outbox)
	s.apiMailOutboxCancel(cw, cr)

	// 두 번 승인은 거부
	w = httptest.NewRecorder()
	s.apiAutoResponseDecide(w, req)
	if w.Code != 409 {
		t.Fatalf("이미 처리된 건: %d", w.Code)
	}

	// 패치 없음(최신 2.0 에도 남은 CVE-2026-0004) → 개발자 수정 요청 초안 + 승인 대기(아직 아무에게도 안 감)
	r2 := s.runAutoResponse(newAutoRun("manual", "admin", "products/prod", "2.0", "CVE-2026-0004"))
	if r2.Outcome != "approval-dev" || r2.State != "waiting" || r2.NoticeID != "" || len(r2.Customers) != 1 || r2.Customers[0] != "감마공사" ||
		!strings.Contains(r2.DevSubject, "CVE-2026-0004") || !strings.Contains(r2.DevBody, "감마공사") {
		t.Fatalf("패치 없음 → 개발자 요청 승인 대기: %+v", r2)
	}
	for _, nt := range s.notify.st.Notices {
		if nt.Kind == "patch-needed" {
			t.Fatal("승인 전에는 개발자에게 보내지 않음")
		}
	}
	// 승인(후보가 없으면 거부) → 후보를 넣고 승인하면 화면 알림
	w = httptest.NewRecorder()
	req2 := httptest.NewRequest("POST", "/api/auto-response/"+r2.ID+"/approve", strings.NewReader(`{"delay":0}`))
	req2.SetPathValue("id", r2.ID)
	s.apiAutoResponseDecide(w, req2)
	if w.Code != 400 {
		t.Fatalf("받는 사람 없으면 거부: %d %s", w.Code, w.Body.String())
	}
	autoUpdate(r2.ID, func(x *autoRun) { x.DevCands = []devCand{{Username: "dev1", Email: "dev1@out.example"}} })
	w = httptest.NewRecorder()
	req2 = httptest.NewRequest("POST", "/api/auto-response/"+r2.ID+"/approve", strings.NewReader(`{"keys":["dev1"],"delay":0}`))
	req2.SetPathValue("id", r2.ID)
	s.apiAutoResponseDecide(w, req2)
	if w.Code != 200 {
		t.Fatalf("개발자 요청 승인: %d %s", w.Code, w.Body.String())
	}
	found := false
	for _, nt := range s.notify.st.Notices {
		if nt.Kind == "patch-needed" && len(nt.To) == 1 && nt.To[0] == "dev1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("승인 후 개발자 화면 알림: %+v", s.notify.st.Notices)
	}

	// 주기 검색: 고객 설치 버전(1.0·1.1·2.0)+최신의 미대응 치명(CVE-2026-0004)을 찾아 처리
	autoRes.Lock()
	autoRes.Settings.SweepMax = 5
	autoRes.Unlock()
	n0 := len(autoRes.Runs)
	got := s.autoSweep("test")
	if got == 0 || len(autoRes.Runs) != n0+got {
		t.Fatalf("주기 검색이 새 건을 처리: %d", got)
	}
	if again := s.autoSweep("test"); again != 0 {
		t.Fatalf("이미 대응한 건은 다시 안 함: %d", again)
	}
	if autoRes.Settings.LastSweep == "" || !strings.Contains(autoRes.Settings.SweepMsg, "검사") {
		t.Fatalf("검색 기록: %+v", autoRes.Settings)
	}

	// 없는 취약점은 탐지 단계 오류
	r3 := s.runAutoResponse(newAutoRun("manual", "admin", "products/prod", "1.0", "CVE-1999-0000"))
	if r3.State != "error" || r3.Stages[0].State != "error" {
		t.Fatalf("없는 취약점: %+v", r3)
	}
}
