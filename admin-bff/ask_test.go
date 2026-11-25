package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func askServer(t *testing.T) *Server {
	s := testCustServer(t)
	s.notify = newNotifier(filepath.Join(t.TempDir(), "notify.json"))
	for _, v := range []string{"1.0", "1.1", "1.2", "2.0"} {
		s.notify.st.Projects["prod@"+v] = "products/prod"
	}
	vexQueueCache.Lock()
	vexQueueCache.rows, vexQueueCache.idx = nil, nil // 다른 테스트의 집계가 남지 않게
	vexQueueCache.Unlock()
	return s
}

// 관리자: 취약점 번호를 물으면 제품·버전과, 그 버전을 설치한 고객까지 답한다.
func TestAskVulnAdmin(t *testing.T) {
	s := askServer(t)
	a := s.askAnswer(Session{Username: "admin1", Groups: []string{"admins"}}, "cve-2026-0004 가 어디에 걸리나?")
	if a.Intent != "vuln" || len(a.Rows) != 4 || !strings.Contains(a.Lead, "버전 4개") {
		t.Fatalf("취약점 영향: %s %q %+v", a.Intent, a.Lead, a.Rows)
	}
	for _, name := range []string{"알파은행", "Beta Corp", "감마공사"} {
		if !strings.Contains(a.Lead, name) {
			t.Errorf("영향 고객에 %s 없음: %q", name, a.Lead)
		}
	}
	if len(a.facts) == 0 || a.Rows[0].Link == "" {
		t.Errorf("근거·링크 없음: %+v", a)
	}
	if b := s.askAnswer(Session{Username: "admin1", Groups: []string{"admins"}}, "CVE-2026-9999"); len(b.Rows) != 0 || !strings.Contains(b.Lead, "발견되지 않았습니다") {
		t.Errorf("없는 취약점: %q", b.Lead)
	}
}

// 고객: 자기 설치 버전에서만 찾고, 다른 고객 이름이나 관리자 할 일은 나오지 않는다.
func TestAskCustomerScope(t *testing.T) {
	s := askServer(t)
	alpha := Session{Username: "u-alpha", Groups: []string{"org-alpha"}} // 1.0 설치
	a := s.askAnswer(alpha, "CVE-2026-0001 이 내 제품에 있나?")
	if a.Intent != "vuln" || len(a.Rows) != 1 || !strings.Contains(a.Rows[0].Title, "1.0") {
		t.Fatalf("내 설치 버전: %+v", a)
	}
	if strings.Contains(a.Lead+a.Rows[0].Detail, "Beta") || strings.Contains(a.Lead, "고객") {
		t.Errorf("다른 고객 정보가 나옴: %q", a.Lead)
	}
	if b := s.askAnswer(alpha, "CVE-2026-0003 은?"); len(b.Rows) != 0 { // 1.1 에만 있음(다른 고객의 버전)
		t.Errorf("남의 버전이 나옴: %+v", b.Rows)
	}
	c := s.askAnswer(alpha, "오늘 승인할 것?")
	if c.Intent != "my" {
		t.Errorf("고객에게 관리자 할 일이 나옴: %s", c.Intent)
	}
	d := s.askAnswer(alpha, "내가 조치할 게 있나?")
	if d.Intent != "my" || len(d.Rows) != 1 || !strings.Contains(d.Rows[0].Detail, "권장 버전 2.0") {
		t.Errorf("내 제품: %+v", d)
	}
}

func TestAskComponentTodoHelp(t *testing.T) {
	s := askServer(t)
	dev := Session{Username: "dev1", Groups: []string{"developers"}}
	a := s.askAnswer(dev, "lib-a 를 쓰는 제품은?")
	if a.Intent != "component" || len(a.Rows) != 4 {
		t.Fatalf("구성요소: %s %+v", a.Intent, a.Rows)
	}
	b := s.askAnswer(dev, "내 할 일은?")
	if b.Intent != "todo" || len(b.Rows) == 0 || !strings.Contains(b.Lead, "판단 대기") {
		t.Errorf("할 일(개발자): %s %q", b.Intent, b.Lead)
	}
	if c := s.askAnswer(dev, "제로트러스트가 뭐야"); c.Intent != "free" || len(c.Suggest) == 0 {
		t.Errorf("그 밖의 질문: %s", c.Intent)
	}
}

// AI 정리는 질문한 본인만 요청할 수 있다.
func TestAskSummaryOwner(t *testing.T) {
	s := askServer(t)
	a := s.askAnswer(Session{Username: "admin1", Groups: []string{"admins"}}, "CVE-2026-0004")
	a.user = "admin1"
	askKeep(a)
	sid := s.store.put(Session{Username: "other", Groups: []string{"developers"}, Expiry: time.Now().Add(time.Hour)})
	r := httptest.NewRequest("POST", "/api/ask/"+a.ID+"/summary", nil)
	r.SetPathValue("id", a.ID)
	r.AddCookie(&http.Cookie{Name: cookieName, Value: sid})
	w := httptest.NewRecorder()
	s.apiAskSummary(w, r)
	if w.Code != 404 {
		t.Errorf("남의 질문 정리: %d", w.Code)
	}
}
