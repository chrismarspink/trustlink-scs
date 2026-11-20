package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNormalizeCustomer(t *testing.T) {
	ok := Customer{Name: "예시", Industry: "일반", OrgGroup: "example",
		Contacts: []CustContact{{Name: "a", Role: "security", Email: "a@example.com", Notify: []string{"vuln"}}},
		Usages:   []CustUsage{{Repo: "products/x", Installs: []CustInstall{{Tag: "1.0"}}, NotifyContacts: []string{"A@example.com"}}}}
	if err := normalizeCustomer(&ok); err != nil {
		t.Fatal(err)
	}
	if ok.ID == "" || ok.Lang != "ko" || ok.OrgGroup != "org-example" || ok.Usages[0].ID == "" || ok.Usages[0].NotifyLevel != "high" || ok.Usages[0].Installs[0].Env != "운영" {
		t.Fatalf("기본값: %+v", ok)
	}
	bad := []func(c *Customer){
		func(c *Customer) { c.Name = "" },
		func(c *Customer) { c.Industry = "기타" },
		func(c *Customer) { c.Lang = "jp" },
		func(c *Customer) { c.Contacts[0].Email = "x" },
		func(c *Customer) { c.Contacts[0].Role = "boss" },
		func(c *Customer) { c.Contacts[0].Notify = []string{"spam"} },
		func(c *Customer) { c.Contacts = append(c.Contacts, c.Contacts[0]) },
		func(c *Customer) { c.Usages[0].Repo = "Bad Repo" },
		func(c *Customer) { c.Usages[0].MaintExpiry = "2026-13-01" },
		func(c *Customer) { c.Usages[0].LicenseType = "free" },
		func(c *Customer) { c.Usages[0].NotifyContacts = []string{"none@example.com"} },
		func(c *Customer) { c.Usages[0].Installs[0].Env = "QA" },
	}
	for i, f := range bad {
		c := Customer{Name: "예시", Industry: "일반",
			Contacts: []CustContact{{Name: "a", Role: "security", Email: "a@example.com"}},
			Usages:   []CustUsage{{Repo: "products/x", Installs: []CustInstall{{Tag: "1.0"}}}}}
		f(&c)
		if err := normalizeCustomer(&c); err == nil {
			t.Errorf("%d: 오류여야 함", i)
		}
	}
	vs := []VerPolicy{{Tag: "1.10"}, {Tag: "1.9", EOS: "2026-01-01"}}
	if err := normalizeVersions(vs); err != nil || vs[0].Tag != "1.9" {
		t.Fatalf("버전 정렬: %v %+v", err, vs)
	}
	if normalizeVersions([]VerPolicy{{Tag: "1"}, {Tag: "1"}}) == nil {
		t.Fatal("중복 버전 거부")
	}
}

func TestCustExpiriesAndMismatch(t *testing.T) {
	now := time.Date(2026, 11, 20, 3, 0, 0, 0, time.UTC)
	c := Customer{ID: "a", Name: "A", Usages: []CustUsage{{ID: "u1", Repo: "p/x", LicenseType: "perpetual", LicenseExpiry: "2026-01-01", MaintExpiry: "2026-12-20",
		Installs: []CustInstall{{Tag: "1.0"}, {Tag: "1.0"}}}}}
	ex := custExpiries(c, map[string][]VerPolicy{"p/x": {{Tag: "1.0", EOS: "2026-11-27"}}}, now)
	if len(ex) != 2 || ex[0].Kind != "eos" || ex[0].Days != 7 || ex[1].Kind != "maint" || ex[1].Days != 30 {
		t.Fatalf("영구 라이선스 제외, EOS D-7, 유지보수 D-30: %+v", ex)
	}
	log := strings.Join([]string{
		`{"time":"2026-11-01T00:00:00Z","message":"HTTP API","username":"u1","method":"GET","path":"/v2/p/x/manifests/1.0","statusCode":200}`,
		`{"time":"2026-11-10T00:00:00Z","message":"HTTP API","username":"u1","method":"GET","path":"/v2/p/x/manifests/1.2","statusCode":200}`,
		`{"time":"2026-11-11T00:00:00Z","message":"HTTP API","username":"u1","method":"GET","path":"/v2/p/y/manifests/3.0","statusCode":200}`,
		`{"time":"2026-11-12T00:00:00Z","message":"HTTP API","username":"other","method":"GET","path":"/v2/p/x/manifests/9.0","statusCode":200}`,
	}, "\n")
	est := downloadEstimates(strings.NewReader(log), map[string]string{"u1": "org-a"})
	if est["org-a"]["p/x"].Tag != "1.2" || len(est) != 1 {
		t.Fatalf("마지막 다운로드 버전: %+v", est)
	}
	mm := custMismatches(c, est["org-a"])
	if len(mm) != 2 || mm[0].Estimated != "1.2" || mm[1].Repo != "p/y" || len(mm[1].Installed) != 0 {
		t.Fatalf("확인 필요(추정 1.2 ≠ 등록 1.0, 등록 안 된 제품 p/y): %+v", mm)
	}
}

func TestCustExpiryDedupe(t *testing.T) {
	s := testCustServer(t)
	c := s.cust()
	day := time.Date(2026, 11, 20, 3, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return day }
	c.d.Customers = c.d.Customers[:1]
	c.d.Customers[0].Usages[0].MaintExpiry = "2026-12-10" // D-20 → 30일 임계값
	c.d.Products = map[string][]VerPolicy{}
	logLen := func() int { return len(c.snapshot().ExpiryLog) }

	// 메일 서버 없음 → 실패로 보고 표시하지 않음(다음 날 재시도)
	s.custExpiryCheck()
	if logLen() != 1 || len(c.snapshot().ExpirySent) != 0 {
		t.Fatalf("실패는 표시 안 함: %+v", c.snapshot().ExpiryLog)
	}
	s.mail = &Mailer{Host: "smtp.invalid", Port: "587", From: "tl@example.com", Allow: map[string]bool{"allowed@example.com": true}}
	s.custExpiryCheck()
	d := c.snapshot()
	last := d.ExpiryLog[len(d.ExpiryLog)-1]
	if len(d.ExpirySent) != 1 || last.Error != "" || len(last.Dropped) != 2 || last.Audience != "internal" {
		t.Fatalf("영업·지원 담당 → 허용 목록 밖 건너뜀 + 30일 임계값 표시: %+v %+v", d.ExpirySent, last)
	}
	s.custExpiryCheck()
	if logLen() != 2 {
		t.Fatal("같은 임계값은 한 번만")
	}
	day = day.AddDate(0, 0, 15) // D-5 → 7일 임계값
	c.d.Settings.ExpiryToCustomer = true
	s.custExpiryCheck()
	d = c.snapshot()
	if len(d.ExpirySent) != 2 || logLen() != 4 || d.ExpiryLog[3].Audience != "customer" || d.ExpiryLog[3].Dropped[0] != "buy@alpha.example.com" {
		t.Fatalf("7일 임계값 1회 + 고객 구매 담당(설정 시): %+v", d.ExpiryLog)
	}
	s.custExpiryCheck()
	if logLen() != 4 {
		t.Fatal("7일도 한 번만")
	}
	w := httptest.NewRecorder()
	s.apiCustomerExpiring(w, httptest.NewRequest("GET", "/api/customer-expiring", nil))
	var out struct {
		Items []struct {
			Days int   `json:"days"`
			Sent []int `json:"sent"`
		}
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	if len(out.Items) != 1 || out.Items[0].Days != 5 || len(out.Items[0].Sent) != 2 {
		t.Fatalf("만료 예정 목록: %s", w.Body.String())
	}
}

func TestCustomerCRUD(t *testing.T) {
	s := testCustServer(t)
	body := `{"id":"delta","name":"델타","industry":"일반","contacts":[],"usages":[{"repo":"products/prod","installs":[{"tag":"1.0","env":"검증","qty":1}]}]}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/customers", bytes.NewBufferString(body))
	s.apiCustomerSave(w, req)
	if w.Code != 201 {
		t.Fatalf("생성: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.apiCustomerSave(w, httptest.NewRequest("POST", "/api/customers", bytes.NewBufferString(body)))
	if w.Code != 409 {
		t.Fatal("ID 중복 거부")
	}
	w = httptest.NewRecorder()
	req = httptest.NewRequest("PUT", "/api/customers/delta", bytes.NewBufferString(strings.Replace(body, "델타", "델타2", 1)))
	req.SetPathValue("id", "delta")
	s.apiCustomerSave(w, req)
	if x, _ := s.cust().find("delta"); w.Code != 200 || x.Name != "델타2" {
		t.Fatalf("수정: %d %+v", w.Code, x)
	}
	w = httptest.NewRecorder()
	s.apiCustomers(w, httptest.NewRequest("GET", "/api/customers", nil))
	if !strings.Contains(w.Body.String(), `"kind":"maint"`) || !strings.Contains(w.Body.String(), "델타2") {
		t.Fatalf("목록 D-day: %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	req = httptest.NewRequest("DELETE", "/api/customers/delta", nil)
	req.SetPathValue("id", "delta")
	s.apiCustomerDelete(w, req)
	if _, ok := s.cust().find("delta"); w.Code != 200 || ok {
		t.Fatal("삭제")
	}
	evs, _ := s.sor.list()
	acts := []string{}
	for _, e := range evs {
		acts = append(acts, e.Action)
	}
	if strings.Join(acts, ",") != "customer-create,customer-update,customer-delete" {
		t.Fatalf("감사 기록: %v", acts)
	}
}
