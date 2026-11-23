package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCustomerStatusAndLogo(t *testing.T) {
	s := testCustServer(t)
	c := s.cust()
	id := c.d.Customers[0].ID
	// 사유 없이 중지 → 거부
	w := httptest.NewRecorder()
	r := httptest.NewRequest("PUT", "/api/customers/"+id+"/status", strings.NewReader(`{"enabled":false}`))
	r.SetPathValue("id", id)
	s.apiCustomerStatus(w, r)
	if w.Code != 400 {
		t.Fatalf("사유 필수: %d", w.Code)
	}
	w = httptest.NewRecorder()
	r = httptest.NewRequest("PUT", "/", strings.NewReader(`{"enabled":false,"reason":"terminated","note":"2026-11 해지"}`))
	r.SetPathValue("id", id)
	s.apiCustomerStatus(w, r)
	x, _ := c.find(id)
	if w.Code != 200 || !x.Disabled || x.DisabledReason != "terminated" || x.DisabledAt == "" {
		t.Fatalf("중지: %d %+v", w.Code, x)
	}
	if len(activeCustomers(c.snapshot().Customers)) != len(c.snapshot().Customers)-1 {
		t.Fatal("중지된 회사는 통지 대상에서 빠짐")
	}
	// 편집 저장이 상태를 지우지 않음
	x.Name = "이름 바꿈"
	x.Disabled = false
	body, _ := json.Marshal(x)
	w = httptest.NewRecorder()
	r = httptest.NewRequest("PUT", "/", bytes.NewReader(body))
	r.SetPathValue("id", id)
	s.apiCustomerSave(w, r)
	if y, _ := c.find(id); w.Code != 200 || !y.Disabled || y.Name != "이름 바꿈" {
		t.Fatalf("편집 저장 후에도 중지 유지: %d %+v %s", w.Code, y, w.Body.String())
	}
	// 로고: SVG 거부, PNG 저장·조회
	w = httptest.NewRecorder()
	r = httptest.NewRequest("PUT", "/", strings.NewReader(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`))
	r.SetPathValue("id", id)
	s.apiCustomerLogoPut(w, r)
	if w.Code != 400 {
		t.Fatalf("SVG 거부: %d", w.Code)
	}
	png := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89")
	w = httptest.NewRecorder()
	r = httptest.NewRequest("PUT", "/", bytes.NewReader(png))
	r.SetPathValue("id", id)
	s.apiCustomerLogoPut(w, r)
	y, _ := c.find(id)
	if w.Code != 200 || !strings.HasPrefix(y.Logo, id+".png?v=") {
		t.Fatalf("PNG 저장: %d %s %s", w.Code, y.Logo, w.Body.String())
	}
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "/", nil)
	r.SetPathValue("file", id+".png")
	s.apiCustomerLogoGet(w, r)
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/png" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("로고 조회: %d %v", w.Code, w.Header())
	}
	r = httptest.NewRequest("GET", "/", nil)
	r.SetPathValue("file", "../customers.json")
	w = httptest.NewRecorder()
	s.apiCustomerLogoGet(w, r)
	if w.Code != 404 {
		t.Fatal("경로 이탈 거부")
	}
}
