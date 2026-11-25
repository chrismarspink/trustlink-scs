package main

import (
	"strings"
	"testing"
)

// 넓힌 질문 유형: 사용법·현황·실제 악용·제품·고객, 그리고 맞는 것이 없을 때의 자유 질문.
func TestAskMoreIntents(t *testing.T) {
	s := askServer(t)
	dev := Session{Username: "dev1", Groups: []string{"developers"}}
	for _, c := range []struct {
		sess   Session
		q      string
		intent string
		want   string
	}{
		{askAdmin, "VEX 가 뭐야?", "howto", "판단 문서"},
		{dev, "SBOM 어떻게 올려?", "howto", "SBOM"},
		{askAdmin, "취약점 몇 건이야?", "status", "감시하고 있습니다"},
		{askAdmin, "급한 것부터 보여 줘", "urgent", ""},
		{askAdmin, "prod 상태는?", "product", "products/prod"},
		{askAdmin, "알파은행은 뭘 쓰나?", "customer", "알파은행"},
		{askAdmin, "고객 목록", "customer", "등록돼 있습니다"},
		{askAdmin, "계약 만료 임박한 고객은?", "customer", "90일"},
		{askAdmin, "점심 뭐 먹지", "free", "바로 찾지 못했습니다"},
	} {
		a := s.askAnswer(c.sess, c.q)
		if a.Intent != c.intent || !strings.Contains(a.Title+a.Lead, c.want) {
			t.Errorf("%q → %s %q %q (기대 %s, %q)", c.q, a.Intent, a.Title, a.Lead, c.intent, c.want)
		}
	}
	// 기존 유형은 그대로
	if a := s.askAnswer(askAdmin, "오늘 승인할 것?"); a.Intent != "todo" {
		t.Errorf("할 일: %s", a.Intent)
	}
	if a := s.askAnswer(askAdmin, "CVE-2026-0004 가 어디에 걸리나?"); a.Intent != "vuln" {
		t.Errorf("취약점: %s", a.Intent)
	}
}

// 질문 종류는 열되, 자료는 보는 사람의 범위 그대로: 고객 등록부는 관리자만, 고객 계정은 자기 제품만.
func TestAskMoreScope(t *testing.T) {
	s := askServer(t)
	dev := Session{Username: "dev1", Groups: []string{"developers"}}
	if a := s.askAnswer(dev, "고객 알파은행은 뭘 쓰나?"); a.Intent != "customer" || len(a.Rows) != 0 || !strings.Contains(a.Lead, "관리자만") {
		t.Errorf("개발자에게 고객 정보: %q %+v", a.Lead, a.Rows)
	}
	cust := Session{Username: "u", Groups: []string{"org-alpha"}}
	for _, q := range []string{"취약점 몇 건이야?", "급한 것부터", "고객 목록", "prod 상태는?", "아무 질문"} {
		a := s.askAnswer(cust, q)
		for _, r := range a.Rows {
			if strings.HasPrefix(r.Link, "/artifact/") || strings.HasPrefix(r.Link, "/admin/") {
				t.Errorf("고객 계정 %q 답에 내부 링크: %+v", q, r)
			}
		}
		for _, name := range []string{"Beta Corp", "감마공사"} {
			if strings.Contains(a.Lead, name) {
				t.Errorf("고객 계정 %q 답에 다른 고객 %s: %q", q, name, a.Lead)
			}
		}
	}
	// 사용법은 누구에게나
	if a := s.askAnswer(cust, "VEX 가 뭐야?"); a.Intent != "howto" {
		t.Errorf("고객 사용법: %s %q", a.Intent, a.Lead)
	}
}
