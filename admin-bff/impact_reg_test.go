package main

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func impactRegGet(s *Server, q string) (int, string) {
	w := httptest.NewRecorder()
	s.apiImpactReg(w, httptest.NewRequest("GET", "/api/impact/reg"+q, nil))
	return w.Code, w.Body.String()
}

// 규제 영향 지도: 고객의 국가·업종으로 "해당 가능"을 가리고, 그 고객이 쓰는 제품까지 잇는다.
func TestImpactReg(t *testing.T) {
	s := askServer(t)
	t.Setenv("REG_DIR", filepath.Join(t.TempDir(), "regs"))
	if code, body := impactRegGet(s, ""); code != 200 || !strings.Contains(body, `"id":"kr-fin"`) || !strings.Contains(body, `"region":"한국"`) {
		t.Fatalf("규제 목록: %d %.200s", code, body)
	}
	// 금융 규제 → 금융 업종 고객(알파은행)만. 공공 고객(감마공사)과 해외 고객은 빠진다
	code, body := impactRegGet(s, "?id=kr-fin")
	if code != 200 || !strings.Contains(body, "알파은행") || strings.Contains(body, "감마공사") || strings.Contains(body, "Beta Corp") {
		t.Fatalf("금융 규제: %d %s", code, body)
	}
	for _, want := range []string{`"type":"reg"`, `"type":"customer"`, `"type":"product"`, "해당 가능", `"kind":"reg"`, `"cols"`, `"reqs"`, "추정"} {
		if !strings.Contains(body, want) {
			t.Errorf("금융 규제 지도에 %s 없음", want)
		}
	}
	// 공공·금융 모두 대상인 규제 → 두 고객
	if _, body := impactRegGet(s, "?id=kr-ismsp"); !strings.Contains(body, "알파은행") || !strings.Contains(body, "감마공사") {
		t.Errorf("공공·금융 규제: %s", body)
	}
	// 미국 방산 규제 → 국내 고객은 해당 없음
	if _, body := impactRegGet(s, "?id=us-cmmc"); !strings.Contains(body, `"empty"`) || strings.Contains(body, `"type":"customer"`) {
		t.Errorf("미국 규제: %s", body)
	}
	if code, _ := impactRegGet(s, "?id=nope"); code != 404 {
		t.Errorf("없는 규제: %d", code)
	}
	if custRegion("") != "KR" || custRegion("미국") != "US" || custRegion("Germany") != "EU" || custRegion("화성") != "" {
		t.Error("국가 표기 맞추기")
	}
}
