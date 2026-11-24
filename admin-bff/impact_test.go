package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func impactGet(s *Server, sess Session, vuln string) (int, map[string]any, string) {
	sid := s.store.put(Session{Username: sess.Username, Groups: sess.Groups, Expiry: time.Now().Add(time.Hour)})
	r := httptest.NewRequest("GET", "/api/impact?vuln="+vuln, nil)
	r.AddCookie(&http.Cookie{Name: cookieName, Value: sid})
	w := httptest.NewRecorder()
	s.apiImpact(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out, w.Body.String()
}

// 영향 지도: 관리자는 고객까지, 개발자는 버전까지, 고객 계정은 볼 수 없다.
func TestImpactMap(t *testing.T) {
	s := askServer(t)
	code, out, raw := impactGet(s, askAdmin, "CVE-2026-0004")
	if code != 200 || len(out["nodes"].([]any)) < 6 {
		t.Fatalf("관리자: %d %s", code, raw)
	}
	for _, want := range []string{`"type":"vuln"`, `"type":"component"`, `"type":"version"`, `"type":"customer"`, "알파은행", `"key":"found"`} {
		if !strings.Contains(raw, want) {
			t.Errorf("지도에 %s 없음", want)
		}
	}
	// CVE-2026-0001 은 1.0·1.1 에만 있다 → 1.2·2.0 은 "이 취약점 없음"으로
	if _, _, raw := impactGet(s, askAdmin, "CVE-2026-0001"); !strings.Contains(raw, `"type":"safe"`) || !strings.Contains(raw, `"state":"affected"`) {
		t.Errorf("안전한 버전·판정 상태: %s", raw)
	}
	if _, _, raw := impactGet(s, Session{Username: "dev1", Groups: []string{"developers"}}, "CVE-2026-0004"); strings.Contains(raw, "customer") && strings.Contains(raw, "알파은행") {
		t.Errorf("개발자에게 고객이 보임")
	}
	if code, _, _ := impactGet(s, Session{Username: "u", Groups: []string{"org-alpha"}}, "CVE-2026-0004"); code != 403 {
		t.Errorf("고객 계정: %d", code)
	}
	if code, out, _ := impactGet(s, askAdmin, "CVE-2026-9999"); code != 200 || out["empty"] == nil {
		t.Errorf("없는 취약점: %d %v", code, out)
	}
	if code, _, _ := impactGet(s, askAdmin, "not-a-vuln-id"); code != 400 {
		t.Errorf("잘못된 번호: %d", code)
	}
}
