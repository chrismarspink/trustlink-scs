package main

// 통합 테스트(opt-in): 실제 Keycloak 이 도달 가능한 네트워크에서만 동작.
// OIDC_TEST_TOKEN(실 액세스 토큰)이 없으면 skip 하여 일반 빌드/CI 에 영향 없음.
//
//	docker run --network zot-keycloak_default \
//	  -e OIDC_TEST_TOKEN=... -e KC_INTERNAL=... -e REALM=... -e CLIENT_ID=... \
//	  golang:1.22 go test -run TestOIDCVerify -v ./...

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestOIDCVerify(t *testing.T) {
	tok := os.Getenv("OIDC_TEST_TOKEN")
	if tok == "" {
		t.Skip("OIDC_TEST_TOKEN 미설정 — 통합 테스트 skip")
	}
	cfg := Config{
		KCInternal: env("KC_INTERNAL", "http://keycloak:8085/auth"),
		Realm:      env("REALM", "trustlink"),
		ClientID:   env("CLIENT_ID", "trustlink-admin"),
	}
	v := newOIDCVerifier(cfg, &http.Client{Timeout: 15 * time.Second})

	// 1) 유효 토큰 → 통과 + username 추출
	user, groups, err := v.verify(tok)
	if err != nil {
		t.Fatalf("유효 토큰이 거부됨: %v", err)
	}
	if user == "" {
		t.Fatalf("username 미추출 (groups=%v)", groups)
	}
	t.Logf("OK: user=%s groups=%v", user, groups)

	// 2) 서명 변조 → 거부 (fail-closed). 서명 segment 중간 문자를 바꾼다.
	// (마지막 문자는 base64url 패딩 비트라 디코딩 시 무시될 수 있어 중간을 변조)
	parts := strings.Split(tok, ".")
	sig := []byte(parts[2])
	mid := len(sig) / 2
	if sig[mid] == 'A' {
		sig[mid] = 'B'
	} else {
		sig[mid] = 'A'
	}
	bad := parts[0] + "." + parts[1] + "." + string(sig)
	if _, _, err := v.verify(bad); err == nil {
		t.Fatal("서명 변조 토큰이 통과됨 (fail-closed 위반)")
	} else {
		t.Logf("OK: 변조 토큰 거부됨: %v", err)
	}
}
