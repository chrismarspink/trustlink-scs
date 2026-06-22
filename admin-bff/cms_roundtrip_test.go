package main

// CMS 서명+암호화 라운드트립(opt-in): openssl 이 있는 환경에서만. CMS_RT_TEST=1 로 활성.
// 자체 루트 CA → 서명자/수신자 인증서를 생성해 sign→encrypt→decrypt→verify 전 경로를 검증한다.
//
//	docker run --rm -v "$PWD":/src -w /src -e CMS_RT_TEST=1 golang:1.22 \
//	  sh -c 'apk add openssl 2>/dev/null || (apt-get update && apt-get install -y openssl); go test -run TestCMSRoundTrip -v .'

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCMSRoundTrip(t *testing.T) {
	if os.Getenv("CMS_RT_TEST") == "" {
		t.Skip("CMS_RT_TEST 미설정 — 라운드트립 테스트 skip")
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl 미설치 — skip")
	}
	dir := t.TempDir()
	run := func(name string, args ...string) {
		t.Helper()
		if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
	}
	p := func(f string) string { return filepath.Join(dir, f) }

	// 루트 CA
	run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", p("root.key"),
		"-out", p("root.crt"), "-subj", "/CN=test-root", "-days", "1")
	// 서명자 인증서(루트 서명)
	run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", p("signer.key"),
		"-out", p("signer.csr"), "-subj", "/CN=signer")
	run("openssl", "x509", "-req", "-in", p("signer.csr"), "-CA", p("root.crt"), "-CAkey", p("root.key"),
		"-CAcreateserial", "-out", p("signer.crt"), "-days", "1")
	// 수신자 인증서(자체서명이면 충분 — 암호화는 공개키만 사용)
	run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", p("recip.key"),
		"-out", p("recip.crt"), "-subj", "/CN=recipient", "-days", "1")

	read := func(f string) []byte { b, _ := os.ReadFile(p(f)); return b }
	payload := []byte("artifact-bundle-bytes: SBOM+VEX+binary")

	// 1) 서명
	signed, err := cmsSign(payload, read("signer.crt"), read("signer.key"))
	if err != nil {
		t.Fatalf("cmsSign: %v", err)
	}
	// 2) 암호화 (FIPS 승인 기본: AES-256-GCM + RSA-OAEP)
	enc, err := cmsEncrypt(signed, [][]byte{read("recip.crt")}, "-aes-256-gcm", "oaep")
	if err != nil {
		t.Fatalf("cmsEncrypt(gcm/oaep): %v", err)
	}
	if len(enc) == 0 || string(enc) == string(signed) {
		t.Fatal("암호문이 평문과 동일/빈값")
	}
	// 3) 복호
	dec, err := cmsDecrypt(enc, read("recip.crt"), read("recip.key"))
	if err != nil {
		t.Fatalf("cmsDecrypt: %v", err)
	}
	// 4) 검증 + 원문 추출
	ok, content, detail := cmsVerify(dec, p("root.crt"))
	if !ok {
		t.Fatalf("cmsVerify 실패: %s", detail)
	}
	if string(content) != string(payload) {
		t.Fatalf("복호+검증 후 원문 불일치: %q", content)
	}
	t.Logf("OK: sign→encrypt(gcm/oaep)→decrypt→verify 원문 일치 (%d→enc %d bytes)", len(payload), len(enc))

	// 5) CBC + OAEP 도 동작(상호운용 폴백) 확인
	enc2, err := cmsEncrypt(signed, [][]byte{read("recip.crt")}, "-aes-256-cbc", "oaep")
	if err != nil {
		t.Fatalf("cmsEncrypt(cbc/oaep): %v", err)
	}
	if _, err := cmsDecrypt(enc2, read("recip.crt"), read("recip.key")); err != nil {
		t.Fatalf("cmsDecrypt(cbc): %v", err)
	}
	t.Log("OK: AES-256-CBC + OAEP 폴백도 라운드트립 성공")
}
