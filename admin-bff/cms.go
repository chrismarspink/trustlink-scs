package main

// CMS (RFC 5652) 서명/검증 모듈 — OpenSSL `cms` 명령 호출.
//   서명: SignedData(opaque, DER). 입력(산출물+SBOM+VEX 묶음 매니페스트) → .p7s.
//   검증: 신뢰 앵커(루트)로 체인 검증 + 원문 추출.
// FIPS: 실행 OpenSSL 의 provider 목록에서 fips 활성 여부를 탐지·기록한다.
//   ("FIPS 모드 켜짐 ≠ FIPS 검증" — 검증 모듈 OE 는 배포 시점 사안, §12.)
// 비고: step-ca 기본 leaf 의 EKU 가 serverAuth/clientAuth 라 `cms -verify` 가 기본 smimesign
//   purpose 를 거부 → `-purpose any` 사용. (운영: codeSigning/emailProtection 템플릿으로 발급 권장.)

import (
	"context"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func opensslRun(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "openssl", args...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("openssl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// fipsStatus: openssl provider 목록에 fips 가 있으면 활성으로 간주.
func fipsStatus() (active bool, detail string) {
	out, err := opensslRun("list", "-providers")
	if err != nil {
		return false, "provider 조회 실패: " + err.Error()
	}
	if strings.Contains(strings.ToLower(string(out)), "fips") {
		return true, "OpenSSL FIPS provider 활성"
	}
	return false, "default provider (FIPS 검증 모듈 미적용 — 배포 OE 에서 fips provider 구성 필요, §12)"
}

// splitLeafChain: PEM 인증서 묶음에서 첫 블록(서명자) / 나머지(중간 체인) 분리.
func splitLeafChain(certPEM []byte) (leaf, chain []byte) {
	rest := certPEM
	first := true
	for {
		b, r := pem.Decode(rest)
		if b == nil {
			break
		}
		rest = r
		enc := pem.EncodeToMemory(b)
		if first {
			leaf = enc
			first = false
		} else {
			chain = append(chain, enc...)
		}
	}
	if leaf == nil {
		leaf = certPEM // 디코드 실패 시 원본을 서명자로
	}
	return leaf, chain
}

func writeTemp(prefix string, data []byte) (string, error) {
	f, err := os.CreateTemp("", prefix)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// cmsSign: SignedData(opaque, DER). certPEM=leaf(+중간체인), keyPEM=개인키, data=서명 대상.
// 중간 인증서는 -certfile 로 CMS 에 임베드해야 수신자가 루트만으로 체인 검증 가능.
func cmsSign(data, certPEM, keyPEM []byte) ([]byte, error) {
	leaf, chain := splitLeafChain(certPEM)
	inPath, err := writeTemp("tl-cms-in-*", data)
	if err != nil {
		return nil, err
	}
	defer os.Remove(inPath)
	signerPath, err := writeTemp("tl-cms-signer-*", leaf)
	if err != nil {
		return nil, err
	}
	defer os.Remove(signerPath)
	keyPath, err := writeTemp("tl-cms-key-*", keyPEM)
	if err != nil {
		return nil, err
	}
	defer os.Remove(keyPath)
	outPath, err := writeTemp("tl-cms-out-*", nil)
	if err != nil {
		return nil, err
	}
	defer os.Remove(outPath)

	args := []string{"cms", "-sign", "-binary", "-nodetach", "-in", inPath,
		"-signer", signerPath, "-inkey", keyPath, "-outform", "DER", "-out", outPath}
	if len(chain) > 0 {
		chainPath, err := writeTemp("tl-cms-chain-*", chain)
		if err != nil {
			return nil, err
		}
		defer os.Remove(chainPath)
		args = append(args, "-certfile", chainPath)
	}
	if _, err := opensslRun(args...); err != nil {
		return nil, err
	}
	return os.ReadFile(outPath)
}

// cmsEncrypt: CMS EnvelopedData(또는 AEAD 시 AuthEnvelopedData) 로 content 를 수신자 인증서들에게 암호화.
//   콘텐츠 암호화 = 대칭(기본 AES-256-GCM), 키 전송 = 수신자 RSA 공개키(기본 OAEP). 둘 다 FIPS 승인.
//   알고리즘은 Config(env)로 교체 가능 — 배포 OE 의 검증 모듈에 맞춤. 산출물 .p7m(DER).
//   수신자: `openssl cms -decrypt -recip cert -inkey key` 로 복호.
func cmsEncrypt(content []byte, recipientCertsPEM [][]byte, cipher, rsaPad string) ([]byte, error) {
	if len(recipientCertsPEM) == 0 {
		return nil, fmt.Errorf("수신자 인증서가 없습니다")
	}
	inPath, err := writeTemp("tl-enc-in-*", content)
	if err != nil {
		return nil, err
	}
	defer os.Remove(inPath)
	outPath, err := writeTemp("tl-enc-out-*", nil)
	if err != nil {
		return nil, err
	}
	defer os.Remove(outPath)

	if cipher == "" {
		cipher = "-aes-256-gcm"
	}
	args := []string{"cms", "-encrypt", "-binary", cipher, "-in", inPath, "-outform", "DER", "-out", outPath}
	// 수신자별 인증서 + RSA 패딩 옵션(OAEP 권장). -keyopt 는 직전 -recip 에 적용된다.
	for i, certPEM := range recipientCertsPEM {
		certPath, err := writeTemp(fmt.Sprintf("tl-enc-recip%d-*", i), certPEM)
		if err != nil {
			return nil, err
		}
		defer os.Remove(certPath)
		args = append(args, "-recip", certPath)
		if rsaPad != "" && rsaPad != "pkcs1" {
			args = append(args, "-keyopt", "rsa_padding_mode:"+rsaPad)
		}
	}
	if _, err := opensslRun(args...); err != nil {
		return nil, err
	}
	return os.ReadFile(outPath)
}

// cmsEncryptPassword: 패스워드 기반 CMS 암호화(RFC 3211 PWRI). 수신자 인증서 없이 공유 비밀번호로 보호.
//   주의: PWRI 의 KEK 알고리즘은 GCM 미지원 → 콘텐츠 암호도 AES-256-CBC 로 고정.
//   수신자: `openssl cms -decrypt -pwri_password <pw>`.
func cmsEncryptPassword(content []byte, password string) ([]byte, error) {
	if password == "" {
		return nil, fmt.Errorf("패스워드가 비어있습니다")
	}
	inPath, err := writeTemp("tl-pwenc-in-*", content)
	if err != nil {
		return nil, err
	}
	defer os.Remove(inPath)
	outPath, err := writeTemp("tl-pwenc-out-*", nil)
	if err != nil {
		return nil, err
	}
	defer os.Remove(outPath)
	if _, err := opensslRun("cms", "-encrypt", "-binary", "-aes-256-cbc", "-pwri_password", password,
		"-in", inPath, "-outform", "DER", "-out", outPath); err != nil {
		return nil, err
	}
	return os.ReadFile(outPath)
}

// cmsDecrypt: EnvelopedData 복호(라운드트립 검증·테스트용). 수신자 개인키 필요.
func cmsDecrypt(p7mDER, recipCertPEM, recipKeyPEM []byte) ([]byte, error) {
	inPath, err := writeTemp("tl-dec-in-*", p7mDER)
	if err != nil {
		return nil, err
	}
	defer os.Remove(inPath)
	certPath, err := writeTemp("tl-dec-cert-*", recipCertPEM)
	if err != nil {
		return nil, err
	}
	defer os.Remove(certPath)
	keyPath, err := writeTemp("tl-dec-key-*", recipKeyPEM)
	if err != nil {
		return nil, err
	}
	defer os.Remove(keyPath)
	outPath, err := writeTemp("tl-dec-out-*", nil)
	if err != nil {
		return nil, err
	}
	defer os.Remove(outPath)
	if _, err := opensslRun("cms", "-decrypt", "-inform", "DER", "-in", inPath,
		"-recip", certPath, "-inkey", keyPath, "-out", outPath); err != nil {
		return nil, err
	}
	return os.ReadFile(outPath)
}

// cmsVerify: 신뢰 앵커(rootPath)로 SignedData 검증 + 원문 추출. ok=false 면 detail 에 사유.
func cmsVerify(p7sDER []byte, rootPath string) (ok bool, content []byte, detail string) {
	inPath, err := writeTemp("tl-cmsv-in-*", p7sDER)
	if err != nil {
		return false, nil, err.Error()
	}
	defer os.Remove(inPath)
	outPath, err := writeTemp("tl-cmsv-out-*", nil)
	if err != nil {
		return false, nil, err.Error()
	}
	defer os.Remove(outPath)
	out, err := opensslRun("cms", "-verify", "-inform", "DER", "-in", inPath,
		"-CAfile", rootPath, "-purpose", "any", "-out", outPath)
	if err != nil {
		return false, nil, strings.TrimSpace(string(out))
	}
	content, _ = os.ReadFile(outPath)
	return true, content, "CMS Verification successful"
}
