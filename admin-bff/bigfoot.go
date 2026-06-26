package main

// bigfoot.go: 외부 CA·서명 어플라이언스(bigfoot) 위임 클라이언트.
//   BIGFOOT_URL 설정 시 발급/서명/암호화를 bigfoot HTTP API 로 위임한다(TrustLink 는 키·step-ca 미보유
//   → 모듈 독립). 미설정 시 내장 step-ca(StepCaAdapter)를 쓰는 기존 경로로 폴백한다.
//   bigfoot API: POST /api/sign(.p7s) · POST /api/encrypt(.p7m) · GET /api/ca/root(PEM).

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
)

func (s *Server) bigfootEnabled() bool { return s.cfg.BigfootURL != "" }

// signingAvailable: bigfoot 위임 또는 내장 CA 중 하나라도 가능한지.
func (s *Server) signingAvailable() bool { return s.bigfootEnabled() || s.caEnabled() }

// bigfootSign: 본문을 bigfoot /api/sign 으로 CMS 서명(.p7s) 받는다. (p7s, serial)
func (s *Server) bigfootSign(content []byte, cn string) ([]byte, string, error) {
	u := s.cfg.BigfootURL + "/api/sign?profile=codesign&cn=" + url.QueryEscape(cn)
	return s.bigfootPost(u, content)
}

// bigfootEncrypt: bigfoot /api/encrypt 로 (서명 후) 수신자 암호화(.p7m). recipientIDs=bigfoot 수신자 레지스트리 ID.
func (s *Server) bigfootEncrypt(content []byte, recipientIDs []string, cn string, sign bool) ([]byte, string, error) {
	q := url.Values{}
	q.Set("cn", cn)
	if !sign {
		q.Set("sign", "false")
	}
	for _, id := range recipientIDs {
		q.Add("recipient", id)
	}
	return s.bigfootPost(s.cfg.BigfootURL+"/api/encrypt?"+q.Encode(), content)
}

func (s *Server) bigfootPost(u string, content []byte) ([]byte, string, error) {
	req, _ := http.NewRequest("POST", u, bytes.NewReader(content))
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("bigfoot 호출 실패: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("bigfoot %d: %s", resp.StatusCode, string(body))
	}
	return body, resp.Header.Get("X-Bigfoot-Serial"), nil
}

var (
	bigfootRootMu   sync.Mutex
	bigfootRootPath string
)

// bigfootRootFile: bigfoot 의 Root PEM 을 받아 임시파일로 캐시(cmsVerify -CAfile 용).
func (s *Server) bigfootRootFile() (string, error) {
	bigfootRootMu.Lock()
	defer bigfootRootMu.Unlock()
	if bigfootRootPath != "" {
		return bigfootRootPath, nil
	}
	resp, err := s.http.Get(s.cfg.BigfootURL + "/api/ca/root")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	pem, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || len(pem) == 0 {
		return "", fmt.Errorf("bigfoot root %d", resp.StatusCode)
	}
	p, err := writeTemp("bigfoot-root-*.crt", pem)
	if err != nil {
		return "", err
	}
	bigfootRootPath = p
	return p, nil
}

// signContent: bigfoot 위임 또는 내장 step-ca 로 CMS 서명. (p7s, serial)
func (s *Server) signContent(actor, cn string, content []byte) ([]byte, string, error) {
	if s.bigfootEnabled() {
		return s.bigfootSign(content, cn)
	}
	if !s.caEnabled() {
		return nil, "", fmt.Errorf("CA 미구성")
	}
	ic, err := s.ca.IssueCert(actor, cn, nil, "24h")
	if err != nil {
		return nil, "", err
	}
	p7s, err := cmsSign(content, ic.CertPEM, ic.KeyPEM)
	return p7s, ic.Serial, err
}

// verifyCMS: bigfoot 모드면 bigfoot Root, 아니면 내장 Root 로 검증.
func (s *Server) verifyCMS(p7s []byte) (bool, string) {
	root := s.cfg.StepCaRoot
	if s.bigfootEnabled() {
		rp, err := s.bigfootRootFile()
		if err != nil {
			return false, "bigfoot root 조회 실패: " + err.Error()
		}
		root = rp
	}
	ok, _, detail := cmsVerify(p7s, root)
	return ok, detail
}
