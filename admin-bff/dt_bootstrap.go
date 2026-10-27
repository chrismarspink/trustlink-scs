package main

// Dependency-Track 서비스 API 키 자동 확보(무수정 공식 DT 를 compose 만으로 연동하기 위함).
//   우선순위: DT_API_KEY env → 키 파일(DT_KEY_FILE, 볼륨) → DT_ADMIN_PASSWORD 로 부트스트랩 후 파일 저장.
//   부트스트랩 = admin 초기 비밀번호 변경 → 로그인 → 팀(trustlink-bff) → 권한 → 키 발급.
//   DT 는 첫 기동(DB 마이그레이션)에 수 분 걸리므로 백그라운드에서 재시도한다. 그동안 dtEnabled()=false.

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const dtTeamName = "trustlink-bff"

var dtPermissions = []string{"BOM_UPLOAD", "PROJECT_CREATION_UPLOAD", "VIEW_PORTFOLIO",
	"VIEW_VULNERABILITY", "VULNERABILITY_ANALYSIS", "PORTFOLIO_MANAGEMENT"}

func (s *Server) dtAPIKey() string {
	if v, ok := s.dtKey.Load().(string); ok {
		return v
	}
	return ""
}

// initDTKey: 서버 기동 시 1회 호출.
func (s *Server) initDTKey() {
	if s.cfg.DTApiKey != "" {
		s.dtKey.Store(s.cfg.DTApiKey)
		return
	}
	if b, err := os.ReadFile(s.cfg.DTKeyFile); err == nil && strings.TrimSpace(string(b)) != "" {
		s.dtKey.Store(strings.TrimSpace(string(b)))
		return
	}
	if s.cfg.DTBaseURL == "" || s.cfg.DTAdminPassword == "" {
		return
	}
	go func() {
		for wait := 10 * time.Second; ; {
			key, err := s.dtBootstrap()
			if err == nil {
				if err := writeSecretFile(s.cfg.DTKeyFile, key); err != nil {
					log.Printf("DT 키 파일 저장 실패(메모리로만 사용): %v", err)
				}
				s.dtKey.Store(key)
				log.Printf("DT API 키 확보(팀 %s)", dtTeamName)
				return
			}
			log.Printf("DT 부트스트랩 대기: %v (%s 후 재시도)", err, wait)
			time.Sleep(wait)
			if wait < time.Minute {
				wait *= 2
			}
		}
	}()
}

func writeSecretFile(path, v string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(v+"\n"), 0o600)
}

func (s *Server) dtBootstrap() (string, error) {
	base := s.cfg.DTBaseURL
	if resp, err := s.http.Get(base + "/api/version"); err != nil {
		return "", err
	} else {
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return "", fmt.Errorf("DT 미기동(version %d)", resp.StatusCode)
		}
	}
	pw := s.cfg.DTAdminPassword
	// 최초 1회: admin/admin → 설정값 (이미 바뀌었으면 실패해도 무시)
	if resp, err := s.http.PostForm(base+"/api/v1/user/forceChangePassword", url.Values{
		"username": {"admin"}, "password": {"admin"}, "newPassword": {pw}, "confirmPassword": {pw}}); err == nil {
		resp.Body.Close()
	}
	resp, err := s.http.PostForm(base+"/api/v1/user/login", url.Values{"username": {"admin"}, "password": {pw}})
	if err != nil {
		return "", err
	}
	jwt, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(string(jwt), "eyJ") {
		return "", fmt.Errorf("DT admin 로그인 실패(%d) — DT_ADMIN_PASSWORD 확인", resp.StatusCode)
	}
	auth := "Bearer " + string(jwt)
	call := func(method, p, body string) (int, []byte, error) {
		req, _ := http.NewRequest(method, base+p, strings.NewReader(body))
		req.Header.Set("Authorization", auth)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		r, err := s.http.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return r.StatusCode, b, nil
	}

	uuid := ""
	if _, b, err := call("GET", "/api/v1/team", ""); err == nil {
		var teams []struct{ UUID, Name string }
		_ = json.Unmarshal(b, &teams)
		for _, t := range teams {
			if t.Name == dtTeamName {
				uuid = t.UUID
			}
		}
	}
	if uuid == "" {
		code, b, err := call("PUT", "/api/v1/team", `{"name":"`+dtTeamName+`"}`)
		if err != nil {
			return "", err
		}
		var t struct{ UUID string }
		if json.Unmarshal(b, &t); t.UUID == "" {
			return "", fmt.Errorf("DT 팀 생성 실패(%d)", code)
		}
		uuid = t.UUID
	}
	for _, p := range dtPermissions { // 이미 부여돼 있으면 304 — 무시
		if _, _, err := call("POST", "/api/v1/permission/"+p+"/team/"+uuid, ""); err != nil {
			return "", err
		}
	}
	// 키는 발급 응답에서만 원문이 보인다(이후 목록은 마스킹) → 항상 새로 발급해 파일로 보관.
	code, b, err := call("PUT", "/api/v1/team/"+uuid+"/key", "")
	if err != nil {
		return "", err
	}
	var k struct{ Key string }
	if json.Unmarshal(b, &k); k.Key == "" {
		return "", fmt.Errorf("DT API 키 발급 실패(%d)", code)
	}
	return k.Key, nil
}
