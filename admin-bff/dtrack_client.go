package main

// Dependency-Track API Server (헤드리스) REST 클라이언트 — stdlib only, X-Api-Key 인증.
// 참고: 엔드포인트/필드는 DT 버전에 따라 다를 수 있어 dt-bootstrap/dt-verify 로 검증한다.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
)

func (s *Server) dtEnabled() bool { return s.cfg.DTBaseURL != "" && s.cfg.DTApiKey != "" }

func (s *Server) dtReq(method, path string, body []byte) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, s.cfg.DTBaseURL+path, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", s.cfg.DTApiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return s.http.Do(req)
}

// 프로젝트 조회: (제품,버전) → uuid. 없으면 "".
func (s *Server) dtLookupProject(name, version string) (string, error) {
	q := url.Values{}
	q.Set("name", name)
	q.Set("version", version)
	resp, err := s.dtReq("GET", "/api/v1/project/lookup?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return "", nil
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("lookup status %d", resp.StatusCode)
	}
	var p struct {
		UUID string `json:"uuid"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&p)
	return p.UUID, nil
}

// SBOM 업로드(없으면 autoCreate) → 처리 토큰.
func (s *Server) dtUploadBOM(name, version, bomB64 string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"projectName": name, "projectVersion": version, "autoCreate": true, "bom": bomB64,
	})
	resp, err := s.dtReq("PUT", "/api/v1/bom", body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("bom upload status %d: %s", resp.StatusCode, string(b))
	}
	var t struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&t)
	return t.Token, nil
}

// 분석 처리중 여부 (false = 완료).
func (s *Server) dtBomProcessing(token string) (bool, error) {
	resp, err := s.dtReq("GET", "/api/v1/bom/token/"+url.PathEscape(token), nil)
	if err != nil {
		return true, err
	}
	defer resp.Body.Close()
	var p struct {
		Processing bool `json:"processing"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&p)
	return p.Processing, nil
}

// findings 원본 JSON (UI 렌더용 패스스루).
func (s *Server) dtFindings(projectUUID string) ([]byte, error) {
	resp, err := s.dtReq("GET", "/api/v1/finding/project/"+url.PathEscape(projectUUID), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("findings status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// 프로젝트 현재 취약점 메트릭. ok=false 면 데이터 없음/미가용(메트릭 미산출 포함).
func (s *Server) dtProjectMetrics(uuid string) (total, critical, high int, ok bool) {
	resp, err := s.dtReq("GET", "/api/v1/metrics/project/"+url.PathEscape(uuid)+"/current", nil)
	if err != nil {
		return 0, 0, 0, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, 0, 0, false
	}
	var m struct {
		Vulnerabilities int `json:"vulnerabilities"`
		Critical        int `json:"critical"`
		High            int `json:"high"`
	}
	if json.NewDecoder(resp.Body).Decode(&m) != nil {
		return 0, 0, 0, false
	}
	return m.Vulnerabilities, m.Critical, m.High, true
}

// repo:tag → DT 프로젝트(name=basename(repo), version=tag) 취약점 수.
// ok=false 면 DT 미구성/프로젝트 없음/메트릭 미산출 → 호출자가 폴백.
// 바이너리·SBOM 아티팩트는 zot Trivy(이미지 레이어)로 스캔 불가하므로 DT(SBOM 분석)가 1차 소스.
func (s *Server) dtVulnCount(repo, tag string) (total int, ok bool) {
	if !s.dtEnabled() {
		return 0, false
	}
	uuid, err := s.dtLookupProject(path.Base(repo), tag)
	if err != nil || uuid == "" {
		return 0, false
	}
	total, _, _, ok = s.dtProjectMetrics(uuid)
	return total, ok
}

// audit 결정 기록.
func (s *Server) dtPutAnalysis(payload map[string]any) (int, []byte, error) {
	body, _ := json.Marshal(payload)
	resp, err := s.dtReq("PUT", "/api/v1/analysis", body)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, nil
}

// CycloneDX VEX 동적 생성/추출. (DT 는 Accept: application/vnd.cyclonedx+json 요구 — 기본 application/json 은 406)
func (s *Server) dtExportVEX(projectUUID string) ([]byte, int, error) {
	req, err := http.NewRequest("GET", s.cfg.DTBaseURL+"/api/v1/vex/cyclonedx/project/"+url.PathEscape(projectUUID), nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("X-Api-Key", s.cfg.DTApiKey)
	req.Header.Set("Accept", "application/vnd.cyclonedx+json")
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return b, resp.StatusCode, nil
}
