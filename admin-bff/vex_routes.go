package main

// TrustLink 관리 페이지가 호출하는 VEX/취약점 API 핸들러.
// 흐름: SBOM 업로드 → 분석 폴링 → findings 조회 → audit 기록(매핑) → CycloneDX VEX 추출.
// 모두 admins 게이트(s.guard) 하에서 동작. DT 미설정 시 503.

import (
	"encoding/json"
	"net/http"
)

func (s *Server) requireDT(w http.ResponseWriter) bool {
	if !s.dtEnabled() {
		writeJSON(w, 503, map[string]string{"error": "Dependency-Track 미설정 (DT_BASE_URL/DT_API_KEY)"})
		return false
	}
	return true
}

func (s *Server) apiVexEnabled(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"enabled": s.dtEnabled(), "base": s.cfg.DTBaseURL})
}

// POST /api/vex/upload {project, version, bomBase64}
func (s *Server) apiVexUpload(w http.ResponseWriter, r *http.Request) {
	if !s.requireDT(w) {
		return
	}
	var in struct{ Project, Version, BomBase64 string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Project == "" || in.BomBase64 == "" {
		writeJSON(w, 400, map[string]string{"error": "project, bomBase64 필수"})
		return
	}
	if in.Version == "" {
		in.Version = "latest"
	}
	token, err := s.dtUploadBOM(in.Project, in.Version, in.BomBase64)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"token": token})
}

// GET /api/vex/status?token=
func (s *Server) apiVexStatus(w http.ResponseWriter, r *http.Request) {
	if !s.requireDT(w) {
		return
	}
	token := r.URL.Query().Get("token")
	processing, err := s.dtBomProcessing(token)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"processing": processing})
}

// GET /api/vex/findings?project=&version=&repo=&tag=
// repo/tag 가 있으면 DT 프로젝트가 없을 때 zot SBOM referrer 를 자동 적재(ingest)한다.
func (s *Server) apiVexFindings(w http.ResponseWriter, r *http.Request) {
	if !s.requireDT(w) {
		return
	}
	name := r.URL.Query().Get("project")
	version := r.URL.Query().Get("version")
	if version == "" {
		version = "latest"
	}
	repo := r.URL.Query().Get("repo")
	tag := r.URL.Query().Get("tag")
	var uuid string
	var err error
	if repo != "" {
		if tag == "" {
			tag = version
		}
		uuid, err = s.ensureDTProject(r, repo, tag, name, version) // 없으면 SBOM 적재
	} else {
		uuid, err = s.dtLookupProject(name, version)
	}
	if err != nil {
		writeJSON(w, httpStatus(err), map[string]string{"error": err.Error()})
		return
	}
	if uuid == "" {
		writeJSON(w, 404, map[string]string{"error": "프로젝트 없음 (SBOM referrer 확인)"})
		return
	}
	data, err := s.dtFindings(uuid)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Project-Uuid", uuid)
	w.Write(data) // DT findings 원본 패스스루
}

// PUT /api/vex/analysis — CycloneDX 어휘 입력을 DT enum 으로 매핑해 기록.
func (s *Server) apiVexAnalysis(w http.ResponseWriter, r *http.Request) {
	if !s.requireDT(w) {
		return
	}
	var in struct {
		Project       string `json:"project"`       // project uuid
		Component     string `json:"component"`     // component uuid
		Vulnerability string `json:"vulnerability"` // vuln uuid
		Status        string `json:"status"`        // CycloneDX status
		Justification string `json:"justification"` // CycloneDX justification
		Response      string `json:"response"`      // CycloneDX response (선택)
		Details       string `json:"details"`
		Comment       string `json:"comment"`
		Suppressed    bool   `json:"suppressed"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Project == "" || in.Component == "" || in.Vulnerability == "" {
		writeJSON(w, 400, map[string]string{"error": "project, component, vulnerability uuid 필수"})
		return
	}
	payload := map[string]any{
		"project":               in.Project,
		"component":             in.Component,
		"vulnerability":         in.Vulnerability,
		"analysisState":         mapOr(vexStatusToDT, in.Status, "IN_TRIAGE"),
		"analysisJustification": mapOr(vexJustToDT, in.Justification, "NOT_SET"),
		"analysisDetails":       in.Details,
		"comment":               in.Comment,
		"suppressed":            in.Suppressed,
	}
	if dt := mapOr(vexResponseToDT, in.Response, ""); dt != "" {
		payload["analysisResponse"] = dt
	}
	code, body, err := s.dtPutAnalysis(payload)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	if code != 200 {
		writeJSON(w, code, map[string]string{"error": "DT analysis 실패", "detail": string(body)})
		return
	}
	writeJSON(w, 200, map[string]string{"status": "recorded", "analysisState": payload["analysisState"].(string)})
}

// GET /api/vex/export?project=uuid  → CycloneDX VEX (서명·attach 전 단계)
func (s *Server) apiVexExport(w http.ResponseWriter, r *http.Request) {
	if !s.requireDT(w) {
		return
	}
	uuid := r.URL.Query().Get("project")
	if uuid == "" {
		writeJSON(w, 400, map[string]string{"error": "project uuid 필수"})
		return
	}
	data, code, err := s.dtExportVEX(uuid)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	if code != 200 {
		writeJSON(w, code, map[string]string{"error": "VEX 추출 실패"})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=vex.cdx.json")
	w.Write(data)
}
