package main

// pdf.go: 보고서 인쇄 화면 → PDF (Gotenberg, 크로미움). 메일 첨부·정기 발행에 쓴다.
// 인쇄 화면은 관리자 세션이 있어야 API 를 읽을 수 있으므로, 변환하는 동안만 쓰는 3분짜리 세션을 만들어
// 쿠키로 넘기고 끝나면 지운다. Gotenberg 는 내부 네트워크에만 있고(포트 비공개) BFF 주소만 열 수 있다.
// 인쇄 화면은 데이터와 AI 요약이 다 채워지면 window.__tlReady = true 로 알린다.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func gotenbergURL() string { return strings.TrimRight(env("GOTENBERG_URL", ""), "/") }

// pdfBaseURL: Gotenberg 가 여는 BFF 내부 주소(예: http://trustlink-admin:8443).
func pdfBaseURL() string { return strings.TrimRight(env("PDF_BASE_URL", ""), "/") }

func pdfEnabled() bool { return gotenbergURL() != "" && pdfBaseURL() != "" }

var pdfMu sync.Mutex // 크로미움 변환은 무거우니 한 번에 하나

// regReportPDF: 규제 보고서 PDF. 만든 적 있으면 저장본을 쓴다(보고서는 발행 후 바뀌지 않음).
func (s *Server) regReportPDF(id, actor string) ([]byte, *regReport, error) {
	if !regReportIDRe.MatchString(id) {
		return nil, nil, fmt.Errorf("잘못된 보고서 ID")
	}
	var rep regReport
	jp := filepath.Join(regDir(), "reports", id+".json")
	if err := readJSONFile(jp, &rep); err != nil {
		return nil, nil, fmt.Errorf("보고서 없음: %s", id)
	}
	if rep.State == "running" {
		return nil, &rep, fmt.Errorf("AI 요약 작성 중인 보고서입니다(%s)", rep.DocNo)
	}
	pp := filepath.Join(regDir(), "reports", id+".pdf")
	if b, err := os.ReadFile(pp); err == nil && len(b) > 0 {
		return b, &rep, nil
	}
	b, err := s.renderPDF("/admin/regs/print/"+id, actor)
	if err != nil {
		return nil, &rep, err
	}
	_ = os.WriteFile(pp, b, 0o640)
	return b, &rep, nil
}

// renderPDF: BFF 화면 경로를 Gotenberg 로 PDF 변환.
func (s *Server) renderPDF(path, actor string) ([]byte, error) {
	if !pdfEnabled() {
		return nil, fmt.Errorf("PDF 변환 서버 미설정(GOTENBERG_URL·PDF_BASE_URL)")
	}
	base, err := url.Parse(pdfBaseURL())
	if err != nil || base.Hostname() == "" {
		return nil, fmt.Errorf("PDF_BASE_URL 이 올바르지 않습니다")
	}
	pdfMu.Lock()
	defer pdfMu.Unlock()
	sid := s.store.put(Session{Username: actor, Groups: []string{"admins"}, Expiry: time.Now().Add(3 * time.Minute)})
	defer s.store.del(sid)

	cookies, _ := json.Marshal([]map[string]any{{"name": cookieName, "value": sid, "domain": base.Hostname(), "path": "/", "httpOnly": true}})
	// 점 없는 내부 호스트 이름은 쿠키 저장이 안 될 수 있어 헤더로도 넘긴다(변환 대상은 BFF 하나뿐)
	hdrs, _ := json.Marshal(map[string]string{"Cookie": cookieName + "=" + sid})
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range map[string]string{
		"url":               pdfBaseURL() + path,
		"cookies":           string(cookies),
		"extraHttpHeaders":  string(hdrs),
		"waitForExpression": "window.__tlReady === true",
		"preferCssPageSize": "true", // 인쇄 화면의 @page(A4, 여백) 를 따른다
		"printBackground":   "true",
		"paperWidth":        "8.27",
		"paperHeight":       "11.7",
		"marginTop":         "0", "marginBottom": "0", "marginLeft": "0", "marginRight": "0",
		"failOnHttpStatusCodes": "[499,599]",
	} {
		_ = mw.WriteField(k, v)
	}
	mw.Close()
	req, _ := http.NewRequest("POST", gotenbergURL()+"/forms/chromium/convert/url", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := (&http.Client{Timeout: 120 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("PDF 변환 서버 연결 실패: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 50<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("PDF 변환 실패(%d): %s", resp.StatusCode, strings.TrimSpace(string(b[:min(len(b), 300)])))
	}
	if !bytes.HasPrefix(b, []byte("%PDF")) {
		return nil, fmt.Errorf("PDF 변환 결과가 PDF 가 아닙니다")
	}
	return b, nil
}

// GET /api/regs-report/{id}/pdf — 서버에서 만든 PDF 내려받기(파일 이름은 보고서 fileName).
func (s *Server) apiRegReportPDF(w http.ResponseWriter, r *http.Request) {
	b, rep, err := s.regReportPDF(r.PathValue("id"), w.Header().Get("X-User"))
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+url.PathEscape(rep.FileName+".pdf"))
	w.Write(b)
}
