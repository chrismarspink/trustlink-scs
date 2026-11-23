package main

// mail_templates.go: 현황 메일 템플릿 — 제목·인사말(전할 말)·넣을 항목을 미리 정해 두고 골라 쓴다.
// 기본 템플릿은 고칠 수 없고(복사해서 고침), 관리자가 만든 템플릿은 서버 데이터(mail-templates.json)에 둔다.
// 본문 안의 {날짜}·{보낸 사람}·{받는 분} 은 화면에서 고를 때 채운다.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type mailTemplate struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Subject   string   `json:"subject"`
	Note      string   `json:"note"`
	Sections  []string `json:"sections"`
	Builtin   bool     `json:"builtin,omitempty"`
	UpdatedBy string   `json:"updatedBy,omitempty"`
	UpdatedAt string   `json:"updatedAt,omitempty"`
}

var builtinMailTemplates = []mailTemplate{
	{ID: "weekly", Name: "정기 현황 보고(주간)", Builtin: true, Sections: []string{"summary", "vulns", "todo"},
		Subject: "주간 공급망 보안 현황 — {날짜}",
		Note:    "안녕하세요, {받는 분}.\n\n이번 주 공급망 보안 현황을 정리해 보내 드립니다.\n판단 대기 중인 취약점과 이번 주 처리할 일을 먼저 확인해 주시면 감사하겠습니다.\n\n{보낸 사람} 드림"},
	{ID: "exec", Name: "경영진 요약 보고", Builtin: true, Sections: []string{"summary", "regs"},
		Subject: "공급망 보안 요약 보고 — {날짜}",
		Note:    "안녕하십니까.\n\n제품 보안 현황과 다가오는 규제 일정을 요약해 보고드립니다.\n세부 내용은 첨부 보고서를 참고해 주시기 바랍니다.\n\n{보낸 사람} 올림"},
	{ID: "urgent", Name: "긴급 취약점 공유", Builtin: true, Sections: []string{"vulns", "todo"},
		Subject: "[긴급] 조치가 필요한 취약점 공유 — {날짜}",
		Note:    "{받는 분}, 급히 공유드립니다.\n\n실제 악용 중(KEV)이거나 심각도가 높은 취약점이 확인되었습니다.\n아래 목록의 제품 담당자께서는 영향 여부를 오늘 중으로 판단해 주시기 바랍니다.\n\n{보낸 사람}"},
	{ID: "regs", Name: "규제 일정 안내", Builtin: true, Sections: []string{"regs"},
		Subject: "공급망 보안 규제 일정 안내 — {날짜}",
		Note:    "안녕하세요.\n\n다가오는 공급망 보안 규제의 시행·적용 일정을 안내드립니다.\n준비가 필요한 항목은 규제 대응 검증 화면에서 확인하실 수 있습니다.\n\n{보낸 사람} 드림"},
	{ID: "en-monthly", Name: "Monthly status (English)", Builtin: true, Sections: []string{"summary", "vulns"},
		Subject: "Monthly supply-chain security status — {날짜}",
		Note:    "Dear {받는 분},\n\nPlease find this month's software supply-chain security status below.\nLet us know if you have any questions.\n\nBest regards,\n{보낸 사람}"},
}

var mailTplMu sync.Mutex

func mailTplPath() string { return filepath.Join(filepath.Dir(aiConfigPath()), "mail-templates.json") }

func loadMailTemplates() []mailTemplate {
	var custom []mailTemplate
	_ = readJSONFile(mailTplPath(), &custom)
	return append(append([]mailTemplate{}, builtinMailTemplates...), custom...)
}

// GET /api/mail/templates
func (s *Server) apiMailTemplates(w http.ResponseWriter, r *http.Request) {
	mailTplMu.Lock()
	defer mailTplMu.Unlock()
	writeJSON(w, 200, loadMailTemplates())
}

var mailTplIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)

// PUT /api/mail/templates — 관리자가 만든 템플릿 전체(기본 템플릿은 빼고 보낸다)
func (s *Server) apiMailTemplatesPut(w http.ResponseWriter, r *http.Request) {
	var in []mailTemplate
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<18)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "요청 형식 오류"})
		return
	}
	if len(in) > 50 {
		writeJSON(w, 400, map[string]string{"error": "템플릿은 50개까지"})
		return
	}
	actor := w.Header().Get("X-User")
	now := time.Now().UTC().Format(time.RFC3339)
	seen := map[string]bool{}
	for _, b := range builtinMailTemplates {
		seen[b.ID] = true
	}
	out := []mailTemplate{}
	for _, t := range in {
		if t.Builtin {
			continue
		}
		t.Name, t.Subject, t.Note = truncate(strings.TrimSpace(t.Name), 60), truncate(strings.TrimSpace(t.Subject), 120), truncate(t.Note, 2000)
		if t.Name == "" || !mailTplIDRe.MatchString(t.ID) || seen[t.ID] {
			writeJSON(w, 400, map[string]string{"error": fmt.Sprintf("템플릿 이름·ID 를 확인하세요(%q)", t.Name)})
			return
		}
		seen[t.ID] = true
		secs := []string{}
		for _, x := range mailSections {
			if inList(x.ID, t.Sections) {
				secs = append(secs, x.ID)
			}
		}
		t.Sections, t.UpdatedBy, t.UpdatedAt = secs, actor, now
		out = append(out, t)
	}
	mailTplMu.Lock()
	err := writeJSONFile(mailTplPath(), out)
	mailTplMu.Unlock()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_ = s.sor.append(SoREvent{Actor: actor, Action: "mail-templates", Detail: map[string]any{"count": len(out)}})
	writeJSON(w, 200, append(append([]mailTemplate{}, builtinMailTemplates...), out...))
}
