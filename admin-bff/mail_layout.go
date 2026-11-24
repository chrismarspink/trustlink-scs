package main

// mail_layout.go: TrustLink 가 자동으로 보내는 메일의 공통 틀.
//   - 맨 위: 운영 회사 로고(서버 데이터의 mail-logo.*, 메일 안에 넣어 보냄) + 제품 이름(TrustLink)
//   - 띠: 메일의 목적(결정 요청·알림·작업 요청…)과 보낸 모듈, 제목, 대상 제품·버전
//   - 본문: 핵심 한 문단 → 항목 표 → AI 분석(“AI 생성” 표시) → 버튼 → 다음 순서
//   - 바닥: 보낸 모듈·참조 번호·보낸 시각·받는 이유
// 평문(text/plain)도 같은 내용으로 함께 만든다(HTML 을 못 보는 메일 프로그램용).

import (
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type mailFact struct {
	K, V  string
	Chips []string // 값 앞에 붙는 표시(CRITICAL, KEV …)
}

type mailAI struct {
	Label string // 예: "AI 분석 — 조사 필요"
	Text  string
	Model string
	Rule  bool // 판정은 규칙으로 냈다(Model 이 있으면 권고문 요약만 AI)
}

type mailCard struct {
	Module  string // 보낸 모듈(자동 대응, 취약점 감시 …)
	Purpose string // 메일의 목적(결정 요청, 알림 …)
	Tone    string // decide / alert / info
	Title   string
	Product string // 제품 이름
	Version string
	Lead    string
	Facts   []mailFact
	AI      *mailAI
	Body    string // 여러 줄 평문(목록·AI 가 쓴 초안 등)
	BodyAI  string // Body 를 AI 가 썼으면 모델 이름("AI" 만 써도 됨)
	Action  string
	URL     string
	Alt     string
	AltURL  string
	Steps   []string // 다음 순서
	Reason  string   // 이 메일을 받는 이유
	Ref     string   // 참조 번호(실행 ID 등)
	plain   string   // 화면 알림용 짧은 평문(메일에는 쓰지 않음)
}

const mailLogoCID = "tl-org-logo"

var mailLogoTypes = map[string]string{"image/png": ".png", "image/jpeg": ".jpg", "image/gif": ".gif"} // 메일 프로그램이 두루 보여 주는 형식만

func mailLogoDir() string { return filepath.Dir(aiConfigPath()) }

// mailLogo: 서버 데이터에 올려 둔 회사 로고(없으면 nil).
func mailLogo() *mailAttachment {
	for typ, ext := range mailLogoTypes {
		if b, err := os.ReadFile(filepath.Join(mailLogoDir(), "mail-logo"+ext)); err == nil && len(b) > 0 {
			return &mailAttachment{Name: "logo" + ext, Type: typ, Data: b, CID: mailLogoCID}
		}
	}
	return nil
}

func mailOrgName() string { return strings.TrimSpace(env("MAIL_ORG_NAME", "")) }

func chipStyle(t string) (fg, bg string) {
	switch strings.ToUpper(t) {
	case "CRITICAL", "KEV":
		return "#b91c1c", "#fee2e2"
	case "HIGH":
		return "#c2410c", "#ffedd5"
	case "MEDIUM":
		return "#a16207", "#fef9c3"
	}
	return "#334155", "#e2e8f0"
}

func mailPill(text, fg, bg string) string {
	return fmt.Sprintf(`<span style="display:inline-block;padding:2px 9px;border-radius:10px;font-size:11px;font-weight:700;color:%s;background:%s;white-space:nowrap">%s</span>`, fg, bg, html.EscapeString(text))
}

// renderMail: 틀에 맞춘 평문 + HTML(+ 메일 안에 넣는 로고).
func (s *Server) renderMail(c mailCard) mailContent {
	e := html.EscapeString
	br := func(t string) string { return strings.ReplaceAll(e(t), "\n", "<br>") }
	const (
		cText  = "#0f172a"
		cSub   = "#334155"
		cMuted = "#64748b"
		cLine  = "#e2e8f0"
	)
	band, bandFg, pillFg, pillBg := "#0f766e", "#ffffff", "#0f766e", "#ffffff"
	switch c.Tone {
	case "decide":
		band, pillFg = "#92400e", "#92400e"
	case "alert":
		band, pillFg = "#b91c1c", "#b91c1c"
	}
	org, logo := mailOrgName(), mailLogo()
	now := time.Now().In(kst).Format("2006-01-02 15:04 KST")
	prod := strings.TrimSpace(c.Product + " " + c.Version)

	var tx, hb strings.Builder
	// ---------- 평문 ----------
	fmt.Fprintf(&tx, "[%s] %s\n", c.Purpose, c.Title)
	if prod != "" {
		fmt.Fprintf(&tx, "제품: %s\n", prod)
	}
	if c.Lead != "" {
		tx.WriteString("\n" + c.Lead + "\n")
	}
	if len(c.Facts) > 0 {
		tx.WriteString("\n")
		for _, f := range c.Facts {
			v := f.V
			if len(f.Chips) > 0 {
				v = strings.TrimSpace("[" + strings.Join(f.Chips, "·") + "] " + v)
			}
			fmt.Fprintf(&tx, "- %s: %s\n", f.K, v)
		}
	}
	if c.AI != nil {
		how := "AI 생성" + map[bool]string{true: " · " + c.AI.Model, false: ""}[c.AI.Model != ""]
		if c.AI.Rule {
			how = "규칙 판정" + map[bool]string{true: " · 권고문 요약은 AI 생성(" + c.AI.Model + ")", false: ""}[c.AI.Model != ""]
		}
		fmt.Fprintf(&tx, "\n■ %s (%s — 사람의 확인이 필요합니다)\n%s\n", c.AI.Label, how, c.AI.Text)
	}
	if c.Body != "" {
		if c.BodyAI != "" {
			tx.WriteString("\n(아래 내용은 AI 가 쓴 초안을 담당자가 확인해 보낸 것입니다)\n")
		}
		tx.WriteString("\n" + c.Body + "\n")
	}
	if c.URL != "" {
		fmt.Fprintf(&tx, "\n▶ %s: %s\n", c.Action, c.URL)
	}
	if c.AltURL != "" {
		fmt.Fprintf(&tx, "▶ %s: %s\n", c.Alt, c.AltURL)
	}
	if len(c.Steps) > 0 {
		tx.WriteString("\n다음 순서\n")
		for i, st := range c.Steps {
			fmt.Fprintf(&tx, "%d. %s\n", i+1, st)
		}
	}
	fmt.Fprintf(&tx, "\n--\n보낸 곳: TrustLink · %s", c.Module)
	if c.Ref != "" {
		fmt.Fprintf(&tx, " · 참조 %s", c.Ref)
	}
	fmt.Fprintf(&tx, " · %s\n", now)
	if c.Reason != "" {
		tx.WriteString("받는 이유: " + c.Reason + "\n")
	}
	tx.WriteString("TrustLink 가 자동으로 보낸 메일입니다.\n")

	// ---------- HTML ----------
	hb.WriteString(`<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"></head>` +
		`<body style="margin:0;padding:0;background:#f1f5f9;font-family:'Apple SD Gothic Neo','Malgun Gothic',Pretendard,Arial,sans-serif">` +
		`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f1f5f9"><tr><td align="center" style="padding:24px 12px">` +
		`<table role="presentation" width="640" cellpadding="0" cellspacing="0" style="max-width:640px;width:100%;background:#ffffff;border:1px solid ` + cLine + `;border-radius:10px;overflow:hidden">`)
	// 맨 위: 회사 로고 | 제품 이름
	left := ""
	switch {
	case logo != nil:
		left = fmt.Sprintf(`<img src="cid:%s" height="30" alt="%s" style="display:block;height:30px;width:auto;border:0">`, mailLogoCID, e(firstNonEmpty(org, "회사 로고")))
	case org != "":
		left = fmt.Sprintf(`<span style="font-size:15px;font-weight:800;letter-spacing:1px;color:%s">%s</span>`, cText, e(org))
	}
	fmt.Fprintf(&hb, `<tr><td style="padding:14px 28px;border-bottom:1px solid %s"><table role="presentation" width="100%%" cellpadding="0" cellspacing="0"><tr>`+
		`<td align="left" valign="middle">%s</td>`+
		`<td align="right" valign="middle" style="line-height:1.3"><span style="font-size:15px;font-weight:800;color:#0f766e">TrustLink</span><br><span style="font-size:11px;color:%s">소프트웨어 공급망 보안</span></td>`+
		`</tr></table></td></tr>`, cLine, left, cMuted)
	// 띠: 목적 · 모듈 · 제목 · 제품
	fmt.Fprintf(&hb, `<tr><td style="background:%s;padding:20px 28px;color:%s">%s <span style="display:inline-block;padding:2px 9px;border-radius:10px;font-size:11px;font-weight:600;color:#ffffff;border:1px solid rgba(255,255,255,.55);white-space:nowrap">%s</span>`+
		`<div style="font-size:20px;font-weight:700;line-height:1.35;margin-top:10px">%s</div>`, band, bandFg, mailPill(c.Purpose, pillFg, pillBg), e(c.Module), e(c.Title))
	if prod != "" {
		fmt.Fprintf(&hb, `<div style="font-size:13px;margin-top:6px;opacity:.92">제품 <b>%s</b></div>`, e(prod))
	}
	hb.WriteString(`</td></tr>`)
	if c.Lead != "" {
		fmt.Fprintf(&hb, `<tr><td style="padding:22px 28px 6px;font-size:14px;line-height:1.75;color:%s">%s</td></tr>`, cText, br(c.Lead))
	}
	if len(c.Facts) > 0 {
		hb.WriteString(`<tr><td style="padding:12px 28px 4px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;font-size:13px;border-top:1px solid ` + cLine + `">`)
		for _, f := range c.Facts {
			chips := ""
			for _, ch := range f.Chips {
				fg, bg := chipStyle(ch)
				chips += mailPill(ch, fg, bg) + " "
			}
			fmt.Fprintf(&hb, `<tr><td width="112" valign="top" style="padding:9px 10px;background:#f8fafc;color:%s;font-weight:600;border-bottom:1px solid %s">%s</td>`+
				`<td valign="top" style="padding:9px 12px;color:%s;line-height:1.6;border-bottom:1px solid %s">%s%s</td></tr>`, cMuted, cLine, e(f.K), cText, cLine, chips, br(f.V))
		}
		hb.WriteString(`</table></td></tr>`)
	}
	aiBadge := func(model string) string {
		t := "AI 생성"
		if model != "" && model != "AI" {
			t += " · " + model
		}
		return mailPill("✦ "+t, "#6d28d9", "#ede9fe")
	}
	if c.AI != nil {
		badge, note := aiBadge(c.AI.Model), "AI 가 작성한 분석입니다."
		if c.AI.Rule {
			badge, note = mailPill("규칙 판정", "#334155", "#e2e8f0"), "미러 데이터(OSV·KEV·익스플로잇)에 규칙을 적용한 판정입니다."
			if c.AI.Model != "" {
				badge += " " + mailPill("✦ 권고문 요약 AI 생성 · "+c.AI.Model, "#6d28d9", "#ede9fe")
				note = "판정은 규칙으로, 권고문 요약은 AI 가 작성했습니다."
			}
		}
		fmt.Fprintf(&hb, `<tr><td style="padding:16px 28px 4px"><div style="border:1px solid #ddd6fe;background:#faf5ff;border-radius:8px;padding:14px 16px">`+
			`<div style="font-size:13px;font-weight:700;color:%s">%s &nbsp;%s</div>`+
			`<div style="font-size:13px;line-height:1.75;color:%s;margin-top:8px">%s</div>`+
			`<div style="font-size:11px;color:%s;margin-top:8px">%s 결정 전에 사람의 확인이 필요합니다.</div></div></td></tr>`,
			cText, e(c.AI.Label), badge, cSub, br(c.AI.Text), cMuted, note)
	}
	if c.Body != "" {
		head := ""
		if c.BodyAI != "" {
			head = fmt.Sprintf(`<div style="margin-bottom:8px">%s <span style="font-size:11px;color:%s">AI 가 쓴 초안을 담당자가 확인해 보냈습니다.</span></div>`, aiBadge(c.BodyAI), cMuted)
		}
		fmt.Fprintf(&hb, `<tr><td style="padding:16px 28px 4px">%s<div style="font-size:13px;line-height:1.8;color:%s">%s</div></td></tr>`, head, cSub, br(c.Body))
	}
	if c.URL != "" {
		fmt.Fprintf(&hb, `<tr><td style="padding:20px 28px 6px"><a href="%s" style="display:inline-block;background:#0f766e;color:#ffffff;text-decoration:none;font-size:14px;font-weight:700;padding:11px 22px;border-radius:8px">%s →</a>`, e(c.URL), e(c.Action))
		if c.AltURL != "" {
			fmt.Fprintf(&hb, ` &nbsp; <a href="%s" style="font-size:13px;color:#0f766e">%s</a>`, e(c.AltURL), e(c.Alt))
		}
		hb.WriteString(`</td></tr>`)
	}
	if len(c.Steps) > 0 {
		hb.WriteString(`<tr><td style="padding:14px 28px 4px"><div style="background:#f8fafc;border:1px solid ` + cLine + `;border-radius:8px;padding:12px 16px"><div style="font-size:12px;font-weight:700;color:` + cMuted + `">다음 순서</div><ol style="margin:6px 0 0;padding-left:18px;font-size:13px;line-height:1.8;color:` + cSub + `">`)
		for _, st := range c.Steps {
			hb.WriteString("<li>" + e(st) + "</li>")
		}
		hb.WriteString(`</ol></div></td></tr>`)
	}
	// 바닥
	meta := "보낸 모듈 <b>TrustLink · " + e(c.Module) + "</b>"
	if c.Ref != "" {
		meta += " &nbsp;|&nbsp; 참조 " + e(c.Ref)
	}
	meta += " &nbsp;|&nbsp; " + now
	fmt.Fprintf(&hb, `<tr><td style="padding:22px 28px 0"><div style="border-top:1px solid %s"></div></td></tr><tr><td style="padding:14px 28px 22px;font-size:11px;line-height:1.8;color:%s">%s`, cLine, cMuted, meta)
	if c.Reason != "" {
		hb.WriteString("<br>받는 이유: " + e(c.Reason))
	}
	hb.WriteString("<br>TrustLink 가 자동으로 보낸 메일입니다.")
	if base := s.publicBase(); base != "" {
		fmt.Fprintf(&hb, ` <a href="%s" style="color:%s">%s</a>`, e(base), cMuted, e(strings.TrimPrefix(base, "https://")))
	}
	if org != "" {
		hb.WriteString(" · " + e(org))
	}
	hb.WriteString(`</td></tr></table></td></tr></table></body></html>`)

	mc := mailContent{Text: tx.String(), HTML: hb.String()}
	if logo != nil {
		mc.Inline = []mailAttachment{*logo}
	}
	return mc
}

// PUT /api/mail/logo (본문 = 이미지 그대로) — 메일 맨 위에 넣는 회사 로고. 서버 데이터에만 둔다.
func (s *Server) apiMailLogoPut(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(io.LimitReader(r.Body, 200<<10+1))
	if err != nil || len(b) == 0 || len(b) > 200<<10 {
		writeJSON(w, 400, map[string]string{"error": "로고는 200KB 이하 이미지여야 합니다(메일마다 함께 나갑니다)"})
		return
	}
	ext := mailLogoTypes[http.DetectContentType(b)]
	if ext == "" {
		writeJSON(w, 400, map[string]string{"error": "PNG·JPEG·GIF 만 받습니다"})
		return
	}
	for _, e := range mailLogoTypes {
		_ = os.Remove(filepath.Join(mailLogoDir(), "mail-logo"+e))
	}
	if err := os.WriteFile(filepath.Join(mailLogoDir(), "mail-logo"+ext), b, 0o640); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_ = s.sor.append(SoREvent{Actor: w.Header().Get("X-User"), Action: "mail-logo", Detail: map[string]any{"bytes": len(b)}})
	writeJSON(w, 200, map[string]any{"ok": true, "bytes": len(b)})
}

// DELETE /api/mail/logo
func (s *Server) apiMailLogoDelete(w http.ResponseWriter, r *http.Request) {
	for _, e := range mailLogoTypes {
		_ = os.Remove(filepath.Join(mailLogoDir(), "mail-logo"+e))
	}
	_ = s.sor.append(SoREvent{Actor: w.Header().Get("X-User"), Action: "mail-logo", Status: "deleted"})
	writeJSON(w, 200, map[string]any{"ok": true})
}

// GET /api/mail/layout-preview — 메일 틀 미리보기(HTML, 예시 내용).
func (s *Server) apiMailLayoutPreview(w http.ResponseWriter, r *http.Request) {
	mc := s.renderMail(mailCard{Module: "자동 대응", Purpose: "결정 요청", Tone: "decide", Title: "고객 보안 권고 발송 승인 요청",
		Product: "example-app", Version: "1.0", Lead: "example-app 1.0 에서 치명적 취약점이 확인되었습니다. 수정 버전이 있어 고객 보안 권고 초안을 준비했습니다. 발송 여부를 결정해 주십시오.",
		Facts:  []mailFact{{K: "취약점", V: "CVE-0000-00000", Chips: []string{"CRITICAL", "KEV"}}, {K: "구성요소", V: "nginx 1.28.0"}, {K: "수정 버전", V: "example-app 1.1"}},
		AI:     &mailAI{Label: "AI 분석 — 조사 필요", Text: "예시 분석 문장입니다.", Model: "local"},
		Action: "승인·반려 화면 열기", URL: s.publicBase() + "/admin/auto-response", Alt: "승인 대기함", AltURL: s.publicBase() + "/admin/inbox",
		Steps:  []string{"승인하면 발송함에서 잠시 기다렸다가 나갑니다(그동안 취소 가능).", "반려하면 보내지 않고 사유를 기록합니다."},
		Reason: "관리자(admins) 그룹", Ref: "예시"})
	h := mc.HTML
	if len(mc.Inline) > 0 { // 미리보기에서는 로고를 data: 로
		h = strings.Replace(h, "cid:"+mailLogoCID, "data:"+mc.Inline[0].Type+";base64,"+b64(mc.Inline[0].Data), 1)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; img-src data:; style-src 'unsafe-inline'")
	_, _ = io.WriteString(w, h)
}
