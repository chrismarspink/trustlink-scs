package main

// mail_digest.go: 내용이 있는 메일(현황 요약 메일) — 관리자가 넣을 항목(분석 요약·취약점·할 일·규제 일정)과
// 첨부할 규제 보고서(PDF, Gotenberg)를 골라 보낸다. AI 는 받는 사람·항목·첨부·제목·인사말을 추천만 하고
// 발송은 관리자가 확인한 뒤 한다. 외부 LLM 에는 메일 주소·계정 이름을 보내지 않는다(U1 같은 번호와 그룹만).

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var mailSections = []struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Desc  string `json:"desc"`
}{
	{"summary", "분석 요약", "제품·버전 수, SBOM·VEX 첨부율, 구성요소·라이선스 현황"},
	{"vulns", "취약점", "판단 대기 취약점(심각도별), 위험 제품 상위, 최근 새 취약점"},
	{"todo", "할 일", "지금 처리할 일(긴급 먼저)"},
	{"regs", "규제 일정", "다가오는 시행·적용 일정과 남은 날(D-day)"},
}

const mailMaxReports = 4

type mailComposeIn struct {
	To         string   `json:"to"` // 이전 화면 호환(한 명)
	Recipients []string `json:"recipients"`
	Sections   []string `json:"sections"`
	Reports    []string `json:"reports"` // 첨부할 규제 보고서 ID
	Subject    string   `json:"subject"`
	Note       string   `json:"note"` // 인사말·전할 말
}

func (in *mailComposeIn) normalize() error {
	seen := map[string]bool{}
	var rc []string
	for _, a := range append([]string{in.To}, in.Recipients...) {
		a = strings.TrimSpace(a)
		if a != "" && !seen[strings.ToLower(a)] {
			seen[strings.ToLower(a)] = true
			rc = append(rc, a)
		}
	}
	if len(rc) == 0 {
		return fmt.Errorf("받는 사람을 한 명 이상 넣어 주세요")
	}
	if len(rc) > 50 {
		return fmt.Errorf("받는 사람은 50명까지")
	}
	in.Recipients = rc
	var secs []string
	for _, x := range mailSections {
		if inList(x.ID, in.Sections) {
			secs = append(secs, x.ID)
		}
	}
	in.Sections = secs
	if len(in.Reports) > mailMaxReports {
		return fmt.Errorf("첨부 보고서는 %d개까지", mailMaxReports)
	}
	for _, id := range in.Reports {
		if !regReportIDRe.MatchString(id) {
			return fmt.Errorf("잘못된 보고서 ID: %s", id)
		}
	}
	in.Subject = truncate(strings.TrimSpace(in.Subject), 120)
	in.Note = truncate(strings.TrimSpace(in.Note), 2000)
	return nil
}

// ---------- 받을 사람 목록 ----------

type mailUser struct {
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Groups   []string `json:"groups"`
	Role     string   `json:"role"` // admin / dev / sales / customer / user
}

func mailRole(groups []string) string {
	switch {
	case contains(groups, "admins"):
		return "admin"
	case contains(groups, "developers") || contains(groups, "security"):
		return "dev"
	}
	for _, g := range groups {
		if l := strings.ToLower(g); strings.Contains(l, "sales") || strings.Contains(g, "영업") {
			return "sales"
		}
	}
	for _, g := range groups {
		if g != "users" {
			return "customer" // 고객사 그룹
		}
	}
	return "user"
}

var mailRoleKo = map[string]string{"admin": "관리자", "dev": "개발·보안", "sales": "영업", "customer": "고객사", "user": "일반"}

func (s *Server) mailDirectory() ([]mailUser, error) {
	gs, err := s.listGroups()
	if err != nil {
		return nil, err
	}
	users := map[string]*mailUser{}
	for _, g := range gs {
		resp, err := s.kcAdmin("GET", "/groups/"+g.ID+"/members?max=10000", nil)
		if err != nil {
			continue
		}
		var us []kcUser
		_ = json.NewDecoder(resp.Body).Decode(&us)
		resp.Body.Close()
		for _, u := range us {
			if !u.Enabled {
				continue
			}
			if users[u.Username] == nil {
				users[u.Username] = &mailUser{Username: u.Username, Email: u.Email}
			}
			users[u.Username].Groups = append(users[u.Username].Groups, g.Name)
		}
	}
	out := []mailUser{}
	for _, u := range users {
		sort.Strings(u.Groups)
		u.Role = mailRole(u.Groups)
		out = append(out, *u)
	}
	order := map[string]int{"admin": 0, "dev": 1, "sales": 2, "user": 3, "customer": 4}
	sort.Slice(out, func(i, j int) bool {
		if order[out[i].Role] != order[out[j].Role] {
			return order[out[i].Role] < order[out[j].Role]
		}
		return out[i].Username < out[j].Username
	})
	return out, nil
}

// ---------- 첨부할 수 있는 보고서 ----------

type mailReport struct {
	ID         string `json:"id"`
	DocNo      string `json:"docNo"`
	Title      string `json:"title"`
	Audience   string `json:"audience"`
	AudienceKo string `json:"audienceKo"`
	Lang       string `json:"lang"`
	Edition    int    `json:"edition"`
	Created    string `json:"created"`
	FileName   string `json:"fileName"`
	Repo       string `json:"repo,omitempty"`
	Tag        string `json:"tag,omitempty"`
	PDF        bool   `json:"pdf"` // 서버에 만들어 둔 PDF 가 있음
}

// latestRegReports: 같은 조건(key) 묶음마다 가장 최근 판만. 작성 중(AI)인 것은 뺀다.
func latestRegReports() []mailReport {
	files, _ := filepath.Glob(filepath.Join(regDir(), "reports", "rr-*.json"))
	sort.Sort(sort.Reverse(sort.StringSlice(files)))
	seen := map[string]bool{}
	out := []mailReport{}
	for _, f := range files {
		var r regReport
		if readJSONFile(f, &r) != nil || r.State == "running" {
			continue
		}
		k := firstNonEmpty(r.Key, r.ID)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, mailReport{ID: r.ID, DocNo: r.DocNo, Title: r.Title, Audience: r.Audience, AudienceKo: r.AudienceKo,
			Lang: firstNonEmpty(r.Lang, "ko"), Edition: r.Edition, Created: r.Created, FileName: r.FileName, Repo: r.Repo, Tag: r.Tag,
			PDF: fileExists(strings.TrimSuffix(f, ".json") + ".pdf")})
		if len(out) >= 30 {
			break
		}
	}
	return out
}

// ---------- 규제 일정 ----------

type mailRegDate struct {
	Date, Label, Reg, Region, Binding string
	Days                              int
}

func upcomingRegDates(now time.Time, within int) []mailRegDate {
	regMu.Lock()
	c, err := loadCatalog()
	regMu.Unlock()
	if err != nil {
		return nil
	}
	today := now.Format("2006-01-02")
	var out []mailRegDate
	for _, g := range c.Regulations {
		for _, d := range g.Dates {
			if len(d.Date) < 10 || d.Date[:10] < today {
				continue
			}
			t, err := time.Parse("2006-01-02", d.Date[:10])
			if err != nil {
				continue
			}
			days := int(t.Sub(now.Truncate(24*time.Hour)).Hours() / 24)
			if days > within {
				continue
			}
			out = append(out, mailRegDate{Date: d.Date[:10], Label: d.Label, Reg: firstNonEmpty(g.NameKo, g.Name),
				Region: firstNonEmpty(regRegionKo[g.Region], g.Region), Binding: g.Binding, Days: days})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Date < out[j].Date })
	return out
}

// ---------- 본문 ----------

type mailBody struct {
	Subject, Text, HTML string
}

func (s *Server) publicBase() string { return strings.TrimSuffix(s.cfg.RedirectURI, "/admin/callback") }

func pctS(a, b int) string {
	if b == 0 {
		return "—"
	}
	return itoa(a*100/b) + "%"
}

func dday(n int) string {
	if n == 0 {
		return "D-day"
	}
	return "D-" + itoa(n)
}

// composeMail: 고른 항목으로 평문·HTML 본문을 만든다. reps 는 첨부할 보고서 목록(본문에 안내).
func (s *Server) composeMail(in mailComposeIn, actor string, reps []mailReport, now time.Time) mailBody {
	date := now.Format("2006-01-02")
	subj := firstNonEmpty(in.Subject, "공급망 보안 현황 — "+date)
	if !strings.HasPrefix(subj, "[TrustLink]") {
		subj = "[TrustLink] " + subj
	}
	var d *Dashboard
	if inList("summary", in.Sections) || inList("vulns", in.Sections) || inList("todo", in.Sections) {
		d = s.dashboardCached(false)
	}
	var tx, hb strings.Builder
	e := html.EscapeString
	const (
		cText  = "#0f172a"
		cMuted = "#64748b"
		cLine  = "#e2e8f0"
		cBrand = "#0f766e"
	)
	sec := func(title string) {
		fmt.Fprintf(&tx, "\n■ %s\n", title)
		fmt.Fprintf(&hb, `<tr><td style="padding:22px 28px 6px"><div style="font-size:15px;font-weight:700;color:%s;border-left:4px solid %s;padding-left:8px">%s</div></td></tr>`, cText, cBrand, e(title))
	}
	open := func() { hb.WriteString(`<tr><td style="padding:4px 28px 4px">`) }
	closeTd := func() { hb.WriteString(`</td></tr>`) }
	table := func(head []string, rows [][]string) {
		hb.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;font-size:13px">`)
		hb.WriteString(`<tr>`)
		for _, h := range head {
			fmt.Fprintf(&hb, `<th align="left" style="padding:6px 8px;background:#f8fafc;color:%s;font-weight:600;border-bottom:1px solid %s">%s</th>`, cMuted, cLine, e(h))
		}
		hb.WriteString(`</tr>`)
		for _, r := range rows {
			hb.WriteString(`<tr>`)
			for _, c := range r {
				fmt.Fprintf(&hb, `<td style="padding:6px 8px;border-bottom:1px solid %s;color:%s">%s</td>`, cLine, cText, c) // c 는 이미 escape 됨
			}
			hb.WriteString(`</tr>`)
		}
		hb.WriteString(`</table>`)
	}
	pill := func(text, color, bg string) string {
		return fmt.Sprintf(`<span style="display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600;color:%s;background:%s">%s</span>`, color, bg, e(text))
	}

	// 머리
	fmt.Fprintf(&tx, "%s\n%s · 보낸 사람 %s\n", strings.TrimPrefix(subj, "[TrustLink] "), date, actor)
	fmt.Fprintf(&hb, `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"></head>`+
		`<body style="margin:0;padding:0;background:#f1f5f9;font-family:'Apple SD Gothic Neo','Malgun Gothic',Pretendard,Arial,sans-serif">`+
		`<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="background:#f1f5f9"><tr><td align="center" style="padding:24px 12px">`+
		`<table role="presentation" width="640" cellpadding="0" cellspacing="0" style="max-width:640px;width:100%%;background:#ffffff;border-radius:10px;overflow:hidden">`+
		`<tr><td style="background:%s;padding:22px 28px;color:#ffffff"><div style="font-size:12px;letter-spacing:2px;opacity:.85">TRUSTLINK</div>`+
		`<div style="font-size:20px;font-weight:700;margin-top:4px">%s</div><div style="font-size:12px;opacity:.85;margin-top:6px">%s · 보낸 사람 %s</div></td></tr>`,
		cBrand, e(strings.TrimPrefix(subj, "[TrustLink] ")), date, e(actor))
	if in.Note != "" {
		tx.WriteString("\n" + in.Note + "\n")
		fmt.Fprintf(&hb, `<tr><td style="padding:20px 28px 4px;font-size:14px;line-height:1.7;color:%s">%s</td></tr>`, cText, strings.ReplaceAll(e(in.Note), "\n", "<br>"))
	}

	if inList("summary", in.Sections) && d != nil {
		sec("분석 요약")
		q := d.Quality
		pend := 0
		for _, v := range d.Security.Pending {
			pend += v
		}
		mttr := "—"
		if d.Security.MTTRSamples > 0 {
			mttr = ftoa(d.Security.MTTRHours, 1) + "시간"
		}
		kpis := [][2]string{{"관리 중인 버전", itoa(q.Versions)}, {"SBOM 첨부율", pctS(q.WithSBOM, q.Versions)}, {"VEX 첨부율", pctS(q.WithVEX, q.Versions)}, {"판단 대기 취약점", itoa(pend)}}
		open()
		hb.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="6"><tr>`)
		for _, k := range kpis {
			fmt.Fprintf(&hb, `<td width="25%%" style="background:#f8fafc;border:1px solid %s;border-radius:8px;padding:10px 12px"><div style="font-size:11px;color:%s">%s</div><div style="font-size:20px;font-weight:700;color:%s;margin-top:2px">%s</div></td>`, cLine, cMuted, e(k[0]), cText, e(k[1]))
			fmt.Fprintf(&tx, "- %s: %s\n", k[0], k[1])
		}
		hb.WriteString(`</tr></table>`)
		lines := []string{
			fmt.Sprintf("구성요소 %d개 — 버전 없음 %d · purl 없음 %d · 라이선스 없음 %d · 카피레프트 %d", q.Components, q.NoVersion, q.NoPurl, q.NoLicense, q.Copyleft),
			fmt.Sprintf("SBOM 출처 — 공급자 제출 %d · TrustLink 생성 %d", q.SBOMSupplier, q.SBOMSyft),
			fmt.Sprintf("취약점 분석 %d / %d건 완료 · 통보 → VEX 발행 평균 %s", d.Security.Analyzed, d.Security.Total, mttr),
		}
		hb.WriteString(`<ul style="margin:8px 0 0;padding-left:18px;font-size:13px;line-height:1.8;color:#334155">`)
		for _, l := range lines {
			fmt.Fprintf(&hb, "<li>%s</li>", e(l))
			tx.WriteString("- " + l + "\n")
		}
		hb.WriteString(`</ul>`)
		closeTd()
	}

	if inList("vulns", in.Sections) && d != nil {
		sec("취약점")
		open()
		sevs := []struct{ k, ko, c, bg string }{{"critical", "긴급", "#b91c1c", "#fef2f2"}, {"high", "높음", "#c2410c", "#fff7ed"}, {"medium", "중간", "#a16207", "#fefce8"}, {"low", "낮음", "#475569", "#f1f5f9"}}
		hb.WriteString(`<div style="font-size:13px;color:#334155;margin-bottom:8px">판단 대기 `)
		tx.WriteString("판단 대기:")
		for _, x := range sevs {
			n := d.Security.Pending[x.k]
			hb.WriteString(pill(x.ko+" "+itoa(n), x.c, x.bg) + " ")
			fmt.Fprintf(&tx, " %s %d", x.ko, n)
		}
		hb.WriteString(`</div>`)
		tx.WriteString("\n")
		if len(d.Security.Products) > 0 {
			var rows [][]string
			for i, p := range d.Security.Products {
				if i >= 5 {
					break
				}
				link := fmt.Sprintf(`<a href="%s" style="color:%s;text-decoration:none">%s:%s</a>`, e(s.artifactURL(p.Repo, p.Tag)), cBrand, e(p.Repo), e(p.Tag))
				rows = append(rows, []string{link, itoa(p.Critical), itoa(p.High), itoa(p.Total), itoa(p.Pending)})
				fmt.Fprintf(&tx, "- %s:%s 긴급 %d · 높음 %d · 전체 %d · 대기 %d\n", p.Repo, p.Tag, p.Critical, p.High, p.Total, p.Pending)
			}
			table([]string{"위험 제품", "긴급", "높음", "전체", "판단 대기"}, rows)
		}
		if len(d.Security.Recent) > 0 {
			hb.WriteString(`<div style="font-size:12px;color:#64748b;margin:12px 0 4px">최근 새 취약점</div><ul style="margin:0;padding-left:18px;font-size:13px;line-height:1.7;color:#334155">`)
			tx.WriteString("최근 새 취약점:\n")
			for i, r := range d.Security.Recent {
				if i >= 5 {
					break
				}
				fmt.Fprintf(&hb, "<li>%s — %s:%s <span style=\"color:%s\">(%s)</span></li>", e(r.Title), e(r.Repo), e(r.Tag), cMuted, e(shortTime(r.Time)))
				fmt.Fprintf(&tx, "- %s — %s:%s (%s)\n", r.Title, r.Repo, r.Tag, shortTime(r.Time))
			}
			hb.WriteString(`</ul>`)
		}
		if len(d.Security.Products) == 0 && len(d.Security.Recent) == 0 {
			hb.WriteString(`<div style="font-size:13px;color:#047857">새로 판단할 취약점이 없습니다.</div>`)
			tx.WriteString("새로 판단할 취약점이 없습니다.\n")
		}
		closeTd()
	}

	if inList("todo", in.Sections) && d != nil {
		sec("할 일")
		open()
		if len(d.Todo) == 0 {
			hb.WriteString(`<div style="font-size:13px;color:#047857">밀린 일이 없습니다.</div>`)
			tx.WriteString("밀린 일이 없습니다.\n")
		}
		for i, t := range d.Todo {
			if i >= 8 {
				break
			}
			c, bg, tag := "#a16207", "#fefce8", "확인"
			if t.Tone == "crit" {
				c, bg, tag = "#b91c1c", "#fef2f2", "긴급"
			}
			cnt := ""
			if t.Count > 0 {
				cnt = " (" + itoa(t.Count) + ")"
			}
			fmt.Fprintf(&hb, `<div style="font-size:13px;color:#334155;padding:5px 0;border-bottom:1px solid %s">%s %s%s</div>`, cLine, pill(tag, c, bg), e(t.Text), e(cnt))
			fmt.Fprintf(&tx, "- [%s] %s%s\n", tag, t.Text, cnt)
		}
		closeTd()
	}

	if inList("regs", in.Sections) {
		sec("규제 일정")
		open()
		ds := upcomingRegDates(now, 365)
		if len(ds) > 8 {
			ds = ds[:8]
		}
		if len(ds) == 0 {
			hb.WriteString(`<div style="font-size:13px;color:#64748b">1년 안에 예정된 시행·적용 일정이 없습니다.</div>`)
			tx.WriteString("1년 안에 예정된 일정이 없습니다.\n")
		} else {
			var rows [][]string
			for _, x := range ds {
				dc, dbg := "#475569", "#f1f5f9"
				if x.Days <= 90 {
					dc, dbg = "#b91c1c", "#fef2f2"
				} else if x.Days <= 180 {
					dc, dbg = "#a16207", "#fefce8"
				}
				rows = append(rows, []string{e(x.Date), pill(dday(x.Days), dc, dbg), e(x.Reg) + ` <span style="color:#64748b">(` + e(x.Region) + `)</span>`, e(x.Label), e(x.Binding)})
				fmt.Fprintf(&tx, "- %s %s %s(%s) — %s [%s]\n", x.Date, dday(x.Days), x.Reg, x.Region, x.Label, x.Binding)
			}
			table([]string{"날짜", "남은 날", "규제", "일정", "구속력"}, rows)
		}
		closeTd()
	}

	if len(reps) > 0 {
		sec("첨부 보고서")
		open()
		hb.WriteString(`<ul style="margin:0;padding-left:18px;font-size:13px;line-height:1.8;color:#334155">`)
		for _, r := range reps {
			lang := map[string]string{"ko": "한글", "en": "영문"}[r.Lang]
			fmt.Fprintf(&hb, `<li><b>%s.pdf</b><br><span style="color:%s">%s · %s용 · %s · 제%d판</span></li>`, e(r.FileName), cMuted, e(r.DocNo), e(r.AudienceKo), lang, r.Edition)
			fmt.Fprintf(&tx, "- %s.pdf (%s, %s용, %s, 제%d판)\n", r.FileName, r.DocNo, r.AudienceKo, lang, r.Edition)
		}
		hb.WriteString(`</ul>`)
		closeTd()
	}

	base := s.publicBase()
	fmt.Fprintf(&hb, `<tr><td style="padding:22px 28px"><a href="%s/admin" style="display:inline-block;background:%s;color:#ffffff;text-decoration:none;padding:9px 16px;border-radius:6px;font-size:13px;font-weight:600">TrustLink 관리 화면 열기</a> `+
		`<a href="%s/admin/reports" style="display:inline-block;color:%s;text-decoration:none;padding:9px 12px;font-size:13px">보고서 보기 →</a></td></tr>`, e(base), cBrand, e(base), cBrand)
	fmt.Fprintf(&hb, `<tr><td style="padding:14px 28px 22px;border-top:1px solid %s;font-size:11px;line-height:1.6;color:%s">이 메일은 TrustLink 가 %s 기준 집계로 만들었습니다. 수치는 보낸 시점 값이며 최신 값은 관리 화면에서 확인하세요.<br>규제 정보는 참고 자료이며 법률 자문이 아닙니다.</td></tr>`,
		cLine, cMuted, now.Format("2006-01-02 15:04 MST"))
	hb.WriteString(`</table></td></tr></table></body></html>`)
	fmt.Fprintf(&tx, "\n관리 화면: %s/admin\n보고서: %s/admin/reports\n\n이 메일은 TrustLink 가 %s 기준 집계로 만들었습니다.\n", base, base, now.Format("2006-01-02 15:04 MST"))
	return mailBody{Subject: subj, Text: tx.String(), HTML: hb.String()}
}

func shortTime(t string) string {
	if tt, err := time.Parse(time.RFC3339, t); err == nil {
		return tt.Local().Format("01-02 15:04")
	}
	return t
}

func findReports(ids []string) ([]mailReport, error) {
	all := map[string]mailReport{}
	for _, id := range ids {
		var r regReport
		if err := readJSONFile(filepath.Join(regDir(), "reports", id+".json"), &r); err != nil {
			return nil, fmt.Errorf("보고서 없음: %s", id)
		}
		all[id] = mailReport{ID: r.ID, DocNo: r.DocNo, Title: r.Title, Audience: r.Audience, AudienceKo: r.AudienceKo,
			Lang: firstNonEmpty(r.Lang, "ko"), Edition: r.Edition, Created: r.Created, FileName: firstNonEmpty(r.FileName, r.ID)}
	}
	out := []mailReport{}
	for _, id := range ids {
		out = append(out, all[id])
	}
	return out, nil
}

// ---------- API ----------

// GET /api/mail/options — 넣을 수 있는 항목·첨부할 보고서·받을 사람 후보.
func (s *Server) apiMailOptions(w http.ResponseWriter, r *http.Request) {
	users, err := s.mailDirectory()
	uerr := ""
	if err != nil {
		uerr = err.Error()
		users = []mailUser{}
	}
	allow := []string{}
	for a := range s.mail.Allow {
		allow = append(allow, a)
	}
	sort.Strings(allow)
	writeJSON(w, 200, map[string]any{"sections": mailSections, "reports": latestRegReports(), "users": users, "usersError": uerr,
		"pdf": pdfEnabled(), "ai": aiEnabledFor("report"), "allowlist": allow, "configured": s.mail.Configured(), "roles": mailRoleKo})
}

// POST /api/mail/preview — 본문 미리보기(발송하지 않음).
func (s *Server) apiMailPreview(w http.ResponseWriter, r *http.Request) {
	var in mailComposeIn
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "잘못된 요청"})
		return
	}
	in.To = "preview@local"
	if err := in.normalize(); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	reps, err := findReports(in.Reports)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	b := s.composeMail(in, w.Header().Get("X-User"), reps, time.Now())
	writeJSON(w, 200, map[string]string{"subject": b.Subject, "html": b.HTML, "text": b.Text})
}

// POST /api/mail/test {to | recipients, sections, reports, subject, note} — 관리자 발송(허용 목록 적용).
// 항목을 고르지 않으면 예전처럼 짧은 시험 메일.
func (s *Server) apiMailTest(w http.ResponseWriter, r *http.Request) {
	var in mailComposeIn
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "잘못된 요청"})
		return
	}
	if err := in.normalize(); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	actor := w.Header().Get("X-User")
	now := time.Now()
	reps, err := findReports(in.Reports)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	var content mailContent
	subject := "[TrustLink] 메일 발송 시험"
	if len(in.Sections) == 0 && len(reps) == 0 && in.Note == "" {
		content.Text = fmt.Sprintf("TrustLink 메일 발송 시험입니다.\n\n보낸 사람(관리자): %s\n보낸 시각: %s\n서버: %s\n\n이 메일을 받았다면 TrustLink 통보 메일 설정이 정상입니다.",
			actor, now.Format("2006-01-02 15:04:05 MST"), r.Host)
	} else {
		b := s.composeMail(in, actor, reps, now)
		subject, content.Text, content.HTML = b.Subject, b.Text, b.HTML
		for _, rp := range reps {
			pdf, _, err := s.regReportPDF(rp.ID, actor)
			if err != nil {
				writeJSON(w, 502, map[string]string{"error": "첨부 PDF 를 만들지 못했습니다(" + rp.DocNo + "): " + err.Error()})
				return
			}
			content.Attachments = append(content.Attachments, mailAttachment{Name: rp.FileName + ".pdf", Type: "application/pdf", Data: pdf})
		}
	}
	sent, dropped, err := s.mail.SendRich(in.Recipients, subject, content)
	status := "sent"
	if err != nil {
		status = "failed"
	} else if len(sent) == 0 {
		status = "blocked"
	}
	_ = s.sor.append(SoREvent{Actor: actor, Action: "mail-test", Status: status,
		Detail: map[string]any{"to": in.Recipients, "sent": sent, "dropped": dropped, "sections": in.Sections, "reports": in.Reports, "subject": subject, "error": errString(err)}})
	switch {
	case err != nil:
		writeJSON(w, 502, map[string]string{"error": err.Error()})
	case len(sent) == 0:
		writeJSON(w, 403, map[string]string{"error": "허용 목록(MAIL_ALLOWLIST)에 없는 주소라 보내지 않았습니다"})
	default:
		writeJSON(w, 200, map[string]any{"status": "sent", "to": sent, "dropped": dropped, "attachments": len(content.Attachments)})
	}
}
