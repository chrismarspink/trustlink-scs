package main

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// HTML + 첨부 메일이 표준 MIME 으로 다시 읽히는지(한글 파일 이름 포함).
func TestBuildMessageRich(t *testing.T) {
	raw := buildMessageRich("tl@x.com", []string{"a@b.c"}, "[TrustLink] 현황", mailContent{
		Text: "평문", HTML: "<b>본문</b>",
		Attachments: []mailAttachment{{Name: "TrustLink_규제보고서_영업용_KO_2026-11-19_v2.pdf", Type: "application/pdf", Data: []byte("%PDF-1.7 x")}},
	}, time.Unix(0, 0), "BND")
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	mt, ps, _ := mime.ParseMediaType(m.Header.Get("Content-Type"))
	if mt != "multipart/mixed" {
		t.Fatalf("mixed: %s", mt)
	}
	mr := multipart.NewReader(m.Body, ps["boundary"])
	p1, _ := mr.NextPart()
	mt1, ps1, _ := mime.ParseMediaType(p1.Header.Get("Content-Type"))
	if mt1 != "multipart/alternative" {
		t.Fatalf("alt: %s", mt1)
	}
	ar := multipart.NewReader(p1, ps1["boundary"])
	var types []string
	for {
		p, err := ar.NextPart()
		if err != nil {
			break
		}
		types = append(types, strings.Split(p.Header.Get("Content-Type"), ";")[0])
	}
	if strings.Join(types, ",") != "text/plain,text/html" {
		t.Fatalf("alt parts: %v", types)
	}
	p2, _ := mr.NextPart()
	if p2.FileName() != "TrustLink_규제보고서_영업용_KO_2026-11-19_v2.pdf" {
		t.Fatalf("첨부 파일 이름: %q", p2.FileName())
	}
	b, _ := io.ReadAll(p2) // multipart 가 base64 를 자동으로 풀지 않으므로 직접 확인
	if !strings.Contains(string(b), "JVBERi0xLjcgeA==") {
		t.Fatalf("첨부 본문: %s", b)
	}
}

func fakeDash() {
	d := &Dashboard{Todo: []dashTodo{{Kind: "vuln", Tone: "crit", Text: "긴급 취약점 판단 필요", Count: 2}}}
	d.Security.Pending = map[string]int{"critical": 2, "high": 3}
	d.Security.Products = []dashProductVuln{{Repo: "products/innopouch", Tag: "10.0", Critical: 2, High: 3, Total: 9, Pending: 5}}
	d.Security.Recent = []dashRecent{{Time: "2026-11-18T01:00:00Z", Repo: "products/innopouch", Tag: "10.0", Title: "CVE-2026-0001 <script>"}}
	d.Quality.Versions, d.Quality.WithSBOM, d.Quality.WithVEX = 10, 8, 5
	dashCache.Lock()
	dashCache.data, dashCache.at = d, time.Now()
	dashCache.Unlock()
}

func writeReport(t *testing.T, rep regReport) {
	_ = os.MkdirAll(filepath.Join(regDir(), "reports"), 0o750)
	if err := writeJSONFile(filepath.Join(regDir(), "reports", rep.ID+".json"), rep); err != nil {
		t.Fatal(err)
	}
}

func TestComposeMailSections(t *testing.T) {
	t.Setenv("REG_DIR", t.TempDir())
	fakeDash()
	s := &Server{cfg: Config{RedirectURI: "https://tl.example/admin/callback"}}
	in := mailComposeIn{To: "a@b.c", Sections: []string{"vulns", "summary", "bogus", "regs", "todo"}, Note: "안녕하세요\n공유드립니다"}
	if err := in.normalize(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(in.Sections, ",") != "summary,vulns,todo,regs" {
		t.Fatalf("항목 정리: %v", in.Sections)
	}
	reps := []mailReport{{ID: "rr-20261119-010101", DocNo: "TL-RR-2026-1119-SAL-KO v2", AudienceKo: "영업", Lang: "ko", Edition: 2, FileName: "TrustLink_규제보고서_영업용_KO_2026-11-19_v2"}}
	b := s.composeMail(in, "admin1", reps, time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC))
	for _, want := range []string{"분석 요약", "SBOM 첨부율", "80%", "긴급 2", "products/innopouch", "규제 일정", "D-", "할 일", "긴급 취약점 판단 필요",
		"TrustLink_규제보고서_영업용_KO_2026-11-19_v2.pdf", "https://tl.example/admin/reports", "안녕하세요<br>공유드립니다"} {
		if !strings.Contains(b.HTML, want) {
			t.Errorf("HTML 에 %q 없음", want)
		}
	}
	if strings.Contains(b.HTML, "<script>") || !strings.Contains(b.HTML, "&lt;script&gt;") {
		t.Fatal("외부 문자열은 escape")
	}
	if !strings.Contains(b.Text, "판단 대기: 긴급 2 높음 3") || !strings.HasPrefix(b.Subject, "[TrustLink] 공급망 보안 현황") {
		t.Fatalf("평문·제목: %s / %s", b.Subject, b.Text)
	}
	bad := mailComposeIn{Recipients: []string{"a@b.c"}, Reports: []string{"../etc/passwd"}}
	if bad.normalize() == nil {
		t.Fatal("잘못된 보고서 ID 거부")
	}
	if (&mailComposeIn{}).normalize() == nil {
		t.Fatal("받는 사람 필수")
	}
}

// PDF: Gotenberg 에 BFF 내부 주소·임시 세션 쿠키·준비 신호를 넘기고, 끝나면 세션을 지운다. 만든 PDF 는 저장해 재사용.
func TestRegReportPDF(t *testing.T) {
	t.Setenv("REG_DIR", t.TempDir())
	s := &Server{store: newStore(filepath.Join(t.TempDir(), "sessions.json"))}
	var form map[string]string
	var sidOK bool
	calls := 0
	gb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/forms/chromium/convert/url" {
			t.Errorf("경로 %s", r.URL.Path)
		}
		_ = r.ParseMultipartForm(1 << 20)
		form = map[string]string{}
		for k, v := range r.MultipartForm.Value {
			form[k] = v[0]
		}
		var cs []map[string]any
		_ = json.Unmarshal([]byte(form["cookies"]), &cs)
		if len(cs) == 1 {
			sess, ok := s.store.get(cs[0]["value"].(string))
			sidOK = ok && contains(sess.Groups, "admins") && time.Until(sess.Expiry) < 5*time.Minute
		}
		w.Write([]byte("%PDF-1.7 fake"))
	}))
	defer gb.Close()
	t.Setenv("GOTENBERG_URL", "")
	if _, _, err := s.regReportPDF("rr-20261119-010101", "admin1"); err == nil {
		t.Fatal("보고서 없으면 오류")
	}
	writeReport(t, regReport{ID: "rr-20261119-010101", State: "done", FileName: "F"})
	if _, _, err := s.regReportPDF("rr-20261119-010101", "admin1"); err == nil || !strings.Contains(err.Error(), "미설정") {
		t.Fatalf("미설정: %v", err)
	}
	t.Setenv("GOTENBERG_URL", gb.URL)
	t.Setenv("PDF_BASE_URL", "http://trustlink-admin:8443")
	b, _, err := s.regReportPDF("rr-20261119-010101", "admin1")
	if err != nil || string(b) != "%PDF-1.7 fake" {
		t.Fatalf("PDF: %v %q", err, b)
	}
	if form["url"] != "http://trustlink-admin:8443/admin/regs/print/rr-20261119-010101" || form["waitForExpression"] != "window.__tlReady === true" || form["printBackground"] != "true" {
		t.Fatalf("변환 요청: %v", form)
	}
	if !sidOK || !strings.Contains(form["extraHttpHeaders"], cookieName+"=") || !strings.Contains(form["cookies"], `"domain":"trustlink-admin"`) {
		t.Fatalf("임시 세션 쿠키: %v %v", sidOK, form)
	}
	var cs []map[string]any
	_ = json.Unmarshal([]byte(form["cookies"]), &cs)
	if _, ok := s.store.get(cs[0]["value"].(string)); ok {
		t.Fatal("변환 후 임시 세션 삭제")
	}
	if _, _, err := s.regReportPDF("rr-20261119-010101", "admin1"); err != nil || calls != 1 {
		t.Fatalf("저장본 재사용: %v calls=%d", err, calls)
	}
	writeReport(t, regReport{ID: "rr-20261119-020202", State: "running"})
	if _, _, err := s.regReportPDF("rr-20261119-020202", "admin1"); err == nil {
		t.Fatal("AI 작성 중이면 거부")
	}
}

func TestMailSuggestRuleAndAI(t *testing.T) {
	t.Setenv("REG_DIR", t.TempDir())
	t.Setenv("AI_CONFIG", filepath.Join(t.TempDir(), "ai.json"))
	fakeDash()
	users := []mailUser{
		{Username: "kim", Email: "kim@x.com", Groups: []string{"admins"}, Role: "admin"},
		{Username: "dev1", Email: "dev1@x.com", Groups: []string{"developers"}, Role: "dev"},
		{Username: "sales1", Email: "s@x.com", Groups: []string{"sales"}, Role: "sales"},
		{Username: "acme", Email: "a@acme.com", Groups: []string{"acme"}, Role: "customer"},
		{Username: "noemail", Groups: []string{"developers"}, Role: "dev"},
	}
	if mailRole([]string{"users", "acme"}) != "customer" || mailRole([]string{"users"}) != "user" || mailRole([]string{"영업팀"}) != "sales" {
		t.Fatal("역할 판정")
	}
	reps := []mailReport{{ID: "rr-1", Audience: "sales", Lang: "en"}, {ID: "rr-2", Audience: "sales", Lang: "ko"}, {ID: "rr-3", Audience: "dev", Lang: "ko"}}
	now := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	sg := ruleSuggest(users, reps, dashCache.data, []mailRegDate{{Days: 20}}, "", now)
	var names []string
	for _, r := range sg.Recipients {
		names = append(names, r.Username)
	}
	if strings.Join(names, ",") != "kim,dev1,sales1" {
		t.Fatalf("고객사·이메일 없는 사람 제외: %v", names)
	}
	if !inList("vulns", sg.Sections) || !inList("regs", sg.Sections) || strings.Join(sg.Reports, ",") != "rr-3,rr-2" {
		t.Fatalf("규칙 추천: %+v", sg)
	}

	// AI: 번호(U1…)와 그룹만 보내고, 없는 ID 는 버린다
	var got map[string]any
	llm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		content := `{"recipients":[{"id":"U2","reason":"개발 대응"},{"id":"U9","reason":"x"}],"sections":["vulns","todo"],"reports":["R3","R99"],"reasons":["판단 대기 5건 [S1]"],"subject":"[TrustLink] 취약점 판단 요청","note":"확인 부탁드립니다.","citations":["S1"]}`
		b, _ := json.Marshal(map[string]any{"model": "m", "choices": []any{map[string]any{"message": map[string]any{"content": content}, "finish_reason": "stop"}}})
		w.Write(b)
	}))
	defer llm.Close()
	c, err := mergeAIConf(aiConfig{}, aiConfigIn{Mode: "local", URL: llm.URL})
	if err != nil {
		t.Fatal(err)
	}
	_ = saveAIConf(c)
	s := &Server{sor: newSoR(filepath.Join(t.TempDir(), "sor.jsonl"))}
	ai := s.aiSuggest(sg, users, reps, dashCache.data, nil, "취약점 판단 독려")
	if ai.By != "ai" || len(ai.Recipients) != 1 || ai.Recipients[0].Email != "dev1@x.com" || strings.Join(ai.Reports, ",") != "rr-3" || ai.Subject != "취약점 판단 요청" {
		t.Fatalf("AI 추천: %+v", ai)
	}
	bs, _ := json.Marshal(got)
	for _, leak := range []string{"@x.com", "kim", "dev1", "sales1", "acme"} {
		if strings.Contains(string(bs), leak) {
			t.Fatalf("LLM 요청에 %q 노출", leak)
		}
	}
}
