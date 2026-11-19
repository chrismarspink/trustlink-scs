package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func regTestServer(t *testing.T) *Server {
	t.Setenv("REG_DIR", t.TempDir())
	t.Setenv("AI_CONFIG", filepath.Join(t.TempDir(), "ai.json"))
	t.Setenv("AI_URL", "")
	return &Server{sor: newSoR(filepath.Join(t.TempDir(), "sor.jsonl"))}
}

func call(t *testing.T, h http.HandlerFunc, method, path, body string, pv map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range pv {
		req.SetPathValue(k, v)
	}
	rec := httptest.NewRecorder()
	rec.Header().Set("X-User", "admin1")
	h(rec, req)
	return rec
}

func TestRegBuiltinValid(t *testing.T) {
	b := loadBuiltin()
	if len(b.Regulations) < 20 {
		t.Fatalf("내장 규제 수: %d", len(b.Regulations))
	}
	ids := map[string]bool{}
	for _, r := range b.Regulations {
		rr := r
		if err := validReg(&rr); err != nil {
			t.Errorf("%s: %v", r.ID, err)
		}
		for _, q := range r.Requirements {
			if ids[q.ID] {
				t.Errorf("요구 ID 전체 중복: %s", q.ID)
			}
			ids[q.ID] = true
			for _, e := range q.Evidence {
				if _, ok := evCheckNames[e]; !ok {
					t.Errorf("%s: 없는 증거 ID %s", q.ID, e)
				}
			}
			for _, d := range r.Dates {
				if _, err := time.Parse("2006-01-02", d.Date); err != nil {
					t.Errorf("%s 날짜 형식: %s", r.ID, d.Date)
				}
			}
		}
	}
	for _, reg := range []string{"US", "EU", "JP", "KR"} {
		n := 0
		for _, r := range b.Regulations {
			if r.Region == reg {
				n++
			}
		}
		if n < 4 {
			t.Errorf("%s 규제가 너무 적음: %d", reg, n)
		}
	}
}

func TestRegCatalogCRUDAndBuiltinDiff(t *testing.T) {
	s := regTestServer(t)
	rec := call(t, s.apiRegs, "GET", "/api/regs", "", nil)
	var g struct {
		Catalog regCatalog
		Builtin struct{ Diff []regDiff }
	}
	json.Unmarshal(rec.Body.Bytes(), &g)
	if len(g.Catalog.Regulations) == 0 || len(g.Builtin.Diff) != 0 {
		t.Fatalf("처음엔 내장본 복사·차이 없음: %d %v", len(g.Catalog.Regulations), g.Builtin.Diff)
	}
	// 확인 → 수정하면 확인 해제·rev 증가·로컬 수정 표시
	if rec := call(t, s.apiRegVerify, "POST", "/x", `{"verified":true}`, map[string]string{"id": "eu-cra"}); rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	var cra regulation
	for _, r := range g.Catalog.Regulations {
		if r.ID == "eu-cra" {
			cra = r
		}
	}
	cra.Status = "전면 적용"
	b, _ := json.Marshal(cra)
	rec = call(t, s.apiRegPut, "PUT", "/x", string(b), map[string]string{"id": "eu-cra"})
	var pr struct{ Regulation regulation }
	json.Unmarshal(rec.Body.Bytes(), &pr)
	if rec.Code != 200 || pr.Regulation.Verified || pr.Regulation.Rev != 2 || !pr.Regulation.Edited {
		t.Fatalf("수정: %d %+v", rec.Code, pr.Regulation)
	}
	// 새 규제 추가·잘못된 ID 거부
	if rec := call(t, s.apiRegPut, "PUT", "/x", `{"region":"kr","nameKo":"테스트 규제","requirements":[{"title":"a","actions":{"dev":"x","bad":"y"}}]}`, map[string]string{"id": "kr-test"}); rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	if rec := call(t, s.apiRegPut, "PUT", "/x", `{"region":"KR","nameKo":"x"}`, map[string]string{"id": "Bad ID"}); rec.Code != 400 {
		t.Fatal("잘못된 ID 는 400")
	}
	// 내장본 변경 흉내: 작업본의 반영 rev 를 낮추고, 내장 규제 하나를 지움
	regMu.Lock()
	c, _ := loadCatalog()
	out := c.Regulations[:0]
	for _, r := range c.Regulations {
		if r.ID == "jp-jcstar" {
			continue
		}
		if r.ID == "us-ssdf" {
			r.BuiltinRev = 0
		}
		out = append(out, r)
	}
	c.Regulations = out
	saveCatalog(c)
	_, diff := builtinDiff(c)
	regMu.Unlock()
	kinds := map[string]string{}
	for _, d := range diff {
		kinds[d.ID] = d.Change
	}
	if kinds["jp-jcstar"] != "added" || kinds["us-ssdf"] != "changed" {
		t.Fatalf("차이: %v", diff)
	}
	rec = call(t, s.apiRegBuiltinApply, "POST", "/x", `{}`, nil)
	var ap struct{ Applied, Skipped []string }
	json.Unmarshal(rec.Body.Bytes(), &ap)
	if len(ap.Applied) != 2 {
		t.Fatalf("반영: %s", rec.Body.String())
	}
	// 삭제
	if rec := call(t, s.apiRegDelete, "DELETE", "/x", "", map[string]string{"id": "kr-test"}); rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
}

func TestRegReportRules(t *testing.T) {
	s := regTestServer(t)
	ev := map[string]evCheck{"sbom.present": {ID: "sbom.present", Result: "pass"}, "sbom.format": {ID: "sbom.format", Result: "fail"},
		"sign.present": {ID: "sign.present", Result: "fail"}}
	if st, _ := reqStatus(regReq{Evidence: []string{"sbom.present", "sbom.format"}}, ev, true); st != "partial" {
		t.Fatal(st)
	}
	if st, _ := reqStatus(regReq{Evidence: []string{"sign.present"}}, ev, true); st != "unmet" {
		t.Fatal(st)
	}
	if st, _ := reqStatus(regReq{Evidence: []string{}}, ev, true); st != "manual" {
		t.Fatal(st)
	}
	regMu.Lock()
	c, _ := loadCatalog()
	regMu.Unlock()
	rep := s.buildRegReport(c, "sales", []string{"EU", "KR"}, "", "", "admin1", "ko")
	if rep.Totals["regs"] == 0 || len(rep.Timeline) == 0 || !strings.Contains(rep.Title, "유럽연합·한국") {
		t.Fatalf("보고서: %+v", rep.Totals)
	}
	for _, g := range rep.Regs {
		if g.Region != "EU" && g.Region != "KR" {
			t.Fatal("지역 필터")
		}
		for _, q := range g.Reqs {
			if q.Action == "" {
				t.Fatal("영업 할 일이 없는 요구는 빠져야 함")
			}
		}
	}
	rec := call(t, s.apiRegReport, "POST", "/x", `{"audience":"dev","regions":["US"]}`, nil)
	var rr regReport
	json.Unmarshal(rec.Body.Bytes(), &rr)
	if rec.Code != 200 || rr.State != "done" || rr.AudienceKo != "개발자" {
		t.Fatalf("API 보고서: %d %s", rec.Code, rec.Body.String()[:200])
	}
	if rec := call(t, s.apiRegReportGet, "GET", "/x", "", map[string]string{"id": rr.ID}); rec.Code != 200 {
		t.Fatal("저장된 보고서 조회")
	}
}

func TestRegDiscover(t *testing.T) {
	s := regTestServer(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v1/documents.json"):
			if r.URL.Query().Get("conditions[term]") == "" {
				w.WriteHeader(400)
				return
			}
			w.Write([]byte(`{"results":[{"title":"Software Supply Chain Rule","abstract":"proposed rule","html_url":"https://fr.example/1","publication_date":"2026-11-01","type":"Proposed Rule","agencies":[{"name":"CISA"}]},
			 {"title":"Executive Order 14028 — Improving the Nation's Cybersecurity","html_url":"https://fr.example/2","publication_date":"2021-05-17","type":"Presidential Document"}]}`))
		case r.URL.Path == "/DRF/lawSearch.do":
			if r.URL.Query().Get("OC") != "myoc" {
				w.WriteHeader(403)
				return
			}
			w.Write([]byte(`{"LawSearch":{"law":[{"법령명한글":"소프트웨어 진흥법","시행일자":"20250101","법령상세링크":"/DRF/lawService.do?x=1","소관부처명":"과학기술정보통신부","법령구분명":"법률"}]}}`))
		default:
			w.Write([]byte("<html><body>v1</body></html>"))
		}
	}))
	defer srv.Close()
	frBaseURL, lawBaseURL = srv.URL, srv.URL
	defer func() { frBaseURL, lawBaseURL = "https://www.federalregister.gov", "https://www.law.go.kr" }()
	if rec := call(t, s.apiRegDiscoverCfg, "PUT", "/x", `{"keywordsUS":["sbom"],"keywordsKR":["공급망"],"lawOC":"myoc"}`, nil); rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	s.runDiscover([]string{"federal-register", "law-kr"}, "admin1")
	rec := call(t, s.apiRegDiscoverGet, "GET", "/x", "", nil)
	if strings.Contains(rec.Body.String(), "myoc") {
		t.Fatal("OC 값 노출")
	}
	var g struct {
		Candidates []regCandidate
		HasLawOC   bool
	}
	json.Unmarshal(rec.Body.Bytes(), &g)
	titles := []string{}
	for _, c := range g.Candidates {
		titles = append(titles, c.Title)
	}
	all := strings.Join(titles, "|")
	if !g.HasLawOC || !strings.Contains(all, "Software Supply Chain Rule") || !strings.Contains(all, "소프트웨어 진흥법") || strings.Contains(all, "14028") {
		t.Fatalf("후보(이미 있는 EO 14028 제외): %v", titles)
	}
	// 채택 → 초안 규제 생성
	var cid string
	for _, c := range g.Candidates {
		if c.Source == "law-kr" {
			cid = c.ID
			if !strings.HasPrefix(c.URL, srv.URL) && !strings.HasPrefix(c.URL, "https://www.law.go.kr") {
				t.Fatalf("상대 링크 보정: %s", c.URL)
			}
		}
	}
	rec = call(t, s.apiRegCandidate, "POST", "/x", `{"action":"adopt"}`, map[string]string{"id": cid})
	var ad struct{ Candidate regCandidate }
	json.Unmarshal(rec.Body.Bytes(), &ad)
	if rec.Code != 200 || ad.Candidate.State != "adopted" || !strings.HasPrefix(ad.Candidate.RegID, "kr-") {
		t.Fatalf("채택: %s", rec.Body.String())
	}
	regMu.Lock()
	c, _ := loadCatalog()
	regMu.Unlock()
	found := false
	for _, r := range c.Regulations {
		if r.ID == ad.Candidate.RegID && r.Origin == "discovered" && !r.Verified {
			found = true
		}
	}
	if !found {
		t.Fatal("채택한 규제가 카탈로그에 없음")
	}
}

// 영문 보고서: 내장 규제 전부 번역이 있고, 제목·요구사항·할 일·일정에 한글이 남지 않는다.
func TestRegReportEnglish(t *testing.T) {
	t.Setenv("REG_DIR", t.TempDir())
	t.Setenv("AI_URL", "")
	b := loadBuiltin()
	hangul := regexp.MustCompile(`[가-힣]`)
	for _, g := range b.Regulations {
		if g.En == nil {
			t.Fatalf("번역 없음: %s", g.ID)
		}
	}
	c := &regCatalog{Version: "1", BuiltinVersion: b.Version, Regulations: b.Regulations}
	s := &Server{sor: newSoR(filepath.Join(t.TempDir(), "sor.jsonl"))}
	rep := s.buildRegReport(c, "all", nil, "", "", "admin1", "en")
	if rep.Lang != "en" || rep.Edition != 1 || !strings.Contains(rep.DocNo, "-EN v1") || hangul.MatchString(rep.Title+rep.Disclaimer+rep.AudienceKo+rep.FileName) {
		t.Fatalf("머리: %+v", rep.DocNo)
	}
	for _, g := range rep.Regs {
		txt := g.NameKo + g.Kind + g.Authority + g.Binding + g.Status + g.Scope + strings.Join(g.Tags, "")
		for _, d := range g.Dates {
			txt += d.Label
		}
		for _, q := range g.Reqs {
			txt += q.Clause + q.Title + q.Text + q.Actions["dev"] + q.Actions["admin"] + q.Actions["sales"]
		}
		if g.Untranslated || hangul.MatchString(txt) {
			t.Errorf("%s 에 한글 남음: %s", g.ID, hangul.FindString(txt))
		}
	}
	for _, tl := range rep.Timeline {
		if hangul.MatchString(tl["reg"].(string) + tl["label"].(string)) {
			t.Errorf("일정 한글: %v", tl)
		}
	}
	// 같은 조건 두 번째 → v2, 언어가 다르면 별도 판
	_ = os.MkdirAll(filepath.Join(regDir(), "reports"), 0o750)
	_ = writeJSONFile(filepath.Join(regDir(), "reports", rep.ID+".json"), rep)
	if r2 := s.buildRegReport(c, "all", nil, "", "", "admin1", "en"); r2.Edition != 2 || r2.PrevID != rep.ID {
		t.Fatalf("다음 판: %d %s", r2.Edition, r2.PrevID)
	}
	if k := s.buildRegReport(c, "all", nil, "", "", "admin1", "ko"); k.Edition != 1 {
		t.Fatal("언어별 판")
	}
}
