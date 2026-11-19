package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// 내장 분석: 한국 규제마다 있고, 조문 번호는 형식이 맞고, 단계·구분 값이 정해진 것만.
func TestRegLawBuiltin(t *testing.T) {
	b := loadBuiltin()
	regs := map[string]regulation{}
	for _, r := range b.Regulations {
		regs[r.ID] = r
		if r.Region == "KR" && b.Analyses[r.ID] == nil {
			t.Errorf("%s: 법규 분석 없음", r.ID)
		}
		if r.En == nil {
			t.Errorf("%s: 영문 없음", r.ID)
		}
	}
	for id, a := range b.Analyses {
		if g, ok := regs[id]; !ok || g.Region != "KR" {
			t.Errorf("%s: 카탈로그에 없는 한국 규제", id)
		}
		if !inList(a.Duty, []string{"legal", "conditional", "voluntary"}) || a.Nature == "" || a.Sanctions == "" || len(a.Questions) == 0 || a.Rev < 1 {
			t.Errorf("%s: 필수 항목", id)
		}
		for k, steps := range a.Plans {
			if !inList(k, regAudiences) {
				t.Errorf("%s: 역할 %s", id, k)
			}
			for _, s := range steps {
				if !inList(s.Stage, lawStages) {
					t.Errorf("%s: 단계 %s", id, s.Stage)
				}
			}
		}
		for _, x := range a.Articles {
			if x.Article != "" && !regexp.MustCompile(`^제\d+조(의\d+)?(제\d+항)?(제\d+호(의\d+)?)?$`).MatchString(x.Article) {
				t.Errorf("%s: 조문 표기 %q", id, x.Article)
			}
			if x.Article == "" && !x.Check {
				t.Errorf("%s: 조문 번호 없으면 확인 필요 표시(%s)", id, x.Law)
			}
			if !strings.HasPrefix(x.URL, "https://www.law.go.kr/") || !inList(x.Kind, []string{"law", "admrul"}) {
				t.Errorf("%s: 링크·종류 %s %s", id, x.URL, x.Kind)
			}
		}
	}
	if lawJO("제47조의4제4항") != "004704" || lawJO("제29조") != "002900" || lawJO("별표 3") != "" {
		t.Fatal("조번호 변환")
	}
	if u := lawURL(lawArticle{Law: "개인정보 보호법", Article: "제26조제8항"}); u != "https://www.law.go.kr/법령/개인정보보호법/제26조" {
		t.Fatal(u)
	}
}

func regsAnalyses(t *testing.T, s *Server) (map[string]*regAnalysis, bool) {
	rec := call(t, s.apiRegs, "GET", "/api/regs", "", nil)
	var g struct {
		Analyses map[string]*regAnalysis
		LawOC    bool
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &g); err != nil {
		t.Fatal(err)
	}
	return g.Analyses, g.LawOC
}

func TestRegLawFetch(t *testing.T) {
	s := regTestServer(t)
	an, hasOC := regsAnalyses(t, s)
	if hasOC || an["kr-netact"] == nil || an["kr-netact"].Origin != "builtin" || an["us-eo14028"] != nil {
		t.Fatal("내장 분석이 /api/regs 에 실림(한국만)")
	}
	// OC 없으면 안내만
	rec := call(t, s.apiRegLawFetch, "POST", "/x", "", map[string]string{"id": "kr-netact"})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "no-oc") || !strings.Contains(rec.Body.String(), "OC 미설정") {
		t.Fatalf("OC 없음: %s", rec.Body.String())
	}
	var jos []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("OC") != "myoc" {
			w.WriteHeader(403)
			return
		}
		switch r.URL.Path {
		case "/DRF/lawSearch.do":
			w.Write([]byte(`{"LawSearch":{"law":[{"법령명한글":"정보통신망 이용촉진 및 정보보호 등에 관한 법률 시행령","법령일련번호":"9"},{"법령명한글":"정보통신망 이용촉진 및 정보보호 등에 관한 법률","법령일련번호":"123"}]}}`))
		case "/DRF/lawService.do":
			jo := q.Get("JO")
			jos = append(jos, jo)
			if q.Get("MST") != "123" || jo == "004500" {
				w.WriteHeader(404)
				return
			}
			n, _ := strconv.Atoi(jo[:4])
			art := "제" + itoa(n) + "조"
			if b, _ := strconv.Atoi(jo[4:]); b > 0 {
				art += "의" + itoa(b)
			}
			w.Write([]byte(`{"법령":{"조문":{"조문단위":[{"조문내용":"` + art + `(테스트) 본문","항":[{"항내용":"① 첫째 항"},{"항내용":"② 둘째 항","호":[{"호내용":"1. 호"}]}]},{"조문내용":"제999조(다른 조) 섞이면 안 됨"}]}}}`))
		}
	}))
	defer srv.Close()
	lawBaseURL = srv.URL
	defer func() { lawBaseURL = "https://www.law.go.kr" }()
	if rec := call(t, s.apiRegDiscoverCfg, "PUT", "/x", `{"keywordsUS":[],"keywordsKR":[],"lawOC":"myoc"}`, nil); rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	rec = call(t, s.apiRegLawFetch, "POST", "/x", "", map[string]string{"id": "kr-netact"})
	var fr struct {
		Status  string
		Fetched int
		Results []struct {
			Article string
			OK      bool
			Error   string
		}
	}
	json.Unmarshal(rec.Body.Bytes(), &fr)
	// 제47조의4·제76조·제48조의3 가져옴(같은 조는 한 번), 제45조는 실패
	if rec.Code != 200 || fr.Status != "done" || fr.Fetched != 3 || strings.Contains(rec.Body.String(), "myoc") {
		t.Fatalf("가져오기: %s", rec.Body.String())
	}
	if !inList("004704", jos) || !inList("007600", jos) {
		t.Fatalf("조번호: %v", jos)
	}
	an, hasOC = regsAnalyses(t, s)
	got := ""
	for _, a := range an["kr-netact"].Articles {
		if a.Article == "제47조의4제4항" {
			got = a.Text
		}
	}
	if !hasOC || !strings.Contains(got, "제47조의4(테스트)") || !strings.Contains(got, "1. 호") || strings.Contains(got, "제999조") {
		t.Fatalf("원문 보관·잘라내기: %q", got)
	}
}

func TestRegLawAnalyzeAndReview(t *testing.T) {
	s := regTestServer(t)
	if rec := call(t, s.apiRegLawAnalyze, "POST", "/x", "", map[string]string{"id": "kr-pipa"}); rec.Code != 400 {
		t.Fatal("AI 없으면 400")
	}
	out := map[string]any{
		"nature": "법률", "duty": "legal", "dutyNote": "수탁자도 의무 [A2]", "questions": []string{"개인정보를 처리하는가?"}, "subjects": []string{"수탁자"},
		"articles": []map[string]string{
			{"law": "개인정보 보호법", "article": "제29조", "gist": "안전조치", "fact": "A1"},
			{"law": "개인정보 보호법", "article": "제999조", "gist": "지어낸 조문", "fact": "Z9"},
		},
		"sanctions": "과태료", "plans": map[string]any{"dev": []map[string]string{{"stage": "now", "do": "패치"}, {"stage": "soon", "do": "잘못된 단계"}}, "admin": []any{}, "sales": []any{}},
		"evidence": []string{"계약서"}, "talking": []string{"설명"}, "checks": []string{}, "citations": []string{"A1", "Q1", "X7"},
	}
	ob, _ := json.Marshal(out)
	var prompt string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []struct{ Content string } `json:"messages"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		for _, m := range req.Messages {
			prompt += m.Content
		}
		resp, _ := json.Marshal(map[string]any{"model": "m1", "choices": []any{map[string]any{"message": map[string]any{"content": string(ob)}, "finish_reason": "stop"}}})
		w.Write(resp)
	}))
	defer srv.Close()
	c, err := mergeAIConf(aiConf(), aiConfigIn{Mode: "external", External: aiExternalIn{Provider: "openai", URL: srv.URL + "/v1", Model: "m1", APIKey: "k"}})
	if err != nil || saveAIConf(c) != nil {
		t.Fatal(err)
	}
	if rec := call(t, s.apiRegLawAnalyze, "POST", "/x", "", map[string]string{"id": "us-eo14028"}); rec.Code != 404 {
		t.Fatal("한국 규제만")
	}
	if rec := call(t, s.apiRegLawAnalyze, "POST", "/x", "", map[string]string{"id": "kr-pipa"}); rec.Code != 202 {
		t.Fatal(rec.Body.String())
	}
	var a *regAnalysis
	for i := 0; i < 100; i++ {
		an, _ := regsAnalyses(t, s)
		if a = an["kr-pipa"]; !a.Running {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if a.Running || a.Draft == nil || a.AIError != "" {
		t.Fatalf("초안: %+v", a)
	}
	d := a.Draft
	if d.Origin != "ai" || d.Verified || len(d.Plans["dev"]) != 1 || strings.Join(d.Citations, ",") != "A1,Q1" || len(d.Articles) != 2 {
		t.Fatalf("초안 정리: %+v", d)
	}
	if d.Articles[0].Kind != "law" || d.Articles[0].Check || d.Articles[1].Article != "" || !d.Articles[1].Check {
		t.Fatalf("근거 없는 조문 번호는 지우고 확인 필요: %+v", d.Articles)
	}
	if !strings.Contains(prompt, "제26조제8항") || a.Origin != "builtin" {
		t.Fatal("기존 분석 조문을 사실로 넘기고, 채택 전에는 내장 분석 유지")
	}
	review := func(act string, code int) {
		if rec := call(t, s.apiRegLawReview, "POST", "/x", `{"action":"`+act+`"}`, map[string]string{"id": "kr-pipa"}); rec.Code != code {
			t.Fatalf("%s: %d %s", act, rec.Code, rec.Body.String())
		}
	}
	review("adopt", 200)
	review("adopt", 404)
	an, _ := regsAnalyses(t, s)
	if a = an["kr-pipa"]; a.Origin != "ai" || a.Verified || a.Draft != nil {
		t.Fatalf("채택: %+v", a)
	}
	review("verify", 200)
	an, _ = regsAnalyses(t, s)
	if a = an["kr-pipa"]; !a.Verified || a.VerifiedBy != "admin1" {
		t.Fatal("확인 표시")
	}
	review("reset", 200)
	review("bogus", 400)
	an, _ = regsAnalyses(t, s)
	if an["kr-pipa"].Origin != "builtin" || an["kr-pipa"].Verified {
		t.Fatal("되돌리기")
	}
}

// 보고서: 한글판에만, 역할에 맞춘 계획만, 영문판에는 없다.
func TestRegLawReport(t *testing.T) {
	s := regTestServer(t)
	regMu.Lock()
	c, _ := loadCatalog()
	regMu.Unlock()
	rep := s.buildRegReport(c, "sales", []string{"KR"}, "", "", "admin1", "ko")
	if len(rep.Law) < 5 {
		t.Fatalf("법규 분석 절: %d", len(rep.Law))
	}
	for _, x := range rep.Law {
		for k := range x.Analysis.Plans {
			if k != "sales" {
				t.Fatalf("영업 보고서에 %s 계획", k)
			}
		}
	}
	dev := s.buildRegReport(c, "dev", []string{"KR"}, "", "", "admin1", "ko")
	for _, x := range dev.Law {
		if _, ok := x.Analysis.Plans["sales"]; ok || len(x.Analysis.Talking) > 0 {
			t.Fatal("개발자 보고서에 영업 내용")
		}
	}
	if s.buildRegReport(c, "dev", []string{"US"}, "", "", "admin1", "ko").Law != nil {
		t.Fatal("한국 미포함이면 없음")
	}
	if en := s.buildRegReport(c, "all", nil, "", "", "admin1", "en"); en.Law != nil {
		t.Fatal("영문 보고서에는 없음")
	}
}
