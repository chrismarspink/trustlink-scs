package main

// 규제 탐색 — 카탈로그에 없는 규제·개정을 찾아 "후보"로 올린다. 관리자가 확인해 채택(초안 규제 생성)하거나 무시한다.
//  - 미국 관보(Federal Register API, 키 불필요): 키워드 검색, 최신순.
//  - 한국 국가법령정보센터 Open API: 발급받은 OC 값이 있을 때만(법령·행정규칙 검색).
//  - 원문 변경 감지: 카탈로그 출처 페이지의 내용 해시가 바뀌면 "개정 가능성" 후보.
//  - AI 제안: 연결된 LLM 에 현재 목록을 주고 빠진 규제를 묻는다(지식 기반 — 반드시 확인 필요로 표시).
//  - 외부 접속은 관리자가 '탐색 실행'을 누를 때만 한다. 폐쇄망이면 AI 제안만 쓴다.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type regCandidate struct {
	ID      string `json:"id"`
	Source  string `json:"source"` // federal-register / law-kr / watch / ai
	Region  string `json:"region"`
	Title   string `json:"title"`
	Summary string `json:"summary,omitempty"`
	URL     string `json:"url,omitempty"`
	Date    string `json:"date,omitempty"`
	Keyword string `json:"keyword,omitempty"`
	RegID   string `json:"regId,omitempty"` // 관련(변경 감지) 또는 채택해 만든 규제
	State   string `json:"state"`           // new / dismissed / adopted
	FoundAt string `json:"foundAt"`
}

type regDiscoverCfg struct {
	KeywordsUS []string `json:"keywordsUS"`
	KeywordsKR []string `json:"keywordsKR"`
	LawOC      string   `json:"lawOC,omitempty"` // 국가법령정보센터 OC(파일에만)
}

type regDiscoverState struct {
	Running  bool     `json:"running"`
	Started  string   `json:"started,omitempty"`
	Finished string   `json:"finished,omitempty"`
	Log      []string `json:"log"`
	Added    int      `json:"added"`
}

var (
	regDiscMu    sync.Mutex
	regDiscState = regDiscoverState{Log: []string{}}
	regTagRe     = regexp.MustCompile(`(?is)<script.*?</script>|<style.*?</style>|<[^>]+>`)
	regWSRe      = regexp.MustCompile(`\s+`)
)

func defaultDiscoverCfg() regDiscoverCfg {
	return regDiscoverCfg{
		KeywordsUS: []string{"software bill of materials", "software supply chain security", "secure software development attestation"},
		KeywordsKR: []string{"소프트웨어 공급망", "공급망 보안", "소프트웨어 자재명세"},
	}
}

func loadDiscoverCfg() regDiscoverCfg {
	c := defaultDiscoverCfg()
	_ = readJSONFile(filepath.Join(regDir(), "discover.json"), &c)
	return c
}

func loadCandidates() []regCandidate {
	var l []regCandidate
	_ = readJSONFile(filepath.Join(regDir(), "candidates.json"), &l)
	return l
}

func saveCandidates(l []regCandidate) error {
	sort.SliceStable(l, func(i, j int) bool { return l[i].FoundAt > l[j].FoundAt })
	if len(l) > 500 {
		l = l[:500]
	}
	return writeJSONFile(filepath.Join(regDir(), "candidates.json"), l)
}

func candID(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return "c" + hex.EncodeToString(h[:6])
}

func discoverLog(msg string) {
	regDiscMu.Lock()
	regDiscState.Log = append(regDiscState.Log, time.Now().In(time.FixedZone("KST", 9*3600)).Format("15:04:05")+" "+msg)
	regDiscMu.Unlock()
}

var (
	regHTTP    = &http.Client{Timeout: 20 * time.Second}
	frBaseURL  = "https://www.federalregister.gov"
	lawBaseURL = "https://www.law.go.kr"
)

func regGet(u string, out any) error {
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "TrustLink-RegDiscover/1.0")
	req.Header.Set("Accept", "application/json")
	resp, err := regHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return &httpErr{resp.StatusCode}
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
}

type httpErr struct{ code int }

func (e *httpErr) Error() string { return "HTTP " + itoa(e.code) }

// 미국 관보
func discoverFederalRegister(keywords []string) ([]regCandidate, error) {
	out := []regCandidate{}
	for _, kw := range keywords {
		q := url.Values{}
		term := kw
		if strings.Contains(kw, " ") && !strings.HasPrefix(kw, "\"") { // 여러 단어는 구문 검색(아니면 단어별 OR 로 무관한 결과가 섞임)
			term = "\"" + kw + "\""
		}
		q.Set("conditions[term]", term)
		q.Set("order", "newest")
		q.Set("per_page", "10")
		for _, f := range []string{"title", "abstract", "html_url", "publication_date", "type", "agencies"} {
			q.Add("fields[]", f)
		}
		var d struct {
			Results []struct {
				Title    string `json:"title"`
				Abstract string `json:"abstract"`
				URL      string `json:"html_url"`
				Date     string `json:"publication_date"`
				Type     string `json:"type"`
				Agencies []struct {
					Name string `json:"name"`
				} `json:"agencies"`
			} `json:"results"`
		}
		if err := regGet(frBaseURL+"/api/v1/documents.json?"+q.Encode(), &d); err != nil {
			return out, err
		}
		for _, x := range d.Results {
			ag := []string{}
			for _, a := range x.Agencies {
				ag = append(ag, a.Name)
			}
			sum := truncate(x.Abstract, 400)
			if len(ag) > 0 {
				sum = "[" + x.Type + " · " + strings.Join(head(ag, 2), ", ") + "] " + sum
			}
			out = append(out, regCandidate{ID: candID("fr", x.URL), Source: "federal-register", Region: "US", Title: x.Title,
				Summary: sum, URL: x.URL, Date: x.Date, Keyword: kw})
		}
	}
	return out, nil
}

// 한국 국가법령정보센터(법령·행정규칙). 응답 필드 이름이 대상별로 달라 관대하게 읽는다.
func discoverLawKR(oc string, keywords []string) ([]regCandidate, error) {
	out := []regCandidate{}
	pick := func(m map[string]any, keys ...string) string {
		for _, k := range keys {
			if v, ok := m[k].(string); ok && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
		return ""
	}
	var walk func(v any, kw, target string)
	walk = func(v any, kw, target string) {
		switch t := v.(type) {
		case map[string]any:
			title := pick(t, "법령명한글", "행정규칙명", "법령명")
			if title != "" {
				link := pick(t, "법령상세링크", "행정규칙상세링크")
				if strings.HasPrefix(link, "/") {
					link = "https://www.law.go.kr" + link
				}
				date := pick(t, "시행일자", "발령일자", "공포일자")
				if len(date) == 8 {
					date = date[:4] + "-" + date[4:6] + "-" + date[6:]
				}
				kind := pick(t, "법령구분명", "행정규칙종류")
				org := pick(t, "소관부처명", "소관부처")
				out = append(out, regCandidate{ID: candID("law", target, title), Source: "law-kr", Region: "KR", Title: title,
					Summary: strings.Trim(kind+" · "+org, " ·"), URL: link, Date: date, Keyword: kw})
				return
			}
			for _, x := range t {
				walk(x, kw, target)
			}
		case []any:
			for _, x := range t {
				walk(x, kw, target)
			}
		}
	}
	for _, kw := range keywords {
		for _, target := range []string{"law", "admrul"} {
			q := url.Values{}
			q.Set("OC", oc)
			q.Set("target", target)
			q.Set("type", "JSON")
			q.Set("query", kw)
			q.Set("display", "20")
			var d any
			if err := regGet(lawBaseURL+"/DRF/lawSearch.do?"+q.Encode(), &d); err != nil {
				return out, err
			}
			walk(d, kw, target)
		}
	}
	return out, nil
}

// 원문 변경 감지: 출처 페이지의 본문 텍스트 해시(스크립트·태그 제거)를 기준값과 비교.
func discoverWatch(c *regCatalog) ([]regCandidate, int, error) {
	base := map[string]string{}
	p := filepath.Join(regDir(), "watch.json")
	_ = readJSONFile(p, &base)
	out := []regCandidate{}
	checked := 0
	type job struct{ url, regID, name string }
	jobs := []job{}
	seen := map[string]bool{}
	for _, g := range c.Regulations {
		for _, s := range g.Sources {
			if s.URL != "" && !seen[s.URL] && len(jobs) < 60 {
				seen[s.URL] = true
				jobs = append(jobs, job{s.URL, g.ID, g.NameKo})
			}
		}
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for _, j := range jobs {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			req, _ := http.NewRequest("GET", j.url, nil)
			req.Header.Set("User-Agent", "TrustLink-RegDiscover/1.0")
			resp, err := regHTTP.Do(req)
			if err != nil {
				return
			}
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
			resp.Body.Close()
			if resp.StatusCode != 200 {
				return
			}
			txt := regWSRe.ReplaceAllString(regTagRe.ReplaceAllString(string(b), " "), " ")
			h := sha256.Sum256([]byte(txt))
			sum := hex.EncodeToString(h[:])
			mu.Lock()
			defer mu.Unlock()
			checked++
			if old, ok := base[j.url]; ok && old != sum {
				out = append(out, regCandidate{ID: candID("watch", j.url, sum), Source: "watch", Region: "", RegID: j.regID,
					Title: "원문 변경 감지 — " + j.name, Summary: "출처 페이지 내용이 지난 확인 이후 바뀌었습니다. 개정·후속 조치 여부를 확인하세요.", URL: j.url})
			}
			base[j.url] = sum
		}(j)
	}
	wg.Wait()
	return out, checked, writeJSONFile(p, base)
}

var regSuggestSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"items": map[string]any{"type": "array", "maxItems": 8, "items": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name":      map[string]any{"type": "string", "maxLength": 160},
				"region":    map[string]any{"type": "string", "maxLength": 8},
				"authority": map[string]any{"type": "string", "maxLength": 80},
				"why":       map[string]any{"type": "string", "maxLength": 300},
			},
			"required": []string{"name", "region", "authority", "why"},
		}},
	},
	"required": []string{"items"},
}

// discoverAIUse: 규제 탐색 AI 는 보고서용 설정을 우선 쓰고, 꺼져 있으면 일반 AI 를 쓴다
// (보내는 내용은 공개된 규제 이름 목록뿐이라 고객 데이터가 없다).
func discoverAIUse() string {
	if aiEnabledFor("report") {
		return "report"
	}
	return "general"
}

// AI 제안: 모델 지식 기반이므로 출처 없음 — 반드시 사람이 확인.
func (s *Server) discoverAI(c *regCatalog) ([]regCandidate, error) {
	names := []string{}
	for _, g := range c.Regulations {
		names = append(names, g.Region+": "+firstNonEmpty(g.NameKo, g.Name))
	}
	facts := []aiFact{{ID: "L1", Text: "이미 관리 중인 규제 목록: " + strings.Join(names, "; ")},
		{ID: "P1", Text: "관점: 소프트웨어(바이너리·SBOM·VEX)를 고객에게 공급하는 기업의 소프트웨어 공급망 보안·SBOM·취약점 관리·보안 업데이트 의무. 시장: 미국·유럽·일본·한국 우선, 그 외 주요국"}}
	task := `L1 에 없는 관련 법규·규제·정부 지침·조달 기준을 최대 8개 제안한다.
- name: 공식 명칭(원어), region: US/EU/JP/KR/UK/IN/AU/SG/CA/CN 등 국가 코드, authority: 소관 기관, why: 왜 관련 있는지와 대략적 시행 시점(불확실하면 '확인 필요').
- L1 과 같은 규제를 다른 이름으로 다시 제안하지 않는다. 확실하지 않은 이름은 쓰지 않는다.`
	var d struct {
		Items []struct{ Name, Region, Authority, Why string } `json:"items"`
	}
	if _, err := s.aiDraftFor(discoverAIUse(), "ko", facts, task, regSuggestSchema, 1400, &d); err != nil {
		return nil, err
	}
	out := []regCandidate{}
	for _, x := range d.Items {
		if strings.TrimSpace(x.Name) == "" {
			continue
		}
		out = append(out, regCandidate{ID: candID("ai", strings.ToLower(x.Name)), Source: "ai", Region: strings.ToUpper(x.Region),
			Title: x.Name, Summary: x.Authority + " — " + x.Why + " (AI 제안: 원문 확인 필요)"})
	}
	return out, nil
}

// 이미 카탈로그에 있는 규제와 이름이 겹치면 제외.
func knownReg(c *regCatalog, title string) bool {
	t := strings.ToLower(title)
	for _, g := range c.Regulations {
		for _, n := range []string{g.Name, g.NameKo} {
			n = strings.ToLower(strings.TrimSpace(n))
			if len(n) >= 6 && (strings.Contains(t, n) || strings.Contains(n, t)) {
				return true
			}
		}
	}
	return false
}

func (s *Server) runDiscover(sources []string, actor string) {
	regMu.Lock()
	c, err := loadCatalog()
	var cc regCatalog
	if err == nil {
		b, _ := json.Marshal(c)
		_ = json.Unmarshal(b, &cc)
	}
	regMu.Unlock()
	found := []regCandidate{}
	if err == nil {
		cfg := loadDiscoverCfg()
		if inList("federal-register", sources) {
			discoverLog("미국 관보 검색: " + strings.Join(cfg.KeywordsUS, ", "))
			l, err := discoverFederalRegister(cfg.KeywordsUS)
			if err != nil {
				discoverLog("미국 관보 실패: " + err.Error())
			}
			discoverLog("미국 관보 결과 " + itoa(len(l)) + "건")
			found = append(found, l...)
		}
		if inList("law-kr", sources) {
			if cfg.LawOC == "" {
				discoverLog("국가법령정보센터: OC 값이 없어 건너뜀(탐색 설정에서 입력)")
			} else {
				discoverLog("국가법령정보센터 검색: " + strings.Join(cfg.KeywordsKR, ", "))
				l, err := discoverLawKR(cfg.LawOC, cfg.KeywordsKR)
				if err != nil {
					discoverLog("국가법령정보센터 실패: " + strings.ReplaceAll(err.Error(), cfg.LawOC, "****"))
				}
				discoverLog("국가법령정보센터 결과 " + itoa(len(l)) + "건")
				found = append(found, l...)
			}
		}
		if inList("watch", sources) {
			discoverLog("출처 페이지 변경 확인 중")
			l, n, err := discoverWatch(&cc)
			if err != nil {
				discoverLog("변경 기준값 저장 실패: " + err.Error())
			}
			discoverLog("출처 " + itoa(n) + "곳 확인, 변경 " + itoa(len(l)) + "건(처음 확인한 곳은 기준값만 저장)")
			found = append(found, l...)
		}
		if inList("ai", sources) {
			if !aiEnabledFor(discoverAIUse()) {
				discoverLog("AI 제안: AI 연결이 꺼져 있어 건너뜀(관리 콘솔 › AI 연결)")
			} else {
				discoverLog("AI 제안 요청 중(로컬 CPU 면 1~2분)")
				l, err := s.discoverAI(&cc)
				if err != nil {
					discoverLog("AI 제안 실패: " + err.Error())
				}
				discoverLog("AI 제안 " + itoa(len(l)) + "건")
				found = append(found, l...)
			}
		}
	} else {
		discoverLog("카탈로그를 읽지 못함: " + err.Error())
	}
	regMu.Lock()
	all := loadCandidates()
	have := map[string]bool{}
	for _, x := range all {
		have[x.ID] = true
	}
	added := 0
	now := time.Now().UTC().Format(time.RFC3339)
	for _, x := range found {
		if have[x.ID] || (x.Source != "watch" && knownReg(&cc, x.Title)) {
			continue
		}
		have[x.ID] = true
		x.State, x.FoundAt = "new", now
		all = append(all, x)
		added++
	}
	_ = saveCandidates(all)
	regMu.Unlock()
	_ = s.sor.append(SoREvent{Actor: actor, Action: "reg-discover", Status: "done", Detail: map[string]any{"sources": sources, "found": len(found), "added": added}})
	discoverLog("완료 — 새 후보 " + itoa(added) + "건")
	regDiscMu.Lock()
	regDiscState.Running, regDiscState.Finished, regDiscState.Added = false, now, added
	regDiscMu.Unlock()
}

// POST /api/regs/discover {sources}
func (s *Server) apiRegDiscover(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Sources []string `json:"sources"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil || len(in.Sources) == 0 {
		writeJSON(w, 400, map[string]string{"error": "탐색할 출처를 고르세요"})
		return
	}
	regDiscMu.Lock()
	if regDiscState.Running {
		regDiscMu.Unlock()
		writeJSON(w, 409, map[string]string{"error": "이미 탐색 중입니다"})
		return
	}
	regDiscState = regDiscoverState{Running: true, Started: time.Now().UTC().Format(time.RFC3339), Log: []string{}}
	regDiscMu.Unlock()
	go s.runDiscover(in.Sources, w.Header().Get("X-User"))
	writeJSON(w, 202, map[string]string{"state": "running"})
}

// GET /api/regs/discover → 진행 상태 + 후보 + 설정(OC 는 가림)
func (s *Server) apiRegDiscoverGet(w http.ResponseWriter, r *http.Request) {
	regDiscMu.Lock()
	st := regDiscState
	st.Log = append([]string{}, regDiscState.Log...)
	regDiscMu.Unlock()
	regMu.Lock()
	cands := loadCandidates()
	cfg := loadDiscoverCfg()
	regMu.Unlock()
	hasOC := cfg.LawOC != ""
	cfg.LawOC = ""
	base := map[string]string{}
	_ = readJSONFile(filepath.Join(regDir(), "watch.json"), &base)
	writeJSON(w, 200, map[string]any{"state": st, "candidates": cands, "config": cfg, "hasLawOC": hasOC,
		"aiReady": aiEnabledFor(discoverAIUse()), "watchBase": len(base)})
}

// PUT /api/regs/discover/config {keywordsUS, keywordsKR, lawOC(빈 값=유지), clearLawOC}
func (s *Server) apiRegDiscoverCfg(w http.ResponseWriter, r *http.Request) {
	var in struct {
		KeywordsUS []string `json:"keywordsUS"`
		KeywordsKR []string `json:"keywordsKR"`
		LawOC      string   `json:"lawOC"`
		ClearLawOC bool     `json:"clearLawOC"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "잘못된 요청"})
		return
	}
	clean := func(l []string) []string {
		out := []string{}
		for _, x := range l {
			if x = strings.TrimSpace(x); x != "" && len(out) < 10 {
				out = append(out, truncate(x, 80))
			}
		}
		return out
	}
	regMu.Lock()
	defer regMu.Unlock()
	cfg := loadDiscoverCfg()
	cfg.KeywordsUS, cfg.KeywordsKR = clean(in.KeywordsUS), clean(in.KeywordsKR)
	if v := strings.TrimSpace(in.LawOC); v != "" {
		cfg.LawOC = v
	}
	if in.ClearLawOC {
		cfg.LawOC = ""
	}
	if err := writeJSONFile(filepath.Join(regDir(), "discover.json"), cfg); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"status": "saved", "hasLawOC": cfg.LawOC != ""})
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

// POST /api/regs/candidates/{id} {action: adopt|dismiss|restore}
func (s *Server) apiRegCandidate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "잘못된 요청"})
		return
	}
	id, user := r.PathValue("id"), w.Header().Get("X-User")
	regMu.Lock()
	defer regMu.Unlock()
	all := loadCandidates()
	for i := range all {
		x := &all[i]
		if x.ID != id {
			continue
		}
		switch in.Action {
		case "dismiss":
			x.State = "dismissed"
		case "restore":
			x.State = "new"
		case "adopt":
			if x.Source == "watch" { // 변경 감지는 기존 규제의 확인 표시를 해제
				c, err := loadCatalog()
				if err == nil {
					for j := range c.Regulations {
						if c.Regulations[j].ID == x.RegID {
							c.Regulations[j].Verified, c.Regulations[j].VerifiedBy, c.Regulations[j].VerifiedAt = false, "", ""
							c.Regulations[j].Note = strings.TrimSpace(c.Regulations[j].Note + " [원문 변경 감지 " + time.Now().Format("2006-01-02") + "]")
						}
					}
					bumpVersion(c)
					_ = saveCatalog(c)
				}
				x.State = "adopted"
				break
			}
			c, err := loadCatalog()
			if err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
			region := firstNonEmpty(strings.ToUpper(x.Region), "INTL")
			slug := strings.Trim(slugRe.ReplaceAllString(strings.ToLower(x.Title), "-"), "-")
			if len(slug) > 30 {
				slug = strings.Trim(slug[:30], "-")
			}
			nid := strings.ToLower(region) + "-" + firstNonEmpty(slug, "draft") + "-" + x.ID[1:5]
			src := []regSource{}
			if x.URL != "" {
				src = append(src, regSource{Title: x.Title, URL: x.URL})
			}
			dates := []regDate{}
			if x.Date != "" {
				dates = append(dates, regDate{Date: x.Date, Label: "공표·시행(탐색 결과 — 확인 필요)"})
			}
			nr := regulation{ID: nid, Region: region, Name: x.Title, NameKo: x.Title, Kind: "확인 필요", Authority: "", Binding: "확인 필요",
				Status: "검토 중(탐색 후보에서 채택)", Scope: x.Summary, Markets: []string{}, Tags: []string{"탐색"}, Dates: dates, Sources: src,
				Requirements: []regReq{}, Rev: 1, Origin: "discovered", UpdatedBy: user, UpdatedAt: time.Now().UTC().Format(time.RFC3339)}
			c.Regulations = append(c.Regulations, nr)
			bumpVersion(c)
			if err := saveCatalog(c); err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
			x.State, x.RegID = "adopted", nid
		default:
			writeJSON(w, 400, map[string]string{"error": "action 은 adopt / dismiss / restore"})
			return
		}
		_ = saveCandidates(all)
		_ = s.sor.append(SoREvent{Actor: user, Action: "reg-candidate", Status: in.Action, Detail: map[string]any{"id": id, "title": x.Title, "regId": x.RegID}})
		writeJSON(w, 200, map[string]any{"candidate": x})
		return
	}
	writeJSON(w, 404, map[string]string{"error": "없는 후보"})
}
