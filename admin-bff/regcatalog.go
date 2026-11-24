package main

// 규제 요구사항 카탈로그 — 미국·유럽·일본·한국 등 공급망 보안 관련 법규·지침을 요구사항 단위로 관리한다.
//  - 내장본(regcatalog_builtin.json)을 처음 한 번 작업본으로 복사한다. 이후 관리자가 추가·수정·삭제·확인 처리.
//  - 새 버전 TrustLink 의 내장본이 바뀌면 "내장 카탈로그 업데이트"로 바뀐 규제만 골라 반영(로컬 수정은 충돌 표시).
//  - 요구사항마다 역할별(개발자·관리자·영업) 할 일과 자동 점검 증거(evCheck ID)를 둔다.
//  - 보고서: 지역·역할·(선택)제품 릴리스를 골라 요구사항별 상태·할 일·시행 일정을 모은다. PDF 는 화면 인쇄용 페이지.
//  - 모든 변경은 원장(SoR)에 남긴다. 법률 자문이 아니며 '확인됨' 표시는 사람이 원문을 본 뒤 한다.

import (
	_ "embed"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed regcatalog_builtin.json
var regBuiltinJSON []byte

// 영문 번역(규제 ID → 영문 필드). 영문 보고서에 쓴다. 이름(name)은 원래 영문.
//
//go:embed regcatalog_builtin_en.json
var regBuiltinEnJSON []byte

type regReqEn struct {
	Clause  string            `json:"clause,omitempty"` // 원래 조항 표기가 한글인 경우
	Title   string            `json:"title"`
	Text    string            `json:"text"`
	Actions map[string]string `json:"actions,omitempty"`
}

type regEn struct {
	Name         string              `json:"name,omitempty"` // 원래 이름이 영문이 아닌 경우(일본·한국 규제)
	Kind         string              `json:"kind,omitempty"`
	Authority    string              `json:"authority,omitempty"`
	Binding      string              `json:"binding,omitempty"`
	Status       string              `json:"status,omitempty"`
	Scope        string              `json:"scope,omitempty"`
	Tags         []string            `json:"tags,omitempty"`
	Dates        []string            `json:"dates,omitempty"` // dates[i].label 의 영문(같은 순서)
	Requirements map[string]regReqEn `json:"requirements,omitempty"`
}

var hangulRe = regexp.MustCompile(`[가-힣]`)

func builtinEn() map[string]*regEn {
	m := map[string]*regEn{}
	_ = json.Unmarshal(regBuiltinEnJSON, &m)
	return m
}

type regDate struct {
	Date  string `json:"date"`
	Label string `json:"label"`
}

type regSource struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

type regReq struct {
	ID       string            `json:"id"`
	Clause   string            `json:"clause"`
	Title    string            `json:"title"`
	Text     string            `json:"text"`
	Evidence []string          `json:"evidence"`
	Actions  map[string]string `json:"actions"` // dev / admin / sales
}

type regulation struct {
	ID           string      `json:"id"`
	Region       string      `json:"region"` // US / EU / JP / KR / UK / IN / INTL …
	Name         string      `json:"name"`
	NameKo       string      `json:"nameKo"`
	Kind         string      `json:"kind"`
	Authority    string      `json:"authority"`
	Binding      string      `json:"binding"`
	Status       string      `json:"status"`
	Scope        string      `json:"scope"`
	Markets      []string    `json:"markets"`
	Tags         []string    `json:"tags"`
	Dates        []regDate   `json:"dates"`
	Sources      []regSource `json:"sources"`
	Requirements []regReq    `json:"requirements"`
	Rev          int         `json:"rev"`
	Origin       string      `json:"origin,omitempty"`     // builtin / custom / discovered
	Edited       bool        `json:"edited,omitempty"`     // 내장본에서 로컬 수정됨
	BuiltinRev   int         `json:"builtinRev,omitempty"` // 반영한 내장본 rev
	Verified     bool        `json:"verified"`
	VerifiedBy   string      `json:"verifiedBy,omitempty"`
	VerifiedAt   string      `json:"verifiedAt,omitempty"`
	Note         string      `json:"note,omitempty"`
	UpdatedBy    string      `json:"updatedBy,omitempty"`
	UpdatedAt    string      `json:"updatedAt,omitempty"`
	En           *regEn      `json:"en,omitempty"` // 영문 번역(없으면 영문 보고서에 한국어로 표시)
}

type regCatalog struct {
	Version        string       `json:"version"`        // 작업본 변경 시 증가하는 일련 표시
	BuiltinVersion string       `json:"builtinVersion"` // 마지막으로 반영한 내장본 버전
	Note           string       `json:"note,omitempty"`
	UpdatedAt      string       `json:"updatedAt,omitempty"`
	Regulations    []regulation `json:"regulations"`
}

type regBuiltin struct {
	Version     string                  `json:"version"`
	AsOf        string                  `json:"asOf"`
	Note        string                  `json:"note"`
	Regulations []regulation            `json:"regulations"`
	Analyses    map[string]*regAnalysis `json:"analyses"` // 국내 법규 분석(규제 ID → 분석, reglaw.go)
}

var (
	regMu         sync.Mutex
	regIDRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)
	regReportIDRe = regexp.MustCompile(`^rr-\d{8}-\d{6}(-\d{1,3})?$`)
	regAudiences  = []string{"dev", "admin", "sales"}
	regAudName    = map[string]string{"dev": "개발자", "admin": "관리자(운영·보안)", "sales": "영업"}
	regRegionKo   = map[string]string{"US": "미국", "EU": "유럽연합", "JP": "일본", "KR": "한국", "UK": "영국", "IN": "인도", "INTL": "국제"}
	regionOrder   = map[string]int{"US": 1, "EU": 2, "JP": 3, "KR": 4, "UK": 5, "IN": 6, "INTL": 7}
)

func regDir() string { return env("REG_DIR", "/var/lib/trustlink/regs") }

func loadBuiltin() regBuiltin {
	var b regBuiltin
	_ = json.Unmarshal(regBuiltinJSON, &b)
	en := builtinEn()
	for i := range b.Regulations {
		if t := en[b.Regulations[i].ID]; t != nil || b.Regulations[i].En == nil { // 번역 파일에 없으면 내장본 안의 en 을 쓴다
			b.Regulations[i].En = t
		}
		b.Regulations[i].Origin = "builtin"
		b.Regulations[i].BuiltinRev = b.Regulations[i].Rev
	}
	return b
}

// loadCatalog: 작업본(없으면 내장본으로 만든다). regMu 를 잡은 상태에서 부른다.
func loadCatalog() (*regCatalog, error) {
	p := filepath.Join(regDir(), "catalog.json")
	var c regCatalog
	if err := readJSONFile(p, &c); err == nil && len(c.Regulations) > 0 {
		return &c, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	b := loadBuiltin()
	c = regCatalog{Version: "1", BuiltinVersion: b.Version, Note: b.Note, Regulations: b.Regulations,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339)}
	if err := saveCatalog(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

func saveCatalog(c *regCatalog) error {
	if err := os.MkdirAll(regDir(), 0o750); err != nil {
		return err
	}
	sortRegs(c.Regulations)
	return writeJSONFile(filepath.Join(regDir(), "catalog.json"), c)
}

func sortRegs(r []regulation) {
	sort.SliceStable(r, func(i, j int) bool {
		oi, oj := regionOrder[r[i].Region], regionOrder[r[j].Region]
		if oi == 0 {
			oi = 99
		}
		if oj == 0 {
			oj = 99
		}
		if oi != oj {
			return oi < oj
		}
		return r[i].ID < r[j].ID
	})
}

func bumpVersion(c *regCatalog) {
	n := 0
	for _, ch := range c.Version {
		if ch >= '0' && ch <= '9' {
			n = n*10 + int(ch-'0')
		}
	}
	c.Version = itoa(n + 1)
	c.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
}

// validReg: 저장 전 검증·정리.
func validReg(r *regulation) error {
	r.ID = strings.TrimSpace(r.ID)
	if !regIDRe.MatchString(r.ID) {
		return errors.New("ID 는 영문 소문자·숫자·하이픈 2~63자")
	}
	if strings.TrimSpace(r.NameKo) == "" && strings.TrimSpace(r.Name) == "" {
		return errors.New("규제 이름이 필요합니다")
	}
	r.Region = strings.ToUpper(strings.TrimSpace(r.Region))
	if r.Region == "" {
		return errors.New("지역이 필요합니다")
	}
	seen := map[string]bool{}
	for i := range r.Requirements {
		q := &r.Requirements[i]
		q.ID = strings.TrimSpace(q.ID)
		if q.ID == "" {
			q.ID = r.ID + "-" + itoa(i+1)
		}
		if seen[q.ID] {
			return errors.New("요구사항 ID 중복: " + q.ID)
		}
		seen[q.ID] = true
		if q.Actions == nil {
			q.Actions = map[string]string{}
		}
		for k := range q.Actions {
			if !inList(k, regAudiences) {
				delete(q.Actions, k)
			}
		}
	}
	for _, s := range r.Sources {
		if s.URL != "" && !validAIURL(s.URL) {
			return errors.New("출처 주소는 http(s):// 여야 합니다: " + s.URL)
		}
	}
	return nil
}

// ---------- 내장본 업데이트 비교 ----------

type regDiff struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Change     string `json:"change"` // added / changed / removed
	LocalEdit  bool   `json:"localEdit"`
	BuiltinRev int    `json:"builtinRev"`
	CurrentRev int    `json:"currentRev"`
}

func builtinDiff(c *regCatalog) (string, []regDiff) {
	b := loadBuiltin()
	cur := map[string]regulation{}
	for _, r := range c.Regulations {
		cur[r.ID] = r
	}
	out := []regDiff{}
	inB := map[string]bool{}
	for _, br := range b.Regulations {
		inB[br.ID] = true
		r, ok := cur[br.ID]
		switch {
		case !ok:
			out = append(out, regDiff{ID: br.ID, Name: br.NameKo, Change: "added", BuiltinRev: br.Rev})
		case r.Origin == "builtin" && br.Rev > r.BuiltinRev:
			out = append(out, regDiff{ID: br.ID, Name: br.NameKo, Change: "changed", LocalEdit: r.Edited, BuiltinRev: br.Rev, CurrentRev: r.BuiltinRev})
		}
	}
	for _, r := range c.Regulations {
		if r.Origin == "builtin" && !inB[r.ID] {
			out = append(out, regDiff{ID: r.ID, Name: r.NameKo, Change: "removed", LocalEdit: r.Edited, CurrentRev: r.BuiltinRev})
		}
	}
	return b.Version, out
}

// ---------- API ----------

func (s *Server) regLoad(w http.ResponseWriter) (*regCatalog, bool) {
	c, err := loadCatalog()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return nil, false
	}
	return c, true
}

// GET /api/regs → 작업본 + 내장본 업데이트 요약
func (s *Server) apiRegs(w http.ResponseWriter, r *http.Request) {
	regMu.Lock()
	defer regMu.Unlock()
	c, ok := s.regLoad(w)
	if !ok {
		return
	}
	bv, diff := builtinDiff(c)
	writeJSON(w, 200, map[string]any{"catalog": c, "builtin": map[string]any{"version": bv, "diff": diff},
		"audiences": regAudName, "regions": regRegionKo, "checks": evCheckNames,
		"analyses": lawAnalysesView(c), "lawOC": loadDiscoverCfg().LawOC != ""})
}

// PUT /api/regs/{id} — 추가·수정(통째 저장)
func (s *Server) apiRegPut(w http.ResponseWriter, r *http.Request) {
	var in regulation
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "잘못된 요청"})
		return
	}
	in.ID = r.PathValue("id")
	if err := validReg(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	user := w.Header().Get("X-User")
	regMu.Lock()
	defer regMu.Unlock()
	c, ok := s.regLoad(w)
	if !ok {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	idx := -1
	for i := range c.Regulations {
		if c.Regulations[i].ID == in.ID {
			idx = i
		}
	}
	action := "added"
	if idx >= 0 {
		old := c.Regulations[idx]
		action = "changed"
		in.Origin, in.BuiltinRev = old.Origin, old.BuiltinRev
		in.Edited = old.Origin == "builtin"
		if in.En == nil { // 편집 화면은 영문을 다루지 않는다 — 기존 번역 유지
			in.En = old.En
		}
		in.Rev = old.Rev + 1
		in.Verified, in.VerifiedBy, in.VerifiedAt = false, "", "" // 내용이 바뀌면 사람이 다시 확인
		c.Regulations[idx] = in
	} else {
		if in.Origin == "" {
			in.Origin = "custom"
		}
		in.Rev, in.Verified, in.VerifiedBy, in.VerifiedAt = 1, false, "", ""
		c.Regulations = append(c.Regulations, in)
		idx = len(c.Regulations) - 1
	}
	c.Regulations[idx].UpdatedBy, c.Regulations[idx].UpdatedAt = user, now
	bumpVersion(c)
	if err := saveCatalog(c); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_ = s.sor.append(SoREvent{Actor: user, Action: "reg-catalog", Status: action,
		Detail: map[string]any{"id": in.ID, "rev": in.Rev, "catalogVersion": c.Version}})
	writeJSON(w, 200, map[string]any{"regulation": in, "catalogVersion": c.Version})
}

// DELETE /api/regs/{id}
func (s *Server) apiRegDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	user := w.Header().Get("X-User")
	regMu.Lock()
	defer regMu.Unlock()
	c, ok := s.regLoad(w)
	if !ok {
		return
	}
	out := c.Regulations[:0]
	found := false
	for _, x := range c.Regulations {
		if x.ID == id {
			found = true
			continue
		}
		out = append(out, x)
	}
	if !found {
		writeJSON(w, 404, map[string]string{"error": "없는 규제"})
		return
	}
	c.Regulations = out
	bumpVersion(c)
	if err := saveCatalog(c); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_ = s.sor.append(SoREvent{Actor: user, Action: "reg-catalog", Status: "removed", Detail: map[string]any{"id": id, "catalogVersion": c.Version}})
	writeJSON(w, 200, map[string]any{"status": "removed", "catalogVersion": c.Version})
}

// POST /api/regs/{id}/verify {verified, note}
func (s *Server) apiRegVerify(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Verified bool   `json:"verified"`
		Note     string `json:"note"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "잘못된 요청"})
		return
	}
	id, user := r.PathValue("id"), w.Header().Get("X-User")
	regMu.Lock()
	defer regMu.Unlock()
	c, ok := s.regLoad(w)
	if !ok {
		return
	}
	for i := range c.Regulations {
		if c.Regulations[i].ID != id {
			continue
		}
		x := &c.Regulations[i]
		x.Verified, x.Note = in.Verified, truncate(in.Note, 500)
		x.VerifiedBy, x.VerifiedAt = "", ""
		if in.Verified {
			x.VerifiedBy, x.VerifiedAt = user, time.Now().UTC().Format(time.RFC3339)
		}
		bumpVersion(c)
		if err := saveCatalog(c); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		_ = s.sor.append(SoREvent{Actor: user, Action: "reg-catalog", Status: map[bool]string{true: "verified", false: "unverified"}[in.Verified],
			Detail: map[string]any{"id": id, "rev": x.Rev}})
		writeJSON(w, 200, map[string]any{"regulation": x})
		return
	}
	writeJSON(w, 404, map[string]string{"error": "없는 규제"})
}

// POST /api/regs/builtin-apply {ids, overwrite}
func (s *Server) apiRegBuiltinApply(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IDs       []string `json:"ids"`
		Overwrite bool     `json:"overwrite"` // 로컬 수정된 항목도 덮어쓰기
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "잘못된 요청"})
		return
	}
	user := w.Header().Get("X-User")
	regMu.Lock()
	defer regMu.Unlock()
	c, ok := s.regLoad(w)
	if !ok {
		return
	}
	b := loadBuiltin()
	bmap := map[string]regulation{}
	for _, x := range b.Regulations {
		bmap[x.ID] = x
	}
	_, diff := builtinDiff(c)
	applied, skipped := []string{}, []string{}
	for _, d := range diff {
		if len(in.IDs) > 0 && !inList(d.ID, in.IDs) {
			continue
		}
		if d.LocalEdit && !in.Overwrite {
			skipped = append(skipped, d.ID)
			continue
		}
		switch d.Change {
		case "added":
			c.Regulations = append(c.Regulations, bmap[d.ID])
		case "changed":
			for i := range c.Regulations {
				if c.Regulations[i].ID == d.ID {
					nr := bmap[d.ID]
					nr.Note = c.Regulations[i].Note
					c.Regulations[i] = nr // 내용이 바뀌었으므로 확인 표시는 해제된 상태로
				}
			}
		case "removed":
			out := c.Regulations[:0]
			for _, x := range c.Regulations {
				if x.ID != d.ID {
					out = append(out, x)
				}
			}
			c.Regulations = out
		}
		applied = append(applied, d.ID)
	}
	if _, rest := builtinDiff(c); len(rest) == 0 {
		c.BuiltinVersion = b.Version
	}
	if len(applied) > 0 {
		bumpVersion(c)
		if err := saveCatalog(c); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		_ = s.sor.append(SoREvent{Actor: user, Action: "reg-catalog", Status: "builtin-apply",
			Detail: map[string]any{"builtinVersion": b.Version, "applied": applied, "skipped": skipped}})
	}
	writeJSON(w, 200, map[string]any{"applied": applied, "skipped": skipped, "catalogVersion": c.Version})
}

// ---------- 보고서 ----------

var evCheckNames = map[string]string{
	"sbom.present": "SBOM 첨부", "sbom.format": "SBOM 표준 형식", "sbom.identity": "구성요소 식별자", "sbom.supplier": "공급자 정보",
	"sbom.license": "라이선스 정보", "sign.present": "릴리스 서명", "vex.present": "VEX 발행", "docs.present": "사용자·보안 문서",
	"vuln.triaged": "취약점 판단 완료", "vuln.critical": "미해결 CRITICAL·HIGH", "vuln.kev": "실제 악용(KEV) 미해결",
	"comp.eol": "지원 종료 구성요소", "db.fresh": "취약점 DB 최신성",
}

var (
	regAudNameEn  = map[string]string{"dev": "Developers", "admin": "Administrators (Ops & Security)", "sales": "Sales", "all": "All roles"}
	regRegionEn   = map[string]string{"US": "United States", "EU": "European Union", "JP": "Japan", "KR": "Korea", "UK": "United Kingdom", "IN": "India", "INTL": "International"}
	evCheckNameEn = map[string]string{
		"sbom.present": "SBOM attached", "sbom.format": "Standard SBOM format", "sbom.identity": "Component identifiers (version, purl)",
		"sbom.supplier": "Supplier information", "sbom.license": "License information", "sign.present": "Release signature",
		"vex.present": "VEX issued", "docs.present": "User & security documentation", "vuln.triaged": "Vulnerabilities triaged",
		"vuln.critical": "Open CRITICAL/HIGH", "vuln.kev": "Open known-exploited (KEV)", "comp.eol": "End-of-life components",
		"db.fresh": "Vulnerability DB used for the assessment",
	}
	evCheckFixEn = map[string]string{
		"sbom.present":  "Attach a CycloneDX or SPDX SBOM to the release (the product page can generate one).",
		"sbom.format":   "Regenerate in CycloneDX 1.4+ or SPDX 2.2+.",
		"sbom.identity": "Fill in component versions and purls in the SBOM generator.",
		"sbom.supplier": "Add supplier information for components.",
		"sbom.license":  "Add license information for components.",
		"sign.present":  "Sign the release with cosign/notation and tell customers how to verify it.",
		"vex.present":   "Analyze vulnerabilities and issue a VEX document.",
		"docs.present":  "Attach installation, security configuration and update documentation to the release.",
		"vuln.triaged":  "Classify untriaged vulnerabilities in VEX (AI drafts available).",
		"vuln.critical": "Upgrade affected components to fixed versions or record not-affected justification in VEX.",
		"vuln.kev":      "Remediate known-exploited vulnerabilities first.",
		"comp.eol":      "Replace with supported versions or record a replacement plan / risk acceptance.",
		"db.fresh":      "Update the vulnerability DB mirror.",
	}
	evValueEn = []struct {
		re  *regexp.Regexp
		rep string
	}{
		{regexp.MustCompile(`구성요소 (\d+)개`), "$1 components"},
		{regexp.MustCompile(`서명 (\d+)건`), "$1 signature(s)"},
		{regexp.MustCompile(`발행 (\d+)건\(최신 1건 기준 판정\)`), "$1 issued (latest one assessed)"},
		{regexp.MustCompile(`(\d+)/(\d+)건 판단`), "$1/$2 triaged"},
		{regexp.MustCompile(`분석 결과 없음\(SBOM 미첨부 또는 분석 전\)`), "No analysis (no SBOM or not yet analyzed)"},
		{regexp.MustCompile(`KEV 사본 없음\(미러 확인\)`), "No KEV copy (check mirror)"},
		{regexp.MustCompile(`EOL 사본 없음\(미러 확인\)`), "No EOL copy (check mirror)"},
		{regexp.MustCompile(`\(purl 일치 기준\)`), " (by purl match)"},
		{regexp.MustCompile(`미러 없음 — 판정 시점 DB 를 증명할 수 없음`), "No mirror — DB at assessment time cannot be proven"},
		{regexp.MustCompile(`버전 `), "version "},
		{regexp.MustCompile(`(\d+)건`), "$1"},
		{regexp.MustCompile(`없음`), "None"},
	}
)

// evCheckEn: 자동 점검 결과를 영문 보고서용으로 바꾼다(이름·보완 방법은 표, 값은 정해진 문구 치환).
func evCheckEn(c evCheck) evCheck {
	c.Name = firstNonEmpty(evCheckNameEn[c.ID], c.Name)
	for _, x := range evValueEn {
		c.Value = x.re.ReplaceAllString(c.Value, x.rep)
	}
	if c.Fix != "" {
		c.Fix = firstNonEmpty(evCheckFixEn[c.ID], c.Fix)
	}
	return c
}

// localizeReg: 영문 보고서용 규제 사본. 번역이 없으면 그대로 두고 false.
// 작업본에 번역이 없으면(이전 작업본·사용자 추가) 같은 ID 의 내장 번역을 쓴다.
func localizeReg(g regulation, en map[string]*regEn) (regulation, bool) {
	t := g.En
	if t == nil {
		t = en[g.ID]
	}
	if t == nil {
		return g, false
	}
	g.NameKo = firstNonEmpty(t.Name, g.Name, g.NameKo)                    // 화면의 제목(nameKo 자리)을 영문으로, 원래 이름(name)은 부제로
	if t.Name != "" && g.Region != "KR" && hangulRe.MatchString(g.Name) { // 원래 이름에 붙은 한글 주석은 영문판에서 뺀다(한국 규제는 원어 제목을 부제로 둔다)
		g.Name = t.Name
	}
	g.Kind, g.Authority, g.Status, g.Scope = firstNonEmpty(t.Kind, g.Kind), firstNonEmpty(t.Authority, g.Authority), firstNonEmpty(t.Status, g.Status), firstNonEmpty(t.Scope, g.Scope)
	if t.Binding != "" {
		g.Binding = t.Binding
	}
	if len(t.Tags) == len(g.Tags) {
		g.Tags = t.Tags
	}
	if len(t.Dates) == len(g.Dates) {
		ds := make([]regDate, len(g.Dates))
		for i, d := range g.Dates {
			ds[i] = regDate{Date: d.Date, Label: firstNonEmpty(t.Dates[i], d.Label)}
		}
		g.Dates = ds
	}
	qs := make([]regReq, len(g.Requirements))
	for i, q := range g.Requirements {
		if tq, ok := t.Requirements[q.ID]; ok {
			q.Clause, q.Title, q.Text = firstNonEmpty(tq.Clause, q.Clause), firstNonEmpty(tq.Title, q.Title), firstNonEmpty(tq.Text, q.Text)
			acts := map[string]string{}
			for k, v := range q.Actions {
				acts[k] = v
				if tv, ok := tq.Actions[k]; ok && (tv != "" || v == "") {
					acts[k] = tv
				}
			}
			q.Actions = acts
		}
		qs[i] = q
	}
	g.Requirements = qs
	g.En = nil
	return g, true
}

type regReportReq struct {
	regReq
	Status string    `json:"status"` // met / partial / unmet / manual
	Checks []evCheck `json:"checks,omitempty"`
	Action string    `json:"action,omitempty"` // 선택 역할의 할 일
}

type regReportReg struct {
	regulation
	Reqs         []regReportReq `json:"reqs"`
	Counts       map[string]int `json:"counts"`
	Next         *regDate       `json:"next,omitempty"`         // 오늘 이후 가장 가까운 일정
	Untranslated bool           `json:"untranslated,omitempty"` // 영문 보고서인데 번역 없음
}

// regChange: 지난 판 대비 바뀐 점.
type regChange struct {
	Kind   string `json:"kind"` // added / removed / revised / date / status
	Reg    string `json:"reg"`
	Detail string `json:"detail,omitempty"`
}

type regReport struct {
	ID          string            `json:"id"`
	State       string            `json:"state"` // running(AI 요약 작성 중) / done
	Lang        string            `json:"lang"`  // ko / en
	Key         string            `json:"key"`   // 같은 조건(역할·지역·제품·언어) 묶음 — 판 번호 기준
	Edition     int               `json:"edition"`
	DocNo       string            `json:"docNo"`
	FileName    string            `json:"fileName"`
	PrevID      string            `json:"prevId,omitempty"`
	PrevDate    string            `json:"prevDate,omitempty"`
	Changes     []regChange       `json:"changes,omitempty"`
	Title       string            `json:"title"`
	Audience    string            `json:"audience"`
	AudienceKo  string            `json:"audienceKo"` // 선택 언어의 역할 이름
	Regions     []string          `json:"regions"`
	RegionNames map[string]string `json:"regionNames"`
	Repo        string            `json:"repo,omitempty"`
	Tag         string            `json:"tag,omitempty"`
	Created     string            `json:"created"`
	CreatedBy   string            `json:"createdBy"`
	Catalog     string            `json:"catalogVersion"`
	Builtin     string            `json:"builtinVersion"`
	Regs        []regReportReg    `json:"regs"`
	Totals      map[string]int    `json:"totals"`
	Timeline    []map[string]any  `json:"timeline"`
	Evidence    []evCheck         `json:"evidence,omitempty"`
	Unverified  int               `json:"unverified"`
	Summary     *regReportSummary `json:"summary,omitempty"`
	AIError     string            `json:"aiError,omitempty"`
	AIMeta      *aiMeta           `json:"aiMeta,omitempty"`
	Law         []regLawSection   `json:"law,omitempty"` // 국내 법규 분석 및 대응 방안(한글 보고서·한국 규제만)
	Disclaimer  string            `json:"disclaimer"`
}

type regReportSummary struct {
	Headline  string   `json:"headline"`
	Points    []string `json:"points"`
	Priority  []string `json:"priority"`
	Citations []string `json:"citations"`
}

func reqStatus(q regReq, ev map[string]evCheck, haveEv bool) (string, []evCheck) {
	if len(q.Evidence) == 0 || !haveEv {
		return "manual", nil
	}
	checks := []evCheck{}
	pass, fail, known := 0, 0, 0
	for _, id := range q.Evidence {
		c, ok := ev[id]
		if !ok || c.Result == "na" {
			continue
		}
		known++
		checks = append(checks, c)
		switch c.Result {
		case "pass":
			pass++
		case "fail":
			fail++
		}
	}
	switch {
	case known == 0:
		return "manual", checks
	case pass == known:
		return "met", checks
	case fail == known:
		return "unmet", checks
	}
	return "partial", checks
}

func regReportKey(audience string, regions []string, repo, tag, lang string) string {
	rs := append([]string{}, regions...)
	sort.Strings(rs)
	return strings.Join([]string{audience, strings.Join(rs, ","), repo, tag, lang}, "|")
}

// prevRegReport: 같은 조건으로 만든 가장 최근 보고서(판 번호·변경점 계산용).
func prevRegReport(key string) *regReport {
	files, _ := filepath.Glob(filepath.Join(regDir(), "reports", "rr-*.json"))
	sort.Sort(sort.Reverse(sort.StringSlice(files)))
	for _, f := range files {
		var r regReport
		if readJSONFile(f, &r) == nil && r.Key == key {
			return &r
		}
	}
	return nil
}

// regChanges: 지난 판 대비 새 규제·빠진 규제·개정(rev)·다음 일정·요구사항 상태 변화.
func regChanges(prev, cur *regReport) []regChange {
	en := cur.Lang == "en"
	stName := map[string]string{"met": "충족", "partial": "일부 충족", "unmet": "미충족", "manual": "수동 확인"}
	if en {
		stName = map[string]string{"met": "Met", "partial": "Partial", "unmet": "Not met", "manual": "Manual"}
	}
	old := map[string]regReportReg{}
	for _, g := range prev.Regs {
		old[g.ID] = g
	}
	out := []regChange{}
	seen := map[string]bool{}
	for _, g := range cur.Regs {
		seen[g.ID] = true
		o, ok := old[g.ID]
		if !ok {
			out = append(out, regChange{Kind: "added", Reg: g.NameKo})
			continue
		}
		if g.Rev != o.Rev {
			d := "카탈로그 개정 rev " + itoa(o.Rev) + " → " + itoa(g.Rev)
			if en {
				d = "Catalog revision rev " + itoa(o.Rev) + " → " + itoa(g.Rev)
			}
			out = append(out, regChange{Kind: "revised", Reg: g.NameKo, Detail: d})
		}
		on, cn := "", ""
		if o.Next != nil {
			on = o.Next.Date
		}
		if g.Next != nil {
			cn = g.Next.Date + " " + g.Next.Label
		}
		if g.Next != nil && on != g.Next.Date {
			out = append(out, regChange{Kind: "date", Reg: g.NameKo, Detail: cn})
		}
		os := map[string]string{}
		for _, q := range o.Reqs {
			os[q.ID] = q.Status
		}
		for _, q := range g.Reqs {
			if p, ok := os[q.ID]; ok && p != q.Status {
				out = append(out, regChange{Kind: "status", Reg: g.NameKo, Detail: q.Title + ": " + stName[p] + " → " + stName[q.Status]})
			}
		}
	}
	for _, g := range prev.Regs {
		if !seen[g.ID] {
			out = append(out, regChange{Kind: "removed", Reg: g.NameKo})
		}
	}
	return out
}

func (s *Server) buildRegReport(c *regCatalog, audience string, regions []string, repo, tag, user, lang string) *regReport {
	if lang != "en" {
		lang = "ko"
	}
	en := lang == "en"
	now := time.Now().UTC()
	rep := &regReport{Audience: audience, Lang: lang, Regions: regions, Repo: repo, Tag: tag,
		Created: now.Format(time.RFC3339), CreatedBy: user, Catalog: c.Version, Builtin: c.BuiltinVersion,
		Totals: map[string]int{}, RegionNames: regRegionKo}
	rep.AudienceKo = firstNonEmpty(regAudName[audience], "전체 역할")
	rep.Disclaimer = "이 보고서는 공개 규제 정보를 요약한 참고 자료이며 법률 자문이 아닙니다. '확인 필요' 항목은 원문과 최신 개정 여부를 확인하십시오."
	if en {
		rep.AudienceKo, rep.RegionNames = regAudNameEn[audience], regRegionEn
		rep.Disclaimer = "This report summarizes publicly available regulatory information for reference only and is not legal advice. Check items marked \"to be verified\" against the original texts and their latest amendments."
	}
	rep.ID = "rr-" + now.Format("20060102-150405")
	var ev map[string]evCheck
	haveEv := repo != "" && tag != ""
	if haveEv {
		list, _ := s.releaseEvidence(repo, tag)
		if en {
			for i := range list {
				list[i] = evCheckEn(list[i])
			}
		}
		rep.Evidence = list
		ev = map[string]evCheck{}
		for _, x := range list {
			ev[x.ID] = x
		}
	}
	var enMap map[string]*regEn
	if en {
		enMap = builtinEn()
	}
	today := now.Format("2006-01-02")
	for _, g0 := range c.Regulations {
		if len(regions) > 0 && !inList(g0.Region, regions) {
			continue
		}
		g, translated := g0, true
		if en {
			g, translated = localizeReg(g0, enMap)
		}
		g.En = nil
		rr := regReportReg{regulation: g, Counts: map[string]int{}, Untranslated: en && !translated}
		for _, q := range g.Requirements {
			act := q.Actions[audience]
			if audience != "all" && act == "" {
				continue // 이 역할이 할 일이 없는 요구는 뺀다
			}
			st, checks := reqStatus(q, ev, haveEv)
			rr.Reqs = append(rr.Reqs, regReportReq{regReq: q, Status: st, Checks: checks, Action: act})
			rr.Counts[st]++
			rep.Totals[st]++
		}
		if len(rr.Reqs) == 0 {
			continue
		}
		for _, d := range g.Dates {
			if d.Date >= today && (rr.Next == nil || d.Date < rr.Next.Date) {
				dd := d
				rr.Next = &dd
			}
			rep.Timeline = append(rep.Timeline, map[string]any{"date": d.Date, "label": d.Label, "reg": g.NameKo, "region": g.Region, "future": d.Date >= today})
		}
		if !g.Verified {
			rep.Unverified++
		}
		rep.Totals["regs"]++
		if strings.HasPrefix(g0.Binding, "의무") {
			rep.Totals["mandatory"]++
		}
		rep.Totals["reqs"] += len(rr.Reqs)
		rep.Regs = append(rep.Regs, rr)
	}
	if !en {
		rep.Law = lawReportSections(rep.Regs, audience)
	}
	sort.SliceStable(rep.Timeline, func(i, j int) bool { return rep.Timeline[i]["date"].(string) < rep.Timeline[j]["date"].(string) })
	names := []string{}
	for _, r := range regions {
		names = append(names, firstNonEmpty(rep.RegionNames[r], r))
	}
	if en {
		rep.Title = "Supply-Chain Security Regulatory Compliance Report"
		if len(names) > 0 {
			rep.Title += " — " + strings.Join(names, " · ")
		}
	} else {
		rep.Title = "공급망 보안 규제 대응 보고서"
		if len(names) > 0 {
			rep.Title += " — " + strings.Join(names, "·")
		}
	}

	// 판 번호: 같은 조건(역할·지역·제품·언어)으로 만든 이전 보고서 다음 판. 지난 판과 달라진 점을 함께 싣는다.
	rep.Key = regReportKey(audience, regions, repo, tag, lang)
	rep.Edition = 1
	if prev := prevRegReport(rep.Key); prev != nil {
		rep.Edition, rep.PrevID, rep.PrevDate = prev.Edition+1, prev.ID, prev.Created
		if rep.Edition < 2 {
			rep.Edition = 2
		}
		rep.Changes = regChanges(prev, rep)
	}
	aud := strings.ToUpper(firstNonEmpty(audience, "all"))
	rep.DocNo = "TL-RR-" + now.Format("2006-0102") + "-" + aud + "-" + strings.ToUpper(lang) + " v" + itoa(rep.Edition)
	date := now.Format("2006-01-02")
	if en {
		rep.FileName = "TrustLink_Regulatory_Report_" + strings.ReplaceAll(firstNonEmpty(regAudNameEn[audience], "All"), " ", "")
	} else {
		rep.FileName = "TrustLink_규제보고서_" + map[string]string{"dev": "개발자용", "admin": "관리자용", "sales": "영업용"}[audience]
		if audience == "all" {
			rep.FileName += "전체"
		}
	}
	if i := strings.Index(rep.FileName, "("); i > 0 { // "Administrators(Ops&Security)" → "Administrators"
		rep.FileName = rep.FileName[:i]
	}
	if repo != "" {
		rep.FileName += "_" + strings.NewReplacer("/", "-", ":", "-").Replace(repo) + "-" + tag
	}
	rep.FileName += "_" + strings.ToUpper(lang) + "_" + date + "_v" + itoa(rep.Edition)
	return rep
}

var regSummarySchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"headline":  map[string]any{"type": "string", "maxLength": 200},
		"points":    map[string]any{"type": "array", "items": map[string]any{"type": "string", "maxLength": 220}, "maxItems": 5},
		"priority":  map[string]any{"type": "array", "items": map[string]any{"type": "string", "maxLength": 220}, "maxItems": 5},
		"citations": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "maxItems": 12},
	},
	"required": []string{"headline", "points", "priority", "citations"},
}

// regReportAI: 보고서 요약(AI 초안). 사실은 규제·요구·상태·일정 목록(공개 정보)만 — 체크리스트 내용은 넣지 않는다.
// 보고서 언어(ko/en)로 쓰고, 연결은 '보고서' 용도 설정을 따른다.
func (s *Server) regReportAI(rep *regReport) {
	en := rep.Lang == "en"
	stName := map[string]string{"met": "충족", "partial": "일부 충족", "unmet": "미충족", "manual": "수동 확인"}
	if en {
		stName = map[string]string{"met": "met", "partial": "partially met", "unmet": "not met", "manual": "manual check"}
	}
	facts := []aiFact{}
	n := 0
	for _, g := range rep.Regs {
		n++
		gid := "G" + itoa(n)
		t := g.NameKo + " (" + firstNonEmpty(rep.RegionNames[g.Region], g.Region) + ", " + g.Binding + ", " + g.Status + ")"
		if g.Next != nil {
			t += map[bool]string{true: " next date ", false: " 다음 일정 "}[en] + g.Next.Date + " " + g.Next.Label
		}
		facts = append(facts, aiFact{ID: gid, Text: t})
		for i, q := range g.Reqs {
			if i >= 4 {
				break
			}
			line := q.Clause + " " + q.Title + " — 상태 " + stName[q.Status] + "; 할 일: " + truncate(firstNonEmpty(q.Action, q.Text), 160)
			if en {
				line = q.Clause + " " + q.Title + " — status " + stName[q.Status] + "; action: " + truncate(firstNonEmpty(q.Action, q.Text), 200)
			}
			facts = append(facts, aiFact{ID: gid + "-" + itoa(i+1), Text: line})
		}
		if len(facts) > 60 {
			break
		}
	}
	task := "위 규제 목록은 " + rep.AudienceKo + " 가 확인할 사항이다. 보고서 첫 쪽 요약을 쓴다.\n" +
		"- headline: 한 문장 결론(가장 시급한 의무와 시점), 90자 이내.\n- points: 핵심 관찰 3~5개, 각 80자 이내.\n- priority: 이 역할이 먼저 할 일 3~5개(시점·규제 이름 포함), 각 80자 이내.\n" +
		"- 각 문장 끝에 근거 사실 ID 를 [G1] 처럼 붙이고 citations 에도 넣는다. 사실에 없는 날짜·조항을 쓰지 않는다."
	if en {
		task = "The regulations above are what the " + rep.AudienceKo + " audience must check. Write the first-page summary of the report.\n" +
			"- headline: one-sentence conclusion (the most urgent obligation and its date), under 40 words.\n- points: 3-5 key observations, each under 40 words.\n" +
			"- priority: 3-5 actions this role should take first (include dates and regulation names), each under 40 words.\n" +
			"- End each sentence with its supporting fact ID like [G1] and also list them in citations. Do not write dates or clauses that are not in the facts."
	}
	var sum regReportSummary
	meta, err := s.aiDraftFor("report", rep.Lang, facts, task, regSummarySchema, 1200, &sum)
	if err != nil {
		rep.AIError = err.Error()
		return
	}
	sum.Points, sum.Priority = capList(sum.Points, 5), capList(sum.Priority, 5)
	sum.Citations = validCitations(sum.Citations, facts)
	rep.Summary, rep.AIMeta = &sum, &meta
}

func capList(l []string, n int) []string {
	if len(l) > n {
		return l[:n]
	}
	return l
}

// POST /api/regs/report {audience, regions, repo, tag, ai, lang}
func (s *Server) apiRegReport(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Audience string   `json:"audience"`
		Regions  []string `json:"regions"`
		Repo     string   `json:"repo"`
		Tag      string   `json:"tag"`
		AI       bool     `json:"ai"`
		Lang     string   `json:"lang"` // ko(기본) / en
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "잘못된 요청"})
		return
	}
	if in.Audience != "all" && !inList(in.Audience, regAudiences) {
		writeJSON(w, 400, map[string]string{"error": "audience 는 dev / admin / sales / all"})
		return
	}
	if in.Lang != "" && in.Lang != "ko" && in.Lang != "en" {
		writeJSON(w, 400, map[string]string{"error": "lang 은 ko / en"})
		return
	}
	if (in.Repo == "") != (in.Tag == "") {
		writeJSON(w, 400, map[string]string{"error": "제품을 고르면 버전도 필요합니다"})
		return
	}
	user := w.Header().Get("X-User")
	rep, err := s.makeRegReport(in.Audience, in.Regions, in.Repo, in.Tag, user, in.Lang, in.AI)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, rep)
}

// makeRegReport: 규제 보고서를 만들어 저장한다(화면과 "묻고 찾기"가 같이 쓴다). ai 면 요약을 뒤에서 채운다.
func (s *Server) makeRegReport(audience string, regions []string, repo, tag, user, lang string, ai bool) (*regReport, error) {
	regMu.Lock()
	c, err := loadCatalog()
	var cc regCatalog
	if err == nil {
		b, _ := json.Marshal(c)
		_ = json.Unmarshal(b, &cc)
	}
	regMu.Unlock()
	if err != nil {
		return nil, err
	}
	regReportMu.Lock() // 판 번호·보고서 ID 가 겹치지 않게(한글·영문을 연달아 요청하는 경우)
	rep := s.buildRegReport(&cc, audience, regions, repo, tag, user, lang)
	path := filepath.Join(regDir(), "reports", rep.ID+".json")
	for i := 2; fileExists(path); i++ {
		rep.ID = "rr-" + time.Now().UTC().Format("20060102-150405") + "-" + itoa(i)
		path = filepath.Join(regDir(), "reports", rep.ID+".json")
	}
	rep.State = "done"
	useAI := ai && aiEnabledFor("report")
	if useAI {
		rep.State = "running"
	}
	_ = os.MkdirAll(filepath.Join(regDir(), "reports"), 0o750)
	_ = writeJSONFile(path, rep)
	regReportMu.Unlock()
	if s.sor != nil {
		_ = s.sor.append(SoREvent{Actor: user, Action: "reg-report", Status: audience, Repo: repo, Tag: tag,
			Detail: map[string]any{"id": rep.ID, "docNo": rep.DocNo, "lang": rep.Lang, "edition": rep.Edition, "regions": regions, "catalogVersion": cc.Version, "ai": useAI}})
	}
	out := *rep // 호출한 쪽에는 지금 상태의 사본을(뒤에서 AI 가 rep 를 고친다)
	if useAI {  // AI 요약은 수 초~수 분 — 뒤에서 채우고 화면은 다시 읽는다
		go func() {
			s.regReportAI(rep)
			rep.State = "done"
			_ = writeJSONFile(path, rep)
		}()
	}
	return &out, nil
}

var regReportMu sync.Mutex

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// GET /api/regs/report/{id}
func (s *Server) apiRegReportGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !regReportIDRe.MatchString(id) {
		writeJSON(w, 400, map[string]string{"error": "잘못된 보고서 ID"})
		return
	}
	var rep regReport
	if err := readJSONFile(filepath.Join(regDir(), "reports", id+".json"), &rep); err != nil {
		writeJSON(w, 404, map[string]string{"error": "보고서 없음"})
		return
	}
	writeJSON(w, 200, rep)
}

// GET /api/regs/reports → 최근 보고서 목록
func (s *Server) apiRegReports(w http.ResponseWriter, r *http.Request) {
	files, _ := filepath.Glob(filepath.Join(regDir(), "reports", "rr-*.json"))
	sort.Sort(sort.Reverse(sort.StringSlice(files)))
	out := []map[string]any{}
	for i, f := range files {
		if i >= 200 {
			break
		}
		var rep regReport
		if readJSONFile(f, &rep) == nil {
			out = append(out, map[string]any{"id": rep.ID, "title": rep.Title, "audienceKo": rep.AudienceKo, "repo": rep.Repo, "tag": rep.Tag,
				"lang": firstNonEmpty(rep.Lang, "ko"), "docNo": rep.DocNo, "edition": rep.Edition, "fileName": rep.FileName,
				"key": rep.Key, "audience": rep.Audience, "regions": rep.Regions, "summary": rep.Summary != nil,
				"created": rep.Created, "createdBy": rep.CreatedBy, "regs": rep.Totals["regs"], "state": rep.State})
		}
	}
	writeJSON(w, 200, out)
}
