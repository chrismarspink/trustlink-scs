package main

// 규제 대응 검증 — 체크리스트(엑셀)를 기준으로 "이 릴리스가 어떤 공급망 규제 대상이며, 무엇이 부족하고, 무엇을 보완할지"를 리포트.
//
// 원칙
//  - 체크리스트 원본(컨설팅사 대외비 문서 등)은 저장소에 넣지 않는다. 관리자가 화면에서 올리면 데이터 볼륨에만 저장된다.
//  - 규제 대상 판정 = 제품 프로필(판매 지역·고객 분야) → 규칙. 항목의 참조문서 열에서 규제를 읽어 대상 항목을 고른다.
//  - 항목 판정 = 릴리스 산출물 증거 점검(규칙). SBOM·서명·VEX·취약점·KEV·EOL·문서를 직접 확인한다.
//    산출물로 판정할 수 없는 항목(조직·교육·프로세스)은 "문서 증거 필요"로 남기고 체크리스트의 자체 평가를 보여 준다.
//  - AI 는 판정하지 않는다. 미충족 항목의 "문제/보완" 설명과 요약만 근거 인용과 함께 쓴다(선택).

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func complianceDir() string { return env("COMPLIANCE_DIR", "/var/lib/trustlink/compliance") }

// ---------- 체크리스트 ----------

type clItem struct {
	ID       string   `json:"id"`
	Stage    string   `json:"stage"`
	Activity string   `json:"activity"`
	Question string   `json:"question"`
	Focus    string   `json:"focus,omitempty"`
	Outputs  string   `json:"outputs,omitempty"`
	Remedy   string   `json:"remedy,omitempty"`
	Roles    []string `json:"roles"` // 개발사·공급사·수요사
	Refs     string   `json:"refs,omitempty"`
	Regs     []string `json:"regs"`               // 참조문서에서 읽은 규제 ID
	SelfEval string   `json:"selfEval,omitempty"` // 체크리스트의 자체 평가(Y/P/N/N/A)
	Status   string   `json:"statusNote,omitempty"`
}

type checklist struct {
	Name       string   `json:"name"`
	ImportedAt string   `json:"importedAt"`
	SHA256     string   `json:"sha256"`
	Sheet      string   `json:"sheet"`
	Items      []clItem `json:"items"`
}

// 규제 식별 — 공개 규제명 기준(체크리스트 문구와 무관).
type regDef struct {
	ID, Name, Scope string
	re              *regexp.Regexp
}

var regDefs = []regDef{
	{"CRA", "EU 사이버복원력법(CRA)", "EU 시장에 디지털 요소 제품 출시", regexp.MustCompile(`\bCRA\b`)},
	{"SSDF", "NIST SSDF(SP 800-218) · 미 연방 자기 증명", "미국 연방기관 납품", regexp.MustCompile(`SSDF|800-218|\b(PO|PS|PW|RV)\.\d+\.\d+`)},
	{"FDA", "미 FDA 의료기기 사이버보안(FD&C 524B)", "미국 의료기기(소프트웨어 포함)", regexp.MustCompile(`FDA`)},
	{"KRFIN", "국내 금융권 SW 공급망 보안", "국내 금융회사 납품", regexp.MustCompile(`금융`)},
	{"CSF", "NIST CSF 2.0", "기본 보안 관리 체계(권고)", regexp.MustCompile(`\bCSF\b`)},
	{"ESF", "CISA·NSA ESF 공급망 가이드", "공급자 보안 실무(권고)", regexp.MustCompile(`\bESF\b`)},
	{"CMMC", "CMMC 2.0 / NIST SP 800-171", "미 국방 조달(CUI 취급)", regexp.MustCompile(`CMMC|800-171`)},
}

func regName(id string) string {
	for _, r := range regDefs {
		if r.ID == id {
			return r.Name
		}
	}
	return id
}

func detectRegs(refs string) []string {
	out := []string{}
	for _, r := range regDefs {
		if r.re.MatchString(refs) {
			out = append(out, r.ID)
		}
	}
	return out
}

// ---------- xlsx 읽기(표준 라이브러리만) ----------

type xlsxSheet struct {
	Name string
	Rows [][]string
}

func colIndex(ref string) int {
	n := 0
	for _, c := range ref {
		if c < 'A' || c > 'Z' {
			break
		}
		n = n*26 + int(c-'A'+1)
	}
	return n - 1
}

func readXLSX(data []byte) ([]xlsxSheet, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, errors.New("xlsx 파일이 아닙니다")
	}
	files := map[string]*zip.File{}
	for _, f := range zr.File {
		files[f.Name] = f
	}
	read := func(name string) ([]byte, error) {
		f := files[name]
		if f == nil {
			return nil, os.ErrNotExist
		}
		if f.UncompressedSize64 > 64<<20 {
			return nil, errors.New("시트가 너무 큽니다")
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(io.LimitReader(rc, 64<<20))
	}
	// 공유 문자열
	var shared []string
	if b, err := read("xl/sharedStrings.xml"); err == nil {
		var sst struct {
			SI []struct {
				T string `xml:"t"`
				R []struct {
					T string `xml:"t"`
				} `xml:"r"`
			} `xml:"si"`
		}
		if err := xml.Unmarshal(b, &sst); err != nil {
			return nil, err
		}
		for _, si := range sst.SI {
			t := si.T
			for _, r := range si.R {
				t += r.T
			}
			shared = append(shared, t)
		}
	}
	// 시트 이름 → 파일
	wb, err := read("xl/workbook.xml")
	if err != nil {
		return nil, errors.New("workbook.xml 없음")
	}
	var w struct {
		Sheets []struct {
			Name string `xml:"name,attr"`
			RID  string `xml:"http://schemas.openxmlformats.org/officeDocument/2006/relationships id,attr"`
		} `xml:"sheets>sheet"`
	}
	if err := xml.Unmarshal(wb, &w); err != nil {
		return nil, err
	}
	rels := map[string]string{}
	if b, err := read("xl/_rels/workbook.xml.rels"); err == nil {
		var rr struct {
			R []struct {
				ID     string `xml:"Id,attr"`
				Target string `xml:"Target,attr"`
			} `xml:"Relationship"`
		}
		_ = xml.Unmarshal(b, &rr)
		for _, r := range rr.R {
			t := strings.TrimPrefix(r.Target, "/")
			if !strings.HasPrefix(t, "xl/") {
				t = path.Join("xl", t)
			}
			rels[r.ID] = t
		}
	}
	out := []xlsxSheet{}
	for _, sh := range w.Sheets {
		b, err := read(rels[sh.RID])
		if err != nil {
			continue
		}
		var ws struct {
			Rows []struct {
				C []struct {
					R  string `xml:"r,attr"`
					T  string `xml:"t,attr"`
					V  string `xml:"v"`
					IS struct {
						T string `xml:"t"`
					} `xml:"is"`
				} `xml:"c"`
			} `xml:"sheetData>row"`
		}
		if err := xml.Unmarshal(b, &ws); err != nil {
			continue
		}
		s := xlsxSheet{Name: sh.Name}
		for _, row := range ws.Rows {
			cells := []string{}
			for _, c := range row.C {
				i := colIndex(c.R)
				if i < 0 || i > 200 {
					continue
				}
				for len(cells) <= i {
					cells = append(cells, "")
				}
				v := c.V
				switch c.T {
				case "s":
					if n, err := strconv.Atoi(c.V); err == nil && n >= 0 && n < len(shared) {
						v = shared[n]
					}
				case "inlineStr":
					v = c.IS.T
				}
				cells[i] = strings.TrimSpace(v)
			}
			s.Rows = append(s.Rows, cells)
		}
		out = append(out, s)
	}
	return out, nil
}

// parseChecklist: 머리글에 "넘버링"(또는 ID)과 "항목"이 있는 시트를 찾아 항목으로 바꾼다.
func parseChecklist(sheets []xlsxSheet) (string, []clItem, error) {
	for _, sh := range sheets {
		for hr := 0; hr < len(sh.Rows) && hr < 6; hr++ {
			col := map[string]int{}
			for i, h := range sh.Rows[hr] {
				h = strings.ReplaceAll(strings.TrimSpace(h), "\n", " ")
				switch {
				case h == "넘버링" || strings.EqualFold(h, "ID") || h == "번호(ID)":
					col["id"] = i
				case strings.HasPrefix(h, "SDLC"):
					col["stage"] = i
				case strings.Contains(h, "보안활동"):
					col["activity"] = i
				case h == "항목" || h == "점검 항목":
					col["question"] = i
				case strings.Contains(h, "주안점"):
					col["focus"] = i
				case h == "산출물":
					col["outputs"] = i
				case h == "대응방안":
					col["remedy"] = i
				case h == "개발사":
					col["dev"] = i
				case h == "공급사":
					col["sup"] = i
				case h == "수요사":
					col["buy"] = i
				case strings.Contains(h, "참조"):
					col["refs"] = i
				case h == "평가":
					col["eval"] = i
				case strings.HasPrefix(h, "이행"):
					col["note"] = i
				}
			}
			if _, ok := col["id"]; !ok {
				continue
			}
			if _, ok := col["question"]; !ok {
				continue
			}
			get := func(row []string, k string) string {
				i, ok := col[k]
				if !ok || i >= len(row) {
					return ""
				}
				return row[i]
			}
			items := []clItem{}
			stage, act := "", ""
			for _, row := range sh.Rows[hr+1:] {
				id := get(row, "id")
				if id == "" || get(row, "question") == "" {
					continue
				}
				if v := get(row, "stage"); v != "" {
					stage = v
				}
				if v := get(row, "activity"); v != "" {
					act = v
				}
				it := clItem{ID: id, Stage: stage, Activity: act, Question: get(row, "question"), Focus: get(row, "focus"),
					Outputs: get(row, "outputs"), Remedy: get(row, "remedy"), Refs: get(row, "refs"),
					SelfEval: strings.ToUpper(get(row, "eval")), Status: get(row, "note"), Roles: []string{}}
				for k, n := range map[string]string{"dev": "개발사", "sup": "공급사", "buy": "수요사"} {
					if strings.TrimSpace(get(row, k)) != "" {
						it.Roles = append(it.Roles, n)
					}
				}
				sort.Strings(it.Roles)
				it.Regs = detectRegs(it.Refs)
				items = append(items, it)
			}
			if len(items) > 0 {
				return sh.Name, items, nil
			}
		}
	}
	return "", nil, errors.New("체크리스트 시트를 찾지 못했습니다(머리글에 '넘버링'·'항목' 열 필요)")
}

func (s *Server) loadChecklist() (*checklist, error) {
	var c checklist
	if err := readJSONFile(filepath.Join(complianceDir(), "checklist.json"), &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// PUT /api/compliance/checklist?name=파일명  (본문 = xlsx)
func (s *Server) apiComplianceUpload(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 20<<20))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "파일이 너무 큽니다(20MB)"})
		return
	}
	sheets, err := readXLSX(data)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	sheet, items, err := parseChecklist(sheets)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	c := checklist{Name: filepath.Base(firstNonEmpty(r.URL.Query().Get("name"), "checklist.xlsx")), ImportedAt: time.Now().UTC().Format(time.RFC3339),
		SHA256: sha256hex(data), Sheet: sheet, Items: items}
	if err := os.MkdirAll(complianceDir(), 0o700); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if err := writeJSONFile(filepath.Join(complianceDir(), "checklist.json"), c); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_ = s.sor.append(SoREvent{Actor: w.Header().Get("X-User"), Action: "compliance-checklist", Status: "imported",
		Detail: map[string]any{"name": c.Name, "sha256": c.SHA256, "items": len(items)}})
	writeJSON(w, 200, checklistSummary(&c))
}

func checklistSummary(c *checklist) map[string]any {
	regs := map[string]int{}
	stages := map[string]int{}
	for _, it := range c.Items {
		for _, g := range it.Regs {
			regs[g]++
		}
		stages[it.Stage]++
	}
	return map[string]any{"name": c.Name, "importedAt": c.ImportedAt, "sha256": c.SHA256, "sheet": c.Sheet,
		"items": len(c.Items), "regs": regs, "stages": stages}
}

// ---------- 제품 프로필 → 적용 규제 ----------

type compProfile struct {
	Markets []string `json:"markets"` // eu, us_fed, us_def, us_med, kr_fin
	Note    string   `json:"note,omitempty"`
}

var marketRegs = map[string][]string{
	"eu":     {"CRA"},
	"us_fed": {"SSDF"},
	"us_def": {"CMMC", "SSDF"},
	"us_med": {"FDA"},
	"kr_fin": {"KRFIN"},
}
var marketName = map[string]string{
	"eu": "EU 판매", "us_fed": "미국 연방기관 납품", "us_def": "미 국방 조달", "us_med": "미국 의료기기", "kr_fin": "국내 금융권 납품",
}

type appliedReg struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Basis    string `json:"basis"` // 왜 대상인지
	Mandate  bool   `json:"mandate"`
	Items    int    `json:"items"`              // 체크리스트에서 이 규제를 근거로 한 항목 수
	NoSource bool   `json:"noSource,omitempty"` // 체크리스트에 근거 항목 없음
}

func applicableRegs(p compProfile, c *checklist) []appliedReg {
	count := map[string]int{}
	for _, it := range c.Items {
		for _, g := range it.Regs {
			count[g]++
		}
	}
	seen := map[string]bool{}
	out := []appliedReg{}
	for _, m := range p.Markets {
		for _, g := range marketRegs[m] {
			if seen[g] {
				continue
			}
			seen[g] = true
			out = append(out, appliedReg{ID: g, Name: regName(g), Basis: marketName[m], Mandate: true, Items: count[g], NoSource: count[g] == 0})
		}
	}
	for _, g := range []string{"CSF", "ESF"} {
		if !seen[g] && count[g] > 0 {
			out = append(out, appliedReg{ID: g, Name: regName(g), Basis: "기본 관리 체계(권고)", Items: count[g]})
		}
	}
	return out
}

// ---------- 산출물 증거 점검(규칙) ----------

type evCheck struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Result string `json:"result"` // pass | partial | fail | na
	Value  string `json:"value"`
	Fix    string `json:"fix,omitempty"` // 미충족 시 보완 방법(결정론)
}

type sbomStats struct {
	Format, Spec                                  string
	Total, WithPurl, WithVersion, WithLic, WithSp int
	Comps                                         []sbomComp
}
type sbomComp struct{ Name, Version, Purl string }

func parseSBOMStats(b []byte) sbomStats {
	var st sbomStats
	var cdx struct {
		BomFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Components  []struct {
			Name      string                 `json:"name"`
			Version   string                 `json:"version"`
			Purl      string                 `json:"purl"`
			Licenses  []json.RawMessage      `json:"licenses"`
			Supplier  *struct{ Name string } `json:"supplier"`
			Publisher string                 `json:"publisher"`
			Author    string                 `json:"author"`
			Authors   []json.RawMessage      `json:"authors"`
		} `json:"components"`
	}
	if json.Unmarshal(b, &cdx) == nil && cdx.BomFormat != "" {
		st.Format, st.Spec = "CycloneDX", cdx.SpecVersion
		for _, c := range cdx.Components {
			st.Total++
			st.Comps = append(st.Comps, sbomComp{c.Name, c.Version, c.Purl})
			if c.Purl != "" {
				st.WithPurl++
			}
			if c.Version != "" {
				st.WithVersion++
			}
			if len(c.Licenses) > 0 {
				st.WithLic++
			}
			if (c.Supplier != nil && c.Supplier.Name != "") || c.Publisher != "" || c.Author != "" || len(c.Authors) > 0 {
				st.WithSp++
			}
		}
		return st
	}
	var spdx struct {
		SpdxVersion string `json:"spdxVersion"`
		Packages    []struct {
			Name         string `json:"name"`
			VersionInfo  string `json:"versionInfo"`
			Supplier     string `json:"supplier"`
			LicConcluded string `json:"licenseConcluded"`
			LicDeclared  string `json:"licenseDeclared"`
			ExternalRefs []struct {
				Type    string `json:"referenceType"`
				Locator string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
	}
	if json.Unmarshal(b, &spdx) == nil && spdx.SpdxVersion != "" {
		st.Format, st.Spec = "SPDX", strings.TrimPrefix(spdx.SpdxVersion, "SPDX-")
		for _, p := range spdx.Packages {
			st.Total++
			purl := ""
			for _, e := range p.ExternalRefs {
				if e.Type == "purl" {
					purl = e.Locator
				}
			}
			st.Comps = append(st.Comps, sbomComp{p.Name, p.VersionInfo, purl})
			if purl != "" {
				st.WithPurl++
			}
			if p.VersionInfo != "" {
				st.WithVersion++
			}
			if okLic(p.LicConcluded) || okLic(p.LicDeclared) {
				st.WithLic++
			}
			if p.Supplier != "" && p.Supplier != "NOASSERTION" {
				st.WithSp++
			}
		}
	}
	return st
}

func okLic(s string) bool { return s != "" && s != "NOASSERTION" && s != "NONE" }

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) * 100 / float64(b)
}

func grade(p, pass, part float64) string {
	switch {
	case p >= pass:
		return "pass"
	case p >= part:
		return "partial"
	}
	return "fail"
}

// eolHits: endoflife.date 사본(미러)으로 지원 종료 구성요소를 찾는다(purl 일치 + 릴리스 주기 접두 일치).
func eolHits(comps []sbomComp) ([]string, bool) {
	v, _, ok := cachedLoad(&eolCache, mirrorDataPath("endoflife.date", "/api/v1/products/full"), func(b []byte) (any, error) {
		var d struct {
			Result []eolProduct `json:"result"`
		}
		if err := json.Unmarshal(b, &d); err != nil || d.Result == nil {
			var arr []eolProduct
			if err2 := json.Unmarshal(b, &arr); err2 != nil {
				return nil, err
			}
			return arr, nil
		}
		return d.Result, nil
	})
	if !ok {
		return nil, false
	}
	prods := v.([]eolProduct)
	byPurl := map[string]*eolProduct{}
	for i := range prods {
		for _, id := range prods[i].Identifiers {
			if id.Type == "purl" {
				byPurl[strings.ToLower(id.ID)] = &prods[i]
			}
		}
	}
	hits := []string{}
	for _, c := range comps {
		base := strings.ToLower(c.Purl)
		if i := strings.IndexAny(base, "@?#"); i > 0 {
			base = base[:i]
		}
		p := byPurl[base]
		if p == nil || c.Version == "" {
			continue
		}
		best := ""
		var rel *eolRelease
		for i := range p.Releases {
			n := p.Releases[i].Name
			if (c.Version == n || strings.HasPrefix(c.Version, n+".")) && len(n) > len(best) {
				best, rel = n, &p.Releases[i]
			}
		}
		if rel != nil && rel.IsEol {
			hits = append(hits, fmt.Sprintf("%s %s (%s %s 주기 지원 종료 %s)", c.Name, c.Version, p.Label, rel.Name, rel.EolFrom))
		}
	}
	return hits, true
}

type eolRelease struct {
	Name    string `json:"name"`
	IsEol   bool   `json:"isEol"`
	EolFrom string `json:"eolFrom"`
}
type eolProduct struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Identifiers []struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"identifiers"`
	Releases []eolRelease `json:"releases"`
}

// releaseEvidence: 릴리스(repo:tag)의 산출물 증거를 규칙으로 점검한다.
func (s *Server) releaseEvidence(repo, tag string) ([]evCheck, map[string]string) {
	info := map[string]string{}
	kinds := map[string][]ociDesc{}
	mr, err := s.zotGetSvc("/v2/"+repo+"/manifests/"+tag, acceptManifest)
	if err == nil {
		dig := mr.Header.Get("Docker-Content-Digest")
		mr.Body.Close()
		info["digest"] = dig
		if dig != "" {
			if rr, err := s.zotGetSvc("/v2/"+repo+"/referrers/"+dig, ""); err == nil {
				var idx ociIndex
				_ = json.NewDecoder(rr.Body).Decode(&idx)
				rr.Body.Close()
				for _, ref := range idx.Manifests {
					k := kindDir(ref.ArtifactType, "")
					kinds[k] = append(kinds[k], ref)
				}
			}
		}
	}
	latest := func(k string) string {
		best, at := "", ""
		for _, d := range kinds[k] {
			if c := d.Annotations["org.opencontainers.image.created"]; best == "" || c > at {
				best, at = d.Digest, c
			}
		}
		return best
	}
	checks := []evCheck{}
	add := func(c evCheck) { checks = append(checks, c) }

	// SBOM
	var st sbomStats
	if d := latest("sbom"); d != "" {
		st = parseSBOMStats(s.svcReferrerBlob(repo, d))
	}
	if st.Format == "" {
		add(evCheck{ID: "sbom.present", Name: "SBOM 첨부", Result: "fail", Value: "없음", Fix: "릴리스에 CycloneDX 또는 SPDX SBOM 을 첨부합니다(제품 화면의 'SBOM 생성' 사용 가능)."})
	} else {
		add(evCheck{ID: "sbom.present", Name: "SBOM 첨부", Result: "pass", Value: fmt.Sprintf("%s %s · 구성요소 %d개", st.Format, st.Spec, st.Total)})
		fr := "pass"
		if (st.Format == "CycloneDX" && cmpVersion(st.Spec, "1.4") < 0) || (st.Format == "SPDX" && cmpVersion(st.Spec, "2.2") < 0) {
			fr = "partial"
		}
		add(evCheck{ID: "sbom.format", Name: "SBOM 표준 형식", Result: fr, Value: st.Format + " " + st.Spec, Fix: "CycloneDX 1.4 이상 또는 SPDX 2.2 이상으로 다시 생성합니다."})
		idp := pct(min(st.WithPurl, st.WithVersion), st.Total)
		add(evCheck{ID: "sbom.identity", Name: "구성요소 식별자(버전·purl)", Result: grade(idp, 95, 70), Value: fmt.Sprintf("purl %.0f%% · 버전 %.0f%%", pct(st.WithPurl, st.Total), pct(st.WithVersion, st.Total)),
			Fix: "purl·버전이 빠진 구성요소를 보완합니다(빌드 시 패키지 관리자 기반 SBOM 생성 권장)."})
		add(evCheck{ID: "sbom.supplier", Name: "공급자 정보", Result: grade(pct(st.WithSp, st.Total), 80, 30), Value: fmt.Sprintf("%.0f%%", pct(st.WithSp, st.Total)),
			Fix: "구성요소별 공급자(supplier/author)를 채웁니다 — 최소 요소(NTIA)·CRA 부속서 요구."})
		add(evCheck{ID: "sbom.license", Name: "라이선스 정보", Result: grade(pct(st.WithLic, st.Total), 90, 50), Value: fmt.Sprintf("%.0f%%", pct(st.WithLic, st.Total)),
			Fix: "라이선스가 빠진 구성요소를 확인해 SBOM 에 기재합니다."})
	}
	// 서명
	if n := len(kinds["signature"]); n > 0 {
		add(evCheck{ID: "sign.present", Name: "릴리스 서명", Result: "pass", Value: fmt.Sprintf("서명 %d건", n)})
	} else {
		add(evCheck{ID: "sign.present", Name: "릴리스 서명", Result: "fail", Value: "없음", Fix: "cosign/notation 으로 릴리스에 서명을 첨부하고 공개키·검증 방법을 고객에게 안내합니다."})
	}
	// VEX
	if n := len(kinds["vex"]); n > 0 {
		add(evCheck{ID: "vex.present", Name: "VEX 발행", Result: "pass", Value: fmt.Sprintf("발행 %d건(최신 1건 기준 판정)", n)})
	} else {
		add(evCheck{ID: "vex.present", Name: "VEX 발행", Result: "fail", Value: "없음", Fix: "취약점 분석 후 VEX 를 발행합니다(제품 화면 'VEX 발행')."})
	}
	// 문서
	if n := len(kinds["docs"]); n > 0 {
		add(evCheck{ID: "docs.present", Name: "사용자·보안 문서", Result: "pass", Value: fmt.Sprintf("%d건", n)})
	} else {
		add(evCheck{ID: "docs.present", Name: "사용자·보안 문서", Result: "fail", Value: "없음", Fix: "설치·보안 설정·업데이트 방법을 담은 매뉴얼을 릴리스에 첨부합니다."})
	}
	// 취약점(DT)
	name := repo[strings.LastIndex(repo, "/")+1:]
	var fs []dtFindingFull
	dtOK := false
	if s.dtEnabled() {
		if uuid, err := s.dtLookupProject(name, tag); err == nil && uuid != "" {
			if raw, err := s.dtFindings(uuid); err == nil && json.Unmarshal(raw, &fs) == nil {
				dtOK = true
			}
		}
	}
	if !dtOK {
		add(evCheck{ID: "vuln.triaged", Name: "취약점 판단 완료", Result: "na", Value: "분석 결과 없음(SBOM 미첨부 또는 분석 전)", Fix: "SBOM 을 첨부해 취약점 분석을 실행합니다."})
	} else {
		done, open, kevOpen := 0, 0, []string{}
		kidx, _, kok := kevIndex()
		for _, f := range fs {
			stt := strings.ToUpper(f.Analysis.State)
			resolved := stt == "NOT_AFFECTED" || stt == "FALSE_POSITIVE" || stt == "RESOLVED"
			if stt != "" && stt != "NOT_SET" && stt != "IN_TRIAGE" {
				done++
			}
			sev := strings.ToUpper(f.Vulnerability.Severity)
			if !resolved && (sev == "CRITICAL" || sev == "HIGH") {
				open++
			}
			if kok && !resolved {
				if _, hit := kidx[strings.ToUpper(f.Vulnerability.VulnID)]; hit {
					kevOpen = append(kevOpen, f.Vulnerability.VulnID+"("+f.Component.Name+")")
				}
			}
		}
		info["findings"] = strconv.Itoa(len(fs))
		r := "pass"
		if len(fs) > 0 {
			r = grade(pct(done, len(fs)), 95, 50)
		}
		add(evCheck{ID: "vuln.triaged", Name: "취약점 판단 완료", Result: r, Value: fmt.Sprintf("%d/%d건 판단", done, len(fs)), Fix: "미판단 취약점을 VEX 로 분류합니다(AI 초안 사용 가능)."})
		r = "pass"
		if open > 0 {
			r = "fail"
		}
		add(evCheck{ID: "vuln.critical", Name: "미해결 CRITICAL·HIGH", Result: r, Value: fmt.Sprintf("%d건", open), Fix: "해당 구성요소를 패치 버전으로 올리거나 영향 없음 근거를 VEX 로 기록합니다."})
		if !kok {
			add(evCheck{ID: "vuln.kev", Name: "실제 악용(KEV) 미해결", Result: "na", Value: "KEV 사본 없음(미러 확인)"})
		} else {
			r = "pass"
			if len(kevOpen) > 0 {
				r = "fail"
			}
			add(evCheck{ID: "vuln.kev", Name: "실제 악용(KEV) 미해결", Result: r, Value: firstNonEmpty(truncate(strings.Join(kevOpen, ", "), 200), "0건"),
				Fix: "KEV 등재 취약점은 최우선으로 패치하고 고객에게 통보합니다(CRA 는 실제 악용 취약점 24시간 내 조기 경보 의무)."})
		}
	}
	// EOL
	if st.Format != "" {
		if hits, ok := eolHits(st.Comps); !ok {
			add(evCheck{ID: "comp.eol", Name: "지원 종료(EOL) 구성요소", Result: "na", Value: "EOL 사본 없음(미러 확인)"})
		} else if len(hits) > 0 {
			add(evCheck{ID: "comp.eol", Name: "지원 종료(EOL) 구성요소", Result: "fail", Value: truncate(strings.Join(hits, "; "), 300), Fix: "지원 중인 버전으로 교체하거나 교체 계획·위험 수용 근거를 남깁니다."})
		} else {
			add(evCheck{ID: "comp.eol", Name: "지원 종료(EOL) 구성요소", Result: "pass", Value: "0건(purl 일치 기준)"})
		}
	}
	// 판정 기준 DB
	if snap := s.mirrorSnapshot(); snap != "" {
		info["dbSnapshot"] = snap
		_, t, ok := kevIndex()
		r, v := "pass", "스냅샷 "+snap[:min(12, len(snap))]
		if ok && time.Since(t) > 72*time.Hour {
			r, v = "partial", v+" · KEV 사본 "+t.UTC().Format("2006-01-02")+"(3일 초과)"
		}
		add(evCheck{ID: "db.fresh", Name: "판정 기준 취약점 DB", Result: r, Value: v, Fix: "취약점 DB 미러를 최신으로 받습니다."})
	} else {
		add(evCheck{ID: "db.fresh", Name: "판정 기준 취약점 DB", Result: "na", Value: "미러 없음 — 판정 시점 DB 를 증명할 수 없음"})
	}
	return checks, info
}

// 항목 문구 → 관련 증거 점검(일반 보안 용어 기준. 특정 체크리스트에 묶이지 않는다).
// q 는 항목(요구사항) 문구에, o 는 산출물 열에 적용한다. 산출물 열은 "취약점·무결성" 같은 일반어가
// 프로세스 문서에도 흔해, 산출물을 직접 가리키는 말(SBOM·서명·VEX·매뉴얼 등)만 본다.
var itemRules = []struct {
	q, o   *regexp.Regexp
	checks []string
}{
	{regexp.MustCompile(`(?i)SBOM|소프트웨어 구성|구성요소 목록|자재명세`), regexp.MustCompile(`(?i)SBOM|자재명세`), []string{"sbom.present", "sbom.format", "sbom.identity", "sbom.supplier"}},
	{regexp.MustCompile(`라이선스|라이센스`), regexp.MustCompile(`라이선스|라이센스`), []string{"sbom.license"}},
	{regexp.MustCompile(`서명|무결성|위변조|해시|진본`), regexp.MustCompile(`서명`), []string{"sign.present"}},
	{regexp.MustCompile(`(?i)VEX|악용 가능`), regexp.MustCompile(`(?i)VEX`), []string{"vex.present"}},
	{regexp.MustCompile(`취약점`), nil, []string{"vuln.triaged", "vuln.critical", "vuln.kev", "db.fresh"}},
	{regexp.MustCompile(`(?i)EOL|지원 ?종료|단종|유지보수 종료|지원 기간`), regexp.MustCompile(`(?i)EOL|지원 ?종료`), []string{"comp.eol"}},
	{regexp.MustCompile(`매뉴얼|설명서|사용자 안내|설치 안내|보안 설정 안내|사용 지침`), regexp.MustCompile(`매뉴얼|설명서`), []string{"docs.present"}},
}

func itemChecks(it clItem) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, r := range itemRules {
		if r.q.MatchString(it.Question) || (r.o != nil && r.o.MatchString(it.Outputs)) {
			for _, c := range r.checks {
				if !seen[c] {
					seen[c] = true
					out = append(out, c)
				}
			}
		}
	}
	return out
}

type itemResult struct {
	ID       string   `json:"id"`
	Stage    string   `json:"stage"`
	Activity string   `json:"activity"`
	Question string   `json:"question"`
	Roles    []string `json:"roles"`
	Regs     []string `json:"regs"`
	Side     string   `json:"side"`   // supplier(공급자 의무) | buyer(원청 확인)
	Result   string   `json:"result"` // met | partial | unmet | doc(문서 증거 필요)
	Checks   []string `json:"checks"`
	SelfEval string   `json:"selfEval,omitempty"`
	Problem  string   `json:"problem,omitempty"` // AI(선택) 또는 결정론
	Remedy   string   `json:"remedy,omitempty"`
	AICites  []string `json:"aiCitations,omitempty"`
	Source   string   `json:"source,omitempty"` // rule | ai
}

func judgeItem(it clItem, ev map[string]evCheck) itemResult {
	ir := itemResult{ID: it.ID, Stage: it.Stage, Activity: it.Activity, Question: it.Question, Roles: it.Roles, Regs: it.Regs, SelfEval: it.SelfEval, Side: "supplier"}
	if !inList("개발사", it.Roles) && !inList("공급사", it.Roles) {
		ir.Side = "buyer"
	}
	pass, fail, n := 0, 0, 0
	fixes := []string{}
	probs := []string{}
	for _, c := range itemChecks(it) {
		e, ok := ev[c]
		if !ok || e.Result == "na" {
			continue
		}
		ir.Checks = append(ir.Checks, c)
		n++
		switch e.Result {
		case "pass":
			pass++
		case "fail":
			fail++
			fallthrough
		default:
			probs = append(probs, e.Name+": "+e.Value)
			if e.Fix != "" && !inList(e.Fix, fixes) {
				fixes = append(fixes, e.Fix)
			}
		}
	}
	switch {
	case n == 0:
		ir.Result = "doc"
	case pass == n:
		ir.Result = "met"
	case fail == n:
		ir.Result = "unmet"
	default:
		ir.Result = "partial"
	}
	if len(probs) > 0 {
		ir.Problem = strings.Join(probs, " / ")
		ir.Remedy = strings.Join(fixes, " ")
		ir.Source = "rule"
	}
	return ir
}

// ---------- 리포트 ----------

type compReport struct {
	ID          string            `json:"id"`
	Repo        string            `json:"repo"`
	Tag         string            `json:"tag"`
	CreatedAt   string            `json:"createdAt"`
	CreatedBy   string            `json:"createdBy"`
	Checklist   string            `json:"checklist"`
	ChecklistSH string            `json:"checklistSha256"`
	Profile     compProfile       `json:"profile"`
	Regs        []appliedReg      `json:"regs"`
	Evidence    []evCheck         `json:"evidence"`
	Info        map[string]string `json:"info"`
	Items       []itemResult      `json:"items"`
	Counts      map[string]int    `json:"counts"`
	Summary     *compSummary      `json:"summary,omitempty"`
	AI          *aiMeta           `json:"ai,omitempty"`
	AIError     string            `json:"aiError,omitempty"`
	State       string            `json:"state"` // running | done | error
	Progress    string            `json:"progress,omitempty"`
	SHA256      string            `json:"sha256,omitempty"`
}

type compSummary struct {
	Summary string `json:"summary"`
	Risks   []struct {
		Title     string   `json:"title"`
		Detail    string   `json:"detail"`
		Citations []string `json:"citations"`
	} `json:"risks"`
	Actions []struct {
		Priority  string   `json:"priority"`
		Action    string   `json:"action"`
		Citations []string `json:"citations"`
	} `json:"actions"`
}

var (
	compMu   sync.Mutex
	compJobs = map[string]*compReport{}
)

func (s *Server) buildReport(rep *compReport, c *checklist, useAI bool) {
	set := func(p string) { compMu.Lock(); rep.Progress = p; compMu.Unlock() }
	set("산출물 증거 점검")
	ev, info := s.releaseEvidence(rep.Repo, rep.Tag)
	evm := map[string]evCheck{}
	for _, e := range ev {
		evm[e.ID] = e
	}
	regs := applicableRegs(rep.Profile, c)
	want := map[string]bool{}
	for _, g := range regs {
		want[g.ID] = true
	}
	items := []itemResult{}
	counts := map[string]int{}
	for _, it := range c.Items {
		hit := false
		for _, g := range it.Regs {
			if want[g] {
				hit = true
			}
		}
		if !hit {
			continue
		}
		ir := judgeItem(it, evm)
		items = append(items, ir)
		counts[ir.Side+"."+ir.Result]++
	}
	compMu.Lock()
	rep.Regs, rep.Evidence, rep.Info, rep.Items, rep.Counts = regs, ev, info, items, counts
	compMu.Unlock()

	if useAI && aiEnabled() && aiConf().Mode == "external" && !aiConf().SendChecklist {
		compMu.Lock()
		rep.AIError = "외부 LLM 사용 중 — 체크리스트 외부 전송이 허용되지 않아 AI 요약을 건너뛰었습니다(관리 콘솔 › AI 연결)"
		compMu.Unlock()
	} else if useAI && aiEnabled() {
		if err := s.reportAI(rep, c, set); err != nil {
			compMu.Lock()
			rep.AIError = err.Error()
			compMu.Unlock()
		}
	}
	compMu.Lock()
	rep.State, rep.Progress = "done", ""
	b, _ := json.Marshal(rep)
	rep.SHA256 = sha256hex(b)
	compMu.Unlock()
	_ = writeJSONFile(filepath.Join(complianceDir(), "reports", rep.ID+".json"), rep)
	d := map[string]any{"report": rep.ID, "sha256": rep.SHA256, "checklistSha256": rep.ChecklistSH, "regs": regIDs(regs), "counts": counts, "dbSnapshot": info["dbSnapshot"]}
	if rep.AI != nil {
		d["model"] = rep.AI.Model
	}
	_ = s.sor.append(SoREvent{Actor: rep.CreatedBy, Action: "compliance-report", Status: "done", Repo: rep.Repo, Tag: rep.Tag, Detail: d})
}

func regIDs(r []appliedReg) []string {
	out := []string{}
	for _, g := range r {
		out = append(out, g.ID)
	}
	return out
}

var gapSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{"items": map[string]any{"type": "array", "items": map[string]any{
		"type": "object",
		"properties": map[string]any{
			"id":        map[string]any{"type": "string"},
			"problem":   map[string]any{"type": "string", "maxLength": 300},
			"remedy":    map[string]any{"type": "string", "maxLength": 400},
			"citations": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "minItems": 1, "maxItems": 6},
		},
		"required": []string{"id", "problem", "remedy", "citations"},
	}}},
	"required": []string{"items"},
}

var summarySchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"summary": map[string]any{"type": "string", "maxLength": 900},
		"risks": map[string]any{"type": "array", "maxItems": 4, "items": map[string]any{"type": "object",
			"properties": map[string]any{"title": map[string]any{"type": "string", "maxLength": 80}, "detail": map[string]any{"type": "string", "maxLength": 300},
				"citations": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "minItems": 1}},
			"required": []string{"title", "detail", "citations"}}},
		"actions": map[string]any{"type": "array", "maxItems": 5, "items": map[string]any{"type": "object",
			"properties": map[string]any{"priority": map[string]any{"type": "string", "enum": []string{"P1", "P2", "P3"}}, "action": map[string]any{"type": "string", "maxLength": 200},
				"citations": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "minItems": 1}},
			"required": []string{"priority", "action", "citations"}}},
	},
	"required": []string{"summary", "risks", "actions"},
}

// reportAI: 미충족 항목 설명(묶음당 4개) + 요약. 항목 판정 자체는 바꾸지 않는다.
func (s *Server) reportAI(rep *compReport, c *checklist, set func(string)) error {
	evFacts := []aiFact{}
	for _, e := range rep.Evidence {
		evFacts = append(evFacts, aiFact{ID: "E-" + e.ID, Text: fmt.Sprintf("%s: %s (%s)", e.Name, e.Value, map[string]string{"pass": "충족", "partial": "일부", "fail": "미충족", "na": "확인 불가"}[e.Result])})
	}
	byID := map[string]clItem{}
	for _, it := range c.Items {
		byID[it.ID] = it
	}
	gaps := []int{}
	for i, ir := range rep.Items {
		if ir.Side == "supplier" && (ir.Result == "unmet" || ir.Result == "partial") {
			gaps = append(gaps, i)
		}
	}
	if len(gaps) > 16 {
		gaps = gaps[:16]
	}
	failed := []string{}
	defer func() {
		if len(failed) > 0 {
			compMu.Lock()
			rep.AIError = firstNonEmpty(rep.AIError, "일부 항목 AI 설명 실패(규칙 설명 유지): "+strings.Join(failed, " / "))
			compMu.Unlock()
		}
	}()
	for b := 0; b < len(gaps); b += 4 {
		set(fmt.Sprintf("AI 보완 설명 작성 %d/%d", b, len(gaps)))
		batch := gaps[b:min(b+4, len(gaps))]
		facts := []aiFact{}
		need := map[string]bool{}
		ids := []string{}
		for _, i := range batch {
			ir := rep.Items[i]
			it := byID[ir.ID]
			facts = append(facts, aiFact{ID: "I-" + ir.ID, Text: "점검 항목 " + ir.ID + ": " + truncate(it.Question, 220) + " / 요구 산출물: " + truncate(it.Outputs, 200)})
			for _, ck := range ir.Checks {
				need["E-"+ck] = true
			}
			ids = append(ids, ir.ID)
		}
		for _, f := range evFacts {
			if need[f.ID] {
				facts = append(facts, f)
			}
		}
		task := "다음 점검 항목(" + strings.Join(ids, ", ") + ") 각각에 대해, 증거 점검(E-) 결과를 근거로 problem(무엇이 부족한지 1~2문장)과 remedy(이 릴리스에서 할 보완 조치 1~3문장)를 쓴다. 항목 ID 는 그대로 쓴다. citations 에는 해당 I- 와 E- 사실 ID 를 넣는다."
		var out struct {
			Items []struct {
				ID        string   `json:"id"`
				Problem   string   `json:"problem"`
				Remedy    string   `json:"remedy"`
				Citations []string `json:"citations"`
			} `json:"items"`
		}
		if _, err := s.aiDraft(facts, task, gapSchema, 1600, &out); err != nil {
			failed = append(failed, strings.Join(ids, ","))
			if len(failed) >= 2 && len(failed)*4 >= len(gaps) {
				return err // 대부분 실패 — AI 서버 문제로 보고 중단
			}
			continue // 이 묶음은 규칙 설명 유지
		}
		for _, o := range out.Items {
			o.ID = strings.TrimPrefix(strings.Trim(strings.TrimSpace(o.ID), "[]"), "I-")
			cites := validCitations(o.Citations, facts)
			if len(cites) == 0 || strings.TrimSpace(o.Remedy) == "" {
				continue // 근거 없는 설명은 버리고 규칙 설명 유지
			}
			for _, i := range batch {
				if rep.Items[i].ID == o.ID {
					compMu.Lock()
					rep.Items[i].Problem, rep.Items[i].Remedy, rep.Items[i].AICites, rep.Items[i].Source = o.Problem, o.Remedy, cites, "ai"
					compMu.Unlock()
				}
			}
		}
	}
	set("AI 요약 작성")
	facts := []aiFact{}
	for _, g := range rep.Regs {
		t := fmt.Sprintf("적용 규제: %s — 근거: %s", g.Name, g.Basis)
		if g.NoSource {
			t += " (체크리스트에 이 규제를 근거로 한 항목 없음 — 별도 기준 필요)"
		}
		facts = append(facts, aiFact{ID: "R-" + g.ID, Text: t})
	}
	facts = append(facts, evFacts...)
	cn := rep.Counts
	facts = append(facts, aiFact{ID: "N1", Text: fmt.Sprintf("공급자 의무 항목: 충족 %d, 일부 %d, 미충족 %d, 문서 증거 필요 %d", cn["supplier.met"], cn["supplier.partial"], cn["supplier.unmet"], cn["supplier.doc"])})
	facts = append(facts, aiFact{ID: "N2", Text: fmt.Sprintf("원청 확인 항목: 충족 %d, 일부 %d, 미충족 %d, 문서 증거 필요 %d", cn["buyer.met"], cn["buyer.partial"], cn["buyer.unmet"], cn["buyer.doc"])})
	task := rep.Repo + ":" + rep.Tag + " 릴리스의 규제 대응 검증 요약을 쓴다. summary: 어떤 규제 대상인지와 전체 상태(4~6문장). risks: 가장 중요한 문제(최대 4개). actions: 이 릴리스에서 실제로 할 구체적 보완 조치(예: 'log4j-core 를 지원 버전으로 교체', '릴리스 서명 첨부')를 급한 순서로 P1~P3 와 함께 최대 5개. 미충족(E-) 사실마다 조치가 하나 이상 있어야 한다. '리포트 작성' 같은 문서 작업은 쓰지 않는다. 모든 항목에 근거 사실 ID 를 citations 로 넣는다."
	var sum compSummary
	meta, err := s.aiDraft(facts, task, summarySchema, 1600, &sum)
	if err != nil {
		return err
	}
	for i := range sum.Risks {
		sum.Risks[i].Citations = validCitations(sum.Risks[i].Citations, facts)
	}
	for i := range sum.Actions {
		sum.Actions[i].Citations = validCitations(sum.Actions[i].Citations, facts)
	}
	meta.Snapshot = rep.Info["dbSnapshot"]
	st := s.aiStatusNow()
	meta.ModelSHA256 = st.SHA256
	if meta.Model == "" {
		meta.Model = st.Model
	}
	compMu.Lock()
	rep.Summary, rep.AI = &sum, &meta
	compMu.Unlock()
	return nil
}

// POST /api/compliance/report {repo, tag, profile, ai}
func (s *Server) apiComplianceRun(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Repo    string      `json:"repo"`
		Tag     string      `json:"tag"`
		Profile compProfile `json:"profile"`
		AI      bool        `json:"ai"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil || in.Repo == "" || in.Tag == "" {
		writeJSON(w, 400, map[string]string{"error": "repo, tag 필수"})
		return
	}
	c, err := s.loadChecklist()
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": "체크리스트를 먼저 올리세요"})
		return
	}
	compMu.Lock()
	for _, j := range compJobs {
		if j.State == "running" {
			compMu.Unlock()
			writeJSON(w, 409, map[string]string{"error": "다른 검증이 진행 중입니다", "id": j.ID})
			return
		}
	}
	id := time.Now().UTC().Format("20060102-150405") + "-" + sha256hex([]byte(in.Repo + in.Tag))[:6]
	rep := &compReport{ID: id, Repo: in.Repo, Tag: in.Tag, CreatedAt: time.Now().UTC().Format(time.RFC3339), CreatedBy: w.Header().Get("X-User"),
		Checklist: c.Name, ChecklistSH: c.SHA256, Profile: in.Profile, State: "running", Progress: "시작"}
	compJobs[id] = rep
	compMu.Unlock()
	// 프로필은 제품별로 기억(다음 검증 기본값)
	profs := map[string]compProfile{}
	pf := filepath.Join(complianceDir(), "profiles.json")
	_ = readJSONFile(pf, &profs)
	profs[in.Repo] = in.Profile
	_ = writeJSONFile(pf, profs)
	go func() {
		defer func() {
			if e := recover(); e != nil {
				compMu.Lock()
				rep.State, rep.AIError = "error", fmt.Sprint(e)
				compMu.Unlock()
			}
		}()
		s.buildReport(rep, c, in.AI)
	}()
	writeJSON(w, 202, map[string]string{"id": id})
}

// GET /api/compliance/report/{id}
func (s *Server) apiComplianceGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	compMu.Lock()
	if j, ok := compJobs[id]; ok {
		b, _ := json.Marshal(j)
		compMu.Unlock()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write(b)
		return
	}
	compMu.Unlock()
	if strings.ContainsAny(id, "/\\.") {
		writeJSON(w, 400, map[string]string{"error": "잘못된 id"})
		return
	}
	var rep compReport
	if err := readJSONFile(filepath.Join(complianceDir(), "reports", id+".json"), &rep); err != nil {
		writeJSON(w, 404, map[string]string{"error": "리포트 없음"})
		return
	}
	if r.URL.Query().Get("format") == "md" {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"compliance-%s.md\"", id))
		w.Write([]byte(reportMarkdown(&rep)))
		return
	}
	writeJSON(w, 200, rep)
}

// GET /api/compliance — 체크리스트 요약, AI 상태, 제품 목록, 저장된 프로필, 최근 리포트
func (s *Server) apiComplianceInfo(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"ai": s.aiStatusNow(), "markets": marketName}
	if c, err := s.loadChecklist(); err == nil {
		out["checklist"] = checklistSummary(c)
	}
	profs := map[string]compProfile{}
	_ = readJSONFile(filepath.Join(complianceDir(), "profiles.json"), &profs)
	out["profiles"] = profs
	prods := []map[string]any{}
	for _, repo := range s.svcCatalog() {
		tags := sortedVersions(s.svcTags(repo))
		if len(tags) > 0 {
			prods = append(prods, map[string]any{"repo": repo, "tags": tags})
		}
	}
	out["products"] = prods
	reps := []map[string]any{}
	ents, _ := os.ReadDir(filepath.Join(complianceDir(), "reports"))
	for i := len(ents) - 1; i >= 0 && len(reps) < 20; i-- {
		var rp compReport
		if readJSONFile(filepath.Join(complianceDir(), "reports", ents[i].Name()), &rp) == nil {
			reps = append(reps, map[string]any{"id": rp.ID, "repo": rp.Repo, "tag": rp.Tag, "createdAt": rp.CreatedAt, "counts": rp.Counts, "ai": rp.AI != nil})
		}
	}
	compMu.Lock()
	for _, j := range compJobs {
		if j.State == "running" {
			out["running"] = map[string]string{"id": j.ID, "progress": j.Progress}
		}
	}
	compMu.Unlock()
	out["reports"] = reps
	writeJSON(w, 200, out)
}

var resultKo = map[string]string{"met": "충족", "partial": "일부", "unmet": "미충족", "doc": "문서 증거 필요", "pass": "충족", "fail": "미충족", "na": "확인 불가"}

func reportMarkdown(r *compReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# 규제 대응 검증 리포트 — %s:%s\n\n", r.Repo, r.Tag)
	fmt.Fprintf(&b, "- 작성: %s (%s)\n- 기준 체크리스트: %s (SHA-256 %s)\n", r.CreatedAt, r.CreatedBy, r.Checklist, r.ChecklistSH)
	if r.Info["digest"] != "" {
		fmt.Fprintf(&b, "- 릴리스 digest: %s\n", r.Info["digest"])
	}
	if r.Info["dbSnapshot"] != "" {
		fmt.Fprintf(&b, "- 취약점 DB 스냅샷: %s\n", r.Info["dbSnapshot"])
	}
	if r.AI != nil {
		fmt.Fprintf(&b, "- AI 초안 모델: %s (SHA-256 %s) — 판정은 규칙, AI 는 설명·요약만 작성\n", r.AI.Model, firstNonEmpty(r.AI.ModelSHA256, "계산 중"))
	}
	fmt.Fprintf(&b, "- 리포트 해시: %s\n\n## 1. 적용 규제\n\n| 규제 | 대상 근거 | 구분 | 체크리스트 항목 |\n|---|---|---|---|\n", r.SHA256)
	for _, g := range r.Regs {
		m := "권고"
		if g.Mandate {
			m = "의무"
		}
		n := strconv.Itoa(g.Items)
		if g.NoSource {
			n = "0 (별도 기준 필요)"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", g.Name, g.Basis, m, n)
	}
	if r.Summary != nil {
		fmt.Fprintf(&b, "\n## 2. 요약 (AI 초안)\n\n%s\n\n", r.Summary.Summary)
		for _, k := range r.Summary.Risks {
			fmt.Fprintf(&b, "- **%s** — %s [%s]\n", k.Title, k.Detail, strings.Join(k.Citations, ", "))
		}
		b.WriteString("\n보완 우선순위\n\n")
		for _, a := range r.Summary.Actions {
			fmt.Fprintf(&b, "- %s %s [%s]\n", a.Priority, a.Action, strings.Join(a.Citations, ", "))
		}
	}
	b.WriteString("\n## 3. 산출물 증거 점검\n\n| 점검 | 결과 | 값 | 보완 |\n|---|---|---|---|\n")
	for _, e := range r.Evidence {
		fix := ""
		if e.Result != "pass" {
			fix = e.Fix
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", e.Name, resultKo[e.Result], e.Value, fix)
	}
	for _, side := range []string{"supplier", "buyer"} {
		title := "4. 공급자(개발사) 의무 항목"
		if side == "buyer" {
			title = "5. 원청이 확인하는 항목"
		}
		fmt.Fprintf(&b, "\n## %s\n\n| ID | 결과 | 규제 | 문제 | 보완 |\n|---|---|---|---|---|\n", title)
		for _, it := range r.Items {
			if it.Side != side {
				continue
			}
			res := resultKo[it.Result]
			if it.Result == "doc" && it.SelfEval != "" {
				res += " (자체평가 " + it.SelfEval + ")"
			}
			src := ""
			if it.Source == "ai" {
				src = " (AI)"
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s%s |\n", it.ID, res, strings.Join(it.Regs, ","), strings.ReplaceAll(it.Problem, "|", "/"), strings.ReplaceAll(it.Remedy, "|", "/"), src)
		}
	}
	b.WriteString("\n> '문서 증거 필요' 항목은 조직·프로세스 문서로 확인해야 하며 릴리스 산출물만으로 판정하지 않았습니다.\n")
	return b.String()
}
