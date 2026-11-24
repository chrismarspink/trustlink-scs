package main

// AI 기반 VEX 판정·대응
//  ① 우선순위(규칙, AI 아님): KEV 등재 > 공개 익스플로잇·EPSS 10%↑·CRITICAL > HIGH > 나머지. 미러 사본으로 판정.
//  ② 판정·대응 초안(AI): 구성요소·취약점·EPSS·KEV·공개 익스플로잇·OSV 수정 버전·현재 상태·사용 맥락을 사실로 주고
//     CycloneDX 상태/근거(justification)/대응(response)/설명/대응 단계/임시 완화/추가 확인 사항을 JSON 으로 받는다.
//     목표 버전·기한은 규칙이 계산한다(AI 가 쓴 버전 표기는 사실과 대조해 경고).
//     안전장치: 인용 검증, 근거 없는 not_affected → under_investigation, KEV 경고, 수정 버전 없는 update 경고.
//  ③ 일괄 판정: 미분석 항목을 우선순위 순으로 한 건씩(CPU 슬롯 1) 초안 작성 → 결과 파일 보관.
//  초안은 DT 에 쓰지 않는다 — 사람이 화면에서 "초안 적용" 후 직접 저장해야 기록된다.

import (
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

// ---------- 미러 사본 읽기(KEV·EOL) ----------

type kevEntry struct {
	CVE        string `json:"cveID"`
	Vendor     string `json:"vendorProject"`
	Product    string `json:"product"`
	DateAdded  string `json:"dateAdded"`
	Action     string `json:"requiredAction"`
	DueDate    string `json:"dueDate"`
	Ransomware string `json:"knownRansomwareCampaignUse"`
}

type fileCache struct {
	mu    sync.Mutex
	mtime time.Time
	val   any
}

var kevCache, eolCache fileCache

func mirrorDataPath(host, p string) string {
	return filepath.Join(env("MIRROR_DIR", "/mirror"), "data", host, filepath.FromSlash(p))
}

// cachedLoad: 파일 수정 시각이 바뀔 때만 다시 읽는다.
func cachedLoad(c *fileCache, path string, load func([]byte) (any, error)) (any, time.Time, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, time.Time{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.val != nil && fi.ModTime().Equal(c.mtime) {
		return c.val, c.mtime, true
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, time.Time{}, false
	}
	v, err := load(b)
	if err != nil {
		return nil, time.Time{}, false
	}
	c.val, c.mtime = v, fi.ModTime()
	return v, c.mtime, true
}

// kevIndex: CVE → KEV 항목. ok=false 면 미러에 KEV 사본 없음.
func kevIndex() (map[string]kevEntry, time.Time, bool) {
	v, t, ok := cachedLoad(&kevCache, mirrorDataPath("www.cisa.gov", "/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
		func(b []byte) (any, error) {
			var d struct {
				Vulnerabilities []kevEntry `json:"vulnerabilities"`
			}
			if err := json.Unmarshal(b, &d); err != nil {
				return nil, err
			}
			m := make(map[string]kevEntry, len(d.Vulnerabilities))
			for _, e := range d.Vulnerabilities {
				m[strings.ToUpper(e.CVE)] = e
			}
			return m, nil
		})
	if !ok {
		return nil, t, false
	}
	return v.(map[string]kevEntry), t, true
}

// ---------- ① 우선순위 ----------

type vexPrio struct {
	KEV      bool        `json:"kev"`
	KEVAdded string      `json:"kevAdded,omitempty"`
	KEVDue   string      `json:"kevDue,omitempty"`
	Ransom   bool        `json:"ransomware,omitempty"`
	Exploit  bool        `json:"exploit,omitempty"` // 공개 익스플로잇(Exploit-DB·Metasploit·Nuclei)
	Exploits exploitInfo `json:"exploits"`
}

// GET /api/vex/kev?ids=CVE-1,CVE-2 → {available, exploitsAvailable, asOf, items{id: vexPrio}}
func (s *Server) apiVexKEV(w http.ResponseWriter, r *http.Request) {
	idx, t, ok := kevIndex()
	out := map[string]any{"available": ok}
	items := map[string]vexPrio{}
	exAvail := false
	for _, id := range strings.Split(r.URL.Query().Get("ids"), ",") {
		id = strings.ToUpper(strings.TrimSpace(id))
		if id == "" {
			continue
		}
		var p vexPrio
		if e, hit := idx[id]; hit {
			p = vexPrio{KEV: true, KEVAdded: e.DateAdded, KEVDue: e.DueDate, Ransom: strings.EqualFold(e.Ransomware, "Known")}
		}
		ex := exploitsFor([]string{id})
		exAvail = exAvail || ex.Checked
		if ex.Any() {
			p.Exploit, p.Exploits = true, ex
		}
		if p.KEV || p.Exploit {
			items[id] = p
		}
	}
	if ok {
		out["asOf"] = t.UTC().Format(time.RFC3339)
	}
	out["exploitsAvailable"] = exAvail
	out["items"] = items
	writeJSON(w, 200, out)
}

// ---------- ② 판정·대응 초안 ----------

type dtFindingFull struct {
	Component struct {
		UUID    string `json:"uuid"`
		Name    string `json:"name"`
		Group   string `json:"group"`
		Version string `json:"version"`
		Purl    string `json:"purl"`
	} `json:"component"`
	Vulnerability struct {
		UUID            string   `json:"uuid"`
		VulnID          string   `json:"vulnId"`
		Source          string   `json:"source"`
		Severity        string   `json:"severity"`
		Description     string   `json:"description"`
		CvssV3BaseScore *float64 `json:"cvssV3BaseScore"`
		CvssV3Vector    string   `json:"cvssV3Vector"`
		EpssScore       *float64 `json:"epssScore"`
		EpssPercentile  *float64 `json:"epssPercentile"`
		CweID           int      `json:"cweId"`
		CweName         string   `json:"cweName"`
		Aliases         []struct {
			CveID  string `json:"cveId"`
			GhsaID string `json:"ghsaId"`
		} `json:"aliases"`
	} `json:"vulnerability"`
	Analysis struct {
		State string `json:"state"`
	} `json:"analysis"`
}

var vexStates = []string{"under_investigation", "not_affected", "affected", "fixed"}
var vexJusts = []string{"", "component_not_present", "vulnerable_code_not_present", "vulnerable_code_not_in_execute_path",
	"vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist"}
var vexResponses = []string{"", "can_not_fix", "will_not_fix", "update", "rollback", "workaround_available"}

var vexDraftSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"status":        map[string]any{"type": "string", "enum": vexStates},
		"justification": map[string]any{"type": "string", "enum": vexJusts},
		"response":      map[string]any{"type": "string", "enum": vexResponses},
		"detail":        map[string]any{"type": "string", "maxLength": 700},
		"plan":          map[string]any{"type": "array", "items": map[string]any{"type": "string", "maxLength": 200}, "maxItems": 5},
		"workaround":    map[string]any{"type": "string", "maxLength": 300},
		"citations":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "minItems": 1, "maxItems": 8},
		"missing":       map[string]any{"type": "array", "items": map[string]any{"type": "string", "maxLength": 160}, "maxItems": 4},
		"confidence":    map[string]any{"type": "string", "enum": []string{"low", "medium", "high"}},
	},
	"required": []string{"status", "justification", "response", "detail", "plan", "workaround", "citations", "missing", "confidence"},
}

type vexDraft struct {
	Status        string   `json:"status"`
	Justification string   `json:"justification"`
	Response      string   `json:"response"`
	Detail        string   `json:"detail"`
	Plan          []string `json:"plan"`
	Workaround    string   `json:"workaround"`
	Citations     []string `json:"citations"`
	Missing       []string `json:"missing"`
	Confidence    string   `json:"confidence"`
}

// vexSignals: 규칙으로 구한 신호(우선순위·대응 계산용).
type vexSignals struct {
	KEV      bool
	KEVDue   string
	Exploits exploitInfo
	OSV      osvRemedy
}

// vexRemedy: 화면에 보여 줄 규칙 계산 결과(AI 아님).
type vexRemedy struct {
	Priority int         `json:"priority"`
	Target   string      `json:"targetVersion,omitempty"`
	Fixed    []string    `json:"fixedVersions,omitempty"`
	InRange  string      `json:"inRange,omitempty"`
	Source   string      `json:"osvId,omitempty"`
	Ranges   []string    `json:"ranges,omitempty"`
	OSVNote  string      `json:"osvNote,omitempty"`
	DueBy    string      `json:"dueBy,omitempty"` // KEV 조치 기한
	Exploits exploitInfo `json:"exploits"`
}

func vulnIDs(f dtFindingFull) []string {
	ids := []string{strings.ToUpper(f.Vulnerability.VulnID)}
	for _, a := range f.Vulnerability.Aliases {
		for _, x := range []string{a.CveID, a.GhsaID} {
			if x != "" && !inList(strings.ToUpper(x), ids) {
				ids = append(ids, strings.ToUpper(x))
			}
		}
	}
	return ids
}

// vexPriority: 1 KEV, 2 공개 익스플로잇·EPSS 10%↑·CRITICAL, 3 HIGH, 4 나머지 (화면 priority() 와 같은 규칙).
func vexPriority(f dtFindingFull, sig vexSignals) int {
	sev := strings.ToUpper(f.Vulnerability.Severity)
	switch {
	case sig.KEV:
		return 1
	case sig.Exploits.Any() || (f.Vulnerability.EpssScore != nil && *f.Vulnerability.EpssScore >= 0.1) || sev == "CRITICAL":
		return 2
	case sev == "HIGH":
		return 3
	}
	return 4
}

// vexSignalsFor: 미러 사본으로 KEV·익스플로잇·OSV 신호를 모은다(AI 호출 없이도 쓰임).
func vexSignalsFor(f dtFindingFull) vexSignals {
	ids := vulnIDs(f)
	var sig vexSignals
	if idx, _, ok := kevIndex(); ok {
		for _, id := range ids {
			if e, hit := idx[id]; hit {
				sig.KEV, sig.KEVDue = true, e.DueDate
				break
			}
		}
	}
	sig.Exploits = exploitsFor(ids)
	sig.OSV = osvLookup(f.Component.Purl, f.Component.Version, ids)
	return sig
}

// vexFacts: 결정론적으로 모은 사실 목록.
func vexFacts(f dtFindingFull, context string, sig vexSignals) []aiFact {
	c, v := f.Component, f.Vulnerability
	name := c.Name
	if c.Group != "" {
		name = c.Group + "/" + c.Name
	}
	facts := []aiFact{{ID: "C1", Text: "구성요소: " + name + " " + c.Version + " (purl " + firstNonEmpty(c.Purl, "없음") + ")"}}
	vt := "취약점: " + v.VulnID + " (출처 " + v.Source + ", 심각도 " + firstNonEmpty(v.Severity, "미상")
	if v.CvssV3BaseScore != nil {
		vt += ", CVSS v3 " + ftoa(*v.CvssV3BaseScore, 1)
	}
	if v.CvssV3Vector != "" {
		vt += " " + v.CvssV3Vector
	}
	facts = append(facts, aiFact{ID: "V1", Text: vt + ")"})
	if v.CweID > 0 {
		facts = append(facts, aiFact{ID: "V2", Text: "약점 유형: CWE-" + itoa(v.CweID) + " " + v.CweName})
	}
	if d := truncate(v.Description, 1200); d != "" {
		facts = append(facts, aiFact{ID: "V3", Text: "권고문 설명: " + d, Untrusted: true})
	}
	if v.EpssScore != nil {
		t := "EPSS(30일 내 악용 확률): " + ftoa(*v.EpssScore*100, 2) + "%"
		if v.EpssPercentile != nil {
			t += ", 상위 " + ftoa((1-*v.EpssPercentile)*100, 1) + "%"
		}
		facts = append(facts, aiFact{ID: "X1", Text: t})
	}
	if idx, t, ok := kevIndex(); ok {
		txt := "CISA KEV(실제 악용 확인 목록): 미등재 (사본 기준 " + t.UTC().Format("2006-01-02") + ")"
		for _, id := range vulnIDs(f) {
			if e, hit := idx[id]; hit {
				txt = "CISA KEV: 등재됨 — " + id + " 등재일 " + e.DateAdded + ", 조치 기한 " + e.DueDate +
					", 랜섬웨어 사용 " + e.Ransomware + ", 요구 조치: " + truncate(e.Action, 200)
				break
			}
		}
		facts = append(facts, aiFact{ID: "X2", Text: txt})
	} else {
		facts = append(facts, aiFact{ID: "X2", Text: "CISA KEV: 확인 불가(취약점 DB 미러에 사본 없음)"})
	}
	facts = append(facts, aiFact{ID: "X3", Text: exploitText(sig.Exploits)})
	facts = append(facts, aiFact{ID: "R1", Text: remedyText(sig.OSV, c.Version)})
	facts = append(facts, aiFact{ID: "A1", Text: "현재 분석 상태: " + firstNonEmpty(f.Analysis.State, "NOT_SET")})
	if ctx := strings.TrimSpace(context); ctx != "" {
		facts = append(facts, aiFact{ID: "U1", Text: "담당자가 적은 사용 맥락: " + truncate(ctx, 800)})
	}
	return facts
}

const vexTask = `위 취약점이 이 제품에 영향을 주는지 CycloneDX VEX 판정 초안과 대응 계획을 쓴다.
- status: under_investigation / not_affected / affected / fixed 중 하나.
- not_affected 는 사용 맥락(U1) 또는 "OSV 영향 범위 밖"(R1) 같은 근거 사실이 있을 때만 고르고, justification 을 반드시 채운다. 그 외에는 justification 을 빈 문자열로 둔다.
- justification 선택 기준: 취약한 함수·클래스를 쓰지 않거나 제거함, 또는 버전이 영향 범위 밖 → vulnerable_code_not_present, 코드는 있으나 실행되지 않음 → vulnerable_code_not_in_execute_path, 외부 입력이 닿지 않음 → vulnerable_code_cannot_be_controlled_by_adversary, 별도 방어 장치가 있음 → inline_mitigations_already_exist.
- affected 이면 response 를 고른다: R1 에 최소 수정 버전이 있으면 update, 수정 버전이 없고 임시 완화가 가능하면 workaround_available, 둘 다 없으면 can_not_fix. affected 가 아니면 빈 문자열.
- detail: 판단 이유 3~5문장. 결론은 반드시 status 와 같아야 한다(under_investigation 이면 "추가 확인 전까지 조사 중"으로 맺는다). 각 문장 끝에 근거 사실 ID 를 [C1] 처럼 붙인다.
- plan: 담당자가 할 일 2~5단계. affected 면 버전 올리기(R1 의 버전만 사용)·재빌드·SBOM 재생성·재스캔·VEX 갱신 순, under_investigation 이면 확인 절차, not_affected·fixed 면 근거 기록과 재확인. KEV 등재(X2)·공개 익스플로잇(X3)이면 첫 단계에 긴급성을 밝힌다. 각 단계 끝에 근거 사실 ID 를 붙인다.
- workaround: 수정 전까지 쓸 임시 완화. 사실(권고문·사용 맥락)에 근거가 있을 때만 쓰고, 없으면 빈 문자열.
- 사실에 없는 버전 번호·패치 이름·설정 값을 지어내지 않는다.
- missing: 판단을 확정하려면 담당자가 확인해야 할 점(최대 4개).
- confidence: 근거가 충분하면 high, 일부만 있으면 medium, 부족하면 low.`

var verLike = regexp.MustCompile(`\b\d+\.\d+(?:\.\d+)*(?:[-.][0-9A-Za-z]+)*\b`)

// guardVexDraft: 규칙 안전장치. 바꾼 점·주의점은 warnings 로 돌려준다.
func guardVexDraft(d *vexDraft, facts []aiFact, sig vexSignals) []string {
	warn := []string{}
	d.Citations = validCitations(d.Citations, facts)
	if !inList(d.Status, vexStates) {
		d.Status = "under_investigation"
	}
	if !inList(d.Justification, vexJusts) {
		d.Justification = ""
	}
	if !inList(d.Response, vexResponses) {
		d.Response = ""
	}
	hasCtx := false
	for _, f := range facts {
		if f.ID == "U1" {
			hasCtx = true
		}
	}
	osvOut := sig.OSV.Checked && sig.OSV.InRange == "no"
	if d.Status == "not_affected" && (d.Justification == "" || !(hasCtx || osvOut)) {
		warn = append(warn, "근거(사용 맥락·justification) 없이 '영향 없음'을 제안해 '조사 중'으로 낮췄습니다. 사용 맥락을 적고 다시 요청하세요.")
		d.Status, d.Justification, d.Confidence = "under_investigation", "", "low"
	}
	if d.Status == "not_affected" && osvOut && !hasCtx {
		warn = append(warn, "'영향 없음'의 근거가 OSV 버전 범위뿐입니다. 분석기(DT)의 매칭과 다르므로 실제 포함 버전을 확인하세요.")
	}
	if d.Status != "not_affected" {
		d.Justification = ""
	}
	if d.Status != "affected" {
		d.Response = ""
	}
	if d.Status == "affected" && d.Response == "" && sig.OSV.Target != "" {
		d.Response = "update"
		warn = append(warn, "수정 버전("+sig.OSV.Target+")이 있어 대응을 '업데이트'로 채웠습니다.")
	}
	if d.Response == "update" && sig.OSV.Target == "" {
		warn = append(warn, "OSV 사본에서 현재 버전보다 높은 수정 버전을 확인하지 못했습니다. 업데이트 대상 버전을 직접 확인하세요.")
	}
	if sig.KEV && d.Status == "not_affected" {
		warn = append(warn, "CISA KEV 등재 취약점입니다. 실제 악용이 확인된 취약점이므로 '영향 없음'은 근거를 문서로 남기고 2인 검토를 권장합니다.")
	}
	// 사실에 없는 버전 표기 탐지(지어낸 버전 방지)
	known := ""
	for _, f := range facts {
		known += " " + f.Text
	}
	bad := []string{}
	for _, t := range append([]string{d.Detail, d.Workaround}, d.Plan...) {
		for _, v := range verLike.FindAllString(t, -1) {
			if !strings.Contains(known, v) && !inList(v, bad) {
				bad = append(bad, v)
			}
		}
	}
	if len(bad) > 0 {
		warn = append(warn, "입력 사실에 없는 버전 표기가 있습니다: "+strings.Join(bad, ", ")+" — 그대로 쓰지 말고 확인하세요.")
	}
	if len(d.Citations) == 0 {
		warn = append(warn, "초안이 입력 사실을 인용하지 않아 신뢰도를 낮췄습니다.")
		d.Confidence = "low"
	}
	return warn
}

func inList(v string, l []string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

type vexDraftResult struct {
	Component     string    `json:"component"`
	Vulnerability string    `json:"vulnerability"`
	VulnID        string    `json:"vulnId"`
	Draft         vexDraft  `json:"draft"`
	Remedy        vexRemedy `json:"remedy"`
	Facts         []aiFact  `json:"facts"`
	Warnings      []string  `json:"warnings"`
	KEV           bool      `json:"kev"`
	Auto          bool      `json:"auto,omitempty"` // 자동 초안(새 취약점 통보 뒤 KEV·치명)
	Meta          aiMeta    `json:"meta"`
	At            string    `json:"at"`
}

// vexDraftFor: 한 건의 판정·대응 초안(규칙 신호 + AI 초안 + 안전장치 + 원장 기록).
func (s *Server) vexDraftFor(actor, repo, tag string, f dtFindingFull, context string) (*vexDraftResult, error) {
	return s.vexDraftMode(actor, repo, tag, f, context, true)
}

// vexDraftMode: 빠른 경로(기본)면 규칙·요약 카드·축약 AI 로, VEX_DRAFT_MODE=full 이면 예전처럼 전체를 AI 로.
func (s *Server) vexDraftMode(actor, repo, tag string, f dtFindingFull, context string, waitCard bool) (*vexDraftResult, error) {
	if vexFastOn() {
		return s.vexFastDraftFor(actor, repo, tag, f, context, waitCard)
	}
	sig := vexSignalsFor(f)
	facts := vexFacts(f, context, sig)
	var d vexDraft
	meta, err := s.aiDraft(facts, vexTask, vexDraftSchema, 1100, &d)
	if err != nil {
		return nil, err
	}
	meta.Snapshot, meta.Method = s.mirrorSnapshot(), "ai-full"
	warn := guardVexDraft(&d, facts, sig)
	ob, _ := json.Marshal(d)
	s.aiRecord(actor, "vex", repo, tag, meta, sha256hex(ob),
		map[string]any{"vulnId": f.Vulnerability.VulnID, "component": f.Component.Name + "@" + f.Component.Version, "suggested": d.Status, "response": d.Response})
	return &vexDraftResult{
		Component: f.Component.UUID, Vulnerability: f.Vulnerability.UUID, VulnID: f.Vulnerability.VulnID,
		Draft: d, Facts: facts, Warnings: warn, KEV: sig.KEV, Meta: meta, At: time.Now().UTC().Format(time.RFC3339),
		Remedy: vexRemedy{Priority: vexPriority(f, sig), Target: sig.OSV.Target, Fixed: sig.OSV.Fixed, InRange: sig.OSV.InRange,
			Source: sig.OSV.Source, Ranges: sig.OSV.Ranges, OSVNote: sig.OSV.NoReason, DueBy: sig.KEVDue, Exploits: sig.Exploits},
	}, nil
}

func (s *Server) projectFindings(project string) ([]dtFindingFull, error) {
	raw, err := s.dtFindings(project)
	if err != nil {
		return nil, err
	}
	var fs []dtFindingFull
	_ = json.Unmarshal(raw, &fs)
	return fs, nil
}

// POST /api/ai/vex-draft {project, component, vulnerability, context, repo, tag}
func (s *Server) apiAIVexDraft(w http.ResponseWriter, r *http.Request) {
	defer aiInteractive()()
	var in struct {
		Project, Component, Vulnerability, Context, Repo, Tag string
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil || in.Project == "" || in.Vulnerability == "" {
		writeJSON(w, 400, map[string]string{"error": "project, vulnerability 필수"})
		return
	}
	if !aiEnabled() {
		writeJSON(w, 503, map[string]string{"error": "AI 미설정 — 관리자에게 AI 서비스 활성화를 요청하세요"})
		return
	}
	fs, err := s.projectFindings(in.Project)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	for _, f := range fs {
		if f.Vulnerability.UUID == in.Vulnerability && (in.Component == "" || f.Component.UUID == in.Component) {
			res, err := s.vexDraftFor(w.Header().Get("X-User"), in.Repo, in.Tag, f, in.Context)
			if err != nil {
				writeJSON(w, 502, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, res)
			return
		}
	}
	writeJSON(w, 404, map[string]string{"error": "해당 취약점을 찾지 못했습니다"})
}

// ---------- ③ 일괄 판정 ----------

type vexBatch struct {
	Project  string `json:"project"`
	Repo     string `json:"repo"`
	Tag      string `json:"tag"`
	Actor    string `json:"actor"`
	Trigger  string `json:"trigger,omitempty"` // "auto": 새 취약점 통보 뒤 자동 초안(KEV·치명)
	State    string `json:"state"`             // running / done / cancelled / error
	Total    int    `json:"total"`
	Done     int    `json:"done"`
	Current  string `json:"current,omitempty"`
	Started  string `json:"started"`
	Finished string `json:"finished,omitempty"`
	Error    string `json:"error,omitempty"`
	// 빠른 경로는 두 단계: ① 판정(규칙, 바로 끝남) ② 권고문 요약 보강(AI, 건당 수십 초). 화면이 따로 보여 준다.
	Phase       string                     `json:"phase,omitempty"`    // judge / enrich
	JudgedAt    string                     `json:"judgedAt,omitempty"` // ① 이 끝난 시각
	EnrichTotal int                        `json:"enrichTotal,omitempty"`
	EnrichDone  int                        `json:"enrichDone,omitempty"`
	Results     map[string]*vexDraftResult `json:"results"` // "컴포넌트UUID|취약점UUID"
	Failed      map[string]string          `json:"failed,omitempty"`
	cancel      bool
}

var (
	vexBatchMu sync.Mutex
	vexBatches = map[string]*vexBatch{}
	dtUUIDRe   = regexp.MustCompile(`^[0-9a-fA-F-]{36}$`)
)

func vexBatchPath(project string) string {
	return filepath.Join(env("AI_VEX_DIR", "/var/lib/trustlink/ai-vex"), project+".json")
}

func (b *vexBatch) save() {
	_ = os.MkdirAll(filepath.Dir(vexBatchPath(b.Project)), 0o750)
	_ = writeJSONFile(vexBatchPath(b.Project), b)
}

// vexBatchPick: 미분석(NOT_SET) 항목만 우선순위·EPSS 순으로 최대 limit 개.
func vexBatchPick(fs []dtFindingFull, limit int) []dtFindingFull {
	type cand struct {
		f    dtFindingFull
		p    int
		epss float64
	}
	cs := []cand{}
	for _, f := range fs {
		if st := strings.ToUpper(f.Analysis.State); st != "" && st != "NOT_SET" {
			continue
		}
		var sig vexSignals
		if idx, _, ok := kevIndex(); ok {
			for _, id := range vulnIDs(f) {
				if _, hit := idx[id]; hit {
					sig.KEV = true
				}
			}
		}
		sig.Exploits = exploitsFor(vulnIDs(f))
		e := 0.0
		if f.Vulnerability.EpssScore != nil {
			e = *f.Vulnerability.EpssScore
		}
		cs = append(cs, cand{f, vexPriority(f, sig), e})
	}
	sort.SliceStable(cs, func(i, j int) bool {
		if cs[i].p != cs[j].p {
			return cs[i].p < cs[j].p
		}
		return cs[i].epss > cs[j].epss
	})
	out := []dtFindingFull{}
	for i := 0; i < len(cs) && i < limit; i++ {
		out = append(out, cs[i].f)
	}
	return out
}

// POST /api/ai/vex-batch {project, repo, tag, context, limit, cancel}
func (s *Server) apiAIVexBatch(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Project, Repo, Tag, Context string
		Limit                       int
		Cancel                      bool
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil || !dtUUIDRe.MatchString(in.Project) {
		writeJSON(w, 400, map[string]string{"error": "project(DT UUID) 필수"})
		return
	}
	if in.Repo != "" && !s.requireRepo(w, r, in.Repo, "read") {
		return
	}
	vexBatchMu.Lock()
	cur := vexBatches[in.Project]
	if in.Cancel {
		if cur != nil && cur.State == "running" { // 바로 멈춘 것으로 표시한다. 돌고 있던 AI 호출 한 건은 끝나면 버린다
			cur.cancel = true
			cur.State, cur.Current, cur.Finished = "cancelled", "", time.Now().UTC().Format(time.RFC3339)
			cur.save()
		}
		vexBatchMu.Unlock()
		writeJSON(w, 200, map[string]string{"status": "cancelling"})
		return
	}
	if cur != nil && cur.State == "running" {
		vexBatchMu.Unlock()
		writeJSON(w, 409, map[string]string{"error": "이미 일괄 판정이 진행 중입니다"})
		return
	}
	vexBatchMu.Unlock()
	if !aiEnabled() {
		writeJSON(w, 503, map[string]string{"error": "AI 미설정 — 관리자에게 AI 서비스 활성화를 요청하세요"})
		return
	}
	fs, err := s.projectFindings(in.Project)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	if in.Limit <= 0 || in.Limit > 50 {
		in.Limit = 20
	}
	picks := vexBatchPick(fs, in.Limit)
	if len(picks) == 0 {
		writeJSON(w, 200, map[string]any{"state": "done", "total": 0, "message": "미분석 항목이 없습니다"})
		return
	}
	b, err := s.startVexBatch(in.Project, in.Repo, in.Tag, w.Header().Get("X-User"), "", in.Context, picks, nil)
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 202, map[string]any{"state": "running", "total": b.Total})
}

var errVexBatchRunning = errors.New("이미 일괄 판정이 진행 중입니다")

// startVexBatch: 일괄 판정 시작(화면 요청·자동 초안 공용). trigger: "" 사람 요청, "auto" 새 취약점 통보 뒤 자동.
// keep: 새 결과에 이어 붙일 이전 초안(자동 초안용, 사람 요청은 nil). 이미 진행 중이면 errVexBatchRunning. picks 는 비어 있지 않아야 한다.
func (s *Server) startVexBatch(project, repo, tag, actor, trigger, context string, picks []dtFindingFull, keep map[string]*vexDraftResult) (*vexBatch, error) {
	b := &vexBatch{Project: project, Repo: repo, Tag: tag, Actor: actor, Trigger: trigger, State: "running",
		Total: len(picks), Phase: "judge", Started: time.Now().UTC().Format(time.RFC3339), Results: map[string]*vexDraftResult{}, Failed: map[string]string{}}
	vexBatchMu.Lock()
	if cur := vexBatches[project]; cur != nil && cur.State == "running" { // 경쟁 재확인
		vexBatchMu.Unlock()
		return nil, errVexBatchRunning
	}
	for k, v := range keep {
		b.Results[k] = v
	}
	vexBatches[project] = b
	vexBatchMu.Unlock()
	go s.runVexBatch(b, picks, context)
	return b, nil
}

func (s *Server) runVexBatch(b *vexBatch, picks []dtFindingFull, context string) {
	for _, f := range picks {
		vexBatchMu.Lock()
		if b.cancel || b.State != "running" {
			b.State = "cancelled"
			vexBatchMu.Unlock()
			break
		}
		b.Current = f.Vulnerability.VulnID + " · " + f.Component.Name
		vexBatchMu.Unlock()
		aiYield(b)                                                            // 사람이 직접 요청한 AI 가 기다리면 먼저 보낸다
		res, err := s.vexDraftMode(b.Actor, b.Repo, b.Tag, f, context, false) // 빠른 경로: 요약 카드는 기다리지 않는다(아래에서 보강)
		key := f.Component.UUID + "|" + f.Vulnerability.UUID
		vexBatchMu.Lock()
		if b.cancel { // 중지 뒤에 끝난 호출 — 결과를 버린다
			vexBatchMu.Unlock()
			break
		}
		if err != nil {
			b.Failed[key] = f.Vulnerability.VulnID + ": " + err.Error()
		} else {
			res.Auto = b.Trigger == "auto"
			b.Results[key] = res
		}
		b.Done++
		b.save()
		vexBatchMu.Unlock()
	}
	vexBatchMu.Lock()
	b.JudgedAt = time.Now().UTC().Format(time.RFC3339)
	vexBatchMu.Unlock()
	s.vexBatchEnrich(b, picks, context)
	vexBatchMu.Lock()
	if b.cancel {
		vexBatchMu.Unlock()
		return // 중지할 때 이미 상태·시각을 적었다
	}
	if b.State == "running" {
		b.State = "done"
		if len(b.Results) == 0 && len(b.Failed) > 0 {
			b.State, b.Error = "error", "모든 항목에서 AI 초안 작성에 실패했습니다"
		}
	}
	b.Current, b.Finished = "", time.Now().UTC().Format(time.RFC3339)
	b.save()
	vexBatchMu.Unlock()
}

// GET /api/ai/vex-batch?project=uuid → 진행 상태·결과(없으면 마지막 저장본)
func (s *Server) apiAIVexBatchGet(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query().Get("project")
	if !dtUUIDRe.MatchString(p) {
		writeJSON(w, 400, map[string]string{"error": "project(DT UUID) 필수"})
		return
	}
	vexBatchMu.Lock()
	var body []byte
	repo := ""
	if b := vexBatches[p]; b != nil {
		body, _ = json.Marshal(b)
		repo = b.Repo
	}
	vexBatchMu.Unlock()
	if body == nil {
		var saved vexBatch
		if readJSONFile(vexBatchPath(p), &saved) != nil {
			writeJSON(w, 200, map[string]any{"state": "none"})
			return
		}
		if saved.State == "running" { // 재시작으로 끊긴 작업
			saved.State, saved.Error = "cancelled", "서비스 재시작으로 중단됨"
		}
		body, _ = json.Marshal(saved)
		repo = saved.Repo
	}
	if repo != "" && !s.requireRepo(w, r, repo, "read") {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(body)
}

// vexBatchEnrich: 빠른 경로의 2단계 — 판정은 이미 다 나왔고, 권고문 요약 카드가 없던 건만 카드를 만들어 초안에 덧붙인다.
func (s *Server) vexBatchEnrich(b *vexBatch, picks []dtFindingFull, context string) {
	if !vexFastOn() {
		return
	}
	need := []dtFindingFull{}
	vexBatchMu.Lock()
	for _, f := range picks {
		if cur := b.Results[f.Component.UUID+"|"+f.Vulnerability.UUID]; cur != nil && cur.Meta.Method == "rule" && f.Vulnerability.Description != "" {
			need = append(need, f)
		}
	}
	b.Phase, b.EnrichTotal, b.EnrichDone = "enrich", len(need), 0
	b.save()
	vexBatchMu.Unlock()
	for _, f := range need {
		key := f.Component.UUID + "|" + f.Vulnerability.UUID
		vexBatchMu.Lock()
		stop := b.cancel || b.State != "running"
		if !stop {
			b.Current = f.Vulnerability.VulnID + " · " + f.Component.Name
		}
		vexBatchMu.Unlock()
		if stop {
			return
		}
		aiYield(b)
		_, err := s.cardMake(f) // 같은 취약점이 앞에서 만들어졌으면 바로 돌아온다
		var res *vexDraftResult
		if err == nil {
			res, err = s.vexDraftMode(b.Actor, b.Repo, b.Tag, f, context, false)
		}
		vexBatchMu.Lock()
		if b.cancel {
			vexBatchMu.Unlock()
			return
		}
		if err == nil {
			res.Auto = b.Trigger == "auto"
			b.Results[key] = res
		}
		b.EnrichDone++
		b.save()
		vexBatchMu.Unlock()
	}
}
