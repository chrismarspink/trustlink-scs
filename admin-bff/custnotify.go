package main

// custnotify.go: 고객 통지(패치 권고 · 영향 없음 확인서).
//   ① 취약점 선택: 등록된 고객 설치 버전(repo@tag)의 DT 분석 결과에서 후보를 모은다.
//   ② 영향 고객: 설치 버전의 DT 분석에 그 취약점이 있고 상태가 NOT_AFFECTED·FALSE_POSITIVE·RESOLVED 가 아닌 고객
//      (영향 없음 확인서는 반대로 NOT_AFFECTED·FALSE_POSITIVE). 패치 권고는 고객별 통지 수준(critical_kev/high/all)을 지킨다.
//   ③ 패치 버전 찾기 = 규칙(AI 아님): 설치 버전보다 새 태그를 버전 순으로 보며, DT 분석에 그 취약점이 없고
//      SBOM 의 해당 구성요소 버전이 달라진(또는 빠진) 첫 태그. OSV 사본이 있으면 수정 버전을 근거로 덧붙인다.
//      AI 는 사실(ID 인용)만으로 쉬운 설명·영향·조치 문구를 쓴다. 사실에 없는 버전을 쓰면 버리고 규칙 문구로 대체.
//   ④ 미리보기: 고객·언어별 메일(HTML+평문). 담당자 이메일은 AI 사실에 넣지 않는다.
//   ⑤ 발송: SendRich(허용 목록은 Mailer 가 적용) → 고객별 결과 기록 + 감사 원장.

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	dtInactive    = []string{"NOT_AFFECTED", "FALSE_POSITIVE", "RESOLVED"}
	dtNotAffected = []string{"NOT_AFFECTED", "FALSE_POSITIVE"}
	reCiteMark    = regexp.MustCompile(`\s?\[[A-Z]\d+\]`)
)

// ---------- DT 조회(요청 단위 캐시) ----------

type dtRepoView struct {
	s     *Server
	repo  string
	uuid  map[string]string
	fs    map[string][]dtFindingFull
	fok   map[string]bool
	comps map[string][]dtComponent
}

func (s *Server) dtView(repo string) *dtRepoView {
	return &dtRepoView{s: s, repo: repo, uuid: map[string]string{}, fs: map[string][]dtFindingFull{}, fok: map[string]bool{}, comps: map[string][]dtComponent{}}
}

func (v *dtRepoView) project(tag string) string {
	if id, ok := v.uuid[tag]; ok {
		return id
	}
	id := ""
	if v.s.dtEnabled() {
		id, _ = v.s.dtLookupProject(path.Base(v.repo), tag)
	}
	v.uuid[tag] = id
	return id
}

// findings: ok=false 면 DT 미설정·프로젝트 없음·조회 실패(판단 불가).
func (v *dtRepoView) findings(tag string) ([]dtFindingFull, bool) {
	if fs, ok := v.fs[tag]; ok {
		return fs, v.fok[tag]
	}
	var fs []dtFindingFull
	ok := false
	if id := v.project(tag); id != "" {
		if b, err := v.s.dtFindings(id); err == nil && json.Unmarshal(b, &fs) == nil {
			ok = true
		}
	}
	v.fs[tag], v.fok[tag] = fs, ok
	return fs, ok
}

func (v *dtRepoView) components(tag string) []dtComponent {
	if cs, ok := v.comps[tag]; ok {
		return cs
	}
	var cs []dtComponent
	if id := v.project(tag); id != "" {
		cs = v.s.dtComponents(id)
	}
	v.comps[tag] = cs
	return cs
}

// findVuln: 그 태그의 분석 결과에서 취약점(ID·별칭 일치)을 찾는다.
func findVuln(fs []dtFindingFull, id string) (dtFindingFull, bool) {
	id = strings.ToUpper(id)
	for _, f := range fs {
		if inList(id, vulnIDs(f)) {
			return f, true
		}
	}
	return dtFindingFull{}, false
}

func stateOf(f dtFindingFull) string {
	return firstNonEmpty(strings.ToUpper(f.Analysis.State), "NOT_SET")
}

// levelOK: 고객 통지 수준. critical_kev = CRITICAL 또는 KEV, high = HIGH 이상 또는 KEV, all = 전부.
func levelOK(level, sev string, kev bool) bool {
	sev = strings.ToUpper(sev)
	switch level {
	case "all":
		return true
	case "critical_kev":
		return kev || sev == "CRITICAL"
	}
	return kev || sev == "CRITICAL" || sev == "HIGH"
}

func isKEV(ids []string) bool {
	if idx, _, ok := kevIndex(); ok {
		for _, id := range ids {
			if _, hit := idx[id]; hit {
				return true
			}
		}
	}
	return false
}

// versionTags: 제품의 버전 태그(zot + 버전 정책) — latest·숫자 없는 태그 제외, 버전 오름차순.
func (s *Server) versionTags(repo string, policy []VerPolicy) []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(t string) {
		if t != "" && t != "latest" && !seen[t] && len(verParts(t)) > 0 {
			seen[t] = true
			out = append(out, t)
		}
	}
	for _, t := range s.svcTags(repo) {
		add(t)
	}
	for _, p := range policy {
		add(p.Tag)
	}
	sort.Slice(out, func(i, j int) bool { return cmpVersion(out[i], out[j]) < 0 })
	return out
}

// ---------- ③ 패치 버전 찾기(규칙) ----------

type fixStep struct {
	Tag         string `json:"tag"`
	Status      string `json:"status"` // fixed | affected | present | unknown
	CompVersion string `json:"compVersion,omitempty"`
	Note        string `json:"note,omitempty"`
}

type osvEvidence struct {
	ID     string   `json:"id"`
	Target string   `json:"target,omitempty"` // 현재 구성요소 버전보다 높은 최소 수정 버전
	Fixed  []string `json:"fixed,omitempty"`
	Ranges []string `json:"ranges,omitempty"`
}

type fixResult struct {
	Found       bool         `json:"found"`
	Tag         string       `json:"tag,omitempty"`
	CompVersion string       `json:"compVersion,omitempty"`
	Note        string       `json:"note,omitempty"`
	From        string       `json:"from,omitempty"` // 비교 시작(영향받는 설치 버전 중 가장 낮은 것)
	Steps       []fixStep    `json:"steps"`
	OSV         *osvEvidence `json:"osv,omitempty"`
	OSVNote     string       `json:"osvNote,omitempty"` // OSV 를 못 본 이유(미러 비었음 등)
	Message     string       `json:"message,omitempty"`
}

func purlBase(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if i := strings.LastIndex(p, "@"); i > strings.LastIndex(p, "/") {
		p = p[:i]
	}
	return p
}

// compIn: 태그의 SBOM 구성요소 중 같은 구성요소(purl 기준, 없으면 이름).
func compIn(cs []dtComponent, f dtFindingFull) (dtComponent, bool) {
	pb := purlBase(f.Component.Purl)
	for _, c := range cs {
		if pb != "" && c.Purl != "" {
			if purlBase(c.Purl) == pb {
				return c, true
			}
		} else if c.Name == f.Component.Name {
			return c, true
		}
	}
	return dtComponent{}, false
}

// fixScan: from 보다 새 태그를 순서대로 판정한다.
func (v *dtRepoView) fixScan(id string, f dtFindingFull, tags []string, from string) []fixStep {
	steps := []fixStep{}
	for _, t := range tags {
		if cmpVersion(t, from) <= 0 {
			continue
		}
		st := fixStep{Tag: t}
		fs, ok := v.findings(t)
		switch g, hit := findVuln(fs, id); {
		case !ok:
			st.Status, st.Note = "unknown", "DT 분석 없음(SBOM 미적재)"
		case hit && inList(stateOf(g), dtInactive):
			st.Status, st.CompVersion, st.Note = "present", g.Component.Version, "취약점은 남아 있음(분석 상태 "+stateOf(g)+")"
		case hit:
			st.Status, st.CompVersion = "affected", g.Component.Version
		default:
			cs := v.components(t)
			c, has := compIn(cs, f)
			switch {
			case len(cs) == 0:
				st.Status, st.Note = "unknown", "구성요소 목록 없음"
			case !has:
				st.Status, st.Note = "fixed", "구성요소 제거됨"
			case c.Version == f.Component.Version:
				st.Status, st.CompVersion, st.Note = "unknown", c.Version, "구성요소 버전 같음(취약점 DB 차이 가능 — 확인 필요)"
			default:
				st.Status, st.CompVersion = "fixed", c.Version
			}
		}
		steps = append(steps, st)
	}
	return steps
}

// pickFix: 설치 버전(from)보다 새 첫 fixed 태그.
func pickFix(steps []fixStep, from string) (fixStep, bool) {
	for _, st := range steps {
		if st.Status == "fixed" && cmpVersion(st.Tag, from) > 0 {
			return st, true
		}
	}
	return fixStep{}, false
}

// ---------- 통지 기록 ----------

type custSendResult struct {
	At        string   `json:"at"`
	Sent      []string `json:"sent,omitempty"`
	Dropped   []string `json:"dropped,omitempty"` // 메일 허용 목록 밖이라 건너뜀
	Error     string   `json:"error,omitempty"`
	Outbox    string   `json:"outbox,omitempty"`    // 발송함 ID(mail_outbox.go)
	Pending   bool     `json:"pending,omitempty"`   // 발송함에서 기다리는 중 — 이때는 취소할 수 있다
	SendAt    string   `json:"sendAt,omitempty"`    // 실제로 나갈 시각
	Cancelled bool     `json:"cancelled,omitempty"` // 보내기 취소됨(다시 보낼 수 있음)
}

// 고객 통지를 읽고-고치고-저장하는 동안 다른 쪽(발송함 완료 처리)과 겹치지 않게
var custNoticeMu sync.Mutex

type CustTarget struct {
	Key        string          `json:"key"` // 고객|사용|언어
	CustomerID string          `json:"customerId"`
	Customer   string          `json:"customer"`
	UsageID    string          `json:"usageId"`
	Lang       string          `json:"lang"`
	Tags       []string        `json:"tags"`
	Recommend  string          `json:"recommend,omitempty"`
	RecComp    string          `json:"recComp,omitempty"`
	Notes      []string        `json:"notes,omitempty"`    // 고객 메일에 넣는 계약·EOS 안내
	Internal   []string        `json:"internal,omitempty"` // 내부 메모(메일 미포함)
	Ring       string          `json:"ring,omitempty"`     // pilot = 내부 검증(사전 배포) 고객 — 외부보다 먼저 보낸다
	Contacts   []string        `json:"contacts"`           // 이름(역할)
	To         []string        `json:"to"`
	Cc         []string        `json:"cc,omitempty"` // 영업 담당(유지보수 만료 시)
	Subject    string          `json:"subject"`
	Text       string          `json:"text"`
	HTML       string          `json:"html"`
	Result     *custSendResult `json:"result,omitempty"`
}

type CustSkip struct {
	CustomerID string `json:"customerId"`
	Customer   string `json:"customer"`
	Reason     string `json:"reason"`
}

type custAIText struct {
	Summary   string   `json:"summary"`
	Impact    string   `json:"impact"`
	Action    string   `json:"action"`
	Citations []string `json:"citations"`
	Source    string   `json:"source"` // ai | rule
	Model     string   `json:"model,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
}

type CustNotice struct {
	ID          string                 `json:"id"`
	Kind        string                 `json:"kind"`                // patch | notaffected
	Status      string                 `json:"status"`              // draft | queued | sent | partial | dropped | failed
	AutoRun     string                 `json:"autoRun,omitempty"`   // 자동 대응(auto_response.go)이 만든 초안이면 그 기록 ID
	AIState     string                 `json:"aiState,omitempty"`   // running | done — AI 설명은 뒤에서 만든다(로컬 LLM 은 수 분)
	AIStarted   string                 `json:"aiStarted,omitempty"` // 진행 표시용
	Created     string                 `json:"created"`
	CreatedBy   string                 `json:"createdBy"`
	SentAt      string                 `json:"sentAt,omitempty"`
	SentBy      string                 `json:"sentBy,omitempty"`
	Repo        string                 `json:"repo"`
	VulnID      string                 `json:"vulnId"`
	Severity    string                 `json:"severity"`
	CVSS        *float64               `json:"cvss,omitempty"`
	KEV         bool                   `json:"kev"`
	Component   string                 `json:"component"`
	CompVersion string                 `json:"compVersion"`
	Fix         fixResult              `json:"fix"`
	Facts       []aiFact               `json:"facts"`
	AI          map[string]*custAIText `json:"ai"`
	AIError     string                 `json:"aiError,omitempty"`
	Targets     []CustTarget           `json:"targets"`
	Skipped     []CustSkip             `json:"skipped"`
}

// ---------- ② 영향 고객 + ③ 규칙 ----------

// recipientsFor: 통지 담당자(사용 지정 → 없으면 전체) 중 통지 종류가 맞는 사람, 언어별로.
func recipientsFor(c Customer, u CustUsage, kind string) map[string][]CustContact {
	want := map[string][]string{"patch": {"patch", "vuln"}, "notaffected": {"vex", "vuln"}}[kind]
	out := map[string][]CustContact{}
	for _, ct := range c.Contacts {
		if len(u.NotifyContacts) > 0 && !inList(strings.ToLower(ct.Email), lower(u.NotifyContacts)) {
			continue
		}
		ok := false
		for _, k := range want {
			ok = ok || inList(k, ct.Notify)
		}
		if ok {
			l := firstNonEmpty(ct.Lang, c.Lang, "ko")
			out[l] = append(out[l], ct)
		}
	}
	return out
}

func lower(l []string) []string {
	out := make([]string, len(l))
	for i, x := range l {
		out[i] = strings.ToLower(x)
	}
	return out
}

// buildNotice: 영향 고객·규칙 패치 버전·사실·메일 초안을 만든다(AI 없이).
func (s *Server) buildNotice(kind, repo, vulnID, actor string) (*CustNotice, error) {
	vulnID = strings.ToUpper(strings.TrimSpace(vulnID))
	if kind != "patch" && kind != "notaffected" {
		return nil, fmt.Errorf("통지 종류는 patch/notaffected")
	}
	if !reRepo.MatchString(repo) || vulnID == "" {
		return nil, fmt.Errorf("제품·취약점 필수")
	}
	if !s.dtEnabled() {
		return nil, fmt.Errorf("DT 미설정 — 분석 결과가 없어 영향 고객을 계산할 수 없음")
	}
	c := s.cust()
	d := c.snapshot()
	v := s.dtView(repo)
	n := &CustNotice{ID: newCustID("n-"), Kind: kind, Status: "draft", Created: c.now().UTC().Format(time.RFC3339), CreatedBy: actor,
		Repo: repo, VulnID: vulnID, AI: map[string]*custAIText{}, Targets: []CustTarget{}, Skipped: []CustSkip{}}
	var ref dtFindingFull
	haveRef := false
	type hit struct {
		c    Customer
		u    CustUsage
		tags []string
	}
	var hits []hit
	minTag := ""
	for _, cu := range activeCustomers(d.Customers) { // 중지된 회사는 통지 대상 아님
		for _, u := range cu.Usages {
			if u.Repo != repo {
				continue
			}
			var tags []string
			reason := ""
			for _, in := range u.Installs {
				if inList(in.Tag, tags) {
					continue
				}
				fs, ok := v.findings(in.Tag)
				f, found := findVuln(fs, vulnID)
				switch {
				case !ok:
					reason = "설치 버전 " + in.Tag + " 의 DT 분석 없음"
					continue
				case !found:
					continue
				}
				st := stateOf(f)
				match := !inList(st, dtInactive)
				if kind == "notaffected" {
					match = inList(st, dtNotAffected)
				}
				if !match {
					continue
				}
				if !haveRef {
					ref, haveRef = f, true
				}
				tags = append(tags, in.Tag)
				if minTag == "" || cmpVersion(in.Tag, minTag) < 0 {
					minTag = in.Tag
				}
			}
			if len(tags) == 0 {
				n.Skipped = append(n.Skipped, CustSkip{cu.ID, cu.Name, firstNonEmpty(reason, map[bool]string{true: "설치 버전이 영향받지 않음", false: "영향 없음(VEX) 판정된 설치 버전 없음"}[kind == "patch"])})
				continue
			}
			hits = append(hits, hit{cu, u, tags})
		}
	}
	if !haveRef {
		return nil, fmt.Errorf("등록된 고객 설치 버전에서 %s 를(을) 찾지 못함", vulnID)
	}
	ids := vulnIDs(ref)
	n.Severity, n.CVSS, n.KEV = strings.ToUpper(ref.Vulnerability.Severity), ref.Vulnerability.CvssV3BaseScore, isKEV(ids)
	n.Component = ref.Component.Name
	if ref.Component.Group != "" {
		n.Component = ref.Component.Group + "/" + ref.Component.Name
	}
	n.CompVersion = ref.Component.Version
	// ③ 규칙: 패치 버전
	if kind == "patch" {
		tags := s.versionTags(repo, d.Products[repo])
		n.Fix.From = minTag
		n.Fix.Steps = v.fixScan(vulnID, ref, tags, minTag)
		if st, ok := pickFix(n.Fix.Steps, minTag); ok {
			n.Fix.Found, n.Fix.Tag, n.Fix.CompVersion, n.Fix.Note = true, st.Tag, st.CompVersion, st.Note
		} else {
			n.Fix.Message = "아직 패치 버전 없음 — 완화 조치 안내"
		}
		if o := osvLookup(ref.Component.Purl, ref.Component.Version, ids); o.Checked && (len(o.Fixed) > 0 || o.Target != "") {
			n.Fix.OSV = &osvEvidence{ID: o.Source, Target: o.Target, Fixed: o.Fixed, Ranges: o.Ranges}
		} else {
			n.Fix.OSVNote = firstNonEmpty(o.NoReason, "OSV 에 수정 버전 없음")
		}
	}
	// ② 영향 고객 → 고객·언어별 대상
	for _, h := range hits {
		if kind == "patch" && !levelOK(h.u.NotifyLevel, n.Severity, n.KEV) { // 영향 없음 확인서는 골라서 보내므로 수준을 보지 않는다
			n.Skipped = append(n.Skipped, CustSkip{h.c.ID, h.c.Name, "통지 수준(" + h.u.NotifyLevel + ") 미달"})
			continue
		}
		byLang := recipientsFor(h.c, h.u, kind)
		if len(byLang) == 0 {
			n.Skipped = append(n.Skipped, CustSkip{h.c.ID, h.c.Name, "받을 담당자 없음(통지 종류 미지정)"})
			continue
		}
		langs := []string{}
		for l := range byLang {
			langs = append(langs, l)
		}
		sort.Strings(langs)
		for _, l := range langs {
			t := CustTarget{Key: h.c.ID + "|" + h.u.ID + "|" + l, CustomerID: h.c.ID, Customer: h.c.Name, UsageID: h.u.ID, Lang: l, Tags: h.tags, Contacts: []string{}, To: []string{}}
			if h.c.Pilot {
				t.Ring = "pilot" // 내부 검증 고객 — 발송은 이 링을 먼저
			}
			for _, ct := range byLang[l] {
				t.Contacts = append(t.Contacts, ct.Name+"("+ct.Role+")")
				t.To = append(t.To, ct.Email)
			}
			if kind == "patch" {
				hi := h.tags[0]
				for _, x := range h.tags {
					if cmpVersion(x, hi) > 0 {
						hi = x
					}
				}
				if st, ok := pickFix(n.Fix.Steps, hi); ok {
					t.Recommend, t.RecComp = st.Tag, st.CompVersion
				}
			}
			s.contractNotes(&t, h.c, h.u, d.Products[repo], l, c.now())
			n.Targets = append(n.Targets, t)
		}
	}
	n.Facts = noticeFacts(n, ref)
	for l := range targetLangs(n) {
		n.AI[l] = ruleText(n, l)
	}
	renderMails(s, n)
	return n, nil
}

// contractNotes: 유지보수 만료 → 영업 담당 참조, 설치 버전 EOS 경과 → 권장 업그레이드 안내.
func (s *Server) contractNotes(t *CustTarget, c Customer, u CustUsage, pol []VerPolicy, lang string, now time.Time) {
	en := lang == "en"
	if d, ok := daysUntil(u.MaintExpiry, now); ok && d < 0 {
		t.Notes = append(t.Notes, map[bool]string{false: "유지보수 계약이 " + u.MaintExpiry + " 에 만료되었습니다. 패치 적용 지원은 영업 담당과 협의해 주십시오.",
			true: "Your maintenance contract expired on " + u.MaintExpiry + ". Please contact your sales representative regarding patch support."}[en])
		t.Internal = append(t.Internal, "유지보수 만료 — 영업 담당("+firstNonEmpty(c.SalesOwner, "미지정")+") 참조")
		if e := s.cust().emailOf(c.SalesOwner); e != "" {
			t.Cc = append(t.Cc, e)
		} else if c.SalesOwner != "" {
			t.Internal = append(t.Internal, "영업 담당 이메일 없음 — 참조 못 함")
		}
	}
	if d, ok := daysUntil(u.LicenseExpiry, now); ok && d < 0 && u.LicenseType != "perpetual" {
		t.Internal = append(t.Internal, "라이선스 만료("+u.LicenseExpiry+")")
	}
	for _, tag := range t.Tags {
		for _, vp := range pol {
			if vp.Tag != tag {
				continue
			}
			if d, ok := daysUntil(vp.EOS, now); ok && d < 0 {
				msg := map[bool]string{false: "사용 중인 버전 " + tag + " 은(는) " + vp.EOS + " 에 지원이 종료(EOS)되었습니다.",
					true: "Version " + tag + " reached end of support (EOS) on " + vp.EOS + "."}[en]
				if vp.Upgrade != "" {
					msg += map[bool]string{false: " 권장 업그레이드 버전: " + vp.Upgrade, true: " Recommended upgrade: " + vp.Upgrade}[en]
				}
				t.Notes = append(t.Notes, msg)
			}
		}
	}
}

func targetLangs(n *CustNotice) map[string]bool {
	out := map[string]bool{}
	for _, t := range n.Targets {
		out[t.Lang] = true
	}
	return out
}

// noticeFacts: AI 에 줄 사실(취약점·제품·규칙 결과). 고객 이름·담당자·이메일은 넣지 않는다.
func noticeFacts(n *CustNotice, ref dtFindingFull) []aiFact {
	v := ref.Vulnerability
	vt := "취약점: " + n.VulnID + " (심각도 " + firstNonEmpty(n.Severity, "미상")
	if v.CvssV3BaseScore != nil {
		vt += ", CVSS v3 " + ftoa(*v.CvssV3BaseScore, 1)
	}
	facts := []aiFact{{ID: "V1", Text: vt + ")"}}
	if v.CweID > 0 {
		facts = append(facts, aiFact{ID: "V2", Text: "약점 유형: CWE-" + itoa(v.CweID) + " " + v.CweName})
	}
	if dsc := truncate(v.Description, 1200); dsc != "" {
		facts = append(facts, aiFact{ID: "V3", Text: "권고문 설명: " + dsc, Untrusted: true})
	}
	facts = append(facts, aiFact{ID: "C1", Text: "영향 구성요소: " + n.Component + " " + n.CompVersion})
	tags := map[string]bool{}
	for _, t := range n.Targets {
		for _, x := range t.Tags {
			tags[x] = true
		}
	}
	tl := []string{}
	for x := range tags {
		tl = append(tl, x)
	}
	sort.Slice(tl, func(i, j int) bool { return cmpVersion(tl[i], tl[j]) < 0 })
	facts = append(facts, aiFact{ID: "P1", Text: "우리 제품: " + path.Base(n.Repo) + ", 고객이 쓰는 해당 버전: " + firstNonEmpty(strings.Join(tl, ", "), "없음") +
		", 분석 상태: " + stateOf(ref)})
	facts = append(facts, aiFact{ID: "X2", Text: map[bool]string{true: "CISA KEV: 실제 악용이 확인된 취약점 목록에 등재됨", false: "CISA KEV: 등재 확인 안 됨"}[n.KEV]})
	if n.Kind == "patch" {
		if n.Fix.Found {
			t := "패치 버전(규칙 판정): " + path.Base(n.Repo) + " " + n.Fix.Tag + " 부터 이 취약점이 분석 결과에 없음"
			if n.Fix.CompVersion != "" {
				t += ", 그 버전의 " + n.Component + " 버전 " + n.Fix.CompVersion
			} else if n.Fix.Note != "" {
				t += " (" + n.Fix.Note + ")"
			}
			facts = append(facts, aiFact{ID: "F1", Text: t})
		} else {
			facts = append(facts, aiFact{ID: "F1", Text: "패치 버전(규칙 판정): 아직 없음 — 더 새 버전에도 이 취약점이 남아 있거나 분석되지 않음"})
		}
		if n.Fix.OSV != nil {
			facts = append(facts, aiFact{ID: "R1", Text: "OSV " + n.Fix.OSV.ID + ": 구성요소 수정 버전 " + strings.Join(n.Fix.OSV.Fixed, ", ") + "; 영향 범위 " + strings.Join(n.Fix.OSV.Ranges, " / ")})
		}
	} else {
		facts = append(facts, aiFact{ID: "F1", Text: "VEX 판정: 영향 없음(" + stateOf(ref) + ") — 우리 제품의 위 버전은 이 취약점의 영향을 받지 않음"})
	}
	return facts
}

// ruleText: AI 없이 쓰는 기본 문구(규칙).
func ruleText(n *CustNotice, lang string) *custAIText {
	p := path.Base(n.Repo)
	t := &custAIText{Source: "rule", Citations: []string{}}
	if lang == "en" {
		t.Summary = fmt.Sprintf("Vulnerability %s (severity %s) was reported in component %s %s.", n.VulnID, firstNonEmpty(n.Severity, "unknown"), n.Component, n.CompVersion)
		if n.Kind == "notaffected" {
			t.Impact = "Our analysis (VEX) concluded that " + p + " is not affected by this vulnerability."
			t.Action = "No action is required for this vulnerability."
		} else {
			t.Impact = p + " includes this component in the versions you use."
			t.Action = map[bool]string{true: "Please upgrade to " + p + " " + n.Fix.Tag + ".", false: "No patched version is available yet. Please restrict exposure (network access, input sources) and wait for our follow-up notice."}[n.Fix.Found]
		}
		return t
	}
	t.Summary = fmt.Sprintf("구성요소 %s %s 에서 취약점 %s(심각도 %s)가 보고되었습니다.", n.Component, n.CompVersion, n.VulnID, firstNonEmpty(n.Severity, "미상"))
	if n.Kind == "notaffected" {
		t.Impact = "분석(VEX) 결과 " + p + " 은(는) 이 취약점의 영향을 받지 않습니다."
		t.Action = "이 취약점과 관련해 별도 조치는 필요하지 않습니다."
	} else {
		t.Impact = "사용 중인 " + p + " 버전에 이 구성요소가 포함되어 있습니다."
		t.Action = map[bool]string{true: p + " " + n.Fix.Tag + " 버전으로 업그레이드해 주십시오.", false: "아직 패치 버전이 없습니다. 외부 노출 제한(네트워크 접근·입력 경로) 등 완화 조치를 적용하고 후속 안내를 기다려 주십시오."}[n.Fix.Found]
	}
	return t
}

// ---------- AI 설명 ----------

var custAISchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"summary":   map[string]any{"type": "string", "maxLength": 600},
		"impact":    map[string]any{"type": "string", "maxLength": 600},
		"action":    map[string]any{"type": "string", "maxLength": 600},
		"citations": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "minItems": 1, "maxItems": 8},
	},
	"required": []string{"summary", "impact", "action", "citations"},
}

const custTaskKo = `고객사 보안 담당자에게 보낼 안내문의 설명 부분을 쉬운 말로 쓴다(전문 용어는 짧게 풀어 쓴다).
- summary: 이 취약점이 무엇이고 왜 위험한지 2~3문장.
- impact: 우리 제품(P1)의 어떤 버전이 어떻게 영향을 받는지(또는 받지 않는지) 2~3문장.
- action: 고객이 할 일 2~4문장. 버전 번호는 F1 에 있는 것만 쓴다. F1 에 패치 버전이 없으면 버전 번호 없이 완화 조치와 후속 안내를 쓴다.
- 문장 끝에 근거 사실 ID 를 [V1] 처럼 붙이고 citations 에 모은다. 사실에 없는 버전·날짜·수치·고객 정보를 쓰지 않는다.`

const custTaskEn = `Write the explanatory part of a notice to a customer's security contact, in plain language (briefly explain technical terms).
- summary: what this vulnerability is and why it matters, 2-3 sentences.
- impact: which versions of our product (P1) are affected (or not) and how, 2-3 sentences.
- action: what the customer should do, 2-4 sentences. Use only version numbers present in F1. If F1 has no patched version, describe mitigations and say a follow-up notice will come, without version numbers.
- End each sentence with the supporting fact ID like [V1] and collect them in citations. Never invent versions, dates, numbers or customer details.`

// guardCustAI: 인용 검증 + 사실에 없는 버전 표기 차단(버전은 규칙만 정한다).
func guardCustAI(t *custAIText, facts []aiFact) error {
	t.Citations = validCitations(t.Citations, facts)
	if len(t.Citations) == 0 {
		return fmt.Errorf("유효한 근거 인용 없음")
	}
	all := "" // 외부 원문(권고문)에 적힌 버전은 근거로 치지 않는다
	for _, f := range facts {
		if !f.Untrusted {
			all += " " + f.Text
		}
	}
	for _, x := range verLike.FindAllString(t.Summary+" "+t.Impact+" "+t.Action, -1) {
		if !strings.Contains(all, x) {
			return fmt.Errorf("사실에 없는 버전 표기(%s)", x)
		}
	}
	return nil
}

// fixCustFields: AI 가 칸을 엉뚱하게 채운 경우(너무 짧음·식별자 모양·한글판인데 한글 없음) 그 칸만 규칙 문구로 바꾼다.
var identLike = regexp.MustCompile(`^[A-Za-z0-9_.\-]+$`)

func fixCustFields(t, rule *custAIText, lang string) {
	bad := func(v string) bool {
		v = strings.TrimSpace(v)
		return len([]rune(v)) < 12 || identLike.MatchString(v) || (lang != "en" && !hangulRe.MatchString(v))
	}
	for _, f := range []struct {
		name     string
		val, alt *string
	}{{"요약", &t.Summary, &rule.Summary}, {"영향", &t.Impact, &rule.Impact}, {"조치", &t.Action, &rule.Action}} {
		if bad(*f.val) {
			t.Warnings = append(t.Warnings, f.name+" 칸은 AI 출력이 올바르지 않아 규칙 문구로 바꿈")
			*f.val = *f.alt
		}
	}
}

// runNoticeAI: 대상 언어별로 AI 설명을 만든다. 실패·꺼짐이면 규칙 문구를 유지하고 사유를 남긴다.
func (s *Server) runNoticeAI(n *CustNotice, actor string) {
	defer aiInteractive()()
	if !aiEnabledFor("vex") {
		n.AIError = "AI 꺼짐 — 규칙 문구로 작성"
		return
	}
	errs := []string{}
	langs := []string{}
	for l := range targetLangs(n) {
		langs = append(langs, l)
	}
	sort.Strings(langs)
	for _, l := range langs {
		var out custAIText
		task := map[bool]string{true: custTaskEn, false: custTaskKo}[l == "en"]
		meta, err := s.aiDraftFor("vex", l, n.Facts, task, custAISchema, 900, &out)
		if err == nil {
			err = guardCustAI(&out, n.Facts)
		}
		if err != nil {
			errs = append(errs, l+": "+err.Error())
			n.AI[l] = ruleText(n, l)
			n.AI[l].Warnings = []string{"AI 초안을 쓰지 않음: " + err.Error()}
			continue
		}
		fixCustFields(&out, ruleText(n, l), l)
		out.Source, out.Model = "ai", meta.Model
		n.AI[l] = &out
		b, _ := json.Marshal(out)
		s.aiRecord(actor, "customer-notice", n.Repo, "", meta, sha256hex(b), map[string]any{"notice": n.ID, "vuln": n.VulnID, "lang": l})
	}
	n.AIError = strings.Join(errs, "; ")
}

// ---------- ④ 메일 ----------

func renderMails(s *Server, n *CustNotice) {
	for i := range n.Targets {
		t := &n.Targets[i]
		t.Subject, t.Text, t.HTML = buildCustMail(s, n, t, n.AI[t.Lang])
	}
}

func buildCustMail(s *Server, n *CustNotice, t *CustTarget, ai *custAIText) (subject, text, htm string) {
	en := t.Lang == "en"
	L := func(ko, e string) string { return map[bool]string{false: ko, true: e}[en] }
	p := path.Base(n.Repo)
	if ai == nil {
		ai = ruleText(n, t.Lang)
	}
	sev := firstNonEmpty(n.Severity, L("미상", "unknown"))
	if n.KEV {
		sev += ", KEV"
	}
	if n.Kind == "notaffected" {
		subject = L("[영향 없음 확인] ", "[Not Affected] ") + p + " — " + n.VulnID
	} else if t.Recommend != "" {
		subject = L("[보안 권고] ", "[Security Advisory] ") + p + " — " + n.VulnID + L(" 패치 버전 "+t.Recommend+" 적용 권고", ": upgrade to "+t.Recommend)
	} else {
		subject = L("[보안 권고] ", "[Security Advisory] ") + p + " — " + n.VulnID + L(" 완화 조치 안내", ": mitigation guidance")
	}
	strip := func(x string) string { return strings.TrimSpace(reCiteMark.ReplaceAllString(x, "")) }
	type sec struct{ h, body string }
	secs := []sec{
		{L("요약", "Summary"), strip(ai.Summary)},
		{L("영향", "Impact"), strip(ai.Impact)},
		{L("조치", "Action"), strip(ai.Action)},
	}
	if n.Kind == "patch" {
		v := ""
		if t.Recommend != "" {
			v = p + " " + t.Recommend
			if t.RecComp != "" {
				v += L(" (구성요소 "+n.Component+" "+t.RecComp+")", " (component "+n.Component+" "+t.RecComp+")")
			}
			v += L(" — 이 버전의 분석 결과에 해당 취약점이 없습니다.", " — this vulnerability is absent from that version's analysis.")
		} else {
			v = L("아직 패치 버전이 없습니다 — 위 완화 조치를 적용해 주십시오. 패치가 준비되면 다시 안내드립니다.",
				"No patched version yet — please apply the mitigations above. We will notify you when a patch is ready.")
		}
		if n.Fix.OSV != nil && len(n.Fix.OSV.Fixed) > 0 {
			v += L(" (참고: OSV "+n.Fix.OSV.ID+" 구성요소 수정 버전 "+strings.Join(n.Fix.OSV.Fixed, ", ")+")",
				" (Reference: OSV "+n.Fix.OSV.ID+" component fixed in "+strings.Join(n.Fix.OSV.Fixed, ", ")+")")
		}
		secs = append(secs, sec{L("권장 패치 버전", "Recommended version"), v})
	}
	if len(t.Notes) > 0 {
		secs = append(secs, sec{L("계약·지원 안내", "Contract & support"), strings.Join(t.Notes, "\n")})
	}
	greet := L(t.Customer+" 보안 담당자님께,", "Dear "+t.Customer+" security team,")
	intro := L(p+" 에 포함된 구성요소 "+n.Component+" "+n.CompVersion+" 의 취약점 "+n.VulnID+"(심각도 "+sev+")에 대해 안내드립니다.",
		"This notice concerns vulnerability "+n.VulnID+" (severity "+sev+") in component "+n.Component+" "+n.CompVersion+" included in "+p+".")
	inst := L("귀사 설치 버전: ", "Your installed version(s): ") + strings.Join(t.Tags, ", ")
	foot := ""
	if ai.Source == "ai" {
		foot = L("※ 설명 문구는 AI 보조로 작성되었고 담당자가 검토했습니다. 버전 판단은 분석 규칙으로 정했습니다.",
			"* The explanation was drafted with AI assistance and reviewed by our staff. Versions were determined by analysis rules.")
	}
	link := s.artifactURL(n.Repo, firstNonEmpty(t.Recommend, t.Tags[0]))
	var b strings.Builder
	b.WriteString(greet + "\n\n" + intro + "\n" + inst + "\n")
	for _, x := range secs {
		b.WriteString("\n[" + x.h + "]\n" + x.body + "\n")
	}
	b.WriteString("\n" + L("제품 페이지: ", "Product page: ") + link + "\n")
	if foot != "" {
		b.WriteString("\n" + foot + "\n")
	}
	text = b.String()
	e := html.EscapeString
	var h strings.Builder
	h.WriteString(`<div style="font-family:sans-serif;font-size:14px;line-height:1.6;color:#0f172a;max-width:680px">`)
	h.WriteString("<p>" + e(greet) + "</p><p>" + e(intro) + "<br><b>" + e(inst) + "</b></p>")
	for _, x := range secs {
		h.WriteString(`<h3 style="font-size:15px;margin:18px 0 6px;border-left:4px solid #2563eb;padding-left:8px">` + e(x.h) + "</h3><p style=\"margin:0\">" +
			strings.ReplaceAll(e(x.body), "\n", "<br>") + "</p>")
	}
	h.WriteString(`<p style="margin-top:18px"><a href="` + e(link) + `">` + e(L("제품 페이지 열기", "Open product page")) + "</a></p>")
	if foot != "" {
		h.WriteString(`<p style="font-size:12px;color:#7c3aed">✦ ` + e(foot) + "</p>")
	}
	h.WriteString("</div>")
	return subject, text, h.String()
}

// ---------- 저장 ----------

func (c *custStore) putNotice(n *CustNotice) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.d.Notices {
		if c.d.Notices[i].ID == n.ID {
			c.d.Notices[i] = *n
			return c.saveLocked()
		}
	}
	c.d.Notices = append(c.d.Notices, *n)
	if len(c.d.Notices) > custNoticeKeep {
		c.d.Notices = c.d.Notices[len(c.d.Notices)-custNoticeKeep:]
	}
	return c.saveLocked()
}

func (c *custStore) notice(id string) (*CustNotice, bool) {
	for _, n := range c.snapshot().Notices {
		if n.ID == id {
			return &n, true
		}
	}
	return nil, false
}

// ---------- ⑤ 발송 ----------

// pilotPending: 아직 보내지 않은(시도조차 안 한) 내부 검증(pilot) 대상 고객 이름. 비어 있으면 외부로 보내도 된다.
// "시도함"(Result != nil)을 기준으로 봐 — 내부 주소가 모두 허용 목록 밖이어도 외부가 영영 막히지 않게.
func pilotPending(n *CustNotice) []string {
	out := []string{}
	for i := range n.Targets {
		if t := &n.Targets[i]; t.Ring == "pilot" && t.Result == nil && !inList(t.Customer, out) {
			out = append(out, t.Customer)
		}
	}
	return out
}

// hasExternalKey: 고른 키 중 외부(비 pilot) 대상이 있는가.
func hasExternalKey(n *CustNotice, keys []string) bool {
	for i := range n.Targets {
		if t := &n.Targets[i]; t.Ring != "pilot" && inList(t.Key, keys) {
			return true
		}
	}
	return false
}

// pilotGate: 외부 대상을 보내려는데 내부 검증(pilot) 링이 아직 안 나갔으면 막을 사유(없으면 ""). 발송하는 모든 경로가 부른다.
func pilotGate(n *CustNotice, keys []string) string {
	if !hasExternalKey(n, keys) {
		return ""
	}
	if p := pilotPending(n); len(p) > 0 {
		return "내부 검증 고객(" + strings.Join(p, ", ") + ")에게 먼저 보내고 확인한 뒤 외부 고객에게 보낼 수 있습니다."
	}
	return ""
}

// sendNotice: 선택한 대상(키)을 발송함에 넣는다(delay 뒤 발송, 그 전에는 취소 가능).
// 이미 보냈거나 기다리는 대상은 다시 넣지 않는다. custNoticeMu 를 잡은 채로 부른다.
func (s *Server) sendNotice(n *CustNotice, keys []string, actor string, delay time.Duration) {
	now := s.cust().now().UTC().Format(time.RFC3339)
	queued, fail := 0, 0
	log := []map[string]any{}
	for i := range n.Targets {
		t := &n.Targets[i]
		if !inList(t.Key, keys) || (t.Result != nil && (len(t.Result.Sent) > 0 || t.Result.Pending)) {
			continue
		}
		res := &custSendResult{At: now}
		to := append(append([]string{}, t.To...), t.Cc...)
		allowed, dropped := s.mail.filter(to)
		switch {
		case !s.mail.Configured():
			res.Error = "메일 서버 미설정(SMTP_HOST)"
		case len(to) == 0:
			res.Error = "받는 주소 없음"
		case len(allowed) == 0:
			res.Dropped = dropped // 모두 허용 목록 밖 — 발송함에 넣지 않음
		default:
			id, key := n.ID, t.Key
			it := s.enqueueMail("custnotify", t.Customer, n.ID, actor, to, t.Subject, mailContent{Text: t.Text, HTML: t.HTML}, delay,
				func(it outboxItem) { s.noticeOutboxDone(id, key, it) })
			res.Outbox, res.Pending, res.SendAt = it.ID, true, it.SendAt
		}
		t.Result = res
		if res.Pending {
			queued++
		} else {
			fail++
		}
		log = append(log, map[string]any{"customer": t.CustomerID, "lang": t.Lang, "outbox": res.Outbox, "dropped": res.Dropped, "error": res.Error})
	}
	n.SentAt, n.SentBy = now, actor
	n.Status = noticeStatus(n)
	_ = s.sor.append(SoREvent{Actor: actor, Action: "customer-notify", Subject: n.ID, Repo: n.Repo, Status: n.Status,
		Detail: map[string]any{"kind": n.Kind, "vuln": n.VulnID, "recommend": n.Fix.Tag, "queued": queued, "failed": fail, "delaySec": int(delay / time.Second), "targets": log}})
}

// noticeStatus: 대상별 결과로 통지 상태를 정한다.
func noticeStatus(n *CustNotice) string {
	sentAny, allSent, dropOnly, pending, tried := false, true, true, false, false
	for _, t := range n.Targets {
		if t.Result != nil {
			tried = true
		}
		pending = pending || (t.Result != nil && t.Result.Pending)
		done := t.Result != nil && len(t.Result.Sent) > 0
		sentAny = sentAny || done
		allSent = allSent && done
		dropOnly = dropOnly && (t.Result == nil || (t.Result.Error == "" && !t.Result.Pending && len(t.Result.Sent) == 0 && len(t.Result.Dropped) > 0))
	}
	switch {
	case pending:
		return "queued" // 발송함에서 기다리는 중
	case allSent && sentAny:
		return "sent"
	case sentAny:
		return "partial"
	case dropOnly && tried:
		return "dropped" // 모두 허용 목록 밖이라 건너뜀
	case !tried:
		return n.Status
	}
	return "failed"
}

// noticeOutboxDone: 발송함에서 보냈거나 취소된 뒤 통지의 대상 결과를 바꾼다.
func (s *Server) noticeOutboxDone(noticeID, key string, it outboxItem) {
	custNoticeMu.Lock()
	defer custNoticeMu.Unlock()
	c := s.cust()
	n, ok := c.notice(noticeID)
	if !ok {
		return
	}
	for i := range n.Targets {
		t := &n.Targets[i]
		if t.Key != key || t.Result == nil || t.Result.Outbox != it.ID {
			continue
		}
		t.Result.Pending, t.Result.At = false, it.DoneAt
		t.Result.Sent, t.Result.Dropped, t.Result.Error = it.Sent, it.Dropped, it.Error
		if it.Status == "cancelled" {
			t.Result.Cancelled, t.Result.Error = true, "보내기 취소됨("+it.DoneBy+")"
		}
	}
	n.Status = noticeStatus(n)
	_ = c.putNotice(n)
}

// ---------- API ----------

type custVulnCand struct {
	VulnID    string   `json:"vulnId"`
	Repo      string   `json:"repo"`
	Severity  string   `json:"severity"`
	KEV       bool     `json:"kev"`
	Component string   `json:"component"`
	Tags      []string `json:"tags"`
	States    []string `json:"states"`
	Customers []string `json:"customers"`
	Notified  string   `json:"notified,omitempty"` // 이미 보낸 통지 시각
}

// GET /api/custnotify/vulns?kind=patch|notaffected — ① 고객 설치 버전에 걸린 취약점 후보.
func (s *Server) apiCustNotifyVulns(w http.ResponseWriter, r *http.Request) {
	kind := firstNonEmpty(r.URL.Query().Get("kind"), "patch")
	if !s.dtEnabled() {
		writeJSON(w, 200, map[string]any{"items": []custVulnCand{}, "error": "DT 미설정"})
		return
	}
	d := s.cust().snapshot()
	byKey := map[string]*custVulnCand{}
	views := map[string]*dtRepoView{}
	for _, c := range activeCustomers(d.Customers) {
		for _, u := range c.Usages {
			v := views[u.Repo]
			if v == nil {
				v = s.dtView(u.Repo)
				views[u.Repo] = v
			}
			for _, in := range u.Installs {
				fs, _ := v.findings(in.Tag)
				for _, f := range fs {
					st := stateOf(f)
					if (kind == "patch" && inList(st, dtInactive)) || (kind == "notaffected" && !inList(st, dtNotAffected)) {
						continue
					}
					id := strings.ToUpper(f.Vulnerability.VulnID)
					k := u.Repo + "|" + id
					cd := byKey[k]
					if cd == nil {
						cd = &custVulnCand{VulnID: id, Repo: u.Repo, Severity: strings.ToUpper(f.Vulnerability.Severity), KEV: isKEV(vulnIDs(f)),
							Component: f.Component.Name + " " + f.Component.Version, Tags: []string{}, States: []string{}, Customers: []string{}}
						byKey[k] = cd
					}
					if !inList(in.Tag, cd.Tags) {
						cd.Tags = append(cd.Tags, in.Tag)
					}
					if !inList(st, cd.States) {
						cd.States = append(cd.States, st)
					}
					if !inList(c.Name, cd.Customers) {
						cd.Customers = append(cd.Customers, c.Name)
					}
				}
			}
		}
	}
	for _, n := range d.Notices {
		if cd := byKey[n.Repo+"|"+n.VulnID]; cd != nil && n.Kind == kind && n.Status != "draft" && n.SentAt > cd.Notified {
			cd.Notified = n.SentAt
		}
	}
	out := []custVulnCand{}
	for _, cd := range byKey {
		out = append(out, *cd)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.KEV != b.KEV {
			return a.KEV
		}
		if severityRank(a.Severity) != severityRank(b.Severity) {
			return severityRank(a.Severity) < severityRank(b.Severity)
		}
		if len(a.Customers) != len(b.Customers) {
			return len(a.Customers) > len(b.Customers)
		}
		return a.VulnID < b.VulnID
	})
	writeJSON(w, 200, map[string]any{"items": out})
}

// POST /api/custnotify {kind, repo, vulnId} — ②③ 영향 고객 + 규칙 패치 버전 + 메일 초안(저장, status=draft).
func (s *Server) apiCustNotifyCreate(w http.ResponseWriter, r *http.Request) {
	var in struct{ Kind, Repo, VulnID string }
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "요청 형식 오류"})
		return
	}
	actor := w.Header().Get("X-User")
	n, err := s.buildNotice(in.Kind, in.Repo, in.VulnID, actor)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if err := s.cust().putNotice(n); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 201, n)
}

// POST /api/custnotify/{id}/ai — ③ AI 설명(언어별) → 메일 다시 작성.
func (s *Server) apiCustNotifyAI(w http.ResponseWriter, r *http.Request) {
	c := s.cust()
	n, ok := c.notice(r.PathValue("id"))
	if !ok || n.Status != "draft" {
		writeJSON(w, 404, map[string]string{"error": "초안 없음(이미 보낸 통지는 바꿀 수 없음)"})
		return
	}
	if t, _ := time.Parse(time.RFC3339, n.AIStarted); n.AIState == "running" && time.Since(t) < 30*time.Minute { // 30분 넘으면(재시작 등) 다시 허용
		writeJSON(w, 409, map[string]string{"error": "AI 설명을 이미 작성하고 있습니다"})
		return
	}
	n.AIState, n.AIStarted = "running", time.Now().UTC().Format(time.RFC3339)
	if err := c.putNotice(n); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 202, n)
	actor := w.Header().Get("X-User")
	go func(n CustNotice) { // 응답은 바로 — 화면은 GET 으로 진행을 본다
		s.runNoticeAI(&n, actor)
		renderMails(s, &n)
		n.AIState = "done"
		_ = c.putNotice(&n)
	}(*n)
}

// POST /api/custnotify/{id}/send {keys:[...]} — ⑤ 발송.
func (s *Server) apiCustNotifySend(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Keys  []string `json:"keys"`
		Delay *int     `json:"delay"` // 발송함 대기(초) — 0·10·30·60·120, 없으면 30
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || len(in.Keys) == 0 {
		writeJSON(w, 400, map[string]string{"error": "보낼 대상을 고르세요"})
		return
	}
	delay := 30 * time.Second
	if in.Delay != nil {
		delay = outboxDelay(*in.Delay)
	}
	custNoticeMu.Lock()
	defer custNoticeMu.Unlock()
	c := s.cust()
	n, ok := c.notice(r.PathValue("id"))
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "통지 없음"})
		return
	}
	if n.AIState == "running" {
		writeJSON(w, 409, map[string]string{"error": "AI 설명을 작성하는 중입니다 — 끝난 뒤 보내세요"})
		return
	}
	if msg := pilotGate(n, in.Keys); msg != "" { // 내부 검증(pilot) 고객을 먼저 보낸 뒤에야 외부로
		writeJSON(w, 409, map[string]string{"error": msg})
		return
	}
	s.sendNotice(n, in.Keys, w.Header().Get("X-User"), delay)
	if err := c.putNotice(n); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, n)
}

// GET /api/custnotify — 이력(최근순, 요약). GET /api/custnotify/{id} — 상세.
func (s *Server) apiCustNotifyList(w http.ResponseWriter, r *http.Request) {
	d := s.cust().snapshot()
	out := []map[string]any{}
	for i := len(d.Notices) - 1; i >= 0; i-- {
		n := d.Notices[i]
		sent, dropped, failed := 0, 0, 0
		for _, t := range n.Targets {
			if t.Result == nil {
				continue
			}
			if len(t.Result.Sent) > 0 {
				sent++
			} else if len(t.Result.Dropped) > 0 && t.Result.Error == "" {
				dropped++
			} else {
				failed++
			}
		}
		out = append(out, map[string]any{"id": n.ID, "kind": n.Kind, "status": n.Status, "created": n.Created, "createdBy": n.CreatedBy,
			"sentAt": n.SentAt, "repo": n.Repo, "vulnId": n.VulnID, "severity": n.Severity, "kev": n.KEV, "recommend": n.Fix.Tag,
			"targets": len(n.Targets), "sent": sent, "dropped": dropped, "failed": failed})
	}
	writeJSON(w, 200, out)
}

func (s *Server) apiCustNotifyGet(w http.ResponseWriter, r *http.Request) {
	n, ok := s.cust().notice(r.PathValue("id"))
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "통지 없음"})
		return
	}
	writeJSON(w, 200, n)
}

// DELETE /api/custnotify/{id} — 초안만 삭제.
func (s *Server) apiCustNotifyDelete(w http.ResponseWriter, r *http.Request) {
	c := s.cust()
	id := r.PathValue("id")
	c.mu.Lock()
	out := []CustNotice{}
	found := false
	for _, n := range c.d.Notices {
		if n.ID == id && n.Status == "draft" {
			found = true
			continue
		}
		out = append(out, n)
	}
	if !found {
		c.mu.Unlock()
		writeJSON(w, 404, map[string]string{"error": "초안 없음(보낸 통지는 기록으로 남는다)"})
		return
	}
	c.d.Notices = out
	err := c.saveLocked()
	c.mu.Unlock()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": id})
}
