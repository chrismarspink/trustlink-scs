package main

// auto_response.go: 자동 대응 — 새 취약점이 잡히면 사람 손을 덜 거치고 다음 단계까지 이어 준다.
//
//   ① 탐지   : DT 새 취약점 알림(notify.go sendVulnNotice) 중 KEV·CRITICAL 을 고른다(또는 화면에서 직접 실행)
//   ② AI 분석: 그 취약점의 VEX 판정 초안(ai_vex.go vexDraftFor). "영향 없음"이면 통지하지 않고 사람 확인으로 넘긴다
//   ③ 패치 확인: 이 버전보다 새 제품 버전 중 취약점이 사라진 버전을 찾는다(custnotify.go fixScan/pickFix)
//   ④-가 패치 있음: 영향 고객 통지 초안(고객별 언어·AI 설명)을 만들고 **관리자 승인을 기다린다**.
//         관리자에게 알림(화면·메일) → 관리자가 받는 사람을 확인하고 "승인·발송" → 발송함(취소 가능) → 고객
//   ④-나 패치 없음: 개발자(제품 쓰기 권한자·관리자)에게 보낼 "수정 버전 필요" 메일 초안 + **관리자 승인 대기**
//   ⑤ 관리자가 화면(관리 › 자동 대응, 대시보드에 승인 대기 표시)에서 받는 사람을 고르고 보낼지 정한다
//      → 승인하면 발송함(취소 가능)을 거쳐 고객 또는 개발자에게
//
// 시작은 두 가지: DT 새 취약점 알림(바로) + 주기 검색(sweep, 기본 6시간 — 고객에게 납품한 제품의
// 고객 설치 버전·최신 버전에서 아직 판단·대응하지 않은 KEV·치명 취약점을 찾아 한 번에 최대 N건).
// 메일은 고객·개발자 모두 관리자가 승인해야 나간다.
// 기록은 auto-response.json(최근 200건)과 원장(SoR)에 남는다.

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type autoStage struct {
	Key    string `json:"key"`   // detect / ai / fix / approve / notify / devreq
	Label  string `json:"label"` // 화면 표시
	State  string `json:"state"` // todo / active / done / skip / error / wait
	At     string `json:"at,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type autoRun struct {
	ID          string      `json:"id"`
	Trigger     string      `json:"trigger"` // auto / manual
	By          string      `json:"by"`
	Repo        string      `json:"repo"`
	Tag         string      `json:"tag"`
	VulnID      string      `json:"vulnId"`
	Component   string      `json:"component,omitempty"`
	Severity    string      `json:"severity,omitempty"`
	KEV         bool        `json:"kev,omitempty"`
	EPSS        float64     `json:"epss,omitempty"`
	Started     string      `json:"started"`
	Finished    string      `json:"finished,omitempty"`
	State       string      `json:"state"`             // running / waiting(승인 대기) / done / error
	Outcome     string      `json:"outcome,omitempty"` // approval / sent / rejected / dev-request / not-affected / no-customers / error
	Stages      []autoStage `json:"stages"`
	AIStatus    string      `json:"aiStatus,omitempty"` // affected / not_affected / under_investigation ...
	AISummary   string      `json:"aiSummary,omitempty"`
	AIModel     string      `json:"aiModel,omitempty"`
	AIMethod    string      `json:"aiMethod,omitempty"` // rule / rule+card / ai-slim / ai-full
	FixTag      string      `json:"fixTag,omitempty"`
	FixComp     string      `json:"fixComp,omitempty"`
	Upstream    string      `json:"upstream,omitempty"` // 구성요소 자체의 수정 버전(OSV 등)
	NoticeID    string      `json:"noticeId,omitempty"`
	Recommended []string    `json:"recommended,omitempty"` // 추천된 받는 사람(고객 담당자)
	Customers   []string    `json:"customers,omitempty"`
	Waiting     []string    `json:"waiting,omitempty"` // 패치가 아직 없는 버전을 쓰는 고객
	DevTo       []string    `json:"devTo,omitempty"`
	DevSubject  string      `json:"devSubject,omitempty"` // 개발자 수정 요청 초안(승인 전)
	DevBody     string      `json:"devBody,omitempty"`
	DevCands    []devCand   `json:"devCandidates,omitempty"` // 추천 받는 사람(제품 쓰기 권한자·관리자)
	Outbox      []string    `json:"outbox,omitempty"`
	FollowedBy  string      `json:"followedBy,omitempty"` // 수정 버전이 나와 이어 간 자동 대응 기록
	FollowOf    string      `json:"followOf,omitempty"`   // 이 기록이 이어받은 개발자 요청 기록
	PatchTag    string      `json:"patchTag,omitempty"`   // 새로 확인된 수정 버전
	Approver    string      `json:"approver,omitempty"`
	Error       string      `json:"error,omitempty"`
}

type devCand struct {
	Username string `json:"username"`
	Email    string `json:"email,omitempty"`
}

type autoSettings struct {
	Mode       string `json:"mode"` // on / off
	MaxPerVer  int    `json:"maxPerVersion"`
	SweepHours int    `json:"sweepHours"` // 주기 검색 간격(시간), 0 = 끔
	SweepMax   int    `json:"sweepMax"`   // 한 번 검색에서 새로 처리할 최대 건수
	LastSweep  string `json:"lastSweep,omitempty"`
	SweepMsg   string `json:"sweepMsg,omitempty"`
	Sweeping   bool   `json:"sweeping,omitempty"`
	UpdatedBy  string `json:"updatedBy,omitempty"`
}

var autoRes = struct {
	sync.Mutex
	loaded   bool
	Runs     []autoRun    `json:"runs"`
	Settings autoSettings `json:"settings"`
}{}

const autoActor = "trustlink-auto"

func autoPath() string { return filepath.Join(filepath.Dir(aiConfigPath()), "auto-response.json") }

func autoLoad() { // 잠근 채로
	if autoRes.loaded {
		return
	}
	autoRes.loaded = true
	var d struct {
		Runs     []autoRun    `json:"runs"`
		Settings autoSettings `json:"settings"`
	}
	_ = readJSONFile(autoPath(), &d)
	autoRes.Runs, autoRes.Settings = d.Runs, d.Settings
	if autoRes.Settings.Mode == "" {
		autoRes.Settings.Mode = "on"
	}
	if autoRes.Settings.MaxPerVer <= 0 {
		autoRes.Settings.MaxPerVer = 3
	}
	if autoRes.Settings.SweepHours == 0 && autoRes.Settings.SweepMax == 0 { // 처음: 6시간마다, 5건
		autoRes.Settings.SweepHours, autoRes.Settings.SweepMax = 6, 5
	}
	if autoRes.Settings.SweepMax <= 0 {
		autoRes.Settings.SweepMax = 5
	}
	autoRes.Settings.Sweeping = false
	for i := range autoRes.Runs { // 재시작으로 끊긴 진행은 오류로
		if autoRes.Runs[i].State == "running" {
			autoRes.Runs[i].State, autoRes.Runs[i].Outcome, autoRes.Runs[i].Error = "error", "error", "서버 재시작으로 중단됨 — 다시 실행하세요"
		}
	}
}

func autoSaveLocked() {
	if n := len(autoRes.Runs); n > 200 {
		autoRes.Runs = autoRes.Runs[n-200:]
	}
	_ = writeJSONFile(autoPath(), map[string]any{"runs": autoRes.Runs, "settings": autoRes.Settings})
}

// autoUpdate: 진행 중 기록을 바꾸고 저장한다.
func autoUpdate(id string, fn func(r *autoRun)) autoRun {
	autoRes.Lock()
	defer autoRes.Unlock()
	autoLoad()
	for i := range autoRes.Runs {
		if autoRes.Runs[i].ID == id {
			fn(&autoRes.Runs[i])
			autoSaveLocked()
			return autoRes.Runs[i]
		}
	}
	return autoRun{}
}

func stage(r *autoRun, key, state, detail string) {
	for i := range r.Stages {
		if r.Stages[i].Key == key {
			r.Stages[i].State, r.Stages[i].Detail, r.Stages[i].At = state, detail, time.Now().UTC().Format(time.RFC3339)
		}
	}
}

func newAutoRun(trigger, by, repo, tag, vuln string) autoRun {
	return autoRun{ID: newCustID("ar-"), Trigger: trigger, By: by, Repo: repo, Tag: tag, VulnID: vuln, Started: time.Now().UTC().Format(time.RFC3339), State: "running",
		Stages: []autoStage{{Key: "detect", Label: "탐지", State: "todo"}, {Key: "ai", Label: "AI 분석", State: "todo"}, {Key: "fix", Label: "패치 버전 확인", State: "todo"},
			{Key: "approve", Label: "관리자 승인", State: "todo"}, {Key: "notify", Label: "고객 통지", State: "todo"}, {Key: "devreq", Label: "개발자 통보", State: "todo"}}}
}

// maybeAutoRespond: 새 취약점 통보 뒤 KEV·CRITICAL 을 골라 자동 대응(백그라운드, 한 건씩).
func (s *Server) maybeAutoRespond(repo, tag string, vulns []vulnInfo) {
	autoRes.Lock()
	autoLoad()
	on, max := autoRes.Settings.Mode == "on", autoRes.Settings.MaxPerVer
	done := map[string]bool{}
	for _, r := range autoRes.Runs {
		if r.Repo == repo && r.Tag == tag && r.State != "error" {
			done[r.VulnID] = true
			if r.Trigger == "auto" {
				max-- // DT 알림이 여러 번에 나뉘어 와도 버전당 최대 건수를 넘지 않게
			}
		}
	}
	autoRes.Unlock()
	if !on || !s.dtEnabled() {
		return
	}
	var picks []string
	for _, v := range vulns { // 이미 심각도순
		if (strings.EqualFold(v.Severity, "CRITICAL") || isKEV([]string{v.ID})) && !done[v.ID] && !inList(v.ID, picks) {
			picks = append(picks, v.ID)
		}
		if len(picks) >= max {
			break
		}
	}
	if len(picks) == 0 || max <= 0 {
		return
	}
	go func() {
		for _, id := range picks {
			s.runAutoResponse(newAutoRun("auto", autoActor, repo, tag, id))
		}
	}()
}

// runAutoResponse: 한 취약점의 자동 대응(동기). 결과 기록을 돌려준다.
func (s *Server) runAutoResponse(r autoRun) autoRun {
	autoRes.Lock()
	autoLoad()
	autoRes.Runs = append(autoRes.Runs, r)
	autoSaveLocked()
	autoRes.Unlock()
	id := r.ID
	fail := func(key, msg string) autoRun {
		return autoUpdate(id, func(x *autoRun) {
			stage(x, key, "error", msg)
			x.State, x.Outcome, x.Error, x.Finished = "error", "error", msg, time.Now().UTC().Format(time.RFC3339)
		})
	}
	finish := func(x *autoRun, outcome, state string) {
		x.Outcome, x.State = outcome, state
		if state != "waiting" {
			x.Finished = time.Now().UTC().Format(time.RFC3339)
		}
		for i := range x.Stages {
			if x.Stages[i].State == "todo" {
				x.Stages[i].State = "skip"
			}
		}
	}

	// ① 탐지 — 이 버전의 DT 분석 결과에서 취약점을 찾는다
	autoUpdate(id, func(x *autoRun) { stage(x, "detect", "active", "분석 결과에서 찾는 중") })
	v := s.dtView(r.Repo)
	fs, ok := v.findings(r.Tag)
	if !ok {
		return fail("detect", "이 버전의 분석 결과가 없습니다(SBOM 미적재)")
	}
	f, ok := findVuln(fs, r.VulnID)
	if !ok {
		return fail("detect", r.VulnID+" 이(가) 이 버전 분석 결과에 없습니다")
	}
	comp := f.Component.Name + " " + f.Component.Version
	autoUpdate(id, func(x *autoRun) {
		x.Component, x.Severity, x.KEV = comp, strings.ToUpper(f.Vulnerability.Severity), isKEV(vulnIDs(f))
		if f.Vulnerability.EpssScore != nil {
			x.EPSS = *f.Vulnerability.EpssScore
		}
		stage(x, "detect", "done", fmt.Sprintf("%s:%s · %s · %s%s", path.Base(r.Repo), r.Tag, comp, x.Severity, map[bool]string{true: " · KEV", false: ""}[x.KEV]))
	})

	// ② AI 분석
	autoUpdate(id, func(x *autoRun) {
		stage(x, "ai", "active", "영향 여부를 분석하는 중(규칙 판정 + AI 권고문 요약)")
	})
	upstream := ""
	if aiEnabledFor("vex") {
		done := aiInteractive()
		actx := "자동 대응: 새로 발견된 취약점의 영향 여부와 대응을 판단"
		if vexFastOn() { // 사람이 적은 사용 맥락이 아니므로 규칙 판정으로(맥락으로 넘기면 '영향 없음' 근거로 쓰일 수 있다)
			actx = ""
		}
		d, err := s.vexDraftFor(autoActor, r.Repo, r.Tag, f, actx)
		done()
		if err != nil {
			autoUpdate(id, func(x *autoRun) {
				stage(x, "ai", "error", "AI 분석 실패 — 규칙으로 계속: "+truncate(err.Error(), 160))
			})
		} else {
			if len(d.Remedy.Fixed) > 0 {
				upstream = strings.Join(d.Remedy.Fixed, ", ")
			}
			sum := truncate(firstNonEmpty(d.Draft.Detail, d.Draft.Justification), 300)
			x := autoUpdate(id, func(x *autoRun) {
				x.AIStatus, x.AISummary, x.AIModel, x.Upstream, x.AIMethod = d.Draft.Status, sum, d.Meta.Model, upstream, d.Meta.Method
				stage(x, "ai", "done", fmt.Sprintf("판정 초안: %s(신뢰도 %s)", vexStateKo(d.Draft.Status), firstNonEmpty(d.Draft.Confidence, "—")))
			})
			if x.AIStatus == "not_affected" || x.AIStatus == "false_positive" {
				return autoUpdate(id, func(x *autoRun) {
					stage(x, "fix", "skip", "AI 가 영향 없음으로 판단 — 통지하지 않음. VEX 판단 화면에서 사람이 확인해 확정하세요")
					finish(x, "not-affected", "done")
				})
			}
		}
	} else {
		autoUpdate(id, func(x *autoRun) { stage(x, "ai", "skip", "AI 꺼짐 — 영향 있음으로 보고 진행") })
	}

	// ③ 패치 버전 확인
	autoUpdate(id, func(x *autoRun) {
		stage(x, "fix", "active", "새 제품 버전에서 취약점이 사라졌는지 확인하는 중")
	})
	c := s.cust()
	tags := s.versionTags(r.Repo, c.snapshot().Products[r.Repo])
	steps := v.fixScan(r.VulnID, f, tags, r.Tag)
	fix, found := pickFix(steps, r.Tag)
	newer := []string{}
	for _, st := range steps {
		newer = append(newer, st.Tag+"="+map[string]string{"fixed": "수정됨", "affected": "영향", "present": "남아 있음", "unknown": "확인 불가"}[st.Status])
	}
	scan := "새 버전 없음"
	if len(newer) > 0 {
		scan = strings.Join(newer, ", ")
	}
	if found {
		autoUpdate(id, func(x *autoRun) {
			x.FixTag, x.FixComp = fix.Tag, fix.CompVersion
			stage(x, "fix", "done", fmt.Sprintf("패치 버전 있음: %s %s(%s %s) — 확인: %s", path.Base(r.Repo), fix.Tag, f.Component.Name, fix.CompVersion, scan))
		})
		return s.autoCustomerNotice(id, r, comp)
	}
	// 참고: 이 제품의 다른 버전 중 같은 취약점이 없는(구성요소를 올린) 버전 — 개발자에게 "이 버전으로 올리면 된다"는 단서
	hint := ""
	for _, st := range v.fixScan(r.VulnID, f, tags, "0") {
		if st.Status == "fixed" && st.CompVersion != "" && st.Tag != r.Tag {
			hint = fmt.Sprintf("%s %s 은(는) %s %s 로 해결됨", path.Base(r.Repo), st.Tag, f.Component.Name, st.CompVersion)
			if upstream == "" {
				upstream = f.Component.Name + " " + st.CompVersion + "(" + path.Base(r.Repo) + " " + st.Tag + " 에서 확인)"
			}
		}
	}
	autoUpdate(id, func(x *autoRun) {
		stage(x, "fix", "done", "패치 버전 없음 — 확인: "+scan+map[bool]string{true: " · 참고: " + hint, false: ""}[hint != ""])
	})
	return s.autoDevRequest(id, r, comp, upstream)
}

func vexStateKo(s string) string {
	m := map[string]string{"affected": "영향 있음", "exploitable": "영향 있음", "not_affected": "영향 없음", "false_positive": "오탐", "under_investigation": "조사 필요", "in_triage": "조사 필요", "resolved": "해결됨"}
	return firstNonEmpty(m[strings.ToLower(s)], s)
}

// ④-가 패치 있음 → 고객 통지 초안 + 관리자 승인 요청
func (s *Server) autoCustomerNotice(id string, r autoRun, comp string) autoRun {
	n, err := s.buildNotice("patch", r.Repo, r.VulnID, autoActor)
	if err != nil {
		return autoUpdate(id, func(x *autoRun) {
			stage(x, "approve", "skip", "영향 고객 없음: "+err.Error())
			x.Outcome, x.State, x.Finished = "no-customers", "done", time.Now().UTC().Format(time.RFC3339)
			for i := range x.Stages {
				if x.Stages[i].State == "todo" {
					x.Stages[i].State = "skip"
				}
			}
		})
	}
	// 패치가 있는 고객만 통지 대상으로(더 새 버전을 쓰는데 아직 패치가 없는 고객은 그 버전의 자동 대응에서)
	keep, waiting := []CustTarget{}, []string{}
	for _, t := range n.Targets {
		if t.Recommend != "" {
			keep = append(keep, t)
		} else if !inList(t.Customer, waiting) {
			waiting = append(waiting, t.Customer+"("+strings.Join(t.Tags, ",")+")")
		}
	}
	n.Targets = keep
	n.CreatedBy = autoActor
	if len(keep) == 0 {
		return autoUpdate(id, func(x *autoRun) {
			x.Waiting = waiting
			stage(x, "approve", "skip", "패치를 받을 영향 고객이 없습니다")
			x.Outcome, x.State, x.Finished = "no-customers", "done", time.Now().UTC().Format(time.RFC3339)
			for i := range x.Stages {
				if x.Stages[i].State == "todo" {
					x.Stages[i].State = "skip"
				}
			}
		})
	}
	autoUpdate(id, func(x *autoRun) { stage(x, "approve", "active", "고객별 언어로 AI 통지 문안을 쓰는 중") })
	s.runNoticeAI(n, autoActor)
	renderMails(s, n)
	n.AutoRun = id
	custNoticeMu.Lock()
	err = s.cust().putNotice(n)
	custNoticeMu.Unlock()
	if err != nil {
		return autoUpdate(id, func(x *autoRun) { stage(x, "approve", "error", err.Error()); x.State, x.Outcome = "error", "error" })
	}
	custs, rec := []string{}, []string{}
	for _, t := range n.Targets {
		if !inList(t.Customer, custs) {
			custs = append(custs, t.Customer)
		}
		for _, a := range t.To {
			if !inList(a, rec) {
				rec = append(rec, a)
			}
		}
	}
	x := autoUpdate(id, func(x *autoRun) {
		x.NoticeID, x.Customers, x.Recommended, x.Waiting = n.ID, custs, rec, waiting
		stage(x, "approve", "wait", fmt.Sprintf("관리자 승인 대기 — 고객 %d곳(%s), 받는 사람 %d명 추천", len(custs), strings.Join(custs, ", "), len(rec)))
		stage(x, "devreq", "skip", "")
		if len(waiting) > 0 {
			stage(x, "devreq", "skip", "아직 패치가 없는 버전 사용 고객: "+strings.Join(waiting, ", ")+" — 그 버전의 자동 대응에서 개발자 수정 요청")
		}
		x.State, x.Outcome = "waiting", "approval"
	})
	s.notifyApproval(x, fmt.Sprintf("고객 통지(%s, 권장 %s)", strings.Join(custs, "·"), x.FixTag), "보안 권고 — "+r.VulnID)
	_ = s.sor.append(SoREvent{Actor: autoActor, Action: "auto-response", Repo: r.Repo, Tag: r.Tag, Status: "approval",
		Detail: map[string]any{"run": id, "vuln": r.VulnID, "notice": n.ID, "fix": x.FixTag, "customers": custs, "ai": x.AIStatus}})
	return x
}

// ④-나 패치 없음 → 개발자 수정 요청 초안 + 관리자 승인 요청
func (s *Server) autoDevRequest(id string, r autoRun, comp, upstream string) autoRun {
	x := autoUpdate(id, func(x *autoRun) {
		stage(x, "notify", "skip", "패치 버전이 없어 고객 통지 대신 개발자 수정 요청")
		stage(x, "devreq", "active", "개발자 수정 요청 메일을 쓰는 중")
	})
	// 이 버전을 쓰는 고객(패치가 나오면 통지할 대상)
	affected := []string{}
	for _, cu := range activeCustomers(s.cust().snapshot().Customers) {
		for _, u := range cu.Usages {
			if u.Repo != r.Repo {
				continue
			}
			for _, in := range u.Installs {
				if in.Tag == r.Tag && !inList(cu.Name, affected) {
					affected = append(affected, cu.Name)
				}
			}
		}
	}
	title := fmt.Sprintf("[TrustLink] 수정 버전 필요 — %s %s · %s · %s", path.Base(r.Repo), r.Tag, comp, r.VulnID)
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s 에서 %s(%s%s)가 발견되었지만, 이 취약점을 고친 제품 버전이 아직 없습니다.\n수정 버전을 만들어 올려 주세요.\n\n",
		path.Base(r.Repo), r.Tag, r.VulnID, x.Severity, map[bool]string{true: " · KEV", false: ""}[x.KEV])
	fmt.Fprintf(&b, "- 구성요소: %s\n", comp)
	if upstream != "" {
		fmt.Fprintf(&b, "- 구성요소 수정 버전(외부): %s 이상으로 올리면 해결됩니다\n", upstream)
	}
	if x.AIStatus != "" {
		fmt.Fprintf(&b, "- AI 판정 초안: %s — %s\n", vexStateKo(x.AIStatus), truncate(x.AISummary, 240))
	}
	if x.EPSS > 0 {
		fmt.Fprintf(&b, "- 악용 가능성(EPSS): %.2f\n", x.EPSS)
	}
	if len(affected) > 0 {
		fmt.Fprintf(&b, "- 이 버전을 쓰는 고객: %s — 수정 버전이 올라오면 TrustLink 가 다시 검증하고 고객 통지(관리자 승인)를 이어 갑니다\n", strings.Join(affected, ", "))
	} else {
		b.WriteString("- 고객 등록부에 이 버전을 쓰는 고객은 없습니다\n")
	}
	fmt.Fprintf(&b, "\n판단 화면: %s\n", s.artifactURL(r.Repo, r.Tag))
	cands := []devCand{}
	for _, u := range s.recipients(r.Repo, false) {
		cands = append(cands, devCand{Username: u.Username, Email: u.Email})
	}
	x = autoUpdate(id, func(x *autoRun) {
		x.Customers, x.Upstream, x.DevSubject, x.DevBody, x.DevCands = affected, upstream, title, b.String(), cands
		stage(x, "approve", "wait", fmt.Sprintf("관리자 승인 대기 — 개발자 수정 요청, 받는 사람 %d명 추천", len(cands)))
		stage(x, "devreq", "todo", "")
		x.State, x.Outcome = "waiting", "approval-dev"
	})
	s.notifyApproval(x, "개발자 수정 요청", title)
	_ = s.sor.append(SoREvent{Actor: autoActor, Action: "auto-response", Repo: r.Repo, Tag: r.Tag, Status: "approval-dev",
		Detail: map[string]any{"run": id, "vuln": r.VulnID, "candidates": len(cands), "upstream": upstream, "customers": affected}})
	return x
}

// notifyApproval: 관리자에게 "보낼지 정해 달라"는 메일(+화면 알림). 패치 유무와 받을 사람·메일 초안 요약을 담는다.
func (s *Server) notifyApproval(x autoRun, what, mailTitle string) {
	patch := x.NoticeID != ""
	c := s.approvalCard(x, mailTitle)
	s.deliver(Notice{Kind: "approval-needed", Audience: "internal", Repo: x.Repo, Tag: x.Tag,
		Title: fmt.Sprintf("[TrustLink] 결정 요청 — %s %s · %s · %s", path.Base(x.Repo), x.Tag, x.VulnID, map[bool]string{true: "고객 통지 승인", false: "개발자 수정 요청 승인"}[patch]),
		Body:  c.plain, card: &c}, s.adminUsers(), nil)
	_ = what
}

// approvalCard: 승인 요청 메일의 내용(틀에 담을 항목 + 화면 알림용 평문).
func (s *Server) approvalCard(x autoRun, mailTitle string) mailCard {
	patch := x.NoticeID != ""
	prod := path.Base(x.Repo)
	chips := []string{x.Severity}
	if x.KEV {
		chips = append(chips, "KEV")
	}
	sevKo := map[string]string{"CRITICAL": "치명적(CRITICAL)", "HIGH": "높음(HIGH)"}[x.Severity]
	c := mailCard{Module: "자동 대응", Purpose: "결정 요청", Tone: "decide", Product: prod, Version: x.Tag, Ref: x.ID,
		Reason: "관리자(admins) 그룹 — 고객·개발자에게 나가는 메일은 관리자 승인이 있어야 발송됩니다",
		Action: "승인·반려 화면 열기", URL: s.publicBase() + "/admin/auto-response", Alt: "결정함에서 보기", AltURL: s.publicBase() + "/admin/inbox"}
	c.Facts = []mailFact{{K: "취약점", V: x.VulnID, Chips: chips}, {K: "구성요소", V: x.Component}}
	trig := map[string]string{"auto": "새 취약점 알림(Dependency-Track)", "sweep": "주기 검색", "manual": "수동 실행", "patch": "수정 버전 확인(이어 가기)"}[x.Trigger]
	if trig != "" {
		c.Facts = append(c.Facts, mailFact{K: "감지 경로", V: trig})
	}
	var b strings.Builder // 화면 알림용 평문
	fmt.Fprintf(&b, "%s %s 에서 %s(%s)가 확인되었습니다.\n", prod, x.Tag, x.VulnID, strings.Join(chips, " · "))
	if patch {
		c.Title = "고객 보안 권고 발송 승인 요청"
		c.Lead = fmt.Sprintf("%s %s 에서 %s 취약점이 확인되었습니다(%s). 수정 버전은 %s 입니다. 이 버전을 쓰는 고객 %d곳에 보낼 보안 권고 초안을 준비했으니, 발송 여부를 결정해 주십시오.",
			prod, x.Tag, firstNonEmpty(sevKo, x.Severity), x.VulnID, x.FixTag, len(x.Customers))
		c.Facts = append(c.Facts, mailFact{K: "수정 버전", V: prod + " " + x.FixTag},
			mailFact{K: "통지 대상", V: fmt.Sprintf("%s\n받는 사람 %d명 추천", strings.Join(x.Customers, ", "), len(x.Recommended))})
		if len(x.Waiting) > 0 {
			c.Facts = append(c.Facts, mailFact{K: "수정 버전 없음", V: strings.Join(x.Waiting, ", ") + " — 이 고객이 쓰는 버전은 아직 수정 버전이 없습니다"})
		}
		c.Steps = []string{"승인하면 고른 받는 사람에게 발송함을 거쳐 나갑니다. 대기 시간 동안 취소할 수 있습니다.", "반려하면 보내지 않고 사유를 기록합니다.", "모든 결정은 감사 원장에 남습니다."}
		fmt.Fprintf(&b, "수정 버전 %s %s 있음 → 고객(%s)에게 보안 권고를 보낼지 결정해 주세요.\n", prod, x.FixTag, strings.Join(x.Customers, ", "))
	} else {
		names := []string{}
		for _, d := range x.DevCands {
			names = append(names, d.Username)
		}
		c.Title = "개발자 수정 요청 발송 승인 요청"
		c.Lead = fmt.Sprintf("%s %s 에서 %s 취약점이 확인되었습니다(%s). 수정 버전은 아직 없습니다. 개발 담당자에게 보낼 수정 요청 초안을 준비했으니, 발송 여부를 결정해 주십시오.",
			prod, x.Tag, firstNonEmpty(sevKo, x.Severity), x.VulnID)
		c.Facts = append(c.Facts, mailFact{K: "수정 버전", V: "없음"}, mailFact{K: "요청 대상", V: "개발자 " + strings.Join(names, ", ")})
		if len(x.Customers) > 0 {
			c.Facts = append(c.Facts, mailFact{K: "사용 고객", V: strings.Join(x.Customers, ", ") + " — 수정 버전이 올라오면 고객 통지로 이어집니다"})
		}
		c.Steps = []string{"승인하면 고른 개발자에게 발송함을 거쳐 나갑니다. 대기 시간 동안 취소할 수 있습니다.", "반려하면 보내지 않고 사유를 기록합니다.", "수정 버전이 올라오면 TrustLink 가 고객 통지 승인 요청으로 이어 갑니다."}
		fmt.Fprintf(&b, "수정 버전 없음 → 개발자(%s)에게 수정 요청을 보낼지 결정해 주세요.\n", strings.Join(names, ", "))
	}
	c.Facts = append(c.Facts, mailFact{K: "메일 제목(초안)", V: mailTitle})
	if x.AIStatus != "" {
		c.AI = &mailAI{Label: "AI 분석 — " + vexStateKo(x.AIStatus), Text: truncate(x.AISummary, 500), Model: x.AIModel}
		if strings.HasPrefix(x.AIMethod, "rule") { // 판정은 규칙, 권고문 요약만 AI(카드가 있을 때)
			c.AI.Label, c.AI.Rule = "판정 초안 — "+vexStateKo(x.AIStatus), true
			c.AI.Model = strings.TrimPrefix(strings.TrimPrefix(x.AIModel, "규칙"), " + ")
		}
		fmt.Fprintf(&b, "AI 분석(AI 생성): %s — %s\n", vexStateKo(x.AIStatus), truncate(x.AISummary, 200))
	}
	fmt.Fprintf(&b, "선택 화면: %s/admin/auto-response\n", s.publicBase())
	c.plain = b.String()
	return c
}

// adminUsers: admins 그룹(활성) — 승인 요청 알림 대상.
func (s *Server) adminUsers() []kcUser {
	gs, err := s.listGroups()
	if err != nil {
		return nil
	}
	var out []kcUser
	for _, g := range gs {
		if g.Name != "admins" {
			continue
		}
		resp, err := s.kcAdmin("GET", "/groups/"+g.ID+"/members?max=1000", nil)
		if err != nil {
			return nil
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
	}
	act := out[:0]
	for _, u := range out {
		if u.Enabled {
			act = append(act, u)
		}
	}
	return act
}

// ---------- API ----------

// GET /api/auto-response — 설정 + 최근 실행(최근순)
func (s *Server) apiAutoResponse(w http.ResponseWriter, r *http.Request) {
	autoRes.Lock()
	autoLoad()
	runs := append([]autoRun(nil), autoRes.Runs...)
	st := autoRes.Settings
	autoRes.Unlock()
	sort.SliceStable(runs, func(i, j int) bool { return runs[i].Started > runs[j].Started })
	if len(runs) > 50 {
		runs = runs[:50]
	}
	writeJSON(w, 200, map[string]any{"settings": st, "runs": runs, "ai": aiEnabledFor("vex")})
}

// PUT /api/auto-response/settings {mode, maxPerVersion}
func (s *Server) apiAutoResponseSettings(w http.ResponseWriter, r *http.Request) {
	var in autoSettings
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&in); err != nil || (in.Mode != "on" && in.Mode != "off") {
		writeJSON(w, 400, map[string]string{"error": "mode 는 on/off"})
		return
	}
	if in.MaxPerVer < 1 || in.MaxPerVer > 10 {
		in.MaxPerVer = 3
	}
	if in.SweepHours < 0 || in.SweepHours > 168 {
		in.SweepHours = 6
	}
	if in.SweepMax < 1 || in.SweepMax > 20 {
		in.SweepMax = 5
	}
	in.UpdatedBy = w.Header().Get("X-User")
	autoRes.Lock()
	autoLoad()
	in.LastSweep, in.SweepMsg, in.Sweeping = autoRes.Settings.LastSweep, autoRes.Settings.SweepMsg, autoRes.Settings.Sweeping
	autoRes.Settings = in
	autoSaveLocked()
	autoRes.Unlock()
	_ = s.sor.append(SoREvent{Actor: in.UpdatedBy, Action: "auto-response-settings", Detail: map[string]any{"mode": in.Mode, "max": in.MaxPerVer}})
	writeJSON(w, 200, in)
}

// POST /api/auto-response/run {repo, tag, vulnId} — 직접 실행(시연·재실행). 백그라운드로 돌고 기록 ID 를 돌려준다.
func (s *Server) apiAutoResponseRun(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Repo   string `json:"repo"`
		Tag    string `json:"tag"`
		VulnID string `json:"vulnId"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&in); err != nil || !reRepo.MatchString(in.Repo) || in.Tag == "" || in.VulnID == "" {
		writeJSON(w, 400, map[string]string{"error": "제품·버전·취약점 ID 를 넣으세요"})
		return
	}
	if !s.dtEnabled() {
		writeJSON(w, 400, map[string]string{"error": "Dependency-Track 미설정"})
		return
	}
	run := newAutoRun("manual", w.Header().Get("X-User"), in.Repo, strings.TrimSpace(in.Tag), strings.ToUpper(strings.TrimSpace(in.VulnID)))
	go func() {
		defer func() {
			if e := recover(); e != nil {
				log.Printf("자동 대응 중단: %v", e)
				autoUpdate(run.ID, func(x *autoRun) { x.State, x.Outcome, x.Error = "error", "error", fmt.Sprint(e) })
			}
		}()
		s.runAutoResponse(run)
	}()
	writeJSON(w, 202, run)
}

// POST /api/auto-response/{id}/approve {keys[], delay} — 관리자 승인 → 발송함(취소 가능) → 고객
// POST /api/auto-response/{id}/reject {reason} — 보내지 않음
func (s *Server) apiAutoResponseDecide(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	approve := strings.HasSuffix(r.URL.Path, "/approve")
	var in struct {
		Keys   []string `json:"keys"`
		Delay  *int     `json:"delay"`
		Reason string   `json:"reason"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<14)).Decode(&in)
	actor := w.Header().Get("X-User")
	autoRes.Lock()
	autoLoad()
	var cur autoRun
	for _, x := range autoRes.Runs {
		if x.ID == id {
			cur = x
		}
	}
	autoRes.Unlock()
	if cur.ID == "" {
		writeJSON(w, 404, map[string]string{"error": "자동 대응 기록 없음"})
		return
	}
	if cur.State != "waiting" {
		writeJSON(w, 409, map[string]string{"error": "승인 대기 중인 건이 아닙니다"})
		return
	}
	if !approve {
		x := autoUpdate(id, func(x *autoRun) {
			stage(x, "approve", "done", "반려 — "+actor+firstNonEmpty(map[bool]string{true: ": " + truncate(in.Reason, 200)}[in.Reason != ""], ""))
			if x.NoticeID != "" {
				stage(x, "notify", "skip", "반려되어 보내지 않음")
			} else {
				stage(x, "devreq", "skip", "반려되어 보내지 않음")
			}
			x.Approver, x.Outcome, x.State, x.Finished = actor, "rejected", "done", time.Now().UTC().Format(time.RFC3339)
		})
		_ = s.sor.append(SoREvent{Actor: actor, Action: "auto-response-reject", Subject: id, Detail: map[string]any{"vuln": cur.VulnID, "notice": cur.NoticeID, "reason": in.Reason}})
		writeJSON(w, 200, x)
		return
	}
	delay := 30 * time.Second
	if in.Delay != nil {
		delay = outboxDelay(*in.Delay)
	}
	if cur.NoticeID == "" { // 개발자 수정 요청
		s.approveDevRequest(w, cur, in.Keys, actor, delay)
		return
	}
	custNoticeMu.Lock()
	n, ok := s.cust().notice(cur.NoticeID)
	if !ok {
		custNoticeMu.Unlock()
		writeJSON(w, 404, map[string]string{"error": "통지 초안이 없습니다"})
		return
	}
	keys := in.Keys
	if len(keys) == 0 {
		for _, t := range n.Targets {
			keys = append(keys, t.Key)
		}
	}
	s.sendNotice(n, keys, actor, delay)
	err := s.cust().putNotice(n)
	custNoticeMu.Unlock()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	sent := 0
	for _, t := range n.Targets {
		if t.Result != nil && t.Result.Pending {
			sent++
		}
	}
	x := autoUpdate(id, func(x *autoRun) {
		stage(x, "approve", "done", fmt.Sprintf("승인 — %s (%d곳)", actor, len(keys)))
		stage(x, "notify", "done", fmt.Sprintf("발송함에 %d건 — %d초 뒤 발송, 그 전에 취소 가능", sent, int(delay/time.Second)))
		x.Approver, x.Outcome, x.State, x.Finished = actor, "sent", "done", time.Now().UTC().Format(time.RFC3339)
	})
	_ = s.sor.append(SoREvent{Actor: actor, Action: "auto-response-approve", Subject: id, Detail: map[string]any{"vuln": cur.VulnID, "notice": cur.NoticeID, "keys": keys}})
	writeJSON(w, 200, map[string]any{"run": x, "notice": n})
}

// approveDevRequest: 고른 개발자에게 수정 요청 — 화면 알림은 바로, 메일은 발송함(취소 가능)을 거쳐.
func (s *Server) approveDevRequest(w http.ResponseWriter, cur autoRun, keys []string, actor string, delay time.Duration) {
	if len(keys) == 0 {
		for _, c := range cur.DevCands {
			keys = append(keys, c.Username)
		}
	}
	users, emails := []string{}, []string{}
	for _, c := range cur.DevCands {
		if inList(c.Username, keys) {
			users = append(users, c.Username)
			if c.Email != "" {
				emails = append(emails, c.Email)
			}
		}
	}
	if len(users) == 0 {
		writeJSON(w, 400, map[string]string{"error": "받는 사람을 한 명 이상 고르세요"})
		return
	}
	s.recordNotice(Notice{Kind: "patch-needed", Audience: "internal", Repo: cur.Repo, Tag: cur.Tag, Title: cur.DevSubject, Body: cur.DevBody}, users)
	var ids []string
	allowed, _ := s.mail.filter(emails)
	if s.mail.Configured() && len(allowed) > 0 {
		it := s.enqueueMail("devreq", path.Base(cur.Repo)+" "+cur.Tag+" 수정 요청", cur.ID, actor, emails, cur.DevSubject, s.renderMail(mailCard{Module: "자동 대응", Purpose: "수정 요청", Tone: "alert",
			Title: strings.TrimSpace(strings.TrimPrefix(cur.DevSubject, "[TrustLink]")), Product: path.Base(cur.Repo), Version: cur.Tag, Ref: cur.ID,
			Facts: []mailFact{{K: "취약점", V: cur.VulnID, Chips: []string{cur.Severity}}, {K: "구성요소", V: cur.Component}},
			Body:  cur.DevBody, Action: "아티팩트 열기", URL: s.artifactURL(cur.Repo, cur.Tag),
			Reason: "이 제품의 개발 담당 — 관리자 " + actor + " 승인"}), delay, nil)
		ids = append(ids, it.ID)
	}
	msg := fmt.Sprintf("화면 알림 %d명", len(users))
	if len(ids) > 0 {
		msg += fmt.Sprintf(" · 메일은 발송함에서 %d초 뒤 발송(그 전에 취소 가능)", int(delay/time.Second))
	} else {
		msg += " · 메일은 보내지 않음(허용 목록 밖 주소이거나 메일 서버 미설정)"
	}
	x := autoUpdate(cur.ID, func(x *autoRun) {
		stage(x, "approve", "done", fmt.Sprintf("승인 — %s (%d명)", actor, len(users)))
		stage(x, "devreq", "done", msg+" — "+strings.Join(users, ", "))
		x.DevTo, x.Outbox = users, ids
		x.Approver, x.Outcome, x.State, x.Finished = actor, "dev-request", "done", time.Now().UTC().Format(time.RFC3339)
	})
	_ = s.sor.append(SoREvent{Actor: actor, Action: "auto-response-approve", Subject: cur.ID, Detail: map[string]any{"vuln": cur.VulnID, "devTo": users, "outbox": ids}})
	writeJSON(w, 200, map[string]any{"run": x})
}

// recordNotice: 메일 없이 화면 알림(내 통보)만 남긴다.
func (s *Server) recordNotice(nt Notice, users []string) {
	now := time.Now().UTC()
	nt.ID, nt.Time, nt.To = fmt.Sprintf("%d", now.UnixNano()), now.Format(time.RFC3339), users
	n := s.notify
	if n == nil {
		return
	}
	n.mu.Lock()
	n.st.Notices = append(n.st.Notices, nt)
	if len(n.st.Notices) > notifyKeep {
		n.st.Notices = n.st.Notices[len(n.st.Notices)-notifyKeep:]
	}
	n.saveLocked()
	n.mu.Unlock()
}

// ---------- 주기 검색(sweep) ----------

// autoSweepLoop: 설정한 간격마다 납품 제품의 고객 설치 버전·최신 버전을 훑어 새 KEV·치명 취약점을 자동 대응에 넣는다.
func (s *Server) autoSweepLoop() {
	time.Sleep(3 * time.Minute) // 기동 직후 부하 피함
	for {
		autoRes.Lock()
		autoLoad()
		st := autoRes.Settings
		autoRes.Unlock()
		due := st.Mode == "on" && st.SweepHours > 0
		if due && st.LastSweep != "" {
			if t, err := time.Parse(time.RFC3339, st.LastSweep); err == nil && time.Since(t) < time.Duration(st.SweepHours)*time.Hour {
				due = false
			}
		}
		if st.Mode == "on" {
			s.autoFollowup() // 수정 버전이 올라왔는지(10분마다, 가볍다)
		}
		if due {
			s.autoSweep("schedule")
		}
		time.Sleep(10 * time.Minute)
	}
}

type sweepPick struct {
	repo, tag, vuln string
	kev             bool
	cvss            float64
}

// autoSweep: 한 번 훑는다. 새로 넣은 건수를 돌려준다(백그라운드 실행은 호출 쪽에서).
func (s *Server) autoSweep(by string) int {
	autoRes.Lock()
	autoLoad()
	if autoRes.Settings.Sweeping {
		autoRes.Unlock()
		return 0
	}
	autoRes.Settings.Sweeping = true
	max := autoRes.Settings.SweepMax
	done := map[string]bool{}
	for _, r := range autoRes.Runs {
		if r.State != "error" {
			done[r.Repo+"|"+r.Tag+"|"+r.VulnID] = true
		}
	}
	autoSaveLocked()
	autoRes.Unlock()
	finish := func(msg string) {
		autoRes.Lock()
		autoRes.Settings.Sweeping, autoRes.Settings.LastSweep, autoRes.Settings.SweepMsg = false, time.Now().UTC().Format(time.RFC3339), msg
		autoSaveLocked()
		autoRes.Unlock()
	}
	if !s.dtEnabled() {
		finish("Dependency-Track 미설정")
		return 0
	}
	// 대상: 고객 등록부의 제품 → 고객 설치 버전 + 최신 버전
	c := s.cust()
	d := c.snapshot()
	targets := map[string]map[string]bool{}
	for _, cu := range activeCustomers(d.Customers) {
		for _, u := range cu.Usages {
			if targets[u.Repo] == nil {
				targets[u.Repo] = map[string]bool{}
			}
			for _, in := range u.Installs {
				targets[u.Repo][in.Tag] = true
			}
		}
	}
	versions, scanned := 0, 0
	var picks []sweepPick
	for repo, tags := range targets {
		all := s.versionTags(repo, d.Products[repo])
		if len(all) > 0 {
			tags[all[len(all)-1]] = true // 최신 버전
		}
		v := s.dtView(repo)
		for tag := range tags {
			fs, ok := v.findings(tag)
			if !ok {
				continue
			}
			versions++
			for _, f := range fs {
				scanned++
				kev := isKEV(vulnIDs(f))
				if !kev && !strings.EqualFold(f.Vulnerability.Severity, "CRITICAL") {
					continue
				}
				if st := stateOf(f); st != "NOT_SET" && st != "IN_TRIAGE" { // 이미 사람이 판단함
					continue
				}
				if done[repo+"|"+tag+"|"+f.Vulnerability.VulnID] {
					continue
				}
				cv := 0.0
				if f.Vulnerability.CvssV3BaseScore != nil {
					cv = *f.Vulnerability.CvssV3BaseScore
				}
				done[repo+"|"+tag+"|"+f.Vulnerability.VulnID] = true
				picks = append(picks, sweepPick{repo, tag, f.Vulnerability.VulnID, kev, cv})
			}
		}
	}
	sort.SliceStable(picks, func(i, j int) bool {
		if picks[i].kev != picks[j].kev {
			return picks[i].kev
		}
		return picks[i].cvss > picks[j].cvss
	})
	total := len(picks)
	if len(picks) > max {
		picks = picks[:max]
	}
	msg := fmt.Sprintf("제품 %d개·버전 %d개·취약점 %d건 검사 → 새 KEV·치명 미대응 %d건 중 %d건 처리", len(targets), versions, scanned, total, len(picks))
	_ = s.sor.append(SoREvent{Actor: autoActor, Action: "auto-response-sweep", Detail: map[string]any{"by": by, "versions": versions, "scanned": scanned, "found": total, "run": len(picks)}})
	finish(msg + map[bool]string{true: " — 처리 중", false: ""}[len(picks) > 0])
	for _, p := range picks {
		s.runAutoResponse(newAutoRun("sweep", autoActor, p.repo, p.tag, p.vuln))
	}
	if len(picks) > 0 {
		finish(msg)
	}
	return len(picks)
}

// autoFollowup: 개발자 수정 요청으로 끝났거나 승인을 기다리는 건 중, 그 뒤 올라온 새 버전에서 취약점이 사라진 것을 찾아
// 원래 건을 "패치 나옴"으로 닫고 같은 취약점의 자동 대응을 다시 돌린다 → 이번엔 패치가 있으니 영향 고객 통지(관리자 승인)로 간다.
var autoFollowMu sync.Mutex // 10분 주기와 "지금 검색"이 겹쳐도 한 번에 하나만(같은 건을 두 번 이어 가지 않게)

func (s *Server) autoFollowup() int {
	if !s.dtEnabled() || !autoFollowMu.TryLock() {
		return 0
	}
	defer autoFollowMu.Unlock()
	autoRes.Lock()
	autoLoad()
	state := map[string]string{}
	for _, r := range autoRes.Runs {
		state[r.ID] = r.State
	}
	var cands []autoRun
	for _, r := range autoRes.Runs {
		retry := r.Outcome == "patched" && r.FollowedBy != "" && state[r.FollowedBy] == "error" // 이어 간 대응이 오류(재시작 등)로 끝났으면 다시
		if retry || (r.FollowedBy == "" && (r.Outcome == "dev-request" || r.Outcome == "approval-dev")) {
			cands = append(cands, r)
		}
	}
	autoRes.Unlock()
	d := s.cust().snapshot()
	n := 0
	for _, r := range cands {
		v := s.dtView(r.Repo)
		fs, ok := v.findings(r.Tag)
		if !ok {
			continue
		}
		f, ok := findVuln(fs, r.VulnID)
		if !ok {
			continue
		}
		fix, found := pickFix(v.fixScan(r.VulnID, f, s.versionTags(r.Repo, d.Products[r.Repo]), r.Tag), r.Tag)
		if !found {
			continue
		}
		next := newAutoRun("patch", autoActor, r.Repo, r.Tag, r.VulnID)
		next.FollowOf = r.ID
		autoUpdate(r.ID, func(x *autoRun) {
			x.FollowedBy, x.PatchTag = next.ID, fix.Tag
			msg := fmt.Sprintf("수정 버전 %s %s 확인(%s %s) — 고객 통지로 이어 감", path.Base(r.Repo), fix.Tag, f.Component.Name, fix.CompVersion)
			if x.State == "waiting" { // 개발자 요청을 아직 승인하지 않았으면 더 보낼 필요가 없다
				stage(x, "approve", "skip", "수정 버전이 먼저 올라와 개발자 요청은 보내지 않음")
				stage(x, "devreq", "skip", msg)
				x.State, x.Finished = "done", time.Now().UTC().Format(time.RFC3339)
			} else {
				stage(x, "devreq", "done", msg)
			}
			x.Outcome = "patched"
		})
		_ = s.sor.append(SoREvent{Actor: autoActor, Action: "auto-response-followup", Repo: r.Repo, Tag: r.Tag,
			Detail: map[string]any{"from": r.ID, "run": next.ID, "vuln": r.VulnID, "fix": fix.Tag}})
		s.runAutoResponse(next)
		n++
	}
	return n
}

// POST /api/auto-response/sweep — 지금 검색(백그라운드)
func (s *Server) apiAutoResponseSweep(w http.ResponseWriter, r *http.Request) {
	autoRes.Lock()
	autoLoad()
	busy := autoRes.Settings.Sweeping
	autoRes.Unlock()
	if busy {
		writeJSON(w, 409, map[string]string{"error": "이미 검색 중입니다"})
		return
	}
	go func() { s.autoFollowup(); s.autoSweep(w.Header().Get("X-User")) }()
	writeJSON(w, 202, map[string]any{"started": true})
}
