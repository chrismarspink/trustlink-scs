package main

// auto_response.go: 자동 대응 — 새 취약점이 잡히면 사람 손을 덜 거치고 다음 단계까지 이어 준다.
//
//   ① 탐지   : DT 새 취약점 알림(notify.go sendVulnNotice) 중 KEV·CRITICAL 을 고른다(또는 화면에서 직접 실행)
//   ② AI 분석: 그 취약점의 VEX 판정 초안(ai_vex.go vexDraftFor). "영향 없음"이면 통지하지 않고 사람 확인으로 넘긴다
//   ③ 패치 확인: 이 버전보다 새 제품 버전 중 취약점이 사라진 버전을 찾는다(custnotify.go fixScan/pickFix)
//   ④-가 패치 있음: 영향 고객 통지 초안(고객별 언어·AI 설명)을 만들고 **관리자 승인을 기다린다**.
//         관리자에게 알림(화면·메일) → 관리자가 받는 사람을 확인하고 "승인·발송" → 발송함(취소 가능) → 고객
//   ④-나 패치 없음: 개발자(제품 쓰기 권한자·관리자)에게 "수정 버전 필요" 메일 — 사내 메일이라 바로 보낸다
//
// 고객에게 나가는 메일은 반드시 사람이 승인한다(방산 고객 대상 — 잘못된 통지는 되돌릴 수 없다).
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
	FixTag      string      `json:"fixTag,omitempty"`
	FixComp     string      `json:"fixComp,omitempty"`
	Upstream    string      `json:"upstream,omitempty"` // 구성요소 자체의 수정 버전(OSV 등)
	NoticeID    string      `json:"noticeId,omitempty"`
	Recommended []string    `json:"recommended,omitempty"` // 추천된 받는 사람(고객 담당자)
	Customers   []string    `json:"customers,omitempty"`
	Waiting     []string    `json:"waiting,omitempty"` // 패치가 아직 없는 버전을 쓰는 고객
	DevTo       []string    `json:"devTo,omitempty"`
	Approver    string      `json:"approver,omitempty"`
	Error       string      `json:"error,omitempty"`
}

type autoSettings struct {
	Mode      string `json:"mode"` // on / off
	MaxPerVer int    `json:"maxPerVersion"`
	UpdatedBy string `json:"updatedBy,omitempty"`
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
	if len(picks) == 0 {
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
		stage(x, "ai", "active", "AI 가 영향 여부를 분석하는 중(로컬 AI 는 1~2분)")
	})
	upstream := ""
	if aiEnabledFor("vex") {
		done := aiInteractive()
		d, err := s.vexDraftFor(autoActor, r.Repo, r.Tag, f, "자동 대응: 새로 발견된 취약점의 영향 여부와 대응을 판단")
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
				x.AIStatus, x.AISummary, x.AIModel, x.Upstream = d.Draft.Status, sum, d.Meta.Model, upstream
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
	autoUpdate(id, func(x *autoRun) {
		stage(x, "fix", "done", "패치 버전 없음 — 확인: "+scan+map[bool]string{true: " · 구성요소 수정 버전: " + upstream, false: ""}[upstream != ""])
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
		if len(waiting) > 0 {
			stage(x, "devreq", "skip", "아직 패치가 없는 버전 사용 고객: "+strings.Join(waiting, ", ")+" — 그 버전의 자동 대응에서 개발자 통보")
		}
		x.State, x.Outcome = "waiting", "approval"
	})
	// 관리자에게 알림(화면·메일)
	title := fmt.Sprintf("[TrustLink] 승인 필요 — %s 고객 통지 %s(%s)", path.Base(r.Repo), r.VulnID, comp)
	var b strings.Builder
	fmt.Fprintf(&b, "자동 대응이 고객 통지 초안을 만들었습니다. 확인 후 승인해야 고객에게 나갑니다.\n\n")
	fmt.Fprintf(&b, "- 취약점: %s (%s%s) · 구성요소 %s\n", r.VulnID, x.Severity, map[bool]string{true: " · KEV", false: ""}[x.KEV], comp)
	if x.AIStatus != "" {
		fmt.Fprintf(&b, "- AI 판정 초안: %s — %s\n", vexStateKo(x.AIStatus), truncate(x.AISummary, 200))
	}
	fmt.Fprintf(&b, "- 권장 버전: %s %s\n- 영향 고객: %s\n- 추천 받는 사람: %d명\n", path.Base(r.Repo), x.FixTag, strings.Join(custs, ", "), len(rec))
	if len(waiting) > 0 {
		fmt.Fprintf(&b, "- 아직 패치 없는 버전 사용: %s\n", strings.Join(waiting, ", "))
	}
	fmt.Fprintf(&b, "\n승인 화면: %s/admin/auto-response\n", s.publicBase())
	s.deliver(Notice{Kind: "approval-needed", Audience: "internal", Repo: r.Repo, Tag: r.Tag, Title: title, Body: b.String()}, s.adminUsers(), nil)
	_ = s.sor.append(SoREvent{Actor: autoActor, Action: "auto-response", Repo: r.Repo, Tag: r.Tag, Status: "approval",
		Detail: map[string]any{"run": id, "vuln": r.VulnID, "notice": n.ID, "fix": x.FixTag, "customers": custs, "ai": x.AIStatus}})
	return x
}

// ④-나 패치 없음 → 개발자 통보(사내)
func (s *Server) autoDevRequest(id string, r autoRun, comp, upstream string) autoRun {
	x := autoUpdate(id, func(x *autoRun) {
		stage(x, "approve", "skip", "패치 버전이 없어 고객 통지 대신 개발자 통보")
		stage(x, "notify", "skip", "")
		stage(x, "devreq", "active", "개발자에게 수정 요청 메일을 보내는 중")
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
	to := s.recipients(r.Repo, false)
	names := []string{}
	for _, u := range to {
		names = append(names, u.Username)
	}
	s.deliver(Notice{Kind: "patch-needed", Audience: "internal", Repo: r.Repo, Tag: r.Tag, Title: title, Body: b.String()}, to, nil)
	_ = s.sor.append(SoREvent{Actor: autoActor, Action: "auto-response", Repo: r.Repo, Tag: r.Tag, Status: "dev-request",
		Detail: map[string]any{"run": id, "vuln": r.VulnID, "to": names, "upstream": upstream, "customers": affected}})
	return autoUpdate(id, func(x *autoRun) {
		x.DevTo, x.Customers, x.Upstream = names, affected, upstream
		stage(x, "devreq", "done", fmt.Sprintf("개발자 %d명에게 수정 요청(%s)", len(names), strings.Join(names, ", ")))
		x.Outcome, x.State, x.Finished = "dev-request", "done", time.Now().UTC().Format(time.RFC3339)
		for i := range x.Stages {
			if x.Stages[i].State == "todo" {
				x.Stages[i].State = "skip"
			}
		}
	})
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
	in.UpdatedBy = w.Header().Get("X-User")
	autoRes.Lock()
	autoLoad()
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
	if cur.State != "waiting" || cur.NoticeID == "" {
		writeJSON(w, 409, map[string]string{"error": "승인 대기 중인 건이 아닙니다"})
		return
	}
	if !approve {
		x := autoUpdate(id, func(x *autoRun) {
			stage(x, "approve", "done", "반려 — "+actor+firstNonEmpty(map[bool]string{true: ": " + truncate(in.Reason, 200)}[in.Reason != ""], ""))
			stage(x, "notify", "skip", "반려되어 보내지 않음")
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
