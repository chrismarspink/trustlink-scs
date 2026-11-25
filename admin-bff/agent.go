package main

// agent.go: 에이전트 — 로그인한 사람의 할 일을 모아 제안하고, 고르면 대신 실행한다.
//
//   GET    /api/agent                  내 권한에 맞는 할 일 제안·예약·실행 기록·설정
//   POST   /api/agent/run {ids}        고른 것을 실행(바로 실행 등급만)
//   POST   /api/agent/undo {id}        실행한 것을 되돌린다(본인 또는 관리자)
//   POST   /api/agent/prefs {autoOpen} 접속하면 자동으로 열지
//   POST   /api/agent/schedules        예약 추가 {recipe, repeat, time, weekday}
//   POST   /api/agent/schedules/{id}   켜기·끄기 {on}
//   DELETE /api/agent/schedules/{id}   예약 삭제
//
// 원칙
//   - 새 처리 경로를 만들지 않는다. 이미 있는 기능을 그 사람의 권한으로 대신 부른다.
//   - 등급: run(바로 실행·되돌릴 수 있음) / approve(고객에게 나감 — 화면이 내용을 보여 주고 기존 승인 API 를 부른다) / go(직접 처리 — 화면으로 안내)
//   - 고객에게 나가는 것은 예약으로 돌아도 승인 대기에서 멈춘다(기존 "승인 후 발송" 그대로).
//   - 예약은 정해진 작업 종류만. 실행할 때 예약한 사람의 계정과 권한을 다시 확인한다.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type agentTask struct {
	ID     string   `json:"id"` // 종류:대상
	Kind   string   `json:"kind"`
	Grade  string   `json:"grade"` // run / approve / go
	Title  string   `json:"title"`
	Why    string   `json:"why,omitempty"`
	Steps  []string `json:"steps"`
	Link   string   `json:"link,omitempty"`
	Ref    string   `json:"ref,omitempty"`
	Urgent bool     `json:"urgent,omitempty"`
}

type agentUndo struct {
	Kind    string   `json:"kind"` // vexdraft / notif
	Ref     string   `json:"ref,omitempty"`
	Started string   `json:"started,omitempty"`
	IDs     []string `json:"ids,omitempty"`
}

type agentLog struct {
	ID     string     `json:"id"`
	At     string     `json:"at"`
	Actor  string     `json:"actor"`
	By     string     `json:"by"` // user / schedule / ask(묻고 찾기로 실행)
	Title  string     `json:"title"`
	Result string     `json:"result"`
	OK     bool       `json:"ok"`
	Undo   *agentUndo `json:"undo,omitempty"`
	Undone string     `json:"undone,omitempty"` // 되돌린 시각
	Ask    string     `json:"ask,omitempty"`    // 결과를 다시 보려면 물을 말(자료 조사)
}

type agentSchedule struct {
	ID      string `json:"id"`
	Recipe  string `json:"recipe"`
	Owner   string `json:"owner"`
	Repeat  string `json:"repeat"` // daily / weekly / once
	Time    string `json:"time"`   // HH:MM (한국 시간)
	Weekday int    `json:"weekday,omitempty"`
	On      bool   `json:"on"`
	Next    string `json:"next,omitempty"`
	Last    string `json:"last,omitempty"`
	LastMsg string `json:"lastMsg,omitempty"`
}

type agentRecipe struct {
	Key   string `json:"key"`
	Title string `json:"title"`
	Out   string `json:"out"`
	who   string // vex / admin
}

var agentRecipes = []agentRecipe{
	{"vex-draft", "판단 대기 취약점의 초안 준비", "초안만 만듭니다. 결과는 할 일 제안과 VEX 판단 화면에 올라오고, 저장·발행은 사람이 합니다.", "vex"},
	{"expiry-check", "만료 예정 고객 점검과 안내 메일 준비", "메일은 승인 대기에 올라갑니다. 자동으로 나가지 않습니다.", "admin"},
	{"reg-discover", "새 규제와 원문 변경 탐색(외부 인터넷)", "후보는 규제 화면에 올라옵니다. 채택은 사람이 합니다.", "admin"},
	{"research", "급한 취약점의 공개 자료 조사(외부 인터넷)", "실제 악용·치명 취약점을 최대 3건 조사해 둡니다. 결과는 실행 기록의 \"결과 보기\"나 \"CVE-… 자료 조사\"로 봅니다.", "vex"},
}

var agentSt struct {
	sync.Mutex
	path      string
	Prefs     map[string]map[string]bool `json:"prefs"` // 사용자 → 설정
	Schedules []agentSchedule            `json:"schedules"`
	Log       []agentLog                 `json:"log"`
}

var (
	agentKST    = time.FixedZone("KST", 9*3600)
	agentTimeRe = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)
)

const (
	agentMaxLog       = 300
	agentMaxSchedules = 10 // 한 사람당
	agentDraftLimit   = 20 // 한 제품·버전에서 한 번에 만드는 초안
	agentDraftBatch   = 3  // 예약 한 번에 초안을 만드는 제품·버전 수(AI 부하)
	agentResearchMax  = 3  // 예약 한 번에 조사하는 취약점 수(외부 요청을 아낀다)
)

func agentPath() string { return filepath.Join(filepath.Dir(aiConfigPath()), "agent.json") }

func agentLoad() { // agentSt 잠근 채로
	if p := agentPath(); agentSt.path != p {
		agentSt.path, agentSt.Prefs, agentSt.Schedules, agentSt.Log = p, nil, nil, nil
		_ = readJSONFile(p, &agentSt)
	}
	if agentSt.Prefs == nil {
		agentSt.Prefs = map[string]map[string]bool{}
	}
}

func agentSave() { // agentSt 잠근 채로
	if len(agentSt.Log) > agentMaxLog {
		agentSt.Log = agentSt.Log[len(agentSt.Log)-agentMaxLog:]
	}
	_ = os.MkdirAll(filepath.Dir(agentSt.path), 0o750)
	_ = writeJSONFile(agentSt.path, map[string]any{"prefs": agentSt.Prefs, "schedules": agentSt.Schedules, "log": agentSt.Log})
}

func agentID(prefix string) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

func agentRole(sess Session, isCustomer bool) string {
	switch {
	case contains(sess.Groups, "admins"):
		return "admin"
	case canEditVex(sess):
		return "vex"
	case isCustomer:
		return "customer"
	}
	return "user"
}

func agentCan(sess Session, who string) bool {
	if who == "admin" {
		return contains(sess.Groups, "admins")
	}
	return canEditVex(sess)
}

// ---------- 할 일 제안 ----------

// agentDraftRows: 초안을 만들 수 있는(또는 만들어 둔) 제품·버전 — 권한이 있는 제품의 최신 버전만.
func (s *Server) agentDraftRows(sess Session) []vexQueueRow {
	if !canEditVex(sess) || !s.dtEnabled() {
		return nil
	}
	latest := map[string]vexQueueRow{}
	for _, r := range s.askVisibleRows(sess) {
		if cur, ok := latest[r.Repo]; !ok || r.Imported > cur.Imported {
			latest[r.Repo] = r
		}
	}
	out := []vexQueueRow{}
	for _, r := range latest {
		if r.Pending > 0 || r.BatchDrafts > 0 {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Demo != b.Demo {
			return !a.Demo
		}
		if a.PendKEV != b.PendKEV {
			return a.PendKEV > b.PendKEV
		}
		if a.PendCrit != b.PendCrit {
			return a.PendCrit > b.PendCrit
		}
		return a.Repo < b.Repo
	})
	return out
}

func (s *Server) agentUnread(user string) []string {
	n := s.notify
	if n == nil {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	ids := []string{}
	for _, nt := range n.st.Notices {
		if contains(nt.To, user) && !nt.Read[user] {
			ids = append(ids, nt.ID)
		}
	}
	return ids
}

func (s *Server) agentTasks(sess Session) []agentTask {
	admin := contains(sess.Groups, "admins")
	out := []agentTask{}

	// 판단 초안(VEX 담당)
	ai := aiEnabled()
	nDraft := 0
	for _, r := range s.agentDraftRows(sess) {
		name := path.Base(r.Repo) + " " + r.Tag
		switch {
		case r.BatchState == "running":
			continue
		case r.BatchDrafts > 0:
			out = append(out, agentTask{ID: "vexreview:" + r.Project, Kind: "vexreview", Grade: "go", Title: "이어서 하기: " + name + " 초안 " + itoa(r.BatchDrafts) + "건 검토",
				Why: "만들어 둔 초안이 저장을 기다립니다.", Steps: []string{"초안을 보고 고칠 것을 고친 뒤 저장합니다", "발행은 판단이 끝난 뒤 따로 합니다"}, Link: artifactLink(r.Repo, r.Tag), Urgent: r.PendKEV > 0})
		case ai && nDraft < 6:
			nDraft++
			why := fmt.Sprintf("판단 대기 %d건(치명 %d · 높음 %d)", r.Pending, r.PendCrit, r.PendHigh)
			if r.PendKEV > 0 {
				why += fmt.Sprintf(" · 실제 악용 %d건", r.PendKEV)
			}
			out = append(out, agentTask{ID: "vexdraft:" + r.Project, Kind: "vexdraft", Grade: "run", Title: name + " 판단 초안 준비", Why: why, Ref: r.Project,
				Steps: []string{fmt.Sprintf("급한 순서로 최대 %d건의 초안을 만듭니다", agentDraftLimit), "초안만 만듭니다. 저장과 발행은 사람이 합니다"}, Link: artifactLink(r.Repo, r.Tag), Urgent: r.PendKEV > 0})
		}
	}

	// 읽지 않은 알림(누구나)
	if ids := s.agentUnread(sess.Username); len(ids) > 0 {
		out = append(out, agentTask{ID: "notif:all", Kind: "notif", Grade: "run", Title: "읽지 않은 알림 " + itoa(len(ids)) + "건 읽음으로 표시",
			Why: "상단 종 모양 알림에 읽지 않은 것이 있습니다.", Steps: []string{"모두 읽음으로 표시합니다. 알림 내용은 그대로 남습니다"}})
	}

	if admin {
		out = append(s.relTasks(), out...) // 운영 문제(디스크, 저장 실패)는 맨 앞에
		// 고객에게 보낼 메일(승인 필요)
		for i, h := range holdWaiting() {
			if i >= 8 {
				break
			}
			out = append(out, agentTask{ID: "hold:" + h.ID, Kind: "hold", Grade: "approve", Title: firstNonEmpty(h.Label, h.Subject), Ref: h.ID, Link: "/admin/outbox",
				Why: "받는 사람 " + joinMax(h.Recipients, 2), Steps: []string{"내용을 한 번 더 보여 드립니다", "승인하면 발송 대기로 넘어가고, 대기 중에는 발송함에서 취소할 수 있습니다"}})
		}
		// 그 밖의 결정 — 화면에서 직접
		groups, _ := s.inboxGroups()
		hint := map[string]string{"auto": "보낼지 말지는 자동 대응 화면에서 정합니다.", "reg": "채택하면 규제 목록이 바뀌므로 화면에서 직접 고릅니다.", "expiry": "고객 화면에서 기간을 확인합니다."}
		for _, g := range groups {
			if g.Count == 0 || hint[g.Key] == "" {
				continue
			}
			t := agentTask{ID: "go:" + g.Key, Kind: "inbox", Grade: "go", Title: fmt.Sprintf("%s — %d건", g.Label, g.Count), Why: hint[g.Key], Link: g.Link, Steps: []string{}}
			for i, it := range g.Items {
				if i >= 3 {
					break
				}
				t.Steps = append(t.Steps, it.Title)
				t.Urgent = t.Urgent || it.Urgent
			}
			out = append(out, t)
		}
		return out
	}

	// 고객: 내 제품에서 조치할 것
	for _, c := range s.myProducts(sess) {
		for _, u := range c.Usages {
			for _, in := range u.Installs {
				act, kev, rec := 0, 0, ""
				for _, v := range in.Vulns {
					if inList(v.State, dtInactive) {
						continue
					}
					act++
					if v.KEV {
						kev++
					}
					if rec == "" {
						rec = v.Recommend
					}
				}
				if act == 0 {
					continue
				}
				t := agentTask{ID: "my:" + u.Repo + ":" + in.Tag, Kind: "my", Grade: "go", Title: path.Base(u.Repo) + " " + in.Tag + " — 조치할 취약점 " + itoa(act) + "건", Link: "/my", Urgent: kev > 0,
					Steps: []string{"내 제품 화면에서 취약점과 판단 내용을 봅니다"}}
				if rec != "" {
					t.Why = "권장 버전 " + rec
					t.Steps = append(t.Steps, "권장 버전 "+rec+"의 자료(SBOM·VEX)를 받아 갑니다")
				} else {
					t.Why = "수정 버전은 아직 없습니다. 나오면 알림으로 알려 드립니다."
				}
				out = append(out, t)
			}
		}
	}
	return out
}

// ---------- 실행 ----------

func (s *Server) agentRun(sess Session, id string) (title, result string, undo *agentUndo, err error) {
	var task *agentTask
	for _, t := range s.agentTasks(sess) { // 지금 그 사람에게 보이는 일만 실행한다(권한 확인을 겸한다)
		if t.ID == id {
			t := t
			task = &t
		}
	}
	if task == nil {
		return id, "", nil, fmt.Errorf("지금은 실행할 수 없는 작업입니다. 이미 처리되었거나 권한이 없습니다")
	}
	title = task.Title
	switch task.Kind {
	case "notif":
		ids := s.agentUnread(sess.Username)
		s.agentMarkRead(sess.Username, ids, true)
		return title, fmt.Sprintf("알림 %d건을 읽음으로 표시했습니다.", len(ids)), &agentUndo{Kind: "notif", IDs: ids}, nil
	case "vexdraft":
		var row *vexQueueRow
		for _, r := range s.agentDraftRows(sess) {
			if r.Project == task.Ref {
				r := r
				row = &r
			}
		}
		if row == nil {
			return title, "", nil, fmt.Errorf("제품을 찾지 못했습니다")
		}
		fs, e := s.projectFindings(row.Project)
		if e != nil {
			return title, "", nil, e
		}
		picks := vexBatchPick(fs, agentDraftLimit)
		if len(picks) == 0 {
			return title, "판단 대기 항목이 없습니다.", nil, nil
		}
		b, e := s.startVexBatch(row.Project, row.Repo, row.Tag, sess.Username, "", "", picks, nil)
		if e != nil {
			return title, "", nil, e
		}
		return title, fmt.Sprintf("초안 %d건을 만들기 시작했습니다. 진행은 VEX 판단 화면에서 볼 수 있습니다.", b.Total), &agentUndo{Kind: "vexdraft", Ref: row.Project, Started: b.Started}, nil
	}
	return title, "", nil, fmt.Errorf("이 작업은 화면에서 직접 처리합니다")
}

func (s *Server) agentMarkRead(user string, ids []string, read bool) {
	n := s.notify
	if n == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for i := range n.st.Notices {
		nt := &n.st.Notices[i]
		if !inList(nt.ID, ids) || !contains(nt.To, user) {
			continue
		}
		if nt.Read == nil {
			nt.Read = map[string]bool{}
		}
		if read {
			nt.Read[user] = true
		} else {
			delete(nt.Read, user)
		}
	}
	n.saveLocked()
}

// 묻고 찾기로 실행한 일의 이름과 결과 문장(실행 기록에 같이 남긴다).
var (
	askKindKo   = map[string]string{"notice": "고객 통지", "vex": "VEX 판정", "report": "규제 보고서"}
	askDoneText = map[string]string{"queued": "발송함에 넣었습니다. 대기 중에는 발송함에서 취소할 수 있습니다.", "made": "보고서를 만들었습니다. 보고서함에서 볼 수 있습니다.", "recorded": "판정을 저장했습니다. 고치려면 제품 화면에서 다시 판정합니다."}
)

// agentLogAdd: 실행 기록에 한 줄(감사 원장은 부르는 쪽이 따로 남긴다).
func agentLogAdd(actor, by, title, result string, ok bool, undo *agentUndo) agentLog {
	e := agentLog{ID: agentID("al-"), At: time.Now().UTC().Format(time.RFC3339), Actor: actor, By: by, Title: title, Result: result, OK: ok, Undo: undo}
	agentSt.Lock()
	agentLoad()
	agentSt.Log = append(agentSt.Log, e)
	agentSave()
	agentSt.Unlock()
	return e
}

func agentLogAsk(id, q string) {
	agentSt.Lock()
	defer agentSt.Unlock()
	for i := range agentSt.Log {
		if agentSt.Log[i].ID == id {
			agentSt.Log[i].Ask = q
		}
	}
	agentSave()
}

func (s *Server) agentRecord(actor, by, title, result string, ok bool, undo *agentUndo) agentLog {
	e := agentLogAdd(actor, by, title, result, ok, undo)
	_ = s.sor.append(SoREvent{Actor: actor, Action: "agent-run", Subject: title, Status: map[bool]string{true: "ok", false: "failed"}[ok], Detail: map[string]any{"by": by, "result": result}})
	return e
}

// agentUndoDo: 되돌린 결과 문장. 되돌릴 수 없으면 오류.
func (s *Server) agentUndoDo(e agentLog) (string, error) {
	u := e.Undo
	switch u.Kind {
	case "notif":
		s.agentMarkRead(e.Actor, u.IDs, false)
		return fmt.Sprintf("알림 %d건을 다시 읽지 않음으로 돌렸습니다.", len(u.IDs)), nil
	case "vexdraft":
		vexBatchMu.Lock()
		defer vexBatchMu.Unlock()
		b := vexBatches[u.Ref]
		if b == nil { // 서버가 다시 떠서 메모리에 없으면 저장본
			var saved vexBatch
			if readJSONFile(vexBatchPath(u.Ref), &saved) == nil && saved.Project == u.Ref {
				b = &saved
			}
		}
		if b == nil || b.Started != u.Started {
			return "", fmt.Errorf("그 뒤에 초안을 다시 만들어, 이 실행만 되돌릴 수 없습니다")
		}
		if b.State == "running" {
			b.cancel = true
			b.State, b.Current, b.Finished = "cancelled", "", time.Now().UTC().Format(time.RFC3339)
		}
		n := len(b.Results)
		b.Results = map[string]*vexDraftResult{}
		b.save()
		return fmt.Sprintf("저장하지 않은 초안 %d건을 지웠습니다. 이미 저장한 판단은 그대로입니다.", n), nil
	}
	return "", fmt.Errorf("되돌릴 수 없는 작업입니다")
}

// ---------- 예약 ----------

// agentNext: after 뒤의 첫 실행 시각(한국 시간 기준).
func agentNext(sc agentSchedule, after time.Time) time.Time {
	var h, m int
	_, _ = fmt.Sscanf(sc.Time, "%d:%d", &h, &m)
	a := after.In(agentKST)
	t := time.Date(a.Year(), a.Month(), a.Day(), h, m, 0, 0, agentKST)
	for !t.After(after) || (sc.Repeat == "weekly" && int(t.Weekday()) != sc.Weekday) {
		t = t.AddDate(0, 0, 1)
	}
	return t
}

func (s *Server) agentRecipeRun(sess Session, key string) (string, error) {
	switch key {
	case "vex-draft":
		if !aiEnabled() {
			return "", fmt.Errorf("AI 가 꺼져 있어 초안을 만들지 못했습니다")
		}
		started := []string{}
		for _, r := range s.agentDraftRows(sess) {
			if len(started) >= agentDraftBatch {
				break
			}
			if r.Pending == 0 || r.BatchDrafts > 0 || r.BatchState == "running" {
				continue
			}
			fs, err := s.projectFindings(r.Project)
			if err != nil {
				continue
			}
			picks := vexBatchPick(fs, agentDraftLimit)
			if len(picks) == 0 {
				continue
			}
			if _, err := s.startVexBatch(r.Project, r.Repo, r.Tag, sess.Username, "", "", picks, nil); err == nil {
				started = append(started, path.Base(r.Repo)+" "+r.Tag)
			}
		}
		if len(started) == 0 {
			return "새로 초안을 만들 제품이 없습니다.", nil
		}
		return "초안 준비를 시작했습니다: " + strings.Join(started, ", "), nil
	case "research":
		ids := []string{}
		for _, r := range s.agentDraftRows(sess) {
			if len(ids) >= agentResearchMax || r.PendKEV+r.PendCrit == 0 {
				continue
			}
			fs, err := s.projectFindings(r.Project)
			if err != nil {
				continue
			}
			for _, f := range vexBatchPick(fs, agentResearchMax) {
				if id := strings.ToUpper(askVulnRe.FindString(f.Vulnerability.VulnID)); id != "" && !inList(id, ids) && len(ids) < agentResearchMax {
					if d := researchFetch(id); len(d.Sources) > 0 {
						ids = append(ids, id)
					}
				}
			}
		}
		if len(ids) == 0 {
			return "새로 조사할 급한 취약점이 없거나 공개 자료를 받지 못했습니다.", nil
		}
		return "공개 자료를 조사해 두었습니다: " + strings.Join(ids, ", "), nil
	case "expiry-check":
		return fmt.Sprintf("만료 예정을 점검했습니다. 준비한 안내 메일 %d건(고객에게 갈 메일은 승인 대기에 있습니다).", s.custExpiryCheck()), nil
	case "reg-discover":
		regDiscMu.Lock()
		if regDiscState.Running {
			regDiscMu.Unlock()
			return "", fmt.Errorf("이미 탐색 중입니다")
		}
		regDiscState = regDiscoverState{Running: true, Started: time.Now().UTC().Format(time.RFC3339), Log: []string{}}
		regDiscMu.Unlock()
		regMu.Lock()
		hasOC := loadDiscoverCfg().LawOC != ""
		regMu.Unlock()
		src := []string{"federal-register", "watch"}
		if hasOC {
			src = append(src, "law-kr")
		}
		go s.runDiscover(src, sess.Username)
		return "규제 탐색을 시작했습니다. 후보는 규제 화면에 올라옵니다.", nil
	}
	return "", fmt.Errorf("모르는 작업 종류입니다")
}

// agentLoop: 1분마다 때가 된 예약을 실행한다.
func (s *Server) agentLoop() {
	for range time.Tick(time.Minute) {
		s.agentTick(time.Now())
	}
}

func (s *Server) agentTick(now time.Time) {
	agentSt.Lock()
	agentLoad()
	due := []agentSchedule{}
	for _, sc := range agentSt.Schedules {
		if t, err := time.Parse(time.RFC3339, sc.Next); sc.On && err == nil && !t.After(now) {
			due = append(due, sc)
		}
	}
	agentSt.Unlock()
	for _, sc := range due {
		var rc agentRecipe
		for _, x := range agentRecipes {
			if x.Key == sc.Recipe {
				rc = x
			}
		}
		gone, groups := s.mcpAccount(sc.Owner) // 예약한 사람의 계정과 권한을 실행할 때 다시 본다
		if !gone && groups == nil {
			continue // 계정 확인이 안 되면(인증 서버 응답 없음) 다음 분에 다시
		}
		sess := Session{Username: sc.Owner, Groups: groups}
		msg, ok, off := "", false, sc.Repeat == "once"
		switch {
		case rc.Key == "":
			msg, off = "없어진 작업 종류라 예약을 껐습니다.", true
		case gone || !agentCan(sess, rc.who):
			msg, off = "예약한 사람의 계정이나 권한이 바뀌어 실행하지 않고 예약을 껐습니다.", true
		default:
			res, err := s.agentRecipeRun(sess, sc.Recipe)
			msg, ok = res, err == nil
			if err != nil {
				msg = err.Error()
			}
		}
		e := s.agentRecord(sc.Owner, "schedule", "예약: "+firstNonEmpty(rc.Title, sc.Recipe), msg, ok, nil)
		if id := askVulnRe.FindString(msg); ok && sc.Recipe == "research" && id != "" {
			agentLogAsk(e.ID, id+" 자료 조사해 줘")
		}
		agentSt.Lock()
		for i := range agentSt.Schedules {
			x := &agentSt.Schedules[i]
			if x.ID != sc.ID {
				continue
			}
			x.Last, x.LastMsg = now.UTC().Format(time.RFC3339), msg
			if off {
				x.On, x.Next = false, ""
			} else {
				x.Next = agentNext(*x, now).UTC().Format(time.RFC3339)
			}
		}
		agentSave()
		agentSt.Unlock()
	}
}

// ---------- API ----------

func (s *Server) apiAgent(w http.ResponseWriter, r *http.Request) {
	sess, _ := s.sessionOf(r)
	admin := contains(sess.Groups, "admins")
	isCustomer := !admin && len(s.myProducts(sess)) > 0
	recipes := []agentRecipe{}
	for _, x := range agentRecipes {
		if agentCan(sess, x.who) {
			recipes = append(recipes, x)
		}
	}
	agentSt.Lock()
	agentLoad()
	scheds, logs := []agentSchedule{}, []agentLog{}
	for _, x := range agentSt.Schedules {
		if admin || x.Owner == sess.Username {
			scheds = append(scheds, x)
		}
	}
	for i := len(agentSt.Log) - 1; i >= 0 && len(logs) < 50; i-- {
		if x := agentSt.Log[i]; admin || x.Actor == sess.Username {
			logs = append(logs, x)
		}
	}
	prefs := map[string]bool{"autoOpen": agentSt.Prefs[sess.Username]["autoOpen"], "askOff": agentSt.Prefs[sess.Username]["askOff"]}
	agentSt.Unlock()
	writeJSON(w, 200, map[string]any{"user": sess.Username, "role": agentRole(sess, isCustomer), "tasks": s.agentTasks(sess),
		"schedules": scheds, "log": logs, "recipes": recipes, "prefs": prefs, "ai": aiEnabled()})
}

func (s *Server) apiAgentRun(w http.ResponseWriter, r *http.Request) {
	sess, _ := s.sessionOf(r)
	var in struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil || len(in.IDs) == 0 || len(in.IDs) > 20 {
		writeJSON(w, 400, map[string]string{"error": "실행할 것을 고르세요(한 번에 20건까지)"})
		return
	}
	out := []agentLog{}
	for _, id := range in.IDs {
		title, res, undo, err := s.agentRun(sess, id)
		if err != nil {
			res = err.Error()
		}
		out = append(out, s.agentRecord(sess.Username, "user", title, res, err == nil, undo))
	}
	writeJSON(w, 200, map[string]any{"results": out})
}

func (s *Server) apiAgentUndo(w http.ResponseWriter, r *http.Request) {
	sess, _ := s.sessionOf(r)
	var in struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in)
	agentSt.Lock()
	agentLoad()
	var e *agentLog
	for i := range agentSt.Log {
		if agentSt.Log[i].ID == in.ID {
			x := agentSt.Log[i]
			e = &x
		}
	}
	agentSt.Unlock()
	switch {
	case e == nil:
		writeJSON(w, 404, map[string]string{"error": "기록을 찾지 못했습니다"})
		return
	case e.Actor != sess.Username && !contains(sess.Groups, "admins"):
		writeJSON(w, 403, map[string]string{"error": "실행한 본인이나 관리자만 되돌릴 수 있습니다"})
		return
	case e.Undo == nil || e.Undone != "":
		writeJSON(w, 409, map[string]string{"error": "되돌릴 수 없는 기록입니다"})
		return
	}
	msg, err := s.agentUndoDo(*e)
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	agentSt.Lock()
	for i := range agentSt.Log {
		if agentSt.Log[i].ID == e.ID {
			agentSt.Log[i].Undone = time.Now().UTC().Format(time.RFC3339)
		}
	}
	agentSave()
	agentSt.Unlock()
	_ = s.sor.append(SoREvent{Actor: sess.Username, Action: "agent-undo", Subject: e.Title, Detail: map[string]any{"result": msg}})
	writeJSON(w, 200, map[string]string{"result": msg})
}

func (s *Server) apiAgentPrefs(w http.ResponseWriter, r *http.Request) {
	sess, _ := s.sessionOf(r)
	var in struct { // 보낸 것만 바꾼다
		AutoOpen *bool `json:"autoOpen"` // 접속하면 에이전트를 자동으로 연다
		AskOff   *bool `json:"askOff"`   // 오른쪽 아래 묻고 찾기 버튼을 끈다
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "잘못된 요청"})
		return
	}
	agentSt.Lock()
	agentLoad()
	p := agentSt.Prefs[sess.Username]
	if p == nil {
		p = map[string]bool{}
	}
	if in.AutoOpen != nil {
		p["autoOpen"] = *in.AutoOpen
	}
	if in.AskOff != nil {
		p["askOff"] = *in.AskOff
	}
	agentSt.Prefs[sess.Username] = p
	agentSave()
	agentSt.Unlock()
	writeJSON(w, 200, p)
}

func (s *Server) apiAgentScheduleAdd(w http.ResponseWriter, r *http.Request) {
	sess, _ := s.sessionOf(r)
	var in agentSchedule
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "잘못된 요청"})
		return
	}
	var rc *agentRecipe
	for i := range agentRecipes {
		if agentRecipes[i].Key == in.Recipe {
			rc = &agentRecipes[i]
		}
	}
	switch {
	case rc == nil || !agentCan(sess, rc.who):
		writeJSON(w, 403, map[string]string{"error": "예약할 수 없는 작업입니다"})
		return
	case !agentTimeRe.MatchString(in.Time) || !inList(in.Repeat, []string{"daily", "weekly", "once"}) || in.Weekday < 0 || in.Weekday > 6:
		writeJSON(w, 400, map[string]string{"error": "시각(HH:MM)과 반복을 확인하세요"})
		return
	}
	sc := agentSchedule{ID: agentID("as-"), Recipe: in.Recipe, Owner: sess.Username, Repeat: in.Repeat, Time: in.Time, Weekday: in.Weekday, On: true}
	sc.Next = agentNext(sc, time.Now()).UTC().Format(time.RFC3339)
	agentSt.Lock()
	agentLoad()
	mine := 0
	for _, x := range agentSt.Schedules {
		if x.Owner == sess.Username {
			mine++
		}
	}
	if mine >= agentMaxSchedules {
		agentSt.Unlock()
		writeJSON(w, 409, map[string]string{"error": fmt.Sprintf("예약은 한 사람당 %d개까지입니다", agentMaxSchedules)})
		return
	}
	agentSt.Schedules = append(agentSt.Schedules, sc)
	agentSave()
	agentSt.Unlock()
	_ = s.sor.append(SoREvent{Actor: sess.Username, Action: "agent-schedule", Subject: rc.Title, Status: "created", Detail: map[string]any{"repeat": sc.Repeat, "time": sc.Time}})
	writeJSON(w, 200, sc)
}

// POST {on} 켜기·끄기, DELETE 삭제 — 예약한 본인이나 관리자만.
func (s *Server) apiAgentSchedule(w http.ResponseWriter, r *http.Request) {
	sess, _ := s.sessionOf(r)
	var in struct {
		On bool `json:"on"`
	}
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&in); err != nil {
			writeJSON(w, 400, map[string]string{"error": "잘못된 요청"})
			return
		}
	}
	id := r.PathValue("id")
	agentSt.Lock()
	agentLoad()
	at := -1
	for i, x := range agentSt.Schedules {
		if x.ID == id && (x.Owner == sess.Username || contains(sess.Groups, "admins")) {
			at = i
		}
	}
	if at < 0 {
		agentSt.Unlock()
		writeJSON(w, 404, map[string]string{"error": "예약을 찾지 못했습니다"})
		return
	}
	title, status := agentSt.Schedules[at].Recipe, "deleted"
	if r.Method == http.MethodDelete {
		agentSt.Schedules = append(agentSt.Schedules[:at], agentSt.Schedules[at+1:]...)
	} else {
		x := &agentSt.Schedules[at]
		x.On, x.Next, status = in.On, "", map[bool]string{true: "on", false: "off"}[in.On]
		if in.On {
			x.Next = agentNext(*x, time.Now()).UTC().Format(time.RFC3339)
		}
	}
	agentSave()
	agentSt.Unlock()
	_ = s.sor.append(SoREvent{Actor: sess.Username, Action: "agent-schedule", Subject: title, Status: status})
	writeJSON(w, 200, map[string]string{"status": status})
}
