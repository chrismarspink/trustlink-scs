package main

// ask.go: 묻고 찾기 — 로그인한 누구나 문장으로 묻고, 자기 권한 안의 기록에서 답을 받는다.
//
// 범용 챗봇이 아니다. 여러 화면을 넘나들어야 답이 나오는 질문 네 가지만 받는다.
//   ① 취약점 영향   "CVE-2026-1234 가 어디에 걸리나?"   → 제품·버전·판단 상태(관리자에게는 영향 고객까지)
//   ② 구성요소 찾기 "log4j 를 쓰는 제품은?"            → 그 구성요소가 든 제품·버전
//   ③ 내 제품      "내가 조치할 게 있나?"             → 설치 버전의 취약점과 권장 버전(고객)
//   ④ 할 일        "오늘 승인할 것?"                  → 승인 대기(관리자)·판단 대기(개발·보안)
// 답은 규칙으로 바로 만든다(조회 + 틀). AI 는 원할 때만 그 결과를 한두 문장으로 정리한다 — 로컬 sLLM 이든 외부 LLM 이든
// "AI 연결"에서 VEX 용도로 고른 모델을 쓴다(고객·제품 정보가 들어가므로 같은 민감도 기준).
// 권한: 별도 관리자 권한으로 조회하지 않고 질문한 사람의 권한 그대로 거른다. 무엇을 물었는지는 감사 원장에 남긴다.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
)

type askRow struct {
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
	Link   string `json:"link,omitempty"`
	Tone   string `json:"tone,omitempty"` // crit / warn / ok / ""
}

type askAnswer struct {
	ID      string   `json:"id"`
	Intent  string   `json:"intent"` // vuln / component / my / todo / howto / status / urgent / product / customer / free
	Title   string   `json:"title"`
	Lead    string   `json:"lead"` // 규칙으로 만든 한 줄 답
	Rows    []askRow `json:"rows"`
	More    int      `json:"more,omitempty"` // 줄이느라 보여 주지 않은 건수
	Sources []string `json:"sources"`        // 답의 출처(어느 기록에서 찾았나)
	Suggest []string `json:"suggest,omitempty"`
	CanAI   bool     `json:"canAI"`         // AI 한 줄 정리를 요청할 수 있는가
	UI      []a2     `json:"ui,omitempty"`  // 행동 양식(A2UI v0.9.1 메시지) — ask_action.go
	Map     string   `json:"map,omitempty"` // 영향 지도 링크(취약점을 찾았을 때)
	facts   []aiFact
	q, user string
	pending *askPending
	notice  *CustNotice
	vex     *vexDraftResult
	report  map[string][]string // 규제 보고서 양식의 처음 값
}

const askMaxRows = 12

var (
	askVulnRe = regexp.MustCompile(`(?i)\b(CVE-\d{4}-\d{3,7}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})\b`)
	askCompRe = regexp.MustCompile(`[A-Za-z][A-Za-z0-9._/@+-]{1,60}`)
	askTodoRe = regexp.MustCompile(`할 ?일|승인|대기|결정|오늘|이번 ?주|해야|처리`)
	askMyRe   = regexp.MustCompile(`내 ?제품|우리 ?제품|조치|업데이트|올려|패치|내가`)
	askCompKw = regexp.MustCompile(`쓰는|사용|포함|들어|구성요소|라이브러리|패키지`)
)

// 최근 답(사용자별 AI 정리 요청용). 메모리에만 둔다.
var askStore = struct {
	sync.Mutex
	m     map[string]*askAnswer
	order []string
}{m: map[string]*askAnswer{}}

func askKeep(a *askAnswer) {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	a.ID = "q-" + hex.EncodeToString(b)
	askStore.Lock()
	defer askStore.Unlock()
	askStore.m[a.ID] = a
	askStore.order = append(askStore.order, a.ID)
	for len(askStore.order) > 200 {
		delete(askStore.m, askStore.order[0])
		askStore.order = askStore.order[1:]
	}
}

func (s *Server) askCanRead(sess Session, repo string) bool {
	return contains(sess.Groups, "admins") || s.access == nil || s.access.allowed(sess.Username, sess.Groups, repo, "read")
}

func artifactLink(repo, tag string) string {
	return "/artifact/" + url.PathEscape(repo) + "/" + url.PathEscape(tag)
}

func askExamples(sess Session, isCustomer bool) []string {
	switch {
	case contains(sess.Groups, "admins"):
		return []string{"오늘 승인할 것?", "CVE-2026-123634 가 어디에 걸리나?", "미국 수출 규제 보고서 만들어 줘"}
	case isCustomer:
		return []string{"내가 조치할 게 있나?", "CVE-2026-123634 가 내 제품에 있나?"}
	}
	return []string{"내 할 일은?", "CVE-2026-123634 가 어디에 걸리나?", "spring 을 쓰는 제품은?"}
}

// POST /api/ask {q}
func (s *Server) apiAsk(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Q string `json:"q"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&in); err != nil || strings.TrimSpace(in.Q) == "" {
		writeJSON(w, 400, map[string]string{"error": "질문을 적어 주세요"})
		return
	}
	sess, _ := s.sessionOf(r)
	a := s.askAnswer(sess, truncate(strings.TrimSpace(in.Q), 300))
	a.q, a.user = in.Q, sess.Username
	a.CanAI = len(a.facts) > 0 && aiEnabledFor("vex")
	askKeep(a)
	if a.pending != nil && a.UI == nil { // 양식은 답의 ID(= A2UI surfaceId)가 정해진 뒤에 만든다
		switch a.pending.Kind {
		case "notice":
			a.UI = s.noticeForm(a, true)
		case "vexpick":
			a.UI = vexPickForm(a)
		case "vex":
			a.UI = vexForm(a, true)
		case "report":
			a.UI = reportForm(a)
		}
	}
	if s.sor != nil {
		_ = s.sor.append(SoREvent{Actor: sess.Username, Action: "ask", Status: a.Intent, Subject: a.ID,
			Detail: map[string]any{"q": truncate(in.Q, 200), "rows": len(a.Rows) + a.More}})
	}
	writeJSON(w, 200, a)
}

// askAnswer: 질문을 네 가지 중 하나로 가려 규칙으로 답을 만든다.
func (s *Server) askAnswer(sess Session, q string) *askAnswer {
	mine := s.myProducts(sess)
	isCustomer := len(mine) > 0 && !contains(sess.Groups, "admins")
	var a *askAnswer
	if a = s.askAction(sess, q); a != nil { // 행동 요청(통지 초안·VEX 판정·규제 보고서)이면 양식을 붙여 답한다
		if a.Rows == nil {
			a.Rows = []askRow{}
		}
		a.Suggest = askExamples(sess, isCustomer)
		return a
	}
	switch {
	case askVulnRe.MatchString(q):
		a = s.askVuln(sess, strings.ToUpper(askVulnRe.FindString(q)), mine, isCustomer)
	case askTodoRe.MatchString(q) && !isCustomer:
		a = s.askTodo(sess)
	case isCustomer && (askMyRe.MatchString(q) || askTodoRe.MatchString(q)):
		a = askMine(mine)
	default:
		if a = s.askMore(sess, q, mine, isCustomer); a != nil { // 사용법·현황·실제 악용·제품·고객
			break
		}
		switch {
		case !isCustomer && (askCompKw.MatchString(q) && askCompRe.MatchString(q) || !strings.Contains(q, " ") && askCompRe.MatchString(q)):
			a = s.askComponent(sess, askCompRe.FindString(q))
		case askMyRe.MatchString(q) && len(mine) > 0:
			a = askMine(mine)
		default:
			a = s.askFree(sess, mine, isCustomer)
		}
	}
	if a.Rows == nil {
		a.Rows = []askRow{}
	}
	a.Suggest = askExamples(sess, isCustomer)
	if id := strings.ToUpper(askVulnRe.FindString(q)); a.Intent == "vuln" && len(a.Rows) > 0 && !isCustomer { // 찾은 취약점으로 이어서 할 일
		a.Map = "/impact?vuln=" + id
		next := []string{}
		if canEditVex(sess) {
			next = append(next, id+" VEX 판정 초안")
		}
		if contains(sess.Groups, "admins") {
			next = append(next, id+" 고객 통지 초안 만들어 줘")
		}
		a.Suggest = append(next, a.Suggest...)
	}
	return a
}

func askStateKo(st string) (string, string) {
	switch strings.ToUpper(st) {
	case "", "NOT_SET", "IN_TRIAGE":
		return "판단 대기", "warn"
	case "EXPLOITABLE":
		return "영향 있음", "crit"
	case "NOT_AFFECTED", "FALSE_POSITIVE":
		return "영향 없음", "ok"
	case "RESOLVED":
		return "해결됨", "ok"
	}
	return st, ""
}

// ① 취약점 영향
func (s *Server) askVuln(sess Session, id string, mine []myCustomer, isCustomer bool) *askAnswer {
	a := &askAnswer{Intent: "vuln", Title: id + " 의 영향"}
	if isCustomer { // 고객은 자기 설치 버전에서만 찾는다
		a.Sources = []string{"내 제품(설치 버전의 취약점 분석)"}
		n := 0
		for _, c := range mine {
			for _, u := range c.Usages {
				for _, in := range u.Installs {
					for _, v := range in.Vulns {
						if v.VulnID != id {
							continue
						}
						n++
						st, tone := askStateKo(v.State)
						d := v.Component + " · " + st
						if v.Recommend != "" {
							d += " · 권장 버전 " + v.Recommend
						}
						a.Rows = append(a.Rows, askRow{Title: path.Base(u.Repo) + " " + in.Tag, Detail: d, Link: "/my", Tone: tone})
						a.facts = append(a.facts, aiFact{ID: fmt.Sprintf("F%d", len(a.facts)+1), Text: path.Base(u.Repo) + " " + in.Tag + ": " + d})
					}
				}
			}
		}
		if n == 0 {
			a.Lead = "설치하신 버전에서는 " + id + " 이(가) 발견되지 않았습니다."
		} else {
			a.Lead = fmt.Sprintf("설치하신 버전 %d곳에 %s 이(가) 있습니다.", n, id)
		}
		return a
	}
	if !s.dtEnabled() {
		a.Lead, a.Sources = "취약점 분석(Dependency-Track)이 꺼져 있어 찾을 수 없습니다.", []string{}
		return a
	}
	s.vexQueueRows(false)
	vexQueueCache.Lock()
	hits := append([]vulnHit(nil), vexQueueCache.idx[id]...)
	vexQueueCache.Unlock()
	a.Sources = []string{"취약점 분석(감시 중인 제품·버전)", "내부 취약점 DB(KEV)"}
	vis := []vulnHit{}
	for _, h := range hits {
		if s.askCanRead(sess, h.Repo) {
			vis = append(vis, h)
		}
	}
	if len(vis) == 0 {
		a.Lead = id + " 은(는) 감시 중인 제품·버전에서 발견되지 않았습니다."
		if len(hits) > 0 {
			a.Lead = id + " 은(는) 권한이 있는 제품에서는 발견되지 않았습니다."
		}
		return a
	}
	sort.SliceStable(vis, func(i, j int) bool { return vis[i].Repo+vis[i].Tag < vis[j].Repo+vis[j].Tag })
	repos, pend, tags := map[string]bool{}, 0, map[string]bool{}
	for _, h := range vis {
		repos[h.Repo], tags[h.Repo+":"+h.Tag] = true, true
		st, tone := askStateKo(h.State)
		if pendingState(strings.ToUpper(h.State)) {
			pend++
		}
		if len(a.Rows) < askMaxRows {
			a.Rows = append(a.Rows, askRow{Title: h.Repo + ":" + h.Tag, Detail: h.Component + " · " + h.Severity + " · " + st, Link: artifactLink(h.Repo, h.Tag), Tone: tone})
		}
	}
	a.More = len(vis) - len(a.Rows)
	kev := ""
	if isKEV([]string{id}) {
		kev = " 실제 악용이 확인된 취약점(KEV)입니다."
	}
	a.Lead = fmt.Sprintf("%s 은(는) 제품 %d개, 버전 %d개에 있습니다. 판단 대기 %d건.%s", id, len(repos), len(tags), pend, kev)
	a.facts = append(a.facts, aiFact{ID: "F1", Text: a.Lead})
	// 관리자에게는 그 버전을 설치한 고객까지
	if contains(sess.Groups, "admins") {
		names := []string{}
		for _, c := range activeCustomers(s.cust().snapshot().Customers) {
			for _, u := range c.Usages {
				for _, in := range u.Installs {
					if tags[u.Repo+":"+in.Tag] && !inList(c.Name, names) {
						names = append(names, c.Name)
					}
				}
			}
		}
		if len(names) > 0 {
			a.Lead += fmt.Sprintf(" 이 버전을 설치한 고객 %d곳: %s.", len(names), strings.Join(names, ", "))
			a.Sources = append(a.Sources, "고객 등록부(설치 버전)")
			a.facts = append(a.facts, aiFact{ID: "F2", Text: "영향 버전을 설치한 고객: " + strings.Join(names, ", ")})
		} else {
			a.Lead += " 이 버전을 설치한 고객은 등록부에 없습니다."
		}
	}
	for i, r := range a.Rows {
		if i < 6 {
			a.facts = append(a.facts, aiFact{ID: fmt.Sprintf("V%d", i+1), Text: r.Title + " — " + r.Detail})
		}
	}
	return a
}

// ② 구성요소 찾기 — Dependency-Track 의 구성요소 검색
func (s *Server) askComponent(sess Session, name string) *askAnswer {
	a := &askAnswer{Intent: "component", Title: "'" + name + "' 구성요소가 든 제품", Sources: []string{"SBOM 구성요소(감시 중인 제품·버전)"}}
	if !s.dtEnabled() {
		a.Lead, a.Sources = "취약점 분석(Dependency-Track)이 꺼져 있어 찾을 수 없습니다.", []string{}
		return a
	}
	resp, err := s.dtReq("GET", "/api/v1/component/identity?pageSize=300&name="+url.QueryEscape(name), nil)
	if err != nil {
		a.Lead = "구성요소를 찾는 중 오류가 났습니다: " + truncate(err.Error(), 120)
		return a
	}
	defer resp.Body.Close()
	var cs []struct {
		Name    string `json:"name"`
		Group   string `json:"group"`
		Version string `json:"version"`
		Project struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"project"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&cs)
	projects := map[string]string{} // "이름@버전" → 저장소
	if n := s.notify; n != nil {
		n.mu.Lock()
		for k, v := range n.st.Projects {
			projects[k] = v
		}
		n.mu.Unlock()
	}
	type hit struct{ repo, tag, comp string }
	seen, hits, repos := map[string]bool{}, []hit{}, map[string]bool{}
	for _, c := range cs {
		repo := projects[c.Project.Name+"@"+c.Project.Version]
		if repo == "" || !s.askCanRead(sess, repo) {
			continue
		}
		comp := strings.TrimSpace(strings.TrimPrefix(c.Group+"/"+c.Name, "/") + " " + c.Version)
		k := repo + ":" + c.Project.Version + "|" + comp
		if seen[k] {
			continue
		}
		seen[k] = true
		repos[repo] = true
		hits = append(hits, hit{repo, c.Project.Version, comp})
	}
	if len(hits) == 0 {
		a.Lead = "'" + name + "' 이(가) 든 제품을 찾지 못했습니다. 이름의 일부만 적어 다시 물어보세요."
		return a
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].repo+hits[i].tag > hits[j].repo+hits[j].tag })
	for _, h := range hits {
		if len(a.Rows) < askMaxRows {
			a.Rows = append(a.Rows, askRow{Title: h.repo + ":" + h.tag, Detail: h.comp, Link: artifactLink(h.repo, h.tag)})
		}
	}
	a.More = len(hits) - len(a.Rows)
	a.Lead = fmt.Sprintf("'%s' 은(는) 제품 %d개의 %d곳에서 쓰입니다.", name, len(repos), len(hits))
	a.facts = []aiFact{{ID: "F1", Text: a.Lead}}
	for i, r := range a.Rows {
		if i < 6 {
			a.facts = append(a.facts, aiFact{ID: fmt.Sprintf("C%d", i+1), Text: r.Title + " — " + r.Detail})
		}
	}
	return a
}

// ③ 내 제품(고객)
func askMine(mine []myCustomer) *askAnswer {
	a := &askAnswer{Intent: "my", Title: "내 제품에서 조치할 것", Sources: []string{"내 제품(설치 버전의 취약점 분석·권장 버전)"}}
	todo, clean := 0, 0
	for _, c := range mine {
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
				name := path.Base(u.Repo) + " " + in.Tag
				switch {
				case !in.Analyzed:
					a.Rows = append(a.Rows, askRow{Title: name, Detail: "아직 분석되지 않은 버전입니다", Link: "/my"})
				case act == 0:
					clean++
				default:
					todo++
					d := fmt.Sprintf("조치가 필요한 취약점 %d건", act)
					if kev > 0 {
						d += fmt.Sprintf("(실제 악용 %d건)", kev)
					}
					if rec != "" {
						d += " · 권장 버전 " + rec
					} else {
						d += " · 수정 버전은 아직 없습니다"
					}
					a.Rows = append(a.Rows, askRow{Title: name, Detail: d, Link: "/my", Tone: map[bool]string{true: "crit", false: "warn"}[kev > 0]})
					a.facts = append(a.facts, aiFact{ID: fmt.Sprintf("F%d", len(a.facts)+1), Text: name + ": " + d})
				}
			}
		}
	}
	if todo == 0 {
		a.Lead = fmt.Sprintf("지금 조치할 것은 없습니다. 설치 버전 %d개가 깨끗합니다.", clean)
	} else {
		a.Lead = fmt.Sprintf("설치 버전 %d개에 조치할 것이 있습니다(나머지 %d개는 깨끗합니다).", todo, clean)
	}
	return a
}

// ④ 할 일 — 관리자는 승인 대기, 그 밖에는 권한이 있는 제품의 판단 대기
func (s *Server) askTodo(sess Session) *askAnswer {
	a := &askAnswer{Intent: "todo", Title: "지금 할 일"}
	if contains(sess.Groups, "admins") {
		groups, total := s.inboxGroups()
		a.Sources = []string{"승인 대기함"}
		for _, g := range groups {
			if g.Count == 0 {
				continue
			}
			tone := ""
			for _, it := range g.Items {
				if it.Urgent {
					tone = "crit"
				}
			}
			a.Rows = append(a.Rows, askRow{Title: fmt.Sprintf("%s — %d건", g.Label, g.Count), Link: g.Link, Tone: tone})
			a.facts = append(a.facts, aiFact{ID: fmt.Sprintf("F%d", len(a.facts)+1), Text: fmt.Sprintf("%s %d건", g.Label, g.Count)})
		}
		a.Lead = fmt.Sprintf("결정할 일이 %d건 있습니다(VEX 판단 대기는 따로 셉니다).", total)
		if len(a.Rows) == 0 {
			a.Lead = "지금 결정할 일이 없습니다."
		}
		return a
	}
	a.Sources = []string{"VEX 판단 대기열(권한이 있는 제품)"}
	if !s.dtEnabled() {
		a.Lead = "취약점 분석이 꺼져 있어 할 일을 셀 수 없습니다."
		return a
	}
	pend, kev, n := 0, 0, 0
	for _, row := range s.vexQueueRows(false) {
		if row.Pending == 0 || !s.askCanRead(sess, row.Repo) {
			continue
		}
		n++
		pend += row.Pending
		kev += row.PendKEV
		if len(a.Rows) < askMaxRows {
			d := fmt.Sprintf("판단 대기 %d건(치명 %d · 높음 %d)", row.Pending, row.PendCrit, row.PendHigh)
			if row.PendKEV > 0 {
				d += fmt.Sprintf(" · 실제 악용 %d건", row.PendKEV)
			}
			a.Rows = append(a.Rows, askRow{Title: row.Repo + ":" + row.Tag, Detail: d, Link: artifactLink(row.Repo, row.Tag), Tone: map[bool]string{true: "crit", false: "warn"}[row.PendKEV > 0]})
			if len(a.facts) < 6 {
				a.facts = append(a.facts, aiFact{ID: fmt.Sprintf("F%d", len(a.facts)+1), Text: row.Repo + ":" + row.Tag + " — " + d})
			}
		}
	}
	a.More = n - len(a.Rows)
	if n == 0 {
		a.Lead = "권한이 있는 제품에 판단할 취약점이 없습니다."
	} else {
		a.Lead = fmt.Sprintf("제품·버전 %d개에 판단 대기 취약점 %d건이 있습니다(실제 악용 %d건). 급한 순으로 보여 드립니다.", n, pend, kev)
	}
	return a
}

// ---------- AI 한 줄 정리(원할 때만) ----------

const askTask = `아래 사실만으로 질문에 두 문장 이내로 답한다. 가장 급한 것부터 말하고, 사실에 없는 내용은 쓰지 않는다. 끝에 근거 사실 ID 를 [F1] 처럼 붙인다.`

var askSchema = map[string]any{
	"type":       "object",
	"properties": map[string]any{"answer": map[string]any{"type": "string", "maxLength": 320}},
	"required":   []string{"answer"},
}

// POST /api/ask/{id}/summary — 그 답을 AI 가 한두 문장으로 정리(질문한 본인만)
func (s *Server) apiAskSummary(w http.ResponseWriter, r *http.Request) {
	sess, _ := s.sessionOf(r)
	askStore.Lock()
	a := askStore.m[r.PathValue("id")]
	askStore.Unlock()
	if a == nil || a.user != sess.Username {
		writeJSON(w, 404, map[string]string{"error": "질문을 찾지 못했습니다 — 다시 물어보세요"})
		return
	}
	if len(a.facts) == 0 || !aiEnabledFor("vex") {
		writeJSON(w, 409, map[string]string{"error": "AI 로 정리할 내용이 없거나 AI 연결이 꺼져 있습니다"})
		return
	}
	defer aiInteractive()()
	facts := append([]aiFact{{ID: "Q", Text: "질문: " + truncate(a.q, 200), Untrusted: true}}, a.facts...)
	var out struct {
		Answer string `json:"answer"`
	}
	task, tok := askTask, 160
	if a.Intent == "free" {
		task, tok = askFreeTask, 220
	}
	meta, err := s.aiDraftOpt("vex", "ko", facts, task, askSchema, tok, &out, true)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"answer": strings.TrimSpace(out.Answer), "model": meta.Model, "provider": meta.Provider, "elapsedMs": meta.ElapsedMs})
}
