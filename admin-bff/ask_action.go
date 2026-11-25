package main

// ask_action.go: 묻고 찾기의 "행동" — 찾아 주는 데서 그치지 않고, 요청한 일을 초안으로 만들어 사람이 고르게 한다.
//
// 설계 원칙
//   1. AI·규칙은 초안과 선택지까지만 만든다. 바깥으로 나가는 일(고객 메일)과 기록으로 남는 일(VEX 판정)은
//      사람이 양식에서 고르고 단추를 눌러야 실행된다. "고객에게 보내"라고 적어도 바로 보내지 않고 양식을 띄운다.
//   2. 실행은 기존 경로를 그대로 탄다 — 고객 메일은 발송함(대기 중 취소 가능)으로, VEX 는 분석 기록으로.
//   3. 권한은 질문한 사람의 것. 고객 통지는 관리자, VEX 판정은 보안·개발·관리자이고 그 제품을 볼 수 있어야 한다.
//   4. 양식은 A2UI(v0.9.1, 기본 카탈로그)로 보낸다 — 서버는 "무슨 부품을 어떤 값으로"만 말하고, 화면은 허용된 부품만 그린다.
//      서버가 코드를 내려보내지 않으므로, 나중에 양식을 모델이 만들게 되어도 화면에서 실행되는 것은 없다.
//   5. 단추가 눌리면 화면이 A2UI action(이름 + 고른 값)을 보낸다. 서버는 이름과 서버에 적어 둔 대기 작업으로만 실행하고,
//      화면이 보낸 값은 "고른 것"(받는 고객, 대기 시간, 판정)으로만 쓴다.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	a2uiVersion = "v0.9.1"
	a2uiCatalog = "https://a2ui.org/specification/v0_9_1/catalogs/basic/catalog.json"
)

type a2 = map[string]any

func a2path(p string) a2 { return a2{"path": p} }

// uiBuild: 부품 목록을 모은다(A2UI 는 부품을 평평한 목록으로 보내고 id 로 잇는다).
type uiBuild struct{ comps []a2 }

func (u *uiBuild) add(c a2) string {
	u.comps = append(u.comps, c)
	return c["id"].(string)
}
func (u *uiBuild) text(id, text, variant string) string {
	c := a2{"id": id, "component": "Text", "text": text}
	if variant != "" {
		c["variant"] = variant
	}
	return u.add(c)
}
func (u *uiBuild) button(id, label, variant, event string, ctx a2) string {
	u.text(id+"_t", label, "")
	c := a2{"id": id, "component": "Button", "child": id + "_t", "action": a2{"event": a2{"name": event, "context": ctx}}}
	if variant != "" {
		c["variant"] = variant
	}
	return u.add(c)
}
func (u *uiBuild) link(id, label, url string) string {
	u.text(id+"_t", label, "")
	return u.add(a2{"id": id, "component": "Button", "variant": "borderless", "child": id + "_t",
		"action": a2{"functionCall": a2{"call": "openUrl", "args": a2{"url": url}}}})
}
func (u *uiBuild) choice(id, label, variant string, opts [][2]string, bind string) string {
	os := []a2{}
	for _, o := range opts {
		os = append(os, a2{"value": o[0], "label": o[1]})
	}
	return u.add(a2{"id": id, "component": "ChoicePicker", "label": label, "variant": variant, "options": os, "value": a2path(bind)})
}

// messages: 새 화면이면 createSurface 부터, 이미 있는 화면을 바꾸는 것이면 부품·자료만.
func (u *uiBuild) messages(surface string, create bool, rootChildren []string, data a2) []a2 {
	comps := append([]a2{{"id": "root", "component": "Column", "children": rootChildren}}, u.comps...)
	out := []a2{}
	if create {
		out = append(out, a2{"version": a2uiVersion, "createSurface": a2{"surfaceId": surface, "catalogId": a2uiCatalog}})
	}
	out = append(out, a2{"version": a2uiVersion, "updateComponents": a2{"surfaceId": surface, "components": comps}})
	if data != nil {
		out = append(out, a2{"version": a2uiVersion, "updateDataModel": a2{"surfaceId": surface, "path": "/", "value": data}})
	}
	return out
}

// askPending: 양식이 떠 있는 동안 서버가 기억하는 대기 작업(화면이 보낸 값만으로 실행하지 않기 위해).
type askPending struct {
	Kind     string // notice / vexpick / vex
	NoticeID string
	Keys     []string // 고를 수 있는 통지 대상
	Hits     []vulnHit
	VulnID   string
	Hit      vulnHit
	Comp     string // 구성요소 UUID
	Vuln     string // 취약점 UUID
	Response string // 규칙 초안의 대응(affected 일 때)
	Done     bool
}

var (
	askNoticeRe = regexp.MustCompile(`통지|권고|안내문`)                  // "알려 줘"는 묻는 말로도 쓰여 넣지 않는다
	askSendRe   = regexp.MustCompile(`고객.*(보내|발송|메일)|(보내|발송).*고객`) // "고객에게 보내"
	askVexRe    = regexp.MustCompile(`(?i)vex|판정|판단|분류`)
)

func canEditVex(sess Session) bool {
	for _, g := range vexEditors {
		if contains(sess.Groups, g) {
			return true
		}
	}
	return false
}

// askAction: 행동 요청이면 양식이 붙은 답을, 아니면 nil.
func (s *Server) askAction(sess Session, q string) *askAnswer {
	id := strings.ToUpper(askVulnRe.FindString(q))
	wantNotice := askNoticeRe.MatchString(q) || askSendRe.MatchString(q)
	switch {
	case askReportRe.MatchString(q) && askRegRe.MatchString(q):
		if !contains(sess.Groups, "admins") {
			return &askAnswer{Intent: "action", Title: "규제 보고서", Lead: "규제 보고서는 관리자만 만들 수 있습니다.", Sources: []string{}}
		}
		return s.askReportStart(sess, q)
	case wantNotice && id != "":
		if !contains(sess.Groups, "admins") {
			return &askAnswer{Intent: "action", Title: "고객 통지", Lead: "고객 통지는 관리자만 만들고 보낼 수 있습니다.", Sources: []string{}}
		}
		return s.askNoticeDraft(sess, id, q)
	case wantNotice && contains(sess.Groups, "admins") && !askTodoRe.MatchString(q):
		if a := askLastPending(sess.Username, "notice"); a != nil { // "고객에게 보내" — 방금 만든 초안의 양식을 다시 띄운다
			b := *a
			b.Lead = "보내기 전에 받는 고객과 대기 시간을 확인하고 단추를 눌러 주세요. 누르기 전에는 아무것도 나가지 않습니다."
			b.UI = s.noticeForm(&b, true)
			return &b
		}
		return &askAnswer{Intent: "action", Title: "고객 통지", Lead: "어느 취약점의 통지인지 번호를 함께 적어 주세요. 예: CVE-2026-123634 고객 통지 초안 만들어 줘", Sources: []string{}}
	case askVexRe.MatchString(q) && id != "":
		if !canEditVex(sess) {
			return &askAnswer{Intent: "action", Title: "VEX 판정", Lead: "VEX 판정은 보안·개발 담당과 관리자만 할 수 있습니다.", Sources: []string{}}
		}
		return s.askVexStart(sess, id, q)
	}
	return nil
}

func askLastPending(user, kind string) *askAnswer {
	askStore.Lock()
	defer askStore.Unlock()
	for i := len(askStore.order) - 1; i >= 0; i-- {
		a := askStore.m[askStore.order[i]]
		if a != nil && a.user == user && a.pending != nil && a.pending.Kind == kind && !a.pending.Done {
			return a
		}
	}
	return nil
}

func (s *Server) askHits(sess Session, id string) []vulnHit {
	if !s.dtEnabled() {
		return nil
	}
	s.vexQueueRows(false)
	vexQueueCache.Lock()
	hits := append([]vulnHit(nil), vexQueueCache.idx[id]...)
	vexQueueCache.Unlock()
	out := []vulnHit{}
	for _, h := range hits {
		if s.askCanRead(sess, h.Repo) {
			out = append(out, h)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Repo+out[i].Tag > out[j].Repo+out[j].Tag })
	return out
}

// ---------- 고객 통지 초안 → 발송함 ----------

func (s *Server) askNoticeDraft(sess Session, id, q string) *askAnswer {
	a := &askAnswer{Intent: "action", Title: id + " 고객 통지 초안", Sources: []string{"고객 등록부(설치 버전·담당자)", "취약점 분석", "규칙으로 고른 권장 버전"}}
	repos := []string{}
	for _, h := range s.askHits(sess, id) {
		if !inList(h.Repo, repos) {
			repos = append(repos, h.Repo)
		}
	}
	// 질문에 제품 이름이 있으면 그것부터
	sort.SliceStable(repos, func(i, j int) bool {
		return strings.Contains(q, path.Base(repos[i])) && !strings.Contains(q, path.Base(repos[j]))
	})
	if len(repos) == 0 {
		a.Lead = id + " 은(는) 감시 중인 제품에서 발견되지 않아 통지할 대상이 없습니다."
		return a
	}
	var n *CustNotice
	var lastErr error
	for _, repo := range repos {
		x, err := s.buildNotice("patch", repo, id, sess.Username)
		if err == nil && len(x.Targets) > 0 {
			n = x
			break
		}
		if err != nil {
			lastErr = err
		}
	}
	if n == nil {
		a.Lead = "통지 초안을 만들지 못했습니다 — 이 취약점이 있는 버전을 설치한 고객이 등록부에 없습니다."
		if lastErr != nil {
			a.Lead = "통지 초안을 만들지 못했습니다: " + truncate(lastErr.Error(), 160)
		}
		return a
	}
	if err := s.cust().putNotice(n); err != nil {
		a.Lead = "초안을 저장하지 못했습니다: " + truncate(err.Error(), 120)
		return a
	}
	keys := []string{}
	for _, t := range n.Targets {
		if len(t.To) > 0 {
			keys = append(keys, t.Key)
		}
	}
	a.pending = &askPending{Kind: "notice", NoticeID: n.ID, Keys: keys, VulnID: id}
	fix := "수정 버전은 아직 없습니다"
	if n.Fix.Found {
		fix = "권장 버전 " + n.Fix.Tag
	}
	a.Lead = fmt.Sprintf("%s 의 %s 통지 초안을 만들었습니다. 영향 고객 %d곳, %s. 받는 고객을 확인하고 단추를 누르면 발송함으로 갑니다.", path.Base(n.Repo), id, len(n.Targets), fix)
	a.notice = n
	return a
}

// noticeForm: 받는 고객·대기 시간을 고르고 보내는 양식(A2UI).
func (s *Server) noticeForm(a *askAnswer, create bool) []a2 {
	n := a.notice
	if n == nil {
		return nil
	}
	u := &uiBuild{}
	opts := [][2]string{}
	for _, t := range n.Targets {
		l := fmt.Sprintf("%s — 받는 사람 %d명", t.Customer, len(t.To))
		if t.Recommend != "" {
			l += " · 권장 " + t.Recommend
		}
		if len(t.To) == 0 {
			l += " (받는 주소 없음)"
		}
		opts = append(opts, [2]string{t.Key, l})
	}
	kids := []string{u.text("h", "고객 보안 권고 — "+n.VulnID, "h4")}
	kids = append(kids, u.text("sub", fmt.Sprintf("%s · %s %s · %s", path.Base(n.Repo), n.Component, n.CompVersion, n.Severity), "caption"))
	kids = append(kids, u.choice("targets", "받는 고객", "multipleSelection", opts, "/targets"))
	kids = append(kids, u.choice("delay", "보내기 전 대기(그동안 취소할 수 있습니다)", "mutuallyExclusive",
		[][2]string{{"30", "30초"}, {"60", "1분"}, {"120", "2분"}}, "/delay"))
	if len(n.Targets) > 0 {
		kids = append(kids, u.add(a2{"id": "d1", "component": "Divider"}))
		kids = append(kids, u.text("subj", "메일 제목: "+n.Targets[0].Subject, "caption"))
		kids = append(kids, u.text("body", truncate(n.Targets[0].Text, 320), "caption"))
	}
	u.button("send", "승인하고 발송함으로", "primary", "notice.send", a2{"targets": a2path("/targets"), "delay": a2path("/delay")})
	u.link("open", "통지 화면에서 고치기", "/admin/customer-notify")
	u.button("cancel", "취소", "borderless", "cancel", a2{})
	kids = append(kids, u.add(a2{"id": "btns", "component": "Row", "children": []string{"send", "open", "cancel"}}))
	return u.messages(a.ID, create, kids, a2{"targets": a.pending.Keys, "delay": []string{"30"}})
}

// ---------- VEX 판정 초안 → 저장 ----------

func (s *Server) askVexStart(sess Session, id, q string) *askAnswer {
	a := &askAnswer{Intent: "action", Title: id + " VEX 판정", Sources: []string{"취약점 분석", "내부 취약점 DB(OSV·KEV·익스플로잇)", "규칙 판정"}}
	hits := s.askHits(sess, id)
	if len(hits) == 0 {
		a.Lead = id + " 은(는) 권한이 있는 제품에서 발견되지 않았습니다."
		return a
	}
	pick := -1
	if len(hits) == 1 {
		pick = 0
	}
	for i, h := range hits { // 질문에 "제품:버전"이나 버전이 적혀 있으면 그것으로
		if strings.Contains(q, h.Repo+":"+h.Tag) || strings.Contains(q, path.Base(h.Repo)+":"+h.Tag) || strings.Contains(q, path.Base(h.Repo)+" "+h.Tag) {
			pick = i
			break
		}
	}
	if pick >= 0 {
		return s.askVexDraft(sess, a, id, hits[pick])
	}
	if len(hits) > askMaxRows {
		hits = hits[:askMaxRows]
	}
	a.pending = &askPending{Kind: "vexpick", Hits: hits, VulnID: id}
	a.Lead = fmt.Sprintf("%s 은(는) %d개 버전에 있습니다. 어느 버전을 판정할지 골라 주세요.", id, len(hits))
	return a
}

func vexPickForm(a *askAnswer) []a2 {
	u := &uiBuild{}
	opts := [][2]string{}
	for i, h := range a.pending.Hits {
		st, _ := askStateKo(h.State)
		opts = append(opts, [2]string{itoa(i), fmt.Sprintf("%s:%s — %s · %s", h.Repo, h.Tag, h.Component, st)})
	}
	kids := []string{u.text("h", "판정할 버전 고르기", "h4"),
		u.choice("target", "제품 · 버전", "mutuallyExclusive", opts, "/target")}
	u.button("go", "이 버전으로 초안 만들기", "primary", "vex.pick", a2{"target": a2path("/target")})
	u.button("cancel", "취소", "borderless", "cancel", a2{})
	kids = append(kids, u.add(a2{"id": "btns", "component": "Row", "children": []string{"go", "cancel"}}))
	return u.messages(a.ID, true, kids, a2{"target": []string{"0"}})
}

var (
	askVexStates = [][2]string{{"under_investigation", "조사 중"}, {"affected", "영향 있음"}, {"not_affected", "영향 없음"}, {"fixed", "수정됨"}}
	askVexJusts  = [][2]string{{"none", "해당 없음(영향 없음이 아닐 때)"}, {"vulnerable_code_not_present", "취약한 코드가 없음"},
		{"vulnerable_code_not_in_execute_path", "취약한 코드가 실행되지 않음"}, {"vulnerable_code_cannot_be_controlled_by_adversary", "공격자가 닿을 수 없음"},
		{"inline_mitigations_already_exist", "별도 방어 장치가 있음"}, {"component_not_present", "구성요소가 제품에 없음"}}
)

func (s *Server) askVexDraft(sess Session, a *askAnswer, id string, h vulnHit) *askAnswer {
	if !s.askCanRead(sess, h.Repo) {
		a.Lead = "이 제품에 대한 권한이 없습니다."
		return a
	}
	fs, err := s.projectFindings(h.Project)
	if err != nil {
		a.Lead = "취약점 분석을 읽지 못했습니다: " + truncate(err.Error(), 120)
		return a
	}
	var f *dtFindingFull
	for i := range fs {
		if strings.EqualFold(fs[i].Vulnerability.VulnID, id) && strings.HasPrefix(h.Component, fs[i].Component.Name) {
			f = &fs[i]
			break
		}
	}
	if f == nil {
		a.Lead = "그 버전에서 " + id + " 을(를) 다시 찾지 못했습니다 — 분석이 갱신됐을 수 있습니다."
		return a
	}
	res, err := s.vexFastDraftFor(sess.Username, h.Repo, h.Tag, *f, "", false) // 규칙 초안(요약 카드가 있으면 포함) — 바로 나온다
	if err != nil {
		a.Lead = "판정 초안을 만들지 못했습니다: " + truncate(err.Error(), 120)
		return a
	}
	a.pending = &askPending{Kind: "vex", VulnID: id, Hit: h, Comp: f.Component.UUID, Vuln: f.Vulnerability.UUID, Response: res.Draft.Response}
	a.vex = res
	st := labelOf2(askVexStates, res.Draft.Status)
	a.Lead = fmt.Sprintf("%s:%s 의 %s 판정 초안입니다. 규칙 판정은 '%s'입니다. 확인하고 고쳐서 저장하면 판정 기록으로 남습니다.", h.Repo, h.Tag, id, st)
	return a
}

func labelOf2(opts [][2]string, v string) string {
	for _, o := range opts {
		if o[0] == v {
			return o[1]
		}
	}
	return v
}

func vexForm(a *askAnswer, create bool) []a2 {
	d, h := a.vex.Draft, a.pending.Hit
	u := &uiBuild{}
	kids := []string{u.text("h", "VEX 판정 — "+a.pending.VulnID, "h4"),
		u.text("sub", fmt.Sprintf("%s:%s · %s · %s", h.Repo, h.Tag, h.Component, h.Severity), "caption"),
		u.text("why", d.Detail, "body")}
	kids = append(kids, u.choice("status", "판정", "mutuallyExclusive", askVexStates, "/status"))
	kids = append(kids, u.choice("just", "영향 없음의 근거", "mutuallyExclusive", askVexJusts, "/justification"))
	kids = append(kids, u.add(a2{"id": "memo", "component": "TextField", "label": "판정 메모(기록에 남습니다)", "variant": "longText", "value": a2path("/detail")}))
	u.button("save", "저장(판정 기록)", "primary", "vex.save", a2{"status": a2path("/status"), "justification": a2path("/justification"), "detail": a2path("/detail")})
	u.link("open", "제품 화면에서 열기", artifactLink(h.Repo, h.Tag))
	u.button("cancel", "취소", "borderless", "cancel", a2{})
	kids = append(kids, u.add(a2{"id": "btns", "component": "Row", "children": []string{"save", "open", "cancel"}}))
	just := firstNonEmpty(d.Justification, "none")
	return u.messages(a.ID, create, kids, a2{"status": []string{d.Status}, "justification": []string{just}, "detail": truncate(d.Detail, 600)})
}

// ---------- 단추가 눌렸을 때 ----------

// resultUI: 양식을 결과 문구로 바꾼다(같은 화면을 갱신 — 다시 누를 수 없게).
func resultUI(surface, title, text, linkLabel, linkURL string) []a2 {
	u := &uiBuild{}
	kids := []string{u.text("h", title, "h4"), u.text("t", text, "body")}
	if linkURL != "" {
		kids = append(kids, u.link("go", linkLabel, linkURL))
	}
	return u.messages(surface, false, kids, nil)
}

func strList(v any) []string {
	out := []string{}
	if xs, ok := v.([]any); ok {
		for _, x := range xs {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// POST /api/ask/action — A2UI 클라이언트 → 서버 action 메시지
func (s *Server) apiAskAction(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Action struct {
			Name      string         `json:"name"`
			SurfaceID string         `json:"surfaceId"`
			Context   map[string]any `json:"context"`
		} `json:"action"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<14)).Decode(&in); err != nil || in.Action.Name == "" {
		writeJSON(w, 400, map[string]string{"error": "잘못된 요청"})
		return
	}
	sess, _ := s.sessionOf(r)
	askStore.Lock()
	a := askStore.m[in.Action.SurfaceID]
	askStore.Unlock()
	if a == nil || a.user != sess.Username || a.pending == nil {
		writeJSON(w, 404, map[string]string{"error": "이 양식은 더 쓸 수 없습니다 — 다시 요청해 주세요"})
		return
	}
	p, ctx, name := a.pending, in.Action.Context, in.Action.Name
	if p.Done {
		writeJSON(w, 409, map[string]string{"error": "이미 처리한 요청입니다"})
		return
	}
	audit := func(status string, detail map[string]any) {
		if s.sor != nil {
			detail["ask"] = a.ID
			_ = s.sor.append(SoREvent{Actor: sess.Username, Action: "ask-action", Status: status, Subject: name, Repo: p.Hit.Repo, Tag: p.Hit.Tag, Detail: detail})
		}
		if res := askDoneText[status]; res != "" { // 묻고 찾기로 실행한 것도 에이전트 실행 기록에 남긴다(되돌리기는 없다)
			agentLogAdd(sess.Username, "ask", strings.TrimSpace("묻고 찾기: "+askKindKo[p.Kind]+" "+p.VulnID), res, true, nil)
		}
	}
	switch {
	case name == "cancel":
		p.Done = true
		audit("cancelled", map[string]any{"kind": p.Kind})
		writeJSON(w, 200, map[string]any{"ui": resultUI(a.ID, "취소했습니다", "아무것도 보내거나 저장하지 않았습니다.", "", "")})

	case name == "notice.send" && p.Kind == "notice":
		if !contains(sess.Groups, "admins") {
			writeJSON(w, 403, map[string]string{"error": "고객 통지는 관리자만 보낼 수 있습니다"})
			return
		}
		keys := []string{}
		for _, k := range strList(ctx["targets"]) {
			if inList(k, p.Keys) { // 양식에 있던 대상만
				keys = append(keys, k)
			}
		}
		if len(keys) == 0 {
			writeJSON(w, 400, map[string]string{"error": "받는 고객을 한 곳 이상 고르세요"})
			return
		}
		sec := 30
		if d := strList(ctx["delay"]); len(d) == 1 && inList(d[0], []string{"30", "60", "120"}) {
			fmt.Sscan(d[0], &sec)
		}
		custNoticeMu.Lock()
		c := s.cust()
		n, ok := c.notice(p.NoticeID)
		if !ok {
			custNoticeMu.Unlock()
			writeJSON(w, 404, map[string]string{"error": "통지 초안이 없습니다 — 다시 만들어 주세요"})
			return
		}
		s.sendNotice(n, keys, sess.Username, outboxDelay(sec))
		err := c.putNotice(n)
		custNoticeMu.Unlock()
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		queued, failed := 0, []string{}
		for _, t := range n.Targets {
			if !inList(t.Key, keys) || t.Result == nil {
				continue
			}
			if t.Result.Pending {
				queued++
			} else if len(t.Result.Sent) == 0 {
				failed = append(failed, t.Customer+"("+firstNonEmpty(t.Result.Error, "허용 목록 밖 주소")+")")
			}
		}
		p.Done = true
		audit("queued", map[string]any{"notice": n.ID, "vulnId": p.VulnID, "targets": keys, "queued": queued, "delay": sec})
		msg := fmt.Sprintf("고객 %d곳의 메일을 발송함에 넣었습니다. %d초 뒤에 나가며, 그 전에는 발송함에서 취소할 수 있습니다.", queued, sec)
		if len(failed) > 0 {
			msg += " 넣지 못한 곳: " + strings.Join(failed, ", ") + "."
		}
		writeJSON(w, 200, map[string]any{"ui": resultUI(a.ID, "발송함에 넣었습니다", msg, "발송함 열기(취소·확인)", "/admin/outbox")})

	case name == "report.make" && p.Kind == "report":
		ui, msg, code := s.askReportMake(sess, a, ctx)
		if code != 200 {
			writeJSON(w, code, map[string]string{"error": msg})
			return
		}
		p.Done = true
		audit("made", map[string]any{"report": msg})
		writeJSON(w, 200, map[string]any{"ui": ui})

	case name == "vex.pick" && p.Kind == "vexpick":
		i := -1
		if t := strList(ctx["target"]); len(t) == 1 {
			fmt.Sscan(t[0], &i)
		}
		if i < 0 || i >= len(p.Hits) {
			writeJSON(w, 400, map[string]string{"error": "판정할 버전을 고르세요"})
			return
		}
		b := s.askVexDraft(sess, &askAnswer{ID: a.ID, Intent: "action", Title: a.Title, Sources: a.Sources}, p.VulnID, p.Hits[i])
		if b.pending == nil {
			writeJSON(w, 409, map[string]string{"error": b.Lead})
			return
		}
		askStore.Lock()
		a.pending, a.vex = b.pending, b.vex
		askStore.Unlock()
		writeJSON(w, 200, map[string]any{"ui": vexForm(a, false), "lead": b.Lead})

	case name == "vex.save" && p.Kind == "vex":
		if !canEditVex(sess) || !s.askCanRead(sess, p.Hit.Repo) {
			writeJSON(w, 403, map[string]string{"error": "이 제품의 VEX 판정 권한이 없습니다"})
			return
		}
		st, ju := strList(ctx["status"]), strList(ctx["justification"])
		if len(st) != 1 || !inList(st[0], vexStates) {
			writeJSON(w, 400, map[string]string{"error": "판정을 하나 고르세요"})
			return
		}
		just := ""
		if len(ju) == 1 && ju[0] != "none" && inList(ju[0], vexJusts) {
			just = ju[0]
		}
		if st[0] == "not_affected" && just == "" {
			writeJSON(w, 400, map[string]string{"error": "'영향 없음'은 근거를 골라야 저장할 수 있습니다"})
			return
		}
		if st[0] != "not_affected" {
			just = ""
		}
		detail, _ := ctx["detail"].(string)
		resp := ""
		if st[0] == "affected" {
			resp = p.Response
		}
		code, body, err := s.vexRecord(p.Hit.Project, p.Comp, p.Vuln, st[0], just, resp, truncate(strings.TrimSpace(detail), 1000), "묻고 찾기에서 저장 — 규칙 초안을 "+sess.Username+" 이(가) 확인")
		if err != nil || code != 200 {
			writeJSON(w, 502, map[string]string{"error": "판정을 기록하지 못했습니다: " + truncate(firstNonEmpty(errString(err), string(body)), 160)})
			return
		}
		p.Done = true
		vexQueueCache.Lock()
		vexQueueCache.at = time.Time{} // 대기 건수를 다시 세게
		vexQueueCache.Unlock()
		audit("recorded", map[string]any{"vulnId": p.VulnID, "status": st[0], "justification": just})
		writeJSON(w, 200, map[string]any{"ui": resultUI(a.ID, "판정을 저장했습니다",
			fmt.Sprintf("%s:%s 의 %s 을(를) '%s'(으)로 기록했습니다. 고객에게 전달하려면 제품 화면에서 VEX 를 발행하세요.", p.Hit.Repo, p.Hit.Tag, p.VulnID, labelOf2(askVexStates, st[0])),
			"제품 화면 열기(VEX 발행)", artifactLink(p.Hit.Repo, p.Hit.Tag))})

	default:
		writeJSON(w, 400, map[string]string{"error": "이 양식에서 쓸 수 없는 요청입니다"})
	}
}

// ---------- 규제 보고서 만들기 → 내려받기 ----------

var (
	askReportRe = regexp.MustCompile(`리포트|보고서|report`)
	askRegRe    = regexp.MustCompile(`(?i)규제|수출|법|CRA|CMMC|EO ?14028|미국|유럽|EU|일본|영국|인도`)
	askRegionKw = [][2]string{{"미국", "US"}, {"US", "US"}, {"CMMC", "US"}, {"유럽", "EU"}, {"EU", "EU"}, {"CRA", "EU"}, {"일본", "JP"}, {"영국", "UK"}, {"인도", "IN"}, {"한국", "KR"}, {"국내", "KR"}}
)

// askReportStart: "이 제품 미국 수출 규제 리포트 만들어 줘" — 지역·독자·제품·언어를 고르는 양식.
func (s *Server) askReportStart(sess Session, q string) *askAnswer {
	a := &askAnswer{Intent: "action", Title: "규제 보고서 만들기", Sources: []string{"규제 카탈로그", "제품의 SBOM·VEX 증빙(제품을 고른 경우)"}}
	regions := []string{}
	up := strings.ToUpper(q)
	for _, kw := range askRegionKw {
		if strings.Contains(up, strings.ToUpper(kw[0])) && !inList(kw[1], regions) {
			regions = append(regions, kw[1])
		}
	}
	if len(regions) == 0 {
		regions = []string{"US"}
	}
	// 고를 수 있는 제품: 권한이 있는 제품마다 가장 최근 버전 하나
	latest := map[string]string{}
	if s.dtEnabled() {
		for _, row := range s.vexQueueRows(false) {
			if s.askCanRead(sess, row.Repo) && row.Tag > latest[row.Repo] {
				latest[row.Repo] = row.Tag
			}
		}
	}
	prods := []string{}
	for repo, tag := range latest {
		prods = append(prods, repo+":"+tag)
	}
	sort.Strings(prods)
	pick := "none"
	for _, p := range prods { // 질문에 제품 이름이 있으면 그것으로
		if strings.Contains(q, path.Base(strings.SplitN(p, ":", 2)[0])) {
			pick = p
			break
		}
	}
	if len(prods) > 20 {
		prods = prods[:20]
	}
	lang := "ko"
	if strings.Contains(q, "영문") || strings.Contains(q, "영어") {
		lang = "en"
	}
	aud := "all"
	if strings.Contains(q, "영업") || strings.Contains(q, "수출") {
		aud = "sales"
	}
	a.pending = &askPending{Kind: "report", Keys: prods}
	a.report = map[string][]string{"regions": regions, "product": {pick}, "lang": {lang}, "audience": {aud}}
	names := []string{}
	for _, r := range regions {
		names = append(names, regRegionKo[r])
	}
	a.Lead = strings.Join(names, "·") + " 규제 보고서를 만들 준비가 됐습니다. 지역·독자·제품을 확인하고 단추를 누르면 바로 만들어 내려받을 수 있습니다."
	return a
}

func reportForm(a *askAnswer) []a2 {
	u := &uiBuild{}
	regs := [][2]string{}
	for _, k := range []string{"US", "EU", "KR", "JP", "UK", "IN", "INTL"} {
		regs = append(regs, [2]string{k, regRegionKo[k]})
	}
	prods := [][2]string{{"none", "제품 지정 안 함(규제 요약만)"}}
	for _, p := range a.pending.Keys {
		prods = append(prods, [2]string{p, p + " — 이 버전의 증빙 점검 포함"})
	}
	kids := []string{u.text("h", "규제 보고서 만들기", "h4"),
		u.choice("regions", "지역", "multipleSelection", regs, "/regions"),
		u.choice("audience", "읽는 사람", "mutuallyExclusive", [][2]string{{"all", "전체"}, {"sales", "영업(고객 설명용)"}, {"dev", "개발"}, {"admin", "관리자"}}, "/audience"),
		u.choice("product", "제품", "mutuallyExclusive", prods, "/product"),
		u.choice("lang", "언어", "mutuallyExclusive", [][2]string{{"ko", "한국어"}, {"en", "영어"}}, "/lang")}
	u.button("make", "보고서 만들기", "primary", "report.make", a2{"regions": a2path("/regions"), "audience": a2path("/audience"), "product": a2path("/product"), "lang": a2path("/lang")})
	u.button("cancel", "취소", "borderless", "cancel", a2{})
	kids = append(kids, u.add(a2{"id": "btns", "component": "Row", "children": []string{"make", "cancel"}}))
	data := a2{}
	for k, v := range a.report {
		data[k] = v
	}
	return u.messages(a.ID, true, kids, data)
}

// askReportMake: 양식의 값으로 보고서를 만들고, 내려받기 단추가 있는 결과 화면을 돌려준다.
func (s *Server) askReportMake(sess Session, a *askAnswer, ctx map[string]any) ([]a2, string, int) {
	if !contains(sess.Groups, "admins") {
		return nil, "규제 보고서는 관리자만 만들 수 있습니다", 403
	}
	regions := []string{}
	for _, r := range strList(ctx["regions"]) {
		if _, ok := regRegionKo[r]; ok {
			regions = append(regions, r)
		}
	}
	if len(regions) == 0 {
		return nil, "지역을 하나 이상 고르세요", 400
	}
	one := func(k, def string, allow []string) string {
		if v := strList(ctx[k]); len(v) == 1 && inList(v[0], allow) {
			return v[0]
		}
		return def
	}
	aud := one("audience", "all", append([]string{"all"}, regAudiences...))
	lang := one("lang", "ko", []string{"ko", "en"})
	repo, tag := "", ""
	if p := one("product", "none", a.pending.Keys); p != "none" { // 양식에 있던 제품만
		repo, tag, _ = strings.Cut(p, ":")
		if !s.askCanRead(sess, repo) {
			return nil, "이 제품에 대한 권한이 없습니다", 403
		}
	}
	rep, err := s.makeRegReport(aud, regions, repo, tag, sess.Username, lang, false)
	if err != nil {
		return nil, "보고서를 만들지 못했습니다: " + truncate(err.Error(), 160), 500
	}
	u := &uiBuild{}
	sum := fmt.Sprintf("문서번호 %s · 규제 %d개", rep.DocNo, len(rep.Regs))
	if n := rep.Totals["requirements"]; n > 0 {
		sum += fmt.Sprintf(" · 요구사항 %d개", n)
	}
	if repo != "" {
		sum += " · " + repo + ":" + tag + " 증빙 점검 포함"
	}
	kids := []string{u.text("h", "보고서를 만들었습니다", "h4"), u.text("t", rep.Title, "body"), u.text("s", sum, "caption")}
	u.text("dl_t", "PDF 내려받기", "")
	u.add(a2{"id": "dl", "component": "Button", "variant": "primary", "child": "dl_t",
		"action": a2{"functionCall": a2{"call": "openUrl", "args": a2{"url": "/api/regs-report/" + rep.ID + "/pdf"}}}})
	u.link("open", "보고서함에서 보기", "/admin/reports")
	kids = append(kids, u.add(a2{"id": "btns", "component": "Row", "children": []string{"dl", "open"}}))
	kids = append(kids, u.text("note", "공개 규제 정보를 요약한 참고 자료이며 법률 자문이 아닙니다.", "caption"))
	return u.messages(a.ID, false, kids, nil), rep.ID, 200
}
