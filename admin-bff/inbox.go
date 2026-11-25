package main

// inbox.go: 승인 대기함 — 사람이 결정할 일을 한 곳에(제품 개념: 신호 → 영향 → **결정** → 전달 → 기록).
// 각 항목은 원래 화면으로 바로 간다. 여기서 새로 판단하지 않고, 흩어진 대기열을 모아 보여 준다.
//   - 자동 대응 승인 대기(고객 통지·개발자 수정 요청)
//   - VEX 판단 대기(KEV·치명 먼저, 버전별)
//   - 규제 탐색 새 후보(채택·무시)
//   - 만료 예정(유지보수·라이선스·EOS, 30일 안)
//   - 발송함 대기(보내기 취소 가능)

import (
	"net/http"
	"sort"
	"time"
)

type inboxItem struct {
	Kind   string `json:"kind"` // auto-customer / auto-dev / vex / reg / expiry / outbox
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
	Link   string `json:"link"`
	Urgent bool   `json:"urgent,omitempty"`
	At     string `json:"at,omitempty"`
	Ref    string `json:"ref,omitempty"`
}

type inboxGroup struct {
	Key   string      `json:"key"`
	Label string      `json:"label"`
	Count int         `json:"count"`
	Link  string      `json:"link"`
	Items []inboxItem `json:"items"`
}

// GET /api/inbox
func (s *Server) apiInbox(w http.ResponseWriter, r *http.Request) {
	groups, total := s.inboxGroups()
	writeJSON(w, 200, map[string]any{"groups": groups, "decisions": total, "generated": time.Now().UTC().Format(time.RFC3339)})
}

// inboxGroups: 사람이 결정할 일 묶음과 그 합계(화면과 "묻고 찾기"가 같이 쓴다).
func (s *Server) inboxGroups() ([]inboxGroup, int) {
	groups := []inboxGroup{}

	// ① 자동 대응 승인 대기
	autoRes.Lock()
	autoLoad()
	runs := append([]autoRun(nil), autoRes.Runs...)
	autoRes.Unlock()
	g := inboxGroup{Key: "auto", Label: "메일 보낼지 선택(자동 대응)", Link: "/admin/auto-response", Items: []inboxItem{}}
	for i := len(runs) - 1; i >= 0; i-- {
		x := runs[i]
		if x.State != "waiting" {
			continue
		}
		it := inboxItem{Link: "/admin/auto-response", At: x.Started, Ref: x.ID, Urgent: x.KEV}
		if x.NoticeID != "" {
			it.Kind, it.Title = "auto-customer", "고객 통지 — "+x.VulnID+" · "+x.Component
			it.Detail = "패치 " + x.FixTag + " 권장 → " + joinMax(x.Customers, 3)
		} else {
			it.Kind, it.Title = "auto-dev", "개발자 수정 요청 — "+x.VulnID+" · "+x.Component
			it.Detail = x.Repo + " " + x.Tag + " 패치 없음"
			if len(x.Customers) > 0 {
				it.Detail += " · 사용 고객 " + joinMax(x.Customers, 3)
			}
		}
		g.Count++
		if len(g.Items) < 8 {
			g.Items = append(g.Items, it)
		}
	}
	groups = append(groups, g)

	// ② VEX 판단 대기(대기열 캐시 사용)
	g = inboxGroup{Key: "vex", Label: "취약점 판단(VEX)", Link: "/vex", Items: []inboxItem{}}
	if s.dtEnabled() {
		rows := s.vexQueueRows(false)
		sort.SliceStable(rows, func(i, j int) bool {
			if rows[i].PendKEV != rows[j].PendKEV {
				return rows[i].PendKEV > rows[j].PendKEV
			}
			return rows[i].PendCrit > rows[j].PendCrit
		})
		for _, q := range rows {
			if q.PendKEV == 0 && q.PendCrit == 0 {
				continue
			}
			g.Count += q.PendKEV + q.PendCrit
			if len(g.Items) < 6 {
				g.Items = append(g.Items, inboxItem{Kind: "vex", Title: q.Repo + " " + q.Tag, Link: "/vex",
					Detail: "KEV " + itoa(q.PendKEV) + " · 치명 " + itoa(q.PendCrit) + " 판단 대기", Urgent: q.PendKEV > 0})
			}
		}
	}
	groups = append(groups, g)

	// ③ 규제 탐색 새 후보
	g = inboxGroup{Key: "reg", Label: "규제 후보(채택·무시)", Link: "/admin/regs", Items: []inboxItem{}}
	for _, c := range loadCandidates() {
		if c.State != "new" {
			continue
		}
		g.Count++
		if len(g.Items) < 6 {
			g.Items = append(g.Items, inboxItem{Kind: "reg", Title: truncate(c.Title, 80), Detail: c.Region + " · " + c.Source, Link: "/admin/regs", At: c.FoundAt, Ref: c.ID})
		}
	}
	groups = append(groups, g)

	// ④ 만료 예정(30일 안, 사용 중인 고객)
	g = inboxGroup{Key: "expiry", Label: "만료 예정(30일 안)", Link: "/admin/customers", Items: []inboxItem{}}
	c := s.cust()
	d := c.snapshot()
	var exp []custExpiry
	for _, cu := range activeCustomers(d.Customers) {
		for _, e := range custExpiries(cu, d.Products, c.now()) {
			if e.Days <= 30 {
				exp = append(exp, e)
			}
		}
	}
	sort.Slice(exp, func(i, j int) bool { return exp[i].Days < exp[j].Days })
	kindKo := map[string]string{"license": "라이선스", "maint": "유지보수", "eos": "EOS"}
	for _, e := range exp {
		g.Count++
		if len(g.Items) < 6 {
			dd := "D-" + itoa(e.Days)
			if e.Days < 0 {
				dd = "만료 D+" + itoa(-e.Days)
			}
			g.Items = append(g.Items, inboxItem{Kind: "expiry", Title: e.Customer + " — " + kindKo[e.Kind] + " " + dd, Detail: e.Repo + " " + e.Tag + " · " + e.Date, Link: "/admin/customers", Urgent: e.Days <= 7})
		}
	}
	groups = append(groups, g)

	// ⑤ 발송함 대기(취소 가능)
	// 고객에게 갈 자동 메일(VEX 발행 통보·만료 안내) — 승인해야 나간다
	g = inboxGroup{Key: "hold", Label: "고객에게 보낼 메일 승인", Link: "/admin/outbox", Items: []inboxItem{}}
	for _, h := range holdWaiting() {
		g.Count++
		if len(g.Items) < 6 {
			g.Items = append(g.Items, inboxItem{Kind: "hold", Title: firstNonEmpty(h.Label, h.Subject), Detail: "→ " + joinMax(h.Recipients, 2), Link: "/admin/outbox", At: h.CreatedAt, Ref: h.ID})
		}
	}
	groups = append(groups, g)

	outbox.Lock()
	outboxLoad()
	items := append([]outboxItem(nil), outbox.items...)
	outbox.Unlock()
	g = inboxGroup{Key: "outbox", Label: "보내기 대기(취소 가능)", Link: "/admin/outbox", Items: []inboxItem{}}
	for _, it := range items {
		if it.Status == "pending" {
			g.Count++
			g.Items = append(g.Items, inboxItem{Kind: "outbox", Title: firstNonEmpty(it.Label, it.Subject), Detail: "→ " + joinMax(it.Recipients, 2) + " · " + it.SendAt, Link: "/admin/outbox", Ref: it.ID})
		}
	}
	groups = append(groups, g)

	total := 0
	for _, x := range groups {
		if x.Key != "vex" { // VEX 판단 대기는 건수가 커서 합계에서 따로
			total += x.Count
		}
	}
	return groups, total
}

func joinMax(l []string, n int) string {
	if len(l) <= n {
		return joinComma(l)
	}
	return joinComma(l[:n]) + " 외 " + itoa(len(l)-n)
}

func joinComma(l []string) string {
	out := ""
	for i, x := range l {
		if i > 0 {
			out += ", "
		}
		out += x
	}
	return out
}
