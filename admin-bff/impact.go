package main

// impact.go: 영향 지도 — 취약점 하나가 구성요소 → 출고한 버전 → 고객으로 번지는 모습을 그릴 자료.
// 화면은 이것을 네 줄(취약점·구성요소·버전·고객)로 그리고, 시간 순서(발견 → 판정 → 통지)로 되감아 보여 준다.
// 권한: 질문한 사람이 볼 수 있는 제품만. 고객은 관리자에게만 보인다.

import (
	"net/http"
	"path"
	"sort"
	"strings"
	"time"
)

type impactNode struct {
	ID    string `json:"id"`
	Type  string `json:"type"` // vuln / component / version / safe(이 취약점이 없는 버전) / customer
	Label string `json:"label"`
	Sub   string `json:"sub,omitempty"`
	State string `json:"state,omitempty"` // 버전: pending / affected / not_affected · 고객: notified / pending
	Link  string `json:"link,omitempty"`
}

type impactEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type impactStep struct {
	Key   string `json:"key"` // shipped / found / judged / notified
	Label string `json:"label"`
	At    string `json:"at,omitempty"`
	Text  string `json:"text"`
}

const impactMaxVersions = 14

// GET /api/impact?vuln=CVE-…
func (s *Server) apiImpact(w http.ResponseWriter, r *http.Request) {
	id := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("vuln")))
	if !askVulnRe.MatchString(id) {
		writeJSON(w, 400, map[string]string{"error": "취약점 번호(CVE-… 또는 GHSA-…)를 주세요"})
		return
	}
	sess, _ := s.sessionOf(r)
	if !canEditVex(sess) && !contains(sess.Groups, "admins") { // 고객 계정에는 내부 제품 지도를 보이지 않는다
		writeJSON(w, 403, map[string]string{"error": "영향 지도는 보안·개발 담당과 관리자만 볼 수 있습니다"})
		return
	}
	hits := s.askHits(sess, id)
	out := map[string]any{"vulnId": id, "kev": isKEV([]string{id}), "nodes": []impactNode{}, "edges": []impactEdge{}, "steps": []impactStep{}}
	if len(hits) == 0 {
		out["empty"] = id + " 은(는) 권한이 있는 제품·버전에서 발견되지 않았습니다."
		writeJSON(w, 200, out)
		return
	}
	more := 0
	if len(hits) > impactMaxVersions {
		more = len(hits) - impactMaxVersions
		hits = hits[:impactMaxVersions]
	}
	nodes := []impactNode{{ID: "vuln", Type: "vuln", Label: id, Sub: hits[0].Severity}}
	if out["kev"].(bool) {
		nodes[0].Sub += " · 실제 악용"
	}
	edges := []impactEdge{}
	seen := map[string]bool{}
	add := func(n impactNode) {
		if !seen[n.ID] {
			seen[n.ID] = true
			nodes = append(nodes, n)
		}
	}
	found, pend, aff := int64(0), 0, 0
	repos, hitTags := []string{}, map[string]bool{}
	for _, h := range hits {
		cid, vid := "c:"+h.Component, "v:"+h.Repo+":"+h.Tag
		add(impactNode{ID: cid, Type: "component", Label: h.Component})
		st := "pending"
		switch strings.ToUpper(h.State) {
		case "EXPLOITABLE":
			st = "affected"
			aff++
		case "NOT_AFFECTED", "FALSE_POSITIVE", "RESOLVED":
			st = "not_affected"
		default:
			pend++
		}
		lab, _ := askStateKo(h.State)
		add(impactNode{ID: vid, Type: "version", Label: path.Base(h.Repo) + " " + h.Tag, Sub: lab, State: st, Link: artifactLink(h.Repo, h.Tag)})
		edges = append(edges, impactEdge{"vuln", cid}, impactEdge{cid, vid})
		hitTags[h.Repo+":"+h.Tag] = true
		if !inList(h.Repo, repos) {
			repos = append(repos, h.Repo)
		}
		if h.Found > 0 && (found == 0 || h.Found < found) {
			found = h.Found
		}
	}
	// 같은 제품에서 이 취약점이 없는 버전(수정 버전이거나 영향 범위 밖) — 제품마다 가장 최근 둘
	safe := 0
	for _, repo := range repos {
		tags := []string{}
		for _, row := range s.vexQueueRows(false) {
			if row.Repo == repo && !hitTags[repo+":"+row.Tag] {
				tags = append(tags, row.Tag)
			}
		}
		sort.Sort(sort.Reverse(sort.StringSlice(tags)))
		for i, t := range tags {
			if i == 2 {
				break
			}
			safe++
			add(impactNode{ID: "s:" + repo + ":" + t, Type: "safe", Label: path.Base(repo) + " " + t, Sub: "이 취약점 없음", Link: artifactLink(repo, t)})
		}
	}
	// 고객(관리자만): 영향 버전을 설치한 곳, 그리고 이 취약점으로 통지를 받은 곳
	notified, sentAt, custN := map[string]bool{}, "", 0
	if contains(sess.Groups, "admins") {
		d := s.cust().snapshot()
		for _, n := range d.Notices {
			if !strings.EqualFold(n.VulnID, id) {
				continue
			}
			for _, t := range n.Targets {
				if t.Result != nil && len(t.Result.Sent) > 0 {
					notified[t.CustomerID] = true
					if t.Result.At > sentAt {
						sentAt = t.Result.At
					}
				}
			}
		}
		for _, c := range activeCustomers(d.Customers) {
			for _, u := range c.Usages {
				for _, in := range u.Installs {
					if !hitTags[u.Repo+":"+in.Tag] {
						continue
					}
					kid := "k:" + c.ID
					if !seen[kid] {
						custN++
						st, sub := "pending", "통지 전"
						if notified[c.ID] {
							st, sub = "notified", "통지 보냄"
						}
						add(impactNode{ID: kid, Type: "customer", Label: c.Name, Sub: sub, State: st, Link: "/admin/customers"})
					}
					edges = append(edges, impactEdge{"v:" + u.Repo + ":" + in.Tag, kid})
				}
			}
		}
	}
	// 시간 순서
	day := func(ms int64) string {
		if ms <= 0 {
			return ""
		}
		return time.UnixMilli(ms).In(kst).Format("2006-01-02")
	}
	steps := []impactStep{{Key: "shipped", Label: "출고 상태", Text: "버전 " + itoa(len(hits)) + "개가 등록돼 있습니다. 이때는 아무 문제도 보이지 않습니다."}}
	ft := "출고한 버전까지 다시 대조해 " + itoa(len(hits)) + "개 버전에서 찾았습니다."
	if custN > 0 {
		ft += " 이 버전을 설치한 고객은 " + itoa(custN) + "곳입니다."
	}
	steps = append(steps, impactStep{Key: "found", Label: "취약점 발견", At: day(found), Text: ft})
	jt := "판단 대기 " + itoa(pend) + "건, 영향 있음 " + itoa(aff) + "건."
	if safe > 0 {
		jt += " 같은 제품에 이 취약점이 없는 버전이 " + itoa(safe) + "개 있습니다."
	}
	steps = append(steps, impactStep{Key: "judged", Label: "판정·수정 버전", Text: jt})
	if len(notified) > 0 {
		steps = append(steps, impactStep{Key: "notified", Label: "고객 통지", At: firstNonEmpty(sentAt, "")[:min(10, len(sentAt))], Text: "고객 " + itoa(len(notified)) + "곳에 보안 권고를 보냈습니다."})
	}
	out["nodes"], out["edges"], out["steps"], out["more"] = nodes, edges, steps, more
	out["canCustomers"] = contains(sess.Groups, "admins")
	writeJSON(w, 200, out)
}
