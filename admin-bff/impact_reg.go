package main

// impact_reg.go: 규제 영향 지도 — 규제 하나가 어느 고객에게 해당될 수 있고, 그 고객이 쓰는 우리 제품이 무엇인지 그린다.
//
//   GET /api/impact/reg          고를 수 있는 규제 목록
//   GET /api/impact/reg?id=…     규제 → 해당 가능 고객 → 그 고객이 쓰는 제품 (+ 요구사항 목록)
//
// "해당"은 법적 판단이 아니라 추정이다. 고객 등록부의 국가·업종과 규제의 지역·시장을 맞춰 "해당 가능"으로만 표시한다.
// 고객 등록부를 쓰므로 관리자 전용이다.

import (
	"fmt"
	"net/http"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// 고객 등록부의 국가는 자유 입력이라 흔한 표기를 모두 본다. 비어 있으면 국내(KR)로 본다.
var regCountryAlias = map[string][]string{
	"US": {"us", "usa", "u.s", "미국", "united states", "america"},
	"EU": {"eu", "유럽", "europe", "독일", "germany", "프랑스", "france", "이탈리아", "italy", "스페인", "spain", "네덜란드", "netherlands", "폴란드", "poland", "스웨덴", "sweden", "벨기에", "belgium", "오스트리아", "austria", "아일랜드", "ireland", "핀란드", "finland", "덴마크", "denmark", "체코", "포르투갈"},
	"JP": {"jp", "일본", "japan"},
	"KR": {"kr", "한국", "대한민국", "korea"},
	"UK": {"uk", "영국", "united kingdom", "britain"},
	"IN": {"in", "인도", "india"},
}

// 규제의 시장 표시 → 고객 업종(등록부의 값). 없으면 업종으로는 거르지 않는다.
var regMarketIndustry = map[string][]string{
	"us_def": {"방산"}, "us_med": {"의료"}, "us_fed": {"공공"}, "kr_pub": {"공공"}, "kr_fin": {"금융"},
}

func custRegion(country string) string {
	c := strings.ToLower(strings.TrimSpace(country))
	if c == "" {
		return "KR"
	}
	for region, names := range regCountryAlias {
		for _, n := range names {
			if c == n || (len(n) > 2 && strings.Contains(c, n)) {
				return region
			}
		}
	}
	return ""
}

// regApplies: 이 규제가 그 고객에게 해당될 수 있는가, 그리고 그렇게 본 근거.
func regApplies(g regulation, cu Customer) (bool, string) {
	region := custRegion(cu.Country)
	if strings.TrimSpace(cu.Country) == "" && cu.Industry == "해외" { // 국가를 적지 않은 해외 고객은 어느 지역인지 알 수 없다
		region = ""
	}
	if g.Region != "INTL" && region != g.Region {
		return false, ""
	}
	why := "국가 " + firstNonEmpty(strings.TrimSpace(cu.Country), "미지정(국내로 봄)")
	if g.Region == "INTL" {
		why = "국제 기준"
	}
	inds := []string{}
	for _, m := range g.Markets {
		inds = append(inds, regMarketIndustry[m]...)
	}
	if len(inds) > 0 {
		if !inList(cu.Industry, inds) {
			return false, ""
		}
		why += " · 업종 " + cu.Industry
	}
	return true, why
}

// GET /api/impact/reg[?id=]
func (s *Server) apiImpactReg(w http.ResponseWriter, r *http.Request) {
	regMu.Lock()
	cat, err := loadCatalog()
	regMu.Unlock()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "규제 카탈로그를 읽지 못했습니다"})
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		list := []map[string]any{}
		for _, g := range cat.Regulations {
			list = append(list, map[string]any{"id": g.ID, "name": firstNonEmpty(g.NameKo, g.Name), "region": firstNonEmpty(regRegionKo[g.Region], g.Region), "reqs": len(g.Requirements)})
		}
		writeJSON(w, 200, map[string]any{"regs": list})
		return
	}
	var g *regulation
	for i := range cat.Regulations {
		if cat.Regulations[i].ID == id {
			g = &cat.Regulations[i]
		}
	}
	if g == nil {
		writeJSON(w, 404, map[string]string{"error": "카탈로그에 없는 규제입니다"})
		return
	}
	name := firstNonEmpty(g.NameKo, g.Name)
	nodes := []impactNode{{ID: "reg", Type: "reg", Label: name, Sub: firstNonEmpty(regRegionKo[g.Region], g.Region) + " · 요구사항 " + itoa(len(g.Requirements)) + "건", Link: "/admin/regs"}}
	edges := []impactEdge{}
	reqs := []map[string]string{}
	for _, q := range g.Requirements {
		reqs = append(reqs, map[string]string{"clause": q.Clause, "title": q.Title})
	}
	// 해당 가능 고객 → 그 고객이 쓰는 제품
	prods, custN := map[string]int{}, 0
	for _, cu := range activeCustomers(s.cust().snapshot().Customers) {
		ok, why := regApplies(*g, cu)
		if !ok {
			continue
		}
		custN++
		if custN > impactMaxVersions {
			continue
		}
		cid := "k:" + cu.ID
		nodes = append(nodes, impactNode{ID: cid, Type: "customer", Label: cu.Name, Sub: "해당 가능 · " + why, State: "pending", Link: "/admin/customers"})
		edges = append(edges, impactEdge{From: "reg", To: cid})
		for _, u := range cu.Usages {
			prods[u.Repo]++
			edges = append(edges, impactEdge{From: cid, To: "p:" + u.Repo})
		}
	}
	repos := make([]string, 0, len(prods))
	for repo := range prods {
		repos = append(repos, repo)
	}
	sort.Strings(repos)
	for _, repo := range repos {
		nodes = append(nodes, impactNode{ID: "p:" + repo, Type: "product", Label: path.Base(repo), Sub: fmt.Sprintf("해당 가능 고객 %d곳이 사용", prods[repo]), State: "pending", Link: "/artifacts"})
	}
	// 이 지역으로 만든 규제 보고서
	reports := 0
	for _, rep := range regReportList(60) {
		if len(rep.Regions) == 0 || inList(g.Region, rep.Regions) {
			reports++
		}
	}
	steps := []impactStep{
		{Key: "shipped", Label: "카탈로그의 규제", Text: fmt.Sprintf("%s — %s. 요구사항 %d건.", name, firstNonEmpty(g.Status, "상태 미기재"), len(g.Requirements))},
		{Key: "found", Label: "해당 가능 고객", Text: fmt.Sprintf("고객 등록부의 국가·업종으로 맞춰 보면 고객 %d곳이 해당될 수 있습니다. 법적 판단이 아니라 추정입니다.", custN)},
		{Key: "judged", Label: "그 고객이 쓰는 제품", Text: fmt.Sprintf("해당 가능 고객이 쓰는 우리 제품은 %d개입니다. 이 제품들이 요구사항의 증빙을 갖췄는지는 규제 보고서에서 점검합니다.", len(repos))},
		{Key: "notified", Label: "보고서", Text: fmt.Sprintf("이 지역을 포함해 만든 규제 보고서가 %d건 있습니다(보고서함).", reports)},
	}
	out := map[string]any{"kind": "reg", "regId": g.ID, "title": name, "nodes": nodes, "edges": edges, "steps": steps, "reqs": reqs, "canCustomers": true,
		"cols": []map[string]any{{"title": "규제", "types": []string{"reg"}}, {"title": "해당 가능 고객", "types": []string{"customer"}}, {"title": "그 고객이 쓰는 제품", "types": []string{"product"}}}}
	if custN > impactMaxVersions {
		out["more"] = custN - impactMaxVersions
	}
	if custN == 0 {
		out["empty"] = name + " 에 해당될 수 있는 고객이 등록부에 없습니다. 고객의 국가·업종을 확인해 보세요."
	}
	writeJSON(w, 200, out)
}

// regReportList: 최근 규제 보고서(머리 정보만).
func regReportList(max int) []regReport {
	files, _ := filepath.Glob(filepath.Join(regDir(), "reports", "rr-*.json"))
	sort.Sort(sort.Reverse(sort.StringSlice(files)))
	out := []regReport{}
	for i, f := range files {
		if i >= max {
			break
		}
		var rep regReport
		if readJSONFile(f, &rep) == nil {
			out = append(out, rep)
		}
	}
	return out
}
