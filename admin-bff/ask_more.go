package main

// ask_more.go: 묻고 찾기가 받는 질문을 넓힌다.
//   ⑤ 사용법·용어   "VEX 가 뭐야?", "SBOM 어떻게 올려?"      → 도움말 표에서 답(누구나)
//   ⑥ 현황          "취약점 몇 건이야?", "전체 현황"          → 권한이 있는 제품의 집계
//   ⑦ 실제 악용     "KEV 있어?", "급한 것부터"                → 실제 악용 취약점이 남은 제품·버전
//   ⑧ 제품          "example-app 상태는?"                     → 그 제품의 버전별 판단 대기
//   ⑨ 고객(관리자)  "알파은행은 뭘 쓰나?", "만료 임박 고객"    → 고객 등록부
//   ⑩ 그 밖         위에 맞지 않는 질문                        → 현황과 도움말을 근거로 AI 가 답해 본다(AI 연결이 켜져 있을 때)
// 질문의 종류는 역할로 막지 않는다. 다만 답에 넣는 자료는 질문한 사람이 화면에서 볼 수 있는 범위 그대로다
// (고객은 자기 설치 버전, 개발자는 읽기 권한이 있는 제품, 고객 등록부는 관리자).

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	askHowRe    = regexp.MustCompile(`뭐야|뭔가|무엇|뭐지|뜻|의미|이란|란\?|방법|어떻게|어디서|설명|알려|차이|왜`)
	askStatRe   = regexp.MustCompile(`현황|요약|통계|몇 ?건|몇 ?개|얼마나|전체|상황|상태`)
	askKevRe    = regexp.MustCompile(`(?i)kev|실제 ?악용|악용|급한|긴급|위험한|치명`)
	askCustRe   = regexp.MustCompile(`고객|거래처|납품처|계약|만료|유지보수`)
	askExpireRe = regexp.MustCompile(`만료|끝나|갱신|유지보수`)
)

var askMcpRe = regexp.MustCompile(`(?i)mcp|클로드|claude|ai ?도구|커넥터|연결 ?토큰`)

// AI 도구 연결(MCP) — 설정 순서를 그대로 답한다. 화면: /mcp
func askMcpHelp() *askAnswer {
	a := &askAnswer{Intent: "howto", Title: "AI 도구에 TrustLink 연결하기(MCP)", Sources: []string{"TrustLink 도움말"},
		Lead: "Claude 같은 AI 도구에 TrustLink 를 연결하면, 그 도구 안에서 취약점 영향과 현황을 바로 물을 수 있습니다. 'AI 도구 연결' 화면에서 토큰을 만들고 명령 한 줄을 붙여 넣으면 됩니다."}
	for _, r := range []askRow{
		{Title: "1. 'AI 도구 연결' 화면 열기", Detail: "사이드바 › 제품·릴리스 › AI 도구 연결", Link: "/mcp"},
		{Title: "2. 연결 토큰 만들기", Detail: "이름과 기한을 정하고 만듭니다. 값은 만든 직후 한 번만 보입니다."},
		{Title: "3. 명령 복사해 붙여 넣기", Detail: "Claude Code 는 터미널에 한 줄, Claude Desktop 은 설정 파일에 한 덩어리. 화면에 토큰이 채워진 채로 나옵니다."},
		{Title: "4. AI 도구에서 묻기", Detail: "예: 'TrustLink 에서 CVE-2026-1234 가 어디에 걸리는지 찾아 줘', '급한 취약점부터 정리해 줘'"},
		{Title: "알아 둘 점", Detail: "조회만 됩니다(보내기·저장 없음). 답은 내 권한 범위 그대로이고, 물은 내용은 감사 원장에 남습니다. 토큰은 같은 화면에서 언제든 끊을 수 있습니다."},
	} {
		a.Rows = append(a.Rows, r)
		a.facts = append(a.facts, aiFact{ID: fmt.Sprintf("K%d", len(a.facts)+1), Text: r.Title + " — " + r.Detail})
	}
	return a
}

type askTopic struct {
	Keys []string // 질문에 이 낱말이 있으면 이 주제(소문자)
	Name string
	Text string
	Link string
}

// 도움말 표 — 화면의 "문서"와 같은 내용을 짧게. 제품 동작이 바뀌면 함께 고친다.
var askTopics = []askTopic{
	{[]string{"sbom", "구성요소 목록", "부품 목록"}, "SBOM", "SBOM 은 소프트웨어에 든 구성요소(라이브러리)와 버전의 목록입니다. 제품 버전을 올릴 때 함께 올리면 TrustLink 가 취약점 DB 와 대조합니다.", "/docs/vuln"},
	{[]string{"vex"}, "VEX", "VEX 는 '이 취약점이 우리 제품에 실제로 영향이 있는가'에 대한 판단 문서입니다. 영향 있음·영향 없음·조사 중으로 적고, 최종 판단은 사람이 저장합니다.", "/docs/vuln"},
	{[]string{"kev", "실제 악용"}, "KEV", "KEV 는 실제 공격에 쓰인 것이 확인된 취약점 목록입니다. TrustLink 는 KEV 에 든 취약점을 가장 급한 것으로 올려 보여 줍니다.", "/docs/vuln"},
	{[]string{"epss"}, "EPSS", "EPSS 는 그 취약점이 가까운 시일 안에 악용될 가능성을 0~1 로 추정한 점수입니다. 등급(치명·높음)과 함께 급한 순서를 정하는 데 씁니다.", "/docs/vuln"},
	{[]string{"올리", "업로드", "push", "등록 방법"}, "제품 올리기", "제품 버전과 SBOM 은 '문서 > 업로드·다운로드'의 명령으로 올립니다. 올리려면 그 제품에 쓰기 권한과 API 키가 필요합니다.", "/docs/share"},
	{[]string{"내려받", "다운로드", "pull", "받아"}, "내려받기", "권한이 있는 제품은 '아티팩트'에서 버전을 열어 SBOM·VEX 를 내려받거나, '문서 > 업로드·다운로드'의 명령으로 받습니다.", "/docs/share"},
	{[]string{"api 키", "api키", "apikey", "토큰"}, "API 키", "'내 API 키'에서 만듭니다. 명령줄이나 CI 에서 비밀번호 대신 쓰며, 만든 직후에만 값을 볼 수 있습니다.", "/apikeys"},
	{[]string{"권한", "역할", "접근"}, "권한", "관리자는 전체를, 개발자는 권한이 있는 제품을, 고객 계정은 자기 회사가 받은 제품만 봅니다. 자세한 표는 '문서 > 권한·참고'에 있습니다.", "/docs/rbac"},
	{[]string{"자동 대응", "자동대응"}, "자동 대응", "새 취약점이 잡히면 영향 분석과 수정 버전 확인까지 자동으로 하고, 고객 통지나 개발자 수정 요청은 관리자가 승인해야 나갑니다.", "/admin/auto-response"},
	{[]string{"영향 지도", "영향지도"}, "영향 지도", "취약점 하나가 구성요소, 출고한 버전, 고객으로 번지는 모습을 그림으로 보여 줍니다. 취약점 번호를 물은 뒤 '영향 지도 보기'로 엽니다.", "/impact"},
	{[]string{"승인 대기", "대기함"}, "승인 대기함", "사람이 결정해야 하는 일(자동 대응 승인, 규제 후보, 계약 만료, 발송 대기)을 한 화면에 모은 곳입니다.", "/admin/inbox"},
	{[]string{"발송함", "취소", "회수", "다시 보내"}, "발송함", "고객 메일은 발송함에서 잠깐 기다렸다가 나갑니다. 기다리는 동안 취소할 수 있고, 실패한 최근 메일은 다시 보낼 수 있습니다.", "/admin/outbox"},
	{[]string{"규제", "보고서", "cra", "cmmc"}, "규제 보고서", "지역과 읽는 사람, 제품을 고르면 규제 카탈로그와 그 제품의 증빙으로 보고서를 만듭니다. '미국 수출 규제 보고서 만들어 줘'처럼 시킬 수 있습니다. 법률 자문은 아닙니다.", "/admin/reports"},
	{[]string{"일괄", "ai 판정", "판정 초안"}, "AI 일괄 판정", "'VEX 판단'에서 제품별로 걸면 규칙으로 초안을 먼저 만들고 AI 가 요약을 덧붙입니다. 초안일 뿐이며 저장은 사람이 합니다.", "/vex"},
	{[]string{"내 제품"}, "내 제품", "고객 계정이 자기 회사가 설치한 버전의 취약점과 권장 버전을 보는 화면입니다.", "/my"},
	{[]string{"mcp", "ai 도구", "클로드", "claude"}, "AI 도구 연결(MCP)", "Claude 같은 AI 도구에 TrustLink 를 연결해 그 도구 안에서 바로 묻는 기능입니다. 'AI 도구 연결'에서 토큰을 만들어 등록하며, 조회만 됩니다.", "/mcp"},
	{[]string{"휴대폰", "모바일", "핸드폰"}, "휴대폰", "같은 주소를 휴대폰 브라우저로 열면 됩니다. 메뉴는 왼쪽 위 단추로 열고, 큰 표는 옆으로 밀어서 봅니다.", ""},
	{[]string{"뭘 물어", "무엇을 물어", "할 수 있", "도움말", "사용법", "기능"}, "묻고 찾기", "취약점 번호, 구성요소 이름, 제품 이름, 현황, 실제 악용 취약점, 할 일, 용어와 사용법을 물을 수 있습니다. 관리자는 고객과 계약 만료도 물을 수 있고, 통지 초안·VEX 판정·규제 보고서를 시킬 수 있습니다.", ""},
}

func askTopicHits(q string) []askTopic {
	lq := strings.ToLower(q)
	out := []askTopic{}
	for _, t := range askTopics {
		for _, k := range t.Keys {
			if strings.Contains(lq, k) {
				out = append(out, t)
				break
			}
		}
	}
	return out
}

// askMore: 네 가지 기본 질문에 맞지 않을 때 ⑤~⑨ 를 차례로 본다. 맞는 것이 없으면 nil.
func (s *Server) askMore(sess Session, q string, mine []myCustomer, isCustomer bool) *askAnswer {
	admin := contains(sess.Groups, "admins")
	topics := askTopicHits(q)
	if askMcpRe.MatchString(q) { // AI 도구 연결(MCP) 설정 안내
		return askMcpHelp()
	}
	if len(topics) > 0 && askHowRe.MatchString(q) { // ⑤ 사용법·용어
		return askHowto(topics)
	}
	if admin { // ⑨ 고객 이름이 질문에 있으면(관리자)
		for _, c := range activeCustomers(s.cust().snapshot().Customers) {
			if len([]rune(c.Name)) >= 2 && strings.Contains(strings.ToLower(q), strings.ToLower(c.Name)) {
				return s.askCustomer(q)
			}
		}
	}
	if askCustRe.MatchString(q) && !isCustomer { // ⑨ 고객
		if !admin {
			return &askAnswer{Intent: "customer", Title: "고객 정보", Lead: "고객 등록부는 관리자만 볼 수 있어 답하지 못합니다. 관리자에게 물어보세요.", Sources: []string{}}
		}
		return s.askCustomer(q)
	}
	if !isCustomer && s.dtEnabled() {
		if a := s.askProduct(sess, q); a != nil { // ⑧ 제품 이름
			return a
		}
		if askKevRe.MatchString(q) { // ⑦ 실제 악용
			return s.askUrgent(sess)
		}
		if askStatRe.MatchString(q) { // ⑥ 현황
			return s.askStatus(sess)
		}
	}
	if isCustomer && (askKevRe.MatchString(q) || askStatRe.MatchString(q)) {
		return askMine(mine)
	}
	if len(topics) > 0 {
		return askHowto(topics)
	}
	return nil
}

func askHowto(topics []askTopic) *askAnswer {
	a := &askAnswer{Intent: "howto", Title: topics[0].Name, Lead: topics[0].Text, Sources: []string{"TrustLink 도움말"}}
	for i, t := range topics {
		if i > 0 && len(a.Rows) < 4 {
			a.Rows = append(a.Rows, askRow{Title: t.Name, Detail: t.Text, Link: t.Link})
		}
		a.facts = append(a.facts, aiFact{ID: fmt.Sprintf("K%d", i+1), Text: t.Name + ": " + t.Text})
	}
	if topics[0].Link != "" {
		a.Rows = append([]askRow{{Title: topics[0].Name + " 화면·문서 열기", Link: topics[0].Link}}, a.Rows...)
	}
	return a
}

func (s *Server) askVisibleRows(sess Session) []vexQueueRow {
	out := []vexQueueRow{}
	for _, r := range s.vexQueueRows(false) {
		if s.askCanRead(sess, r.Repo) {
			out = append(out, r)
		}
	}
	return out
}

// ⑥ 현황 — 권한이 있는 제품의 집계
func (s *Server) askStatus(sess Session) *askAnswer {
	a := &askAnswer{Intent: "status", Title: "지금 현황", Sources: []string{"취약점 분석(권한이 있는 제품·버전)"}}
	rows := s.askVisibleRows(sess)
	repos, total, pend, crit, high, kev, aff := map[string]bool{}, 0, 0, 0, 0, 0, 0
	for _, r := range rows {
		repos[r.Repo] = true
		total, pend, crit, high, kev, aff = total+r.Total, pend+r.Pending, crit+r.PendCrit, high+r.PendHigh, kev+r.PendKEV, aff+r.Affected
	}
	if len(rows) == 0 {
		a.Lead = "권한이 있는 제품 가운데 분석된 것이 없습니다."
		return a
	}
	a.Lead = fmt.Sprintf("제품 %d개, 버전 %d개를 감시하고 있습니다. 취약점 %d건 가운데 판단 대기 %d건(실제 악용 %d · 치명 %d · 높음 %d), 영향 있음으로 판정한 것 %d건.", len(repos), len(rows), total, pend, kev, crit, high, aff)
	a.facts = []aiFact{{ID: "F1", Text: a.Lead}}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Pending > rows[j].Pending })
	for _, r := range rows {
		if r.Pending == 0 || len(a.Rows) >= 6 {
			continue
		}
		d := fmt.Sprintf("판단 대기 %d건 / 전체 %d건", r.Pending, r.Total)
		a.Rows = append(a.Rows, askRow{Title: r.Repo + ":" + r.Tag, Detail: d, Link: artifactLink(r.Repo, r.Tag), Tone: map[bool]string{true: "crit", false: "warn"}[r.PendKEV > 0]})
		a.facts = append(a.facts, aiFact{ID: fmt.Sprintf("S%d", len(a.Rows)), Text: r.Repo + ":" + r.Tag + " — " + d})
	}
	return a
}

// ⑦ 실제 악용 취약점이 남은 곳
func (s *Server) askUrgent(sess Session) *askAnswer {
	a := &askAnswer{Intent: "urgent", Title: "급한 것부터", Sources: []string{"취약점 분석(권한이 있는 제품·버전)", "내부 취약점 DB(KEV)"}}
	rows := s.askVisibleRows(sess)
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].PendKEV != rows[j].PendKEV {
			return rows[i].PendKEV > rows[j].PendKEV
		}
		return rows[i].PendCrit > rows[j].PendCrit
	})
	kev, n := 0, 0
	for _, r := range rows {
		if r.PendKEV == 0 && r.PendCrit == 0 {
			continue
		}
		n++
		kev += r.PendKEV
		if len(a.Rows) < askMaxRows {
			d := fmt.Sprintf("실제 악용 %d건 · 치명 %d건 판단 대기", r.PendKEV, r.PendCrit)
			a.Rows = append(a.Rows, askRow{Title: r.Repo + ":" + r.Tag, Detail: d, Link: artifactLink(r.Repo, r.Tag), Tone: map[bool]string{true: "crit", false: "warn"}[r.PendKEV > 0]})
			if len(a.facts) < 6 {
				a.facts = append(a.facts, aiFact{ID: fmt.Sprintf("F%d", len(a.facts)+1), Text: r.Repo + ":" + r.Tag + " — " + d})
			}
		}
	}
	a.More = n - len(a.Rows)
	if n == 0 {
		a.Lead = "판단을 기다리는 실제 악용·치명 취약점이 없습니다."
	} else {
		a.Lead = fmt.Sprintf("제품·버전 %d개에 급한 취약점이 남아 있습니다. 실제 악용이 확인된 것은 %d건입니다.", n, kev)
	}
	return a
}

// ⑧ 제품 이름이 질문에 들어 있으면 그 제품의 버전별 상태
func (s *Server) askProduct(sess Session, q string) *askAnswer {
	lq := strings.ToLower(q)
	rows, best := s.askVisibleRows(sess), ""
	for _, r := range rows {
		if b := strings.ToLower(path.Base(r.Repo)); len(b) >= 3 && strings.Contains(lq, b) && len(r.Repo) > len(best) {
			best = r.Repo
		}
	}
	if best == "" {
		return nil
	}
	a := &askAnswer{Intent: "product", Title: best + " 의 상태", Sources: []string{"취약점 분석(이 제품의 버전)"}}
	n, pend, kev := 0, 0, 0
	for _, r := range rows {
		if r.Repo != best {
			continue
		}
		n++
		pend, kev = pend+r.Pending, kev+r.PendKEV
		if len(a.Rows) < askMaxRows {
			d := fmt.Sprintf("취약점 %d건 · 판단 대기 %d건(실제 악용 %d · 치명 %d) · 영향 있음 %d건", r.Total, r.Pending, r.PendKEV, r.PendCrit, r.Affected)
			tone := "ok"
			if r.PendKEV > 0 {
				tone = "crit"
			} else if r.Pending > 0 {
				tone = "warn"
			}
			a.Rows = append(a.Rows, askRow{Title: r.Tag, Detail: d, Link: artifactLink(r.Repo, r.Tag), Tone: tone})
			if len(a.facts) < 6 {
				a.facts = append(a.facts, aiFact{ID: fmt.Sprintf("F%d", len(a.facts)+1), Text: r.Repo + ":" + r.Tag + " — " + d})
			}
		}
	}
	a.More = n - len(a.Rows)
	a.Lead = fmt.Sprintf("%s 은(는) 버전 %d개가 분석돼 있고, 판단 대기 취약점이 %d건(실제 악용 %d건)입니다.", best, n, pend, kev)
	return a
}

// ⑨ 고객(관리자) — 이름이 있으면 그 고객, 만료를 물으면 90일 안에 끝나는 계약, 아니면 목록
func (s *Server) askCustomer(q string) *askAnswer {
	a := &askAnswer{Intent: "customer", Title: "고객", Sources: []string{"고객 등록부"}}
	cs := activeCustomers(s.cust().snapshot().Customers)
	for _, c := range cs {
		if len([]rune(c.Name)) < 2 || !strings.Contains(strings.ToLower(q), strings.ToLower(c.Name)) {
			continue
		}
		a.Title = c.Name
		for _, u := range c.Usages {
			tags := []string{}
			for _, in := range u.Installs {
				tags = append(tags, in.Tag)
			}
			d := "설치 버전 " + strings.Join(tags, ", ")
			if u.MaintExpiry != "" {
				d += " · 유지보수 만료 " + u.MaintExpiry
			}
			a.Rows = append(a.Rows, askRow{Title: u.Repo, Detail: d, Link: "/admin/customers"})
			a.facts = append(a.facts, aiFact{ID: fmt.Sprintf("F%d", len(a.facts)+1), Text: c.Name + " — " + u.Repo + " " + d})
		}
		a.Lead = fmt.Sprintf("%s 은(는) 제품 %d개를 쓰고 있습니다.", c.Name, len(c.Usages))
		return a
	}
	if askExpireRe.MatchString(q) {
		a.Title = "곧 만료되는 계약"
		now := s.cust().now()
		limit := now.AddDate(0, 0, 90).Format("2006-01-02")
		today := now.Format("2006-01-02")
		for _, c := range cs {
			for _, u := range c.Usages {
				for _, e := range [][2]string{{"유지보수", u.MaintExpiry}, {"라이선스", u.LicenseExpiry}} {
					if _, err := time.Parse("2006-01-02", e[1]); err != nil || e[1] > limit {
						continue
					}
					tone, d := "warn", e[0]+" 만료 "+e[1]
					if e[1] < today {
						tone, d = "crit", e[0]+" 만료됨 "+e[1]
					}
					a.Rows = append(a.Rows, askRow{Title: c.Name + " — " + path.Base(u.Repo), Detail: d, Link: "/admin/customers", Tone: tone})
				}
			}
		}
		sort.SliceStable(a.Rows, func(i, j int) bool {
			return a.Rows[i].Detail[strings.LastIndex(a.Rows[i].Detail, " "):] < a.Rows[j].Detail[strings.LastIndex(a.Rows[j].Detail, " "):]
		})
		if len(a.Rows) > askMaxRows {
			a.More, a.Rows = len(a.Rows)-askMaxRows, a.Rows[:askMaxRows]
		}
		a.Lead = fmt.Sprintf("90일 안에 끝나거나 이미 끝난 계약이 %d건 있습니다.", len(a.Rows)+a.More)
		for i, r := range a.Rows {
			if i < 6 {
				a.facts = append(a.facts, aiFact{ID: fmt.Sprintf("F%d", i+1), Text: r.Title + " — " + r.Detail})
			}
		}
		return a
	}
	for _, c := range cs {
		if len(a.Rows) < askMaxRows {
			a.Rows = append(a.Rows, askRow{Title: c.Name, Detail: fmt.Sprintf("제품 %d개", len(c.Usages)), Link: "/admin/customers"})
		}
	}
	a.More = len(cs) - len(a.Rows)
	a.Lead = fmt.Sprintf("사용 중인 고객이 %d곳 등록돼 있습니다. 고객 이름을 넣어 물으면 그 고객이 쓰는 제품을 답합니다.", len(cs))
	return a
}

// ⑩ 그 밖의 질문 — 바로 찾지 못한 질문은 현황과 도움말을 근거로 AI 가 답해 본다.
func (s *Server) askFree(sess Session, mine []myCustomer, isCustomer bool) *askAnswer {
	a := &askAnswer{Intent: "free", Title: "바로 찾지 못한 질문", Sources: []string{"TrustLink 도움말"}}
	var st *askAnswer
	if isCustomer {
		st = askMine(mine)
	} else if s.dtEnabled() {
		st = s.askStatus(sess)
	}
	if st != nil && st.Lead != "" {
		a.facts = append(a.facts, aiFact{ID: "F1", Text: "지금 현황: " + st.Lead})
		a.Sources = append(a.Sources, st.Sources...)
	}
	for _, i := range []int{len(askTopics) - 1, 1, 0, 8} { // 묻고 찾기 · VEX · SBOM · 자동 대응
		t := askTopics[i]
		a.facts = append(a.facts, aiFact{ID: fmt.Sprintf("K%d", len(a.facts)+1), Text: t.Name + ": " + t.Text})
	}
	if aiEnabledFor("vex") {
		a.Lead = "정해진 질문 유형에 맞지 않아 기록에서 바로 찾지 못했습니다. 현황과 도움말을 근거로 AI 가 답해 봅니다. 근거에 없는 내용은 답하지 않습니다."
	} else {
		a.Lead = "정해진 질문 유형에 맞지 않아 기록에서 바로 찾지 못했습니다. AI 연결이 꺼져 있어 자유 질문에는 답하지 못합니다. 아래처럼 물어보세요."
	}
	for _, ex := range []string{"취약점 번호 — CVE-2026-… 가 어디에 걸리나?", "구성요소 — spring 을 쓰는 제품은?", "현황 — 취약점 몇 건이야? / 급한 것부터", "용어·사용법 — VEX 가 뭐야? / SBOM 어떻게 올려?"} {
		a.Rows = append(a.Rows, askRow{Title: ex})
	}
	return a
}

const askFreeTask = `아래 사실만으로 질문에 세 문장 이내로 답한다. 사실에서 답을 찾을 수 없으면 "기록과 도움말에서는 답을 찾지 못했습니다"라고만 답하고 지어내지 않는다. 끝에 근거 사실 ID 를 [F1] 처럼 붙인다.`
