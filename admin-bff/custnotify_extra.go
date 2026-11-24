package main

// custnotify_extra.go: 고객 등록부 부가 기능.
//   (b) 만료·EOS 알림: 하루 1회 라이선스·유지보수·설치 버전 EOS 가 90/30/7일 안에 들어오면
//       우리 쪽 영업·지원 담당(Keycloak 이메일)에게 메일. 설정 시 고객 구매(계약)·EOS 통지 담당에게도.
//       임계값마다 한 번만 보낸다(고객·사용·종류·버전·날짜·임계값 키). 날짜가 바뀌면(갱신) 다시 센다.
//   (c) 고객 전용 화면(GET /api/my/products): 로그인한 고객 사용자의 고객사 그룹(org-*)에 연결된 고객만 —
//       등록 제품·설치 버전·그 버전의 취약점(VEX 상태)·권장 패치 버전·최근 통지. 다른 고객 데이터·내부 메모는 주지 않는다.

import (
	"log"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"
)

var expiryThresholds = []int{90, 30, 7}

const expiryLogKeep = 200

type expiryRec struct {
	Time       string   `json:"time"`
	CustomerID string   `json:"customerId"`
	Customer   string   `json:"customer"`
	Audience   string   `json:"audience"` // internal | customer
	Items      []string `json:"items"`
	Sent       []string `json:"sent,omitempty"`
	Dropped    []string `json:"dropped,omitempty"` // 허용 목록 밖이라 건너뜀
	Error      string   `json:"error,omitempty"`
}

type expiryDue struct {
	custExpiry
	Threshold int    `json:"threshold"`
	Key       string `json:"key"`
}

func expiryKey(e custExpiry, th int) string {
	return e.CustomerID + "|" + e.UsageID + "|" + e.Kind + "|" + e.Tag + "|" + e.Date + "|" + itoa(th)
}

// dueThreshold: 남은 날이 들어간 가장 작은 임계값(없으면 0). 이미 지난 것은 알리지 않는다(화면에만).
func dueThreshold(days int) int {
	th := 0
	for _, t := range expiryThresholds {
		if days >= 0 && days <= t {
			th = t
		}
	}
	return th
}

// expiryDueItems: 아직 안 보낸 임계값에 걸린 항목.
func expiryDueItems(items []custExpiry, sent map[string]string) []expiryDue {
	var out []expiryDue
	for _, e := range items {
		th := dueThreshold(e.Days)
		if th == 0 {
			continue
		}
		if k := expiryKey(e, th); sent[k] == "" {
			out = append(out, expiryDue{custExpiry: e, Threshold: th, Key: k})
		}
	}
	return out
}

var expiryKindKo = map[string]string{"license": "라이선스 만료", "maint": "유지보수 만료", "eos": "버전 지원 종료(EOS)"}

func expiryLine(e expiryDue) string {
	t := expiryKindKo[e.Kind] + " — " + path.Base(e.Repo)
	if e.Tag != "" {
		t += " " + e.Tag
	}
	return t + ": " + e.Date + " (" + dday(e.Days) + ")"
}

// custExpiryCheck: 만료 임박 항목을 고객별로 묶어 보낸다. 보낸 수(메일 단위)를 돌려준다.
func (s *Server) custExpiryCheck() int {
	c := s.cust()
	d := c.snapshot()
	now := c.now()
	mails := 0
	for _, cu := range activeCustomers(d.Customers) { // 중지된 회사는 만료 알림 없음
		due := expiryDueItems(custExpiries(cu, d.Products, now), d.ExpirySent)
		if len(due) == 0 {
			continue
		}
		lines := []string{}
		for _, e := range due {
			lines = append(lines, expiryLine(e))
		}
		// 우리 쪽 담당
		internal := []string{}
		for _, u := range []string{cu.SalesOwner, cu.SupportOwner} {
			if e := c.emailOf(u); e != "" && !inList(e, internal) {
				internal = append(internal, e)
			}
		}
		subject := "[TrustLink] " + cu.Name + " 계약·지원 만료 예정 " + itoa(len(due)) + "건"
		body := cu.Name + " 의 만료 예정 항목입니다.\n\n- " + strings.Join(lines, "\n- ") + "\n\n고객 등록부: " + s.publicBase() + "/admin/customers\n"
		recs := []expiryRec{s.expiryMail(cu, "internal", internal, subject, body, lines)}
		// 고객 쪽(설정 시): 계약(라이선스·유지보수)은 구매 담당 중 contract 통지, EOS 는 eos 통지 담당
		if d.Settings.ExpiryToCustomer {
			var to, cl []string
			for _, ct := range cu.Contacts {
				for _, e := range due {
					want := (e.Kind == "eos" && inList("eos", ct.Notify)) || (e.Kind != "eos" && ct.Role == "purchase" && inList("contract", ct.Notify))
					if want && !inList(ct.Email, to) {
						to = append(to, ct.Email)
					}
				}
			}
			for _, e := range due {
				cl = append(cl, expiryLine(e))
			}
			if len(to) > 0 {
				body := cu.Name + " 담당자님께,\n\n아래 계약·지원 기간이 곧 만료됩니다. 갱신·업그레이드는 담당 영업에 문의해 주십시오.\n\n- " + strings.Join(cl, "\n- ") + "\n"
				recs = append(recs, s.expiryMail(cu, "customer", to, "[안내] 계약·지원 만료 예정", body, cl))
			}
		}
		failed := false
		for _, r := range recs {
			failed = failed || r.Error != ""
			if len(r.Sent) > 0 {
				mails++
			}
		}
		ts := now.UTC().Format(time.RFC3339)
		c.mu.Lock()
		if !failed { // 실패(메일 서버 오류 등)면 표시하지 않아 다음 날 다시 시도
			for _, e := range due {
				c.d.ExpirySent[e.Key] = ts
			}
		}
		c.d.ExpiryLog = append(c.d.ExpiryLog, recs...)
		if len(c.d.ExpiryLog) > expiryLogKeep {
			c.d.ExpiryLog = c.d.ExpiryLog[len(c.d.ExpiryLog)-expiryLogKeep:]
		}
		_ = c.saveLocked()
		c.mu.Unlock()
		_ = s.sor.append(SoREvent{Actor: "trustlink", Action: "customer-expiry", Subject: cu.ID, Status: map[bool]string{true: "mail-failed", false: "ok"}[failed],
			Detail: map[string]any{"items": lines, "log": recs}})
	}
	return mails
}

func (s *Server) expiryMail(cu Customer, aud string, to []string, subject, body string, items []string) expiryRec {
	r := expiryRec{Time: s.cust().now().UTC().Format(time.RFC3339), CustomerID: cu.ID, Customer: cu.Name, Audience: aud, Items: items}
	switch {
	case len(to) == 0:
		// 받는 사람 없음은 실패로 보지 않는다(기록에 안내만)
		r.Items = append([]string{"(받는 사람 없음 — 영업·지원 담당 또는 이메일 미지정)"}, items...)
	case !s.mail.Configured():
		r.Error = "메일 서버 미설정(SMTP_HOST)"
	default:
		reason := map[string]string{"customer": "고객사 담당자", "internal": "이 고객의 영업·지원 담당"}[aud]
		mc := s.renderMail(mailCard{Module: "계약·지원 만료 관리", Purpose: "만료 안내", Tone: "info",
			Title: strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(subject, "[TrustLink]"), "[안내]")), Body: body, Reason: reason, Ref: cu.ID})
		sent, dropped, err := s.mail.SendRich(to, subject, mc)
		outboxRecord("expiry", cu.Name+" · 만료 안내", cu.ID, to, subject, mc, sent, dropped, err)
		r.Sent, r.Dropped, r.Error = sent, dropped, errString(err)
	}
	return r
}

// custExpiryLoop: 기동 2분 뒤 한 번, 이후 하루 1회. CUSTOMERS_EXPIRY_CHECK=off 면 끈다.
func (s *Server) custExpiryLoop() {
	if env("CUSTOMERS_EXPIRY_CHECK", "on") == "off" {
		return
	}
	time.Sleep(2 * time.Minute)
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		if n := s.custExpiryCheck(); n > 0 {
			log.Printf("만료·EOS 알림: 메일 %d건", n)
		}
		<-t.C
	}
}

// GET /api/customer-expiring?days=90 — 만료 예정(지난 것 포함) + 보낸 임계값 + 최근 발송 기록.
func (s *Server) apiCustomerExpiring(w http.ResponseWriter, r *http.Request) {
	days := atoiDefault(r.URL.Query().Get("days"), 90)
	c := s.cust()
	d := c.snapshot()
	type row struct {
		custExpiry
		Sent []int `json:"sent"` // 이미 알린 임계값
	}
	out := []row{}
	for _, cu := range activeCustomers(d.Customers) {
		for _, e := range custExpiries(cu, d.Products, c.now()) {
			if e.Days > days {
				continue
			}
			rw := row{custExpiry: e, Sent: []int{}}
			for _, th := range expiryThresholds {
				if d.ExpirySent[expiryKey(e, th)] != "" {
					rw.Sent = append(rw.Sent, th)
				}
			}
			out = append(out, rw)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Days < out[j].Days })
	lg := []expiryRec{}
	for i := len(d.ExpiryLog) - 1; i >= 0 && len(lg) < 50; i-- {
		lg = append(lg, d.ExpiryLog[i])
	}
	writeJSON(w, 200, map[string]any{"items": out, "log": lg, "thresholds": expiryThresholds, "settings": d.Settings})
}

// POST /api/customer-expiring/check — 지금 점검(중복 방지 그대로).
func (s *Server) apiCustomerExpiryCheck(w http.ResponseWriter, r *http.Request) {
	n := s.custExpiryCheck()
	_ = s.sor.append(SoREvent{Actor: w.Header().Get("X-User"), Action: "customer-expiry-check", Detail: map[string]any{"mails": n}})
	writeJSON(w, 200, map[string]any{"mails": n})
}

// ---------- (c) 고객 전용 화면 ----------

type myVuln struct {
	VulnID    string `json:"vulnId"`
	Severity  string `json:"severity"`
	State     string `json:"state"` // DT 분석 상태(VEX)
	KEV       bool   `json:"kev"`
	Component string `json:"component"`
	Recommend string `json:"recommend,omitempty"` // 규칙 판정 패치 버전
}

type myInstall struct {
	Tag      string   `json:"tag"`
	Env      string   `json:"env"`
	Qty      int      `json:"qty"`
	EOS      string   `json:"eos,omitempty"`
	EOSDays  *int     `json:"eosDays,omitempty"`
	Upgrade  string   `json:"upgrade,omitempty"`
	Analyzed bool     `json:"analyzed"`
	Vulns    []myVuln `json:"vulns"`
}

type myUsage struct {
	Repo          string      `json:"repo"`
	LicenseType   string      `json:"licenseType,omitempty"`
	LicenseExpiry string      `json:"licenseExpiry,omitempty"`
	MaintExpiry   string      `json:"maintExpiry,omitempty"`
	SupportTier   string      `json:"supportTier,omitempty"`
	Installs      []myInstall `json:"installs"`
}

type myNotice struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Repo      string `json:"repo"`
	VulnID    string `json:"vulnId"`
	Severity  string `json:"severity"`
	SentAt    string `json:"sentAt"`
	Subject   string `json:"subject"`
	Text      string `json:"text"`
	Recommend string `json:"recommend,omitempty"`
}

type myCustomer struct {
	Name    string     `json:"name"`
	Logo    string     `json:"logo,omitempty"`
	Usages  []myUsage  `json:"usages"`
	Notices []myNotice `json:"notices"`
}

// GET /api/my/products — 로그인 사용자의 고객사 그룹에 연결된 고객만(guardSession).
func (s *Server) apiMyProducts(w http.ResponseWriter, r *http.Request) {
	sess, _ := s.sessionOf(r)
	c := s.cust()
	d := c.snapshot()
	now := c.now()
	out := []myCustomer{}
	views := map[string]*dtRepoView{}
	for _, cu := range activeCustomers(d.Customers) { // 중지(계약 해지 등)된 회사는 내 제품에서 빠짐
		if cu.OrgGroup == "" || !contains(sess.Groups, cu.OrgGroup) {
			continue
		}
		mc := myCustomer{Name: cu.Name, Logo: cu.Logo, Usages: []myUsage{}, Notices: []myNotice{}}
		for _, u := range cu.Usages {
			v := views[u.Repo]
			if v == nil {
				v = s.dtView(u.Repo)
				views[u.Repo] = v
			}
			var tags []string
			mu := myUsage{Repo: u.Repo, LicenseType: u.LicenseType, LicenseExpiry: u.LicenseExpiry, MaintExpiry: u.MaintExpiry, SupportTier: u.SupportTier, Installs: []myInstall{}}
			for _, in := range u.Installs {
				mi := myInstall{Tag: in.Tag, Env: in.Env, Qty: in.Qty, Vulns: []myVuln{}}
				if vp, ok := verPolicyOf(d.Products, u.Repo, in.Tag); ok {
					mi.EOS, mi.Upgrade = vp.EOS, vp.Upgrade
					if dd, ok := daysUntil(vp.EOS, now); ok {
						mi.EOSDays = &dd
					}
				}
				fs, ok := v.findings(in.Tag)
				mi.Analyzed = ok
				for _, f := range fs {
					mv := myVuln{VulnID: strings.ToUpper(f.Vulnerability.VulnID), Severity: strings.ToUpper(f.Vulnerability.Severity), State: stateOf(f),
						KEV: isKEV(vulnIDs(f)), Component: f.Component.Name + " " + f.Component.Version}
					if !inList(mv.State, dtInactive) {
						if tags == nil {
							tags = s.versionTags(u.Repo, d.Products[u.Repo])
						}
						if st, ok := pickFix(v.fixScan(mv.VulnID, f, tags, in.Tag), in.Tag); ok {
							mv.Recommend = st.Tag
						}
					}
					mi.Vulns = append(mi.Vulns, mv)
					if len(mi.Vulns) >= 300 {
						break
					}
				}
				sort.Slice(mi.Vulns, func(i, j int) bool {
					a, b := mi.Vulns[i], mi.Vulns[j]
					if a.KEV != b.KEV {
						return a.KEV
					}
					return severityRank(a.Severity) < severityRank(b.Severity)
				})
				mu.Installs = append(mu.Installs, mi)
			}
			mc.Usages = append(mc.Usages, mu)
		}
		for i := len(d.Notices) - 1; i >= 0 && len(mc.Notices) < 20; i-- {
			n := d.Notices[i]
			for _, t := range n.Targets {
				if t.CustomerID == cu.ID && t.Result != nil {
					mc.Notices = append(mc.Notices, myNotice{ID: n.ID, Kind: n.Kind, Repo: n.Repo, VulnID: n.VulnID, Severity: n.Severity,
						SentAt: t.Result.At, Subject: t.Subject, Text: t.Text, Recommend: t.Recommend})
					break
				}
			}
		}
		out = append(out, mc)
	}
	writeJSON(w, 200, map[string]any{"customers": out, "user": sess.Username})
}
