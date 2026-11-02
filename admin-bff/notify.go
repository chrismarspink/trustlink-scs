package main

// notify.go: 보안 이슈 자동 통보(설계: docs/NOTIFY-DESIGN.md).
//   ① 동기화: 주기적으로 CycloneDX SBOM 이 붙은 모든 버전을 DT 에 적재(SBOM 이 바뀌면 재적재).
//      첫 동기화 분은 기준선 — 그때 쏟아지는 기존 취약점은 통보하지 않는다.
//   ② DT 웹훅(NEW_VULNERABILITY)을 내부 전용 포트로 받아 제품·버전 단위로 묶은 뒤
//      그 제품 업로드 권한자 + 관리자에게 통보(화면 + 메일).
//   ③ VEX 발행 시 그 제품 읽기 권한이 있는 고객에게 판단 결과를 통보(개발자 코멘트 제외).
// 상태는 파일 하나(NOTIFY_STORE)에 저장 — 세션·권한 저장과 같은 방식(stdlib, 외부 DB 없음).

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	notifyBaselineQuiet = time.Hour       // 기준선 적재 후 이 시간 안의 DT 알림은 통보하지 않음
	notifyBatchWait     = 5 * time.Minute // 같은 제품·버전 알림을 모으는 시간(DT 는 한 버전의 CVE 를 수 분에 걸쳐 알림)
	notifyKeep          = 2000            // 보관할 통보 수
)

type Notice struct {
	ID       string          `json:"id"`
	Time     string          `json:"time"`
	Kind     string          `json:"kind"`     // vuln-new | vex-published
	Audience string          `json:"audience"` // internal | customer
	Repo     string          `json:"repo"`
	Tag      string          `json:"tag"`
	Title    string          `json:"title"`
	Body     string          `json:"body"`
	To       []string        `json:"to"`
	Mailed   []string        `json:"mailed,omitempty"`
	NoEmail  []string        `json:"noEmail,omitempty"` // 이메일이 없어 메일을 받지 못한 사용자
	Dropped  []string        `json:"dropped,omitempty"` // 메일 허용 목록 밖이라 보내지 않은 주소
	MailErr  string          `json:"mailError,omitempty"`
	Read     map[string]bool `json:"read,omitempty"`
}

type notifyState struct {
	Notices     []Notice          `json:"notices"`
	Seen        map[string]bool   `json:"seen"`     // repo|tag|vulnId — 같은 취약점은 한 번만
	SBOM        map[string]string `json:"sbom"`     // repo|tag → DT 에 적재한 SBOM referrer digest
	Projects    map[string]string `json:"projects"` // DT 이름@버전 → repo
	Baseline    map[string]string `json:"baseline"` // repo|tag → 기준선 적재 시각(RFC3339)
	Initialized bool              `json:"initialized"`
	LastSync    string            `json:"lastSync"`
	LastSyncMsg string            `json:"lastSyncMsg"`
	QuietUntil  string            `json:"quietUntil,omitempty"` // 취약점 DB 변경 직후 통보 보류 기한(RFC3339)
	QuietSince  string            `json:"quietSince,omitempty"` // 보류는 이 시각 전부터 감시하던 버전에만 적용
	SyncedAt    map[string]string `json:"syncedAt"`             // repo|tag → 처음 감시 대상이 된 시각
	Rebase      *rebaseState      `json:"rebase,omitempty"`     // 취약점 DB 변경 후 재분석 대기
}

// rebaseState: 새로 켠 출처(OSV·GITHUB)의 취약점이 DT 에 다 들어오면(개수 안정) 재분석하고 보류를 푼다.
type rebaseState struct {
	Since string         `json:"since"`
	Start map[string]int `json:"start"` // 출처 → 변경 시점 취약점 수
	Last  map[string]int `json:"last"`  // 출처 → 직전 확인 때 수
}

type vulnInfo struct {
	ID, Severity, Source, Component string
	CVSS                            float64
}

type notifyBatch struct {
	repo, tag string
	first     time.Time
	vulns     []vulnInfo
}

type notifier struct {
	mu      sync.Mutex
	path    string
	st      notifyState
	pending map[string]*notifyBatch
	syncMu  sync.Mutex
}

func newNotifier(p string) *notifier {
	n := &notifier{path: p, pending: map[string]*notifyBatch{}}
	if b, err := os.ReadFile(p); err == nil {
		if err := json.Unmarshal(b, &n.st); err != nil {
			log.Printf("통보 상태 파일 손상(새로 시작): %v", err)
		}
	}
	if n.st.Seen == nil {
		n.st.Seen = map[string]bool{}
	}
	if n.st.SBOM == nil {
		n.st.SBOM = map[string]string{}
	}
	if n.st.Projects == nil {
		n.st.Projects = map[string]string{}
	}
	if n.st.Baseline == nil {
		n.st.Baseline = map[string]string{}
	}
	if n.st.SyncedAt == nil {
		n.st.SyncedAt = map[string]string{}
	}
	return n
}

func (n *notifier) saveLocked() {
	if n.path == "" {
		return
	}
	b, _ := json.Marshal(n.st)
	_ = os.MkdirAll(filepath.Dir(n.path), 0o750)
	tmp := n.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		_ = os.Rename(tmp, n.path)
	}
}

// ---------- 기동 ----------

func (s *Server) initNotify() {
	s.notify = newNotifier(env("NOTIFY_STORE", "/var/lib/trustlink/notify.json"))
	if s.cfg.DTBaseURL == "" {
		return
	}
	if addr := env("NOTIFY_ADDR", ":8089"); addr != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("POST /dt/webhook", s.dtWebhook)
		go func() { log.Printf("DT 웹훅 수신(내부 전용) %s: %v", addr, http.ListenAndServe(addr, mux)) }()
	}
	interval, err := time.ParseDuration(env("NOTIFY_SYNC_INTERVAL", "10m"))
	if err != nil || interval < time.Minute {
		interval = 10 * time.Minute
	}
	go func() {
		time.Sleep(30 * time.Second) // DT 키 확보 대기
		for {
			s.notifySync()
			time.Sleep(interval)
		}
	}()
	go func() {
		for range time.Tick(15 * time.Second) {
			s.flushBatches(false)
		}
	}()
	go s.ensureDTNotificationRule()
	go s.watchRebase() // 재배포 전에 시작한 재분석 대기를 이어서
}

// ---------- ① 동기화 ----------

// notifySync: SBOM 이 붙은 모든 버전을 DT 에 적재. 바뀐 SBOM 만 다시 올린다.
func (s *Server) notifySync() string {
	n := s.notify
	n.syncMu.Lock()
	defer n.syncMu.Unlock()
	if !s.dtEnabled() {
		return "DT 미설정"
	}
	n.mu.Lock()
	initial := !n.st.Initialized
	n.mu.Unlock()
	caller := s.svcCaller()
	uploaded, failed := 0, 0
	for _, repo := range s.svcCatalog() {
		for _, tag := range s.svcTags(repo) {
			key := repo + "|" + tag
			_, subj, err := s.fetchManifest(caller, repo, tag)
			if err != nil {
				continue
			}
			ref := latestSBOM(s.fetchReferrers(caller, repo, subj))
			n.mu.Lock()
			same := ref == "" || n.st.SBOM[key] == ref
			n.mu.Unlock()
			if same {
				continue
			}
			blob := s.svcReferrerBlob(repo, ref)
			if blob == nil {
				failed++
				continue
			}
			name := path.Base(repo)
			if _, err := s.dtUploadBOM(name, tag, base64.StdEncoding.EncodeToString(sanitizeBOM(blob))); err != nil {
				log.Printf("통보 동기화: %s:%s DT 적재 실패: %v", repo, tag, err)
				failed++
				continue
			}
			uploaded++
			n.mu.Lock()
			n.st.SBOM[key] = ref
			n.st.Projects[name+"@"+tag] = repo
			now := time.Now().UTC().Format(time.RFC3339)
			if initial {
				n.st.Baseline[key] = now
			}
			if n.st.SyncedAt[key] == "" {
				n.st.SyncedAt[key] = now
			}
			n.mu.Unlock()
		}
	}
	msg := fmt.Sprintf("적재 %d건, 실패 %d건", uploaded, failed)
	if initial {
		msg += " (기준선)"
	}
	n.mu.Lock()
	n.st.Initialized = true
	n.st.LastSync = time.Now().UTC().Format(time.RFC3339)
	n.st.LastSyncMsg = msg
	n.saveLocked()
	n.mu.Unlock()
	if uploaded > 0 || failed > 0 {
		log.Printf("통보 동기화: %s", msg)
	}
	return msg
}

// latestSBOM: CycloneDX SBOM referrer 중 가장 최근(created) 것의 digest.
func latestSBOM(refs []ociDesc) string {
	best, bestT := "", ""
	for _, r := range refs {
		if !isSBOM(r.ArtifactType) {
			continue
		}
		t := r.Annotations["org.opencontainers.image.created"]
		if best == "" || t > bestT {
			best, bestT = r.Digest, t
		}
	}
	return best
}

// ---------- ② DT 웹훅 → 내부 통보 ----------

type dtNotification struct {
	Notification struct {
		Group   string `json:"group"`
		Subject struct {
			Component struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"component"`
			Vulnerability struct {
				VulnID   string          `json:"vulnId"`
				Source   string          `json:"source"`
				Severity string          `json:"severity"`
				CVSSv3   json.RawMessage `json:"cvssv3"` // 숫자(기본 점수) — 형식이 달라도 전체를 거부하지 않게 Raw
			} `json:"vulnerability"`
			AffectedProjects []struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"affectedProjects"`
		} `json:"subject"`
	} `json:"notification"`
}

func (s *Server) dtWebhook(w http.ResponseWriter, r *http.Request) {
	var in dtNotification
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	s.queueVulnNotice(in)
	w.WriteHeader(204)
}

func (s *Server) queueVulnNotice(in dtNotification) {
	sub := in.Notification.Subject
	if in.Notification.Group != "NEW_VULNERABILITY" || sub.Vulnerability.VulnID == "" {
		return
	}
	v := vulnInfo{ID: sub.Vulnerability.VulnID, Severity: strings.ToUpper(sub.Vulnerability.Severity), Source: sub.Vulnerability.Source,
		Component: strings.TrimSpace(sub.Component.Name + " " + sub.Component.Version)}
	_ = json.Unmarshal(sub.Vulnerability.CVSSv3, &v.CVSS)
	n := s.notify
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, p := range sub.AffectedProjects {
		repo := n.st.Projects[p.Name+"@"+p.Version]
		if repo == "" {
			continue // TrustLink 가 적재하지 않은 DT 프로젝트
		}
		key := repo + "|" + p.Version
		seen := key + "|" + v.ID
		if n.st.Seen[seen] {
			continue
		}
		n.st.Seen[seen] = true
		if t, err := time.Parse(time.RFC3339, n.st.Baseline[key]); err == nil && time.Since(t) < notifyBaselineQuiet {
			continue // 기준선 적재 직후의 기존 취약점
		}
		if n.quietFor(key) {
			continue // 취약점 DB 를 바꾼 직후 — 기존 버전에서 기존 취약점이 새로 잡힌 것
		}
		b := n.pending[key]
		if b == nil {
			b = &notifyBatch{repo: repo, tag: p.Version, first: time.Now()}
			n.pending[key] = b
		}
		b.vulns = append(b.vulns, v)
	}
	n.saveLocked()
}

// quietFor: 취약점 DB 변경에 따른 통보 보류 대상인지(보류 기간 안 + 변경 전부터 감시하던 버전). n.mu 잠근 상태.
func (n *notifier) quietFor(key string) bool {
	t, err := time.Parse(time.RFC3339, n.st.QuietUntil)
	if err != nil || !time.Now().Before(t) {
		return false
	}
	synced := n.st.SyncedAt[key]
	return synced == "" || synced <= n.st.QuietSince // 시각 문자열(RFC3339 UTC)은 사전순 = 시간순
}

// flushBatches: 모으는 시간이 지난 묶음을 통보로 보낸다(force 면 전부).
func (s *Server) flushBatches(force bool) {
	n := s.notify
	n.mu.Lock()
	var ready []*notifyBatch
	for k, b := range n.pending {
		if force || time.Since(b.first) >= notifyBatchWait {
			ready = append(ready, b)
			delete(n.pending, k)
		}
	}
	n.mu.Unlock()
	for _, b := range ready {
		s.sendVulnNotice(b)
	}
}

var sevRank = map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

func severityRank(s string) int {
	if r, ok := sevRank[s]; ok {
		return r
	}
	return 4
}

func (s *Server) sendVulnNotice(b *notifyBatch) {
	sort.Slice(b.vulns, func(i, j int) bool { return severityRank(b.vulns[i].Severity) < severityRank(b.vulns[j].Severity) })
	counts := map[string]int{}
	for _, v := range b.vulns {
		counts[v.Severity]++
	}
	var sum []string
	for _, k := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		if counts[k] > 0 {
			sum = append(sum, fmt.Sprintf("%s %d", k, counts[k]))
		}
	}
	title := fmt.Sprintf("[TrustLink] %s %s — 새 취약점 %d건 (판단 필요)", path.Base(b.repo), b.tag, len(b.vulns))
	var body strings.Builder
	fmt.Fprintf(&body, "%s:%s 의 SBOM 에서 새 취약점 %d건이 발견되었습니다(%s).\n", b.repo, b.tag, len(b.vulns), strings.Join(sum, ", "))
	body.WriteString("영향 여부를 판단해 VEX 를 발행해 주세요. 고객에게는 VEX 발행 시점에 판단 결과가 통보됩니다.\n\n")
	const maxLines = 30 // 메일·화면 본문에 싣는 최대 항목(심각도순). 나머지는 판단 화면에서
	for i, v := range b.vulns {
		if i == maxLines {
			fmt.Fprintf(&body, "- 외 %d건\n", len(b.vulns)-maxLines)
			break
		}
		cvss := ""
		if v.CVSS > 0 {
			cvss = fmt.Sprintf(" · CVSS %.1f", v.CVSS)
		}
		fmt.Fprintf(&body, "- %s [%s%s] %s\n", v.ID, v.Severity, cvss, v.Component)
	}
	fmt.Fprintf(&body, "\n판단 화면: %s\n", s.artifactURL(b.repo, b.tag))
	s.deliver(Notice{Kind: "vuln-new", Audience: "internal", Repo: b.repo, Tag: b.tag, Title: title, Body: body.String()},
		s.recipients(b.repo, false), nil)
}

// ---------- ③ VEX 발행 → 고객 통보 ----------

// notifyVexPublished: VEX(CycloneDX) 판단 결과를 고객에게. 개발자 코멘트(analysis.detail)는 넣지 않는다.
func (s *Server) notifyVexPublished(repo, tag string, vex []byte) {
	var doc struct {
		Vulnerabilities []struct {
			ID      string `json:"id"`
			Ratings []struct {
				Severity string `json:"severity"`
			} `json:"ratings"`
			Analysis struct {
				State         string   `json:"state"`
				Justification string   `json:"justification"`
				Response      []string `json:"response"`
			} `json:"analysis"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(vex, &doc); err != nil || len(doc.Vulnerabilities) == 0 {
		return
	}
	stateKo := map[string]string{"not_affected": "영향 없음", "exploitable": "영향 있음", "resolved": "수정됨",
		"in_triage": "조사 중", "false_positive": "오탐(영향 없음)", "resolved_with_pedigree": "수정됨"}
	justKo := map[string]string{"code_not_present": "해당 코드 미포함", "code_not_reachable": "실행 경로에 없음",
		"requires_configuration": "특정 설정 필요", "requires_dependency": "특정 의존성 필요", "requires_environment": "특정 환경 필요",
		"protected_by_compiler": "컴파일러로 보호", "protected_at_runtime": "실행 시 보호", "protected_at_perimeter": "경계에서 보호",
		"protected_by_mitigating_control": "완화책 적용"}
	counts := map[string]int{}
	var lines []string
	for _, v := range doc.Vulnerabilities {
		st := stateKo[v.Analysis.State]
		if st == "" {
			st = "조사 중"
		}
		counts[st]++
		sev := ""
		if len(v.Ratings) > 0 && v.Ratings[0].Severity != "" {
			sev = " [" + strings.ToUpper(v.Ratings[0].Severity) + "]"
		}
		line := fmt.Sprintf("- %s%s: %s", v.ID, sev, st)
		if j := justKo[v.Analysis.Justification]; j != "" {
			line += " — " + j
		}
		if st == "영향 있음" && len(v.Analysis.Response) > 0 {
			line += " (조치: " + strings.Join(v.Analysis.Response, ", ") + ")"
		}
		lines = append(lines, line)
	}
	var sum []string
	for _, k := range []string{"영향 있음", "조사 중", "수정됨", "영향 없음", "오탐(영향 없음)"} {
		if counts[k] > 0 {
			sum = append(sum, fmt.Sprintf("%s %d", k, counts[k]))
		}
	}
	title := fmt.Sprintf("[TrustLink] %s %s 보안 판단(VEX) 갱신 — %s", path.Base(repo), tag, strings.Join(sum, ", "))
	var body strings.Builder
	fmt.Fprintf(&body, "%s %s 버전의 취약점 영향 판단(VEX)이 갱신되었습니다.\n\n", path.Base(repo), tag)
	body.WriteString(strings.Join(lines, "\n"))
	if counts["영향 있음"] > 0 {
		body.WriteString("\n\n영향이 있는 항목이 있습니다. 제품 상세 화면의 안내에 따라 업데이트하거나 완화 조치를 적용해 주세요.")
	}
	fmt.Fprintf(&body, "\n\n상세·VEX 파일: %s\n", s.artifactURL(repo, tag))
	s.deliver(Notice{Kind: "vex-published", Audience: "customer", Repo: repo, Tag: tag, Title: title, Body: body.String()},
		s.recipients(repo, true), s.orgContactsFor(repo))
}

// ---------- 받는 사람 · 발송 ----------

// recipients: customer=false → 그 제품 업로드 권한자 + 관리자, true → 읽기 권한이 있는 외부 사용자.
func (s *Server) recipients(repo string, customer bool) []kcUser {
	gs, err := s.listGroups()
	if err != nil {
		log.Printf("통보 받는 사람 조회 실패: %v", err)
		return nil
	}
	users := map[string]kcUser{}
	groups := map[string][]string{}
	for _, g := range gs {
		resp, err := s.kcAdmin("GET", "/groups/"+g.ID+"/members?max=10000", nil)
		if err != nil {
			continue
		}
		var us []kcUser
		_ = json.NewDecoder(resp.Body).Decode(&us)
		resp.Body.Close()
		for _, u := range us {
			if !u.Enabled {
				continue
			}
			users[u.Username] = u
			groups[u.Username] = append(groups[u.Username], g.Name)
		}
	}
	var out []kcUser
	for name, u := range users {
		gr := groups[name]
		internal := contains(gr, "admins") || contains(gr, "developers")
		ok := false
		switch {
		case customer:
			ok = !internal && s.access != nil && s.access.allowed(name, gr, repo, "read")
		case contains(gr, "admins"):
			ok = true
		default:
			ok = s.access == nil && contains(gr, "developers") || s.access != nil && s.access.allowed(name, gr, repo, "create")
		}
		if ok {
			out = append(out, u)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

// orgContactsFor: 그 제품을 받을 수 있는 고객사(제품 권한의 읽기 대상 그룹)의 보안 담당 통보 주소.
func (s *Server) orgContactsFor(repo string) []string {
	if s.access == nil {
		return nil
	}
	readers := map[string]bool{}
	for _, pp := range s.access.snapshot().Products {
		if pp.Repo != repo {
			continue
		}
		for _, x := range pp.Readers {
			if x.Type == "group" && strings.HasPrefix(x.Name, orgPrefix) {
				readers[x.Name] = true
			}
		}
	}
	if len(readers) == 0 {
		return nil
	}
	gs, err := s.listGroups()
	if err != nil {
		return nil
	}
	var out []string
	for _, g := range gs {
		if readers[g.Name] {
			out = append(out, orgContacts(g)...)
		}
	}
	return out
}

// deliver: 화면 통보 저장 + 메일 발송(허용 목록 적용) + 감사 기록. extra 는 계정 없는 통보 주소(고객사 보안 담당).
func (s *Server) deliver(nt Notice, to []kcUser, extra []string) {
	now := time.Now().UTC()
	nt.ID = fmt.Sprintf("%d", now.UnixNano())
	nt.Time = now.Format(time.RFC3339)
	var emails []string
	for _, u := range to {
		nt.To = append(nt.To, u.Username)
		if u.Email != "" {
			emails = append(emails, u.Email)
		} else {
			nt.NoEmail = append(nt.NoEmail, u.Username)
		}
	}
	for _, a := range extra {
		if !contains(emails, a) {
			emails = append(emails, a)
		}
	}
	for _, a := range strings.Split(env("NOTIFY_CC", ""), ",") { // 운영 참조 주소(모든 통보 사본)
		if a = strings.TrimSpace(a); a != "" {
			emails = append(emails, a)
		}
	}
	if s.mail.Configured() && len(emails) > 0 {
		sent, dropped, err := s.mail.Send(emails, nt.Title, nt.Body)
		nt.Mailed, nt.Dropped = sent, dropped
		if err != nil {
			nt.MailErr = err.Error()
		}
	}
	n := s.notify
	n.mu.Lock()
	n.st.Notices = append(n.st.Notices, nt)
	if len(n.st.Notices) > notifyKeep {
		n.st.Notices = n.st.Notices[len(n.st.Notices)-notifyKeep:]
	}
	n.saveLocked()
	n.mu.Unlock()
	_ = s.sor.append(SoREvent{Actor: "trustlink", Action: "notify-" + nt.Kind, Repo: nt.Repo, Tag: nt.Tag,
		Status: map[bool]string{true: "mail-failed", false: "ok"}[nt.MailErr != ""],
		Detail: map[string]any{"to": nt.To, "mailed": nt.Mailed, "dropped": nt.Dropped, "noEmail": nt.NoEmail, "error": nt.MailErr}})
}

func (s *Server) artifactURL(repo, tag string) string {
	base := strings.TrimSuffix(s.cfg.RedirectURI, "/admin/callback")
	return base + "/artifact/" + url.PathEscape(repo) + "/" + url.PathEscape(tag)
}

// ---------- API ----------

// GET /api/notifications — 내 통보(최근 50) + 안 읽은 수.
func (s *Server) apiNotifications(w http.ResponseWriter, r *http.Request) {
	sess, _ := s.sessionOf(r)
	n := s.notify
	n.mu.Lock()
	defer n.mu.Unlock()
	out := []map[string]any{}
	unread := 0
	for i := len(n.st.Notices) - 1; i >= 0; i-- {
		nt := n.st.Notices[i]
		if !contains(nt.To, sess.Username) {
			continue
		}
		read := nt.Read[sess.Username]
		if !read {
			unread++
		}
		if len(out) < 50 {
			out = append(out, map[string]any{"id": nt.ID, "time": nt.Time, "kind": nt.Kind, "repo": nt.Repo, "tag": nt.Tag,
				"title": nt.Title, "body": nt.Body, "read": read})
		}
	}
	writeJSON(w, 200, map[string]any{"items": out, "unread": unread})
}

// POST /api/notifications/read {id} — id 가 비면 모두 읽음.
func (s *Server) apiNotificationsRead(w http.ResponseWriter, r *http.Request) {
	sess, _ := s.sessionOf(r)
	var in struct{ ID string }
	_ = json.NewDecoder(r.Body).Decode(&in)
	n := s.notify
	n.mu.Lock()
	for i := range n.st.Notices {
		nt := &n.st.Notices[i]
		if (in.ID == "" || nt.ID == in.ID) && contains(nt.To, sess.Username) {
			if nt.Read == nil {
				nt.Read = map[string]bool{}
			}
			nt.Read[sess.Username] = true
		}
	}
	n.saveLocked()
	n.mu.Unlock()
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

// GET /api/notify/log — 관리자: 전체 통보 기록(최근 200)과 동기화 상태.
func (s *Server) apiNotifyLog(w http.ResponseWriter, r *http.Request) {
	n := s.notify
	n.mu.Lock()
	defer n.mu.Unlock()
	items := []Notice{}
	for i := len(n.st.Notices) - 1; i >= 0 && len(items) < 200; i-- {
		nt := n.st.Notices[i]
		nt.Read = nil
		items = append(items, nt)
	}
	writeJSON(w, 200, map[string]any{"items": items, "lastSync": n.st.LastSync, "lastSyncMsg": n.st.LastSyncMsg, "quietUntil": n.st.QuietUntil,
		"tracked": len(n.st.SBOM), "pending": len(n.pending), "initialized": n.st.Initialized})
}

// POST /api/notify/sync — 관리자: 지금 동기화(+ 모아 둔 알림 즉시 발송).
func (s *Server) apiNotifySync(w http.ResponseWriter, r *http.Request) {
	msg := s.notifySync()
	s.flushBatches(true)
	writeJSON(w, 200, map[string]string{"status": "ok", "message": msg})
}
