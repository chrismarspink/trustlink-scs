package main

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 받는 사람 조회(Keycloak)는 닿지 않는 주소로 두어 빈 목록이 되게 한다 — 묶음·중복·기준선·본문만 검사.
func testNotifyServer(t *testing.T) *Server {
	dir := t.TempDir()
	s := &Server{cfg: Config{KCInternal: "http://127.0.0.1:1", RedirectURI: "http://tl.example/admin/callback"},
		http: &http.Client{Timeout: time.Second}, mail: &Mailer{}}
	s.sor = newSoR(filepath.Join(dir, "sor.jsonl"))
	s.notify = newNotifier(filepath.Join(dir, "notify.json"))
	s.notify.st.Projects["innopouch@7.0"] = "products/innopouch"
	return s
}

func dtVuln(id, sev, project, version string) dtNotification {
	var n dtNotification
	n.Notification.Group = "NEW_VULNERABILITY"
	n.Notification.Subject.Vulnerability.VulnID = id
	n.Notification.Subject.Vulnerability.Severity = sev
	n.Notification.Subject.Vulnerability.CVSSv3 = []byte("9.8")
	n.Notification.Subject.Component.Name = "log4j-core"
	n.Notification.Subject.Component.Version = "2.14.1"
	n.Notification.Subject.AffectedProjects = append(n.Notification.Subject.AffectedProjects, struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}{project, version})
	return n
}

func TestNotifyBatchDedupeUnknown(t *testing.T) {
	s := testNotifyServer(t)
	s.queueVulnNotice(dtVuln("CVE-1", "medium", "innopouch", "7.0"))
	s.queueVulnNotice(dtVuln("CVE-2", "critical", "innopouch", "7.0"))
	s.queueVulnNotice(dtVuln("CVE-1", "medium", "innopouch", "7.0")) // 중복
	s.queueVulnNotice(dtVuln("CVE-3", "high", "other", "1.0"))       // TrustLink 가 모르는 프로젝트
	s.flushBatches(false)
	if len(s.notify.st.Notices) != 0 {
		t.Fatal("모으는 시간 전에는 보내지 않아야 함")
	}
	s.flushBatches(true)
	ns := s.notify.st.Notices
	if len(ns) != 1 {
		t.Fatalf("통보 %d건(1건이어야 함)", len(ns))
	}
	n := ns[0]
	if n.Audience != "internal" || !strings.Contains(n.Title, "새 취약점 2건") {
		t.Errorf("title=%q", n.Title)
	}
	if i, j := strings.Index(n.Body, "CVE-2"), strings.Index(n.Body, "CVE-1"); i < 0 || j < 0 || i > j {
		t.Errorf("심각도 순서(CRITICAL 먼저) 아님:\n%s", n.Body)
	}
	if !strings.Contains(n.Body, "CVSS 9.8") || !strings.Contains(n.Body, "http://tl.example/artifact/products%2Finnopouch/7.0") {
		t.Errorf("본문:\n%s", n.Body)
	}
}

func TestNotifyBaselineQuiet(t *testing.T) {
	s := testNotifyServer(t)
	s.notify.st.Baseline["products/innopouch|7.0"] = time.Now().UTC().Format(time.RFC3339)
	s.queueVulnNotice(dtVuln("CVE-9", "high", "innopouch", "7.0"))
	s.flushBatches(true)
	if len(s.notify.st.Notices) != 0 {
		t.Fatal("기준선 직후 알림은 통보하지 않아야 함")
	}
	s.notify.st.Baseline["products/innopouch|7.0"] = time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	s.queueVulnNotice(dtVuln("CVE-10", "high", "innopouch", "7.0"))
	s.flushBatches(true)
	if len(s.notify.st.Notices) != 1 {
		t.Fatal("기준선 이후 새 취약점은 통보해야 함")
	}
}

func TestNotifyVexCustomerBody(t *testing.T) {
	s := testNotifyServer(t)
	vex := `{"vulnerabilities":[
	 {"id":"CVE-1","ratings":[{"severity":"high"}],"analysis":{"state":"exploitable","response":["update"],"detail":"내부 메모: 담당자 확인 중"}},
	 {"id":"CVE-2","analysis":{"state":"not_affected","justification":"code_not_reachable","detail":"비공개 코멘트"}}]}`
	s.notifyVexPublished("products/innopouch", "7.0", []byte(vex))
	n := s.notify.st.Notices[0]
	if n.Audience != "customer" || !strings.Contains(n.Title, "영향 있음 1") || !strings.Contains(n.Title, "영향 없음 1") {
		t.Errorf("title=%q", n.Title)
	}
	if strings.Contains(n.Body, "메모") || strings.Contains(n.Body, "코멘트") {
		t.Errorf("개발자 코멘트가 고객 본문에 들어감:\n%s", n.Body)
	}
	if !strings.Contains(n.Body, "실행 경로에 없음") || !strings.Contains(n.Body, "조치: update") {
		t.Errorf("본문:\n%s", n.Body)
	}
}

func TestLatestSBOM(t *testing.T) {
	refs := []ociDesc{
		{ArtifactType: "application/vnd.cyclonedx+json", Digest: "old", Annotations: map[string]string{"org.opencontainers.image.created": "2026-10-01T00:00:00Z"}},
		{ArtifactType: "application/vnd.cyclonedx.vex+json", Digest: "vex", Annotations: map[string]string{"org.opencontainers.image.created": "2026-12-01T00:00:00Z"}},
		{ArtifactType: "application/vnd.cyclonedx+json", Digest: "new", Annotations: map[string]string{"org.opencontainers.image.created": "2026-11-01T00:00:00Z"}},
	}
	if got := latestSBOM(refs); got != "new" {
		t.Errorf("got %s", got)
	}
}

func TestNotifyQuietOnlyOldVersions(t *testing.T) {
	s := testNotifyServer(t)
	s.notify.st.Projects["innopouch@8.0"] = "products/innopouch"
	now := time.Now().UTC()
	s.notify.st.QuietSince = now.Format(time.RFC3339)
	s.notify.st.QuietUntil = now.Add(time.Hour).Format(time.RFC3339)
	s.notify.st.SyncedAt["products/innopouch|7.0"] = now.Add(-24 * time.Hour).Format(time.RFC3339) // 변경 전부터 감시
	s.notify.st.SyncedAt["products/innopouch|8.0"] = now.Add(time.Minute).Format(time.RFC3339)     // 변경 뒤 새로 올림
	s.queueVulnNotice(dtVuln("CVE-Q1", "high", "innopouch", "7.0"))
	s.queueVulnNotice(dtVuln("CVE-Q2", "high", "innopouch", "8.0"))
	s.flushBatches(true)
	if len(s.notify.st.Notices) != 1 || s.notify.st.Notices[0].Tag != "8.0" {
		t.Fatalf("보류는 변경 전 버전에만: %+v", s.notify.st.Notices)
	}
	s.notify.st.QuietUntil = now.Add(-time.Minute).Format(time.RFC3339)
	s.queueVulnNotice(dtVuln("CVE-Q3", "high", "innopouch", "7.0"))
	s.flushBatches(true)
	if len(s.notify.st.Notices) != 2 {
		t.Fatal("보류 기한이 지나면 통보해야 함")
	}
}

func TestSplitEco(t *testing.T) {
	if got := splitEco(" npm; Maven;;PyPI "); strings.Join(got, ",") != "npm,Maven,PyPI" {
		t.Errorf("got %v", got)
	}
	if got := splitEco(""); len(got) != 0 {
		t.Errorf("got %v", got)
	}
}

func TestNotifyBodyCapped(t *testing.T) {
	s := testNotifyServer(t)
	for i := 0; i < 45; i++ {
		s.queueVulnNotice(dtVuln(fmt.Sprintf("CVE-C%02d", i), "low", "innopouch", "7.0"))
	}
	s.flushBatches(true)
	n := s.notify.st.Notices[0]
	if !strings.Contains(n.Title, "45건") || !strings.Contains(n.Body, "- 외 15건") || strings.Count(n.Body, "\n- CVE-") != 30 {
		t.Errorf("title=%q body=\n%s", n.Title, n.Body)
	}
}
