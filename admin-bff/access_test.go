package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		p, n string
		want bool
	}{
		{"**", "products/npouch", true},
		{"products/**", "products/npouch", true},
		{"products/**", "products/a/b", true},
		{"products/**", "innotium/x", false},
		{"products/npouch", "products/npouch", true},
		{"products/npouch/**", "products/npouch", true},
		{"products/npouch/**", "products/npouch2", false},
		{"products/*", "products/a/b", false},
	}
	for _, c := range cases {
		if got := globMatch(c.p, c.n); got != c.want {
			t.Errorf("globMatch(%q,%q)=%v want %v", c.p, c.n, got, c.want)
		}
	}
}

const testTemplate = `{
 "http": {"accessControl": {
   "repositories": {
     "**": {"defaultPolicy": []},
     "products/**": {"policies": [{"users": ["ci"], "groups": ["developers"], "actions": ["read","create","update"]}], "defaultPolicy": []}
   },
   "adminPolicy": {"groups": ["admins"], "users": ["svc-bff"], "actions": ["read","create","update","delete"]}
 }}
}`

func newTestManager(t *testing.T) *accessManager {
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "tmpl.json")
	os.WriteFile(tmpl, []byte(testTemplate), 0o644)
	m := &accessManager{
		storePath: filepath.Join(dir, "store", "access-policy.json"), tmplPath: tmpl, outDir: filepath.Join(dir, "out"),
		baseUsers: "ci:$2y$base\n", oidcCreds: []byte(`{"clientid":"zot"}`), now: time.Now,
		hasher: func(u, p string) (string, error) { return u + ":$2y$" + p, nil },
	}
	if err := m.render(); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestAccessPolicyRenderAndEvaluate(t *testing.T) {
	m := newTestManager(t)
	// 개별 설정 없는 제품: 내부(개발자·ci)만
	if !m.allowed("dev1", []string{"developers"}, "products/npouch", "create") {
		t.Fatal("개발자는 업로드 가능해야 함")
	}
	if m.allowed("acme1", []string{"users", "org-acme"}, "products/npouch", "read") {
		t.Fatal("권한 없는 고객은 읽기 불가여야 함")
	}
	if !m.allowed("admin1", []string{"admins"}, "products/npouch", "delete") {
		t.Fatal("관리자는 전체 권한")
	}

	err := m.update(func(p *AccessPolicy) error {
		p.Products = append(p.Products, ProductPolicy{Repo: "products/npouch",
			Writers: []Principal{{"group", "developers"}, {"user", "ci-npouch"}},
			Readers: []Principal{{"group", "org-acme"}, {"user", "robot-acme"}}})
		p.Robots = append(p.Robots,
			Robot{Name: "robot-acme", Kind: "pull", Hash: "robot-acme:$2y$x"},
			Robot{Name: "robot-old", Kind: "pull", Hash: "robot-old:$2y$y", Expires: time.Now().Add(-time.Hour).Format(time.RFC3339)})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	chk := []struct {
		user   string
		groups []string
		repo   string
		action string
		want   bool
	}{
		{"acme1", []string{"users", "org-acme"}, "products/npouch", "read", true},
		{"acme1", []string{"users", "org-acme"}, "products/npouch", "create", false}, // 고객은 쓰기 불가
		{"acme1", []string{"users", "org-acme"}, "products/webapp", "read", false},   // 허용 안 된 제품
		{"beta1", []string{"users", "org-beta"}, "products/npouch", "read", false},   // 다른 고객사
		{"robot-acme", nil, "products/npouch", "read", true},
		{"ci-npouch", nil, "products/npouch", "create", true},
		{"ci", nil, "products/npouch", "create", false}, // 개별 설정에서 ci 를 빼면 기본 규칙 대신 이 설정이 적용
		{"dev1", []string{"developers"}, "products/npouch/sub", "update", true},
	}
	for _, c := range chk {
		if got := m.allowed(c.user, c.groups, c.repo, c.action); got != c.want {
			t.Errorf("%s %v %s %s = %v want %v", c.user, c.groups, c.repo, c.action, got, c.want)
		}
	}

	// 렌더 결과: zot 설정에 제품 정책, htpasswd 에 유효한 기계 계정만
	cfgB, _ := os.ReadFile(filepath.Join(m.outDir, "config.json"))
	var cfg map[string]any
	if err := json.Unmarshal(cfgB, &cfg); err != nil {
		t.Fatal(err)
	}
	repos := dig(cfg, "http", "accessControl", "repositories").(map[string]any)
	if repos["products/npouch"] == nil || repos["products/npouch/**"] == nil {
		t.Fatal("제품 정책이 렌더되지 않음")
	}
	hp, _ := os.ReadFile(filepath.Join(m.outDir, "htpasswd"))
	if !strings.Contains(string(hp), "ci:$2y$base") || !strings.Contains(string(hp), "robot-acme:") || strings.Contains(string(hp), "robot-old") {
		t.Fatalf("htpasswd = %q", hp)
	}

	// 계정(htpasswd)만 바뀌어도 config.json 을 다시 써서 zot 리로드를 일으켜야 한다(재발급 반영)
	cfgPath := filepath.Join(m.outDir, "config.json")
	before, _ := os.Stat(cfgPath)
	time.Sleep(20 * time.Millisecond)
	if err := m.update(func(p *AccessPolicy) error { p.Robots[0].Hash = "robot-acme:$2y$new"; return nil }); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(cfgPath)
	if !after.ModTime().After(before.ModTime()) {
		t.Fatal("htpasswd 만 변경 시 config.json 재기록 안 됨")
	}

	// 저장 후 재기동해도 정책 유지
	m2 := &accessManager{storePath: m.storePath, tmplPath: m.tmplPath, outDir: m.outDir, now: time.Now, hasher: m.hasher}
	if err := m2.load(); err != nil || m2.render() != nil {
		t.Fatal("재로드 실패")
	}
	if !m2.allowed("acme1", []string{"org-acme"}, "products/npouch", "read") {
		t.Fatal("재기동 후 정책 유실")
	}
}

func TestUserGroupsFor(t *testing.T) {
	gs, err := userGroupsFor("users", []string{"acme", "org-beta"})
	if err != nil || strings.Join(gs, ",") != "users,org-acme,org-beta" {
		t.Fatalf("%v %v", gs, err)
	}
	if _, err := userGroupsFor("root", nil); err == nil {
		t.Fatal("잘못된 역할 허용")
	}
	if !reservedUserPrefix.MatchString("robot-acme") || !reservedUserPrefix.MatchString("ci") || reservedUserPrefix.MatchString("circle") {
		t.Fatal("예약 이름 규칙 오류")
	}
}
