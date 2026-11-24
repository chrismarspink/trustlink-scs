package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func fastFinding() dtFindingFull {
	var f dtFindingFull
	f.Component.Name, f.Component.Version, f.Component.Purl = "libx", "1.2.0", "pkg:npm/libx@1.2.0"
	f.Vulnerability.VulnID, f.Vulnerability.Severity, f.Vulnerability.Description = "CVE-2026-0001", "HIGH", "A flaw in libx allows remote code execution."
	return f
}

// 사용 맥락이 없으면 규칙만으로 판정한다 — OSV 범위·수정 버전에 따라.
func TestVexRuleDraft(t *testing.T) {
	f := fastFinding()
	cases := []struct {
		name         string
		osv          osvRemedy
		status, resp string
	}{
		{"범위 밖", osvRemedy{Checked: true, InRange: "no", Ranges: []string{"< 1.0.0"}}, "not_affected", ""},
		{"범위 안 + 수정 버전", osvRemedy{Checked: true, InRange: "yes", Target: "1.2.5", Fixed: []string{"1.2.5"}}, "affected", "update"},
		{"범위 안 + 수정 없음", osvRemedy{Checked: true, InRange: "yes"}, "under_investigation", ""},
		{"확인 불가", osvRemedy{NoReason: "purl 없음"}, "under_investigation", ""},
	}
	for _, c := range cases {
		sig := vexSignals{OSV: c.osv}
		facts := vexFacts(f, "", sig)
		d := vexRuleDraft(f, sig, facts, nil)
		warn := guardVexDraft(&d, facts, sig)
		if d.Status != c.status || d.Response != c.resp {
			t.Errorf("%s: %s/%s (경고 %v)", c.name, d.Status, d.Response, warn)
		}
		if len(d.Plan) < 2 || len(d.Citations) == 0 || d.Detail == "" {
			t.Errorf("%s: 빈 칸이 있음 %+v", c.name, d)
		}
		for _, w := range warn { // 규칙 초안이 지어낸 버전 경고를 내면 안 된다
			if strings.Contains(w, "없는 버전") {
				t.Errorf("%s: %s", c.name, w)
			}
		}
	}
	// KEV 면 계획 첫 줄이 긴급, 요약 카드가 있으면 이유에 들어간다
	sig := vexSignals{KEV: true, KEVDue: "2026-12-01", OSV: osvRemedy{Checked: true, InRange: "yes", Target: "1.2.5"}}
	facts := vexFacts(f, "", sig)
	d := vexRuleDraft(f, sig, facts, &vulnCard{Summary: "원격에서 코드를 실행할 수 있습니다.", Condition: "인증 없이 접근 가능할 때", Workaround: "기능을 끈다"})
	if !strings.HasPrefix(d.Plan[0], "긴급") || !strings.Contains(d.Detail, "원격에서 코드를 실행") || d.Workaround != "기능을 끈다" || !inList("V3", d.Citations) {
		t.Errorf("KEV·카드: %+v", d)
	}
}

// 빠른 경로: 맥락 없으면 AI 를 부르지 않고 낸다(AI 미설정이어도 동작).
func TestVexFastDraftNoAI(t *testing.T) {
	s := testCustServer(t)
	t.Setenv("AI_CONFIG", filepath.Join(t.TempDir(), "a.json"))
	res, err := s.vexFastDraftFor("admin", "products/prod", "1.0", fastFinding(), "", false)
	if err != nil || res.Meta.Method != "rule" || res.Draft.Status == "" || res.Meta.ElapsedMs > 2000 {
		t.Fatalf("규칙 초안: %v %+v", err, res)
	}
}
