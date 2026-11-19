package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCmpVersion(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.14.1", "2.15.0", -1}, {"2.15.0", "2.15.0", 0}, {"v1.10.0", "1.9.9", 1},
		{"2.0.0-rc1", "2.0.0", -1}, {"2.0.0", "2.0.0-beta", 1}, {"5.3.18.Final", "5.3.18", 0 + 1},
	}
	for _, c := range cases {
		if got := osvCmpVersion(c.a, c.b); got != c.want {
			t.Errorf("osvCmpVersion(%s,%s)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestParsePurl(t *testing.T) {
	p, ok := parsePurl("pkg:npm/%40babel/traverse@7.22.0?foo=1")
	if !ok || p.Namespace != "@babel" || p.Name != "traverse" || p.Version != "7.22.0" {
		t.Fatalf("%+v", p)
	}
	if eco, n := osvTarget(p); eco != "npm" || n != "@babel/traverse" {
		t.Fatal(eco, n)
	}
	m, _ := parsePurl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
	if eco, n := osvTarget(m); eco != "Maven" || n != "org.apache.logging.log4j:log4j-core" {
		t.Fatal(eco, n)
	}
}

func writeZip(t *testing.T, path string, files map[string]string) {
	os.MkdirAll(filepath.Dir(path), 0o755)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for n, c := range files {
		w, _ := zw.Create(n)
		w.Write([]byte(c))
	}
	zw.Close()
	f.Close()
}

func TestOSVAndExploits(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MIRROR_DIR", dir)
	writeZip(t, filepath.Join(dir, "data/osv-vulnerabilities.storage.googleapis.com/Maven/all.zip"), map[string]string{
		"GHSA-jfh8-c2jp-5v3q.json": `{"id":"GHSA-jfh8-c2jp-5v3q","aliases":["CVE-2021-44228"],"affected":[
		 {"package":{"ecosystem":"Maven","name":"org.apache.logging.log4j:log4j-core"},
		  "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.13.0"},{"fixed":"2.15.0"},{"introduced":"2.0-beta9"},{"fixed":"2.3.1"},{"introduced":"2.4"},{"fixed":"2.12.2"}]}]}]}`,
		"MAL-0001.json": `{"id":"MAL-0001","aliases":["CVE-2021-44228"]}`,
	})
	purl := "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
	r := osvLookup(purl, "2.14.1", []string{"CVE-2021-44228"})
	if !r.Checked || r.InRange != "yes" || r.Target != "2.15.0" || r.Source != "GHSA-jfh8-c2jp-5v3q" {
		t.Fatalf("범위 안·목표 2.15.0: %+v", r)
	}
	r = osvLookup(purl, "2.11.0", []string{"CVE-2021-44228"})
	if r.InRange != "yes" || r.Target != "2.12.2" {
		t.Fatalf("2.4~2.12.2 범위: %+v", r)
	}
	r = osvLookup(purl, "2.17.1", []string{"CVE-2021-44228"})
	if r.InRange != "no" || r.Target != "" {
		t.Fatalf("범위 밖: %+v", r)
	}
	if r := osvLookup("pkg:deb/debian/openssl@3.0", "", []string{"CVE-1"}); r.Checked || r.NoReason == "" {
		t.Fatalf("배포판 패키지는 미지원 표시: %+v", r)
	}

	edb := filepath.Join(dir, "data/gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv")
	os.MkdirAll(filepath.Dir(edb), 0o755)
	os.WriteFile(edb, []byte("id,file,description,codes\n50592,x.py,\"Log4Shell, RCE\",CVE-2021-44228;OSVDB-1\n"), 0o644)
	nuc := filepath.Join(dir, "data/raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json")
	os.MkdirAll(filepath.Dir(nuc), 0o755)
	os.WriteFile(nuc, []byte(`{"ID":"CVE-2021-44228","Info":{}}`+"\n"), 0o644)
	ex := exploitsFor([]string{"cve-2021-44228"})
	if !ex.Checked || len(ex.EDB) != 1 || !ex.Nuclei || !strings.Contains(exploitText(ex), "Exploit-DB 1건") {
		t.Fatalf("익스플로잇: %+v", ex)
	}

	// 판정 사실·우선순위·안전장치
	f := dtFindingFull{}
	f.Vulnerability.VulnID = "CVE-2021-44228"
	f.Vulnerability.Severity = "HIGH"
	f.Component.Name, f.Component.Version, f.Component.Purl = "log4j-core", "2.14.1", purl
	sig := vexSignalsFor(f)
	if vexPriority(f, sig) != 2 {
		t.Fatal("공개 익스플로잇이면 P2")
	}
	facts := vexFacts(f, "", sig)
	blk := factsBlock(facts, "ko")
	if !strings.Contains(blk, "[R1]") || !strings.Contains(blk, "최소 수정 버전 2.15.0") || !strings.Contains(blk, "[X3]") {
		t.Fatalf("대응 사실 누락: %s", blk)
	}
	d := vexDraft{Status: "affected", Detail: "2.16.3 으로 올린다 [R1]", Plan: []string{"2.15.0 으로 올린다 [R1]"}, Citations: []string{"R1"}}
	w := guardVexDraft(&d, facts, sig)
	if d.Response != "update" || !strings.Contains(strings.Join(w, "|"), "2.16.3") || strings.Contains(strings.Join(w, "|"), "2.15.0 —") {
		t.Fatalf("응답 보정·지어낸 버전 경고: %+v %v", d, w)
	}
	// OSV 범위 밖이면 맥락 없이도 not_affected 유지(경고 포함)
	f.Component.Version, f.Component.Purl = "2.17.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"
	sig = vexSignalsFor(f)
	facts = vexFacts(f, "", sig)
	d = vexDraft{Status: "not_affected", Justification: "vulnerable_code_not_present", Citations: []string{"R1"}}
	w = guardVexDraft(&d, facts, sig)
	if d.Status != "not_affected" || !strings.Contains(strings.Join(w, "|"), "OSV") {
		t.Fatalf("OSV 범위 밖 근거: %+v %v", d, w)
	}
}

func TestVexBatchPick(t *testing.T) {
	t.Setenv("MIRROR_DIR", t.TempDir())
	mk := func(id, sev, state string, epss float64) dtFindingFull {
		var f dtFindingFull
		f.Vulnerability.VulnID, f.Vulnerability.Severity, f.Analysis.State = id, sev, state
		f.Vulnerability.EpssScore = &epss
		return f
	}
	fs := []dtFindingFull{mk("A", "LOW", "", 0.01), mk("B", "HIGH", "NOT_SET", 0.02), mk("C", "CRITICAL", "", 0.5),
		mk("D", "CRITICAL", "NOT_AFFECTED", 0.9), mk("E", "MEDIUM", "", 0.3)}
	got := []string{}
	for _, f := range vexBatchPick(fs, 3) {
		got = append(got, f.Vulnerability.VulnID)
	}
	if strings.Join(got, ",") != "C,E,B" {
		t.Fatalf("미분석만 우선순위·EPSS 순: %v", got)
	}
}
