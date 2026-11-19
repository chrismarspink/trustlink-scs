package main

// 취약점 DB 미러(vuln-mirror) — `trustlink-admin mirror` 로 실행하는 별도 프로세스(별도 컨테이너).
//
//  - 공개 취약점·위협·라이선스 DB 를 원본 경로 그대로(<호스트>/<경로>) 로컬 볼륨에 내려받아 HTTP 로 내부에 제공한다.
//    → DT 등은 URL 의 호스트 부분만 http://vuln-mirror:8090/<호스트> 로 바꾸면 같은 경로로 받는다.
//  - 외부 접속은 이 프로세스만, 정책의 "접속 창" 안에서만 한다. 폐쇄망 모드에서는 외부 접속을 전혀 하지 않는다.
//    상위 미러를 지정하면 원본 대신 상위 미러(<상위>/<호스트>/<경로>)에서 받는다(DMZ → 폐쇄망 연쇄).
//  - 파일마다 SHA-256·크기·받은 시각을 매니페스트에 남기고, 매니페스트 전체 해시를 "스냅샷 ID" 로 쓴다
//    (그날 어떤 DB 로 판정했는지 재현·증명용).
//  - 디스크 여유가 MinFreeGB 아래로 내려가면 받지 않는다(같은 디스크를 쓰는 기존 서비스 보호).
//  - 기본 모드는 폐쇄망(외부 접속 없음). 관리 화면에서 정기 접속으로 바꿔야 받기 시작한다.

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

var kst = time.FixedZone("KST", 9*3600)

const mirrorUA = "trustlink-vuln-mirror/1.0"

// ---------- 카탈로그 ----------

type mirrorSource struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Group     string   `json:"group"`    // 1차·2차·스캐너
	Category  string   `json:"category"` // 취약점·악용·위협·EOL·라이선스·제조사 VEX …
	Use       string   `json:"use"`      // TrustLink 에서 어디에 쓰는지
	License   string   `json:"license"`
	Hosts     []string `json:"hosts"` // 외부 접속 허용 도메인(방화벽 목록)
	IntervalH int      `json:"defaultIntervalH"`
	run       func(r *runCtx) error
}

func each(r *runCtx, urls ...string) error {
	for _, u := range urls {
		if err := r.get(u); err != nil {
			return err
		}
	}
	return nil
}

func years(from int) []int {
	out := []int{}
	for y := from; y <= time.Now().In(kst).Year(); y++ {
		out = append(out, y)
	}
	return out
}

// 출처는 2026-11-17 에 접근·크기를 실측한 것만 넣었다.
var mirrorCatalog = []mirrorSource{
	// ── 1차: 분석에 직접 쓰는 DB
	{ID: "nvd-cve", Name: "NVD CVE (JSON 2.0, 연도별)", Group: "1차", Category: "취약점", Use: "CPE 대조·CVSS", License: "공개(미 정부)",
		Hosts: []string{"nvd.nist.gov"}, IntervalH: 24, run: func(r *runCtx) error {
			b := "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-"
			for _, n := range append([]string{"modified", "recent"}, func() (s []string) {
				for _, y := range years(2002) {
					s = append(s, fmt.Sprint(y))
				}
				return
			}()...) {
				if err := each(r, b+n+".json.gz", b+n+".meta"); err != nil {
					return err
				}
			}
			return nil
		}},
	{ID: "nvd-cpe", Name: "NVD CPE 사전", Group: "1차", Category: "식별자", Use: "부품 식별 보정", License: "공개(미 정부)",
		Hosts: []string{"nvd.nist.gov"}, IntervalH: 168, run: func(r *runCtx) error {
			return r.get("https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz")
		}},
	{ID: "nvd-cpematch", Name: "NVD CPE Match", Group: "1차", Category: "식별자", Use: "CPE ↔ 영향 버전 범위", License: "공개(미 정부)",
		Hosts: []string{"nvd.nist.gov"}, IntervalH: 168, run: func(r *runCtx) error {
			return r.get("https://nvd.nist.gov/feeds/json/cpematch/2.0/nvdcpematch-2.0.tar.gz")
		}},
	{ID: "osv", Name: "OSV 전 생태계", Group: "1차", Category: "취약점", Use: "purl 대조(GHSA·악성 패키지 포함)", License: "CC-BY 4.0 등(생태계별)",
		Hosts: []string{"osv-vulnerabilities.storage.googleapis.com"}, IntervalH: 24, run: func(r *runCtx) error {
			base := "https://osv-vulnerabilities.storage.googleapis.com/"
			if err := r.get(base + "ecosystems.txt"); err != nil {
				return err
			}
			lines, err := r.readLines(base + "ecosystems.txt")
			if err != nil {
				return err
			}
			for _, e := range lines {
				if err := r.get(base + url.PathEscape(e) + "/all.zip"); err != nil {
					return err
				}
			}
			return nil
		}},
	{ID: "kev", Name: "CISA KEV (실제 악용 목록)", Group: "1차", Category: "악용", Use: "우선순위·KEV 기한(G-07)", License: "CC0",
		Hosts: []string{"www.cisa.gov"}, IntervalH: 24, run: func(r *runCtx) error {
			return each(r, "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
				"https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv")
		}},
	{ID: "epss", Name: "FIRST EPSS (악용 가능성 점수)", Group: "1차", Category: "악용", Use: "우선순위", License: "FIRST 이용약관(출처 표기)",
		Hosts: []string{"epss.cyentia.com", "epss.empiricalsecurity.com"}, IntervalH: 24, run: func(r *runCtx) error {
			return r.get("https://epss.cyentia.com/epss_scores-current.csv.gz")
		}},
	// ── 2차: 판정·보고 보강
	{ID: "vulnrichment", Name: "CISA Vulnrichment (SSVC·CWE·CVSS 보강)", Group: "2차", Category: "취약점 보강", Use: "NVD 분석 지연 보완·SSVC", License: "CC0",
		Hosts: []string{"codeload.github.com"}, IntervalH: 24, run: func(r *runCtx) error {
			return r.get("https://codeload.github.com/cisagov/vulnrichment/tar.gz/refs/heads/develop")
		}},
	{ID: "cvelist", Name: "CVE List V5 (CVE 원본, 일일 기준본)", Group: "2차", Category: "취약점", Use: "NVD 보다 이른 원천", License: "CVE 이용약관",
		Hosts: []string{"api.github.com", "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}, IntervalH: 168, run: func(r *runCtx) error {
			api := "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
			if err := r.get(api); err != nil {
				return err
			}
			var rel struct {
				Assets []struct {
					Name               string `json:"name"`
					BrowserDownloadURL string `json:"browser_download_url"`
				} `json:"assets"`
			}
			if err := r.readJSON(api, &rel); err != nil {
				return err
			}
			for _, a := range rel.Assets {
				if strings.Contains(a.Name, "_all_CVEs_at_midnight") {
					return r.get(a.BrowserDownloadURL)
				}
			}
			return errors.New("기준본(all_CVEs_at_midnight) 자산을 찾지 못함")
		}},
	{ID: "ghsa", Name: "GitHub Advisory Database", Group: "2차", Category: "취약점", Use: "생태계 권고 원문(검토된 권고)", License: "CC-BY 4.0",
		Hosts: []string{"codeload.github.com"}, IntervalH: 24, run: func(r *runCtx) error {
			return r.get("https://codeload.github.com/github/advisory-database/tar.gz/refs/heads/main")
		}},
	{ID: "euvd", Name: "ENISA EUVD (최근·악용·치명)", Group: "2차", Category: "취약점", Use: "EU CRA 대응(EU 공식 DB)", License: "ENISA 이용약관",
		Hosts: []string{"euvdservices.enisa.europa.eu"}, IntervalH: 24, run: func(r *runCtx) error {
			b := "https://euvdservices.enisa.europa.eu/api/"
			for _, p := range []string{"lastvulnerabilities", "exploitedvulnerabilities", "criticalvulnerabilities"} {
				if err := r.tryGet(b + p); err != nil {
					return err
				}
			}
			return nil
		}},
	{ID: "jvn", Name: "JVN iPedia (일본, 연도별)", Group: "2차", Category: "취약점", Use: "일본 수출 대응", License: "JVN 이용약관",
		Hosts: []string{"jvndb.jvn.jp"}, IntervalH: 168, run: func(r *runCtx) error {
			for _, y := range years(1998) {
				if err := r.tryGet(fmt.Sprintf("https://jvndb.jvn.jp/ja/feed/detail/jvndb_detail_%d.rdf", y)); err != nil {
					return err
				}
			}
			return nil
		}},
	{ID: "eol", Name: "endoflife.date (제품 지원 종료)", Group: "2차", Category: "EOL", Use: "EOL 탐지(G-08)", License: "MIT",
		Hosts: []string{"endoflife.date"}, IntervalH: 168, run: func(r *runCtx) error {
			return r.get("https://endoflife.date/api/v1/products/full")
		}},
	{ID: "redhat-vex", Name: "Red Hat CSAF VEX (전체 묶음)", Group: "2차", Category: "제조사 VEX", Use: "상위 제조사 VEX 재사용", License: "CC-BY 4.0",
		Hosts: []string{"security.access.redhat.com"}, IntervalH: 168, run: func(r *runCtx) error {
			return r.latestArchive("https://security.access.redhat.com/data/csaf/v2/vex/")
		}},
	{ID: "redhat-csaf", Name: "Red Hat CSAF 권고 (전체 묶음)", Group: "2차", Category: "제조사 권고", Use: "배포판 패치 근거", License: "CC-BY 4.0",
		Hosts: []string{"security.access.redhat.com"}, IntervalH: 168, run: func(r *runCtx) error {
			return r.latestArchive("https://security.access.redhat.com/data/csaf/v2/advisories/")
		}},
	{ID: "debian", Name: "Debian Security Tracker", Group: "2차", Category: "제조사 판정", Use: "배포판 패치·미영향 판정", License: "공개",
		Hosts: []string{"security-tracker.debian.org"}, IntervalH: 24, run: func(r *runCtx) error {
			return r.get("https://security-tracker.debian.org/tracker/data/json")
		}},
	{ID: "circl-csaf", Name: "CSAF 권고 묶음 (CISA·CERT-Bund·Siemens·Cisco·Microsoft·CERT-FR)", Group: "2차", Category: "제조사 권고", Use: "ICS·방산 장비 권고", License: "출처별(CIRCL 수집)",
		Hosts: []string{"vulnerability.circl.lu"}, IntervalH: 168, run: func(r *runCtx) error {
			b := "https://vulnerability.circl.lu/dumps/"
			return each(r, b+"csaf_cisa.ndjson", b+"csaf_certbund.ndjson", b+"csaf_siemens.ndjson",
				b+"csaf_cisco.ndjson", b+"csaf_microsoft.ndjson", b+"certfr_avis.ndjson", b+"certfr_alerte.ndjson")
		}},
	{ID: "exploits", Name: "공개 익스플로잇 (Exploit-DB·Metasploit·Nuclei)", Group: "2차", Category: "악용", Use: "공격 코드 공개 여부", License: "GPL·BSD·MIT(메타데이터)",
		Hosts: []string{"gitlab.com", "raw.githubusercontent.com"}, IntervalH: 24, run: func(r *runCtx) error {
			return each(r, "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
				"https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json",
				"https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json")
		}},
	{ID: "mitre", Name: "MITRE CWE·CAPEC·ATT&CK(Enterprise·ICS)", Group: "2차", Category: "위협 분류", Use: "보고서 분류·위협 모델링 근거", License: "MITRE 이용약관",
		Hosts: []string{"cwe.mitre.org", "capec.mitre.org", "raw.githubusercontent.com"}, IntervalH: 720, run: func(r *runCtx) error {
			return each(r, "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip", "https://capec.mitre.org/data/xml/capec_latest.xml",
				"https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
				"https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json")
		}},
	{ID: "spdx", Name: "SPDX 라이선스 목록", Group: "2차", Category: "라이선스", Use: "SBOM 라이선스 정규화", License: "CC0",
		Hosts: []string{"spdx.org"}, IntervalH: 168, run: func(r *runCtx) error {
			return each(r, "https://spdx.org/licenses/licenses.json", "https://spdx.org/licenses/exceptions.json")
		}},
	// ── 스캐너 DB: 폐쇄망에서 Grype·Trivy 를 그대로 돌리기 위한 완성본
	{ID: "grype-db", Name: "Grype DB v6", Group: "스캐너", Category: "스캐너 DB", Use: "폐쇄망 교차 검증 스캔", License: "Apache-2.0(도구)·출처별",
		Hosts: []string{"grype.anchore.io"}, IntervalH: 24, run: func(r *runCtx) error {
			idx := "https://grype.anchore.io/databases/v6/latest.json"
			if err := r.get(idx); err != nil {
				return err
			}
			var l struct{ Path string }
			if err := r.readJSON(idx, &l); err != nil {
				return err
			}
			if l.Path == "" || strings.Contains(l.Path, "/") {
				return errors.New("latest.json 형식이 예상과 다름")
			}
			return r.get("https://grype.anchore.io/databases/v6/" + l.Path)
		}},
	{ID: "trivy-db", Name: "Trivy DB · Java DB", Group: "스캐너", Category: "스캐너 DB", Use: "폐쇄망 교차 검증 스캔", License: "Apache-2.0(도구)·출처별",
		Hosts: []string{"ghcr.io", "pkg-containers.githubusercontent.com"}, IntervalH: 24, run: func(r *runCtx) error {
			if err := r.ociLayer("aquasecurity/trivy-db", "2", "ghcr.io/aquasecurity/trivy-db/2/db.tar.gz"); err != nil {
				return err
			}
			return r.ociLayer("aquasecurity/trivy-java-db", "1", "ghcr.io/aquasecurity/trivy-java-db/1/javadb.tar.gz")
		}},
}

func sourceByID(id string) *mirrorSource {
	for i := range mirrorCatalog {
		if mirrorCatalog[i].ID == id {
			return &mirrorCatalog[i]
		}
	}
	return nil
}

// ---------- 정책·상태 ----------

type mirrorPolicy struct {
	Mode        string                  `json:"mode"`        // scheduled(정기 접속) | offline(외부 접속 없음)
	WindowStart string                  `json:"windowStart"` // "02:00" KST
	WindowEnd   string                  `json:"windowEnd"`   // "06:00" KST (자정을 넘겨도 됨)
	Upstream    string                  `json:"upstream"`    // 비우면 원본. 지정하면 상위 미러에서 받음
	MinFreeGB   int                     `json:"minFreeGB"`
	Sources     map[string]sourcePolicy `json:"sources"`
}

type sourcePolicy struct {
	Enabled   bool `json:"enabled"`
	IntervalH int  `json:"intervalH"`
}

func defaultPolicy() mirrorPolicy {
	p := mirrorPolicy{Mode: "offline", WindowStart: "02:00", WindowEnd: "06:00", MinFreeGB: 20, Sources: map[string]sourcePolicy{}}
	for _, s := range mirrorCatalog {
		p.Sources[s.ID] = sourcePolicy{Enabled: true, IntervalH: s.IntervalH}
	}
	return p
}

type fileEntry struct {
	Path    string `json:"path"`
	Source  string `json:"source"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
	ETag    string `json:"etag,omitempty"`
	LastMod string `json:"lastModified,omitempty"`
	Fetched string `json:"fetched"` // 내용이 바뀌어 새로 받은 시각
	Checked string `json:"checked"` // 마지막으로 원본과 대조한 시각
}

type sourceState struct {
	LastAttempt string `json:"lastAttempt,omitempty"`
	LastSuccess string `json:"lastSuccess,omitempty"`
	Status      string `json:"status"` // never | running | ok | error
	Error       string `json:"error,omitempty"`
	Changed     int    `json:"changed"` // 마지막 실행에서 바뀐 파일 수
}

type runRecord struct {
	ID       string `json:"id"`
	Trigger  string `json:"trigger"` // schedule | manual
	Start    string `json:"start"`
	End      string `json:"end"`
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
	Changed  int    `json:"changed"`
	Bytes    int64  `json:"bytes"`
	Snapshot string `json:"snapshot"`
}

type mirror struct {
	dir     string // 루트(data/, _state/)
	mu      sync.Mutex
	runMu   sync.Mutex // 한 번에 한 출처만 받는다
	policy  mirrorPolicy
	files   map[string]*fileEntry
	states  map[string]*sourceState
	running string
	key     string
	client  *http.Client
}

func (m *mirror) dataDir() string           { return filepath.Join(m.dir, "data") }
func (m *mirror) statePath(n string) string { return filepath.Join(m.dir, "_state", n) }

func readJSONFile(p string, v any) error {
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func writeJSONFile(p string, v any) error {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func (m *mirror) load() error {
	if err := os.MkdirAll(m.statePath(""), 0o750); err != nil {
		return err
	}
	if err := os.MkdirAll(m.dataDir(), 0o755); err != nil {
		return err
	}
	m.policy = defaultPolicy()
	var p mirrorPolicy
	if readJSONFile(m.statePath("policy.json"), &p) == nil {
		m.policy = mergePolicy(p)
	}
	m.files = map[string]*fileEntry{}
	_ = readJSONFile(m.statePath("manifest.json"), &m.files)
	m.states = map[string]*sourceState{}
	_ = readJSONFile(m.statePath("sources.json"), &m.states)
	for _, st := range m.states {
		if st.Status == "running" { // 재시작으로 끊긴 실행
			st.Status, st.Error = "error", "중단됨(재시작)"
		}
	}
	// 내부 API 쓰기 키: 볼륨에 두고 BFF 가 읽기 전용으로 마운트해 쓴다(.env 불필요)
	if b, err := os.ReadFile(m.statePath("api.key")); err == nil && len(b) >= 32 {
		m.key = strings.TrimSpace(string(b))
	} else {
		buf := make([]byte, 24)
		if _, err := rand.Read(buf); err != nil {
			return err
		}
		m.key = hex.EncodeToString(buf)
		if err := os.WriteFile(m.statePath("api.key"), []byte(m.key), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// mergePolicy: 저장된 정책에 카탈로그 신규 출처의 기본값을 채운다.
func mergePolicy(p mirrorPolicy) mirrorPolicy {
	d := defaultPolicy()
	if p.Mode != "scheduled" && p.Mode != "offline" {
		p.Mode = d.Mode
	}
	if _, err := parseHM(p.WindowStart); err != nil {
		p.WindowStart = d.WindowStart
	}
	if _, err := parseHM(p.WindowEnd); err != nil {
		p.WindowEnd = d.WindowEnd
	}
	if p.MinFreeGB < 1 {
		p.MinFreeGB = d.MinFreeGB
	}
	if p.Sources == nil {
		p.Sources = map[string]sourcePolicy{}
	}
	for id, sp := range d.Sources {
		cur, ok := p.Sources[id]
		if !ok {
			p.Sources[id] = sp
			continue
		}
		if cur.IntervalH < 1 {
			cur.IntervalH = sp.IntervalH
			p.Sources[id] = cur
		}
	}
	for id := range p.Sources {
		if sourceByID(id) == nil {
			delete(p.Sources, id)
		}
	}
	return p
}

func (m *mirror) saveStateLocked() {
	_ = writeJSONFile(m.statePath("manifest.json"), m.files)
	_ = writeJSONFile(m.statePath("sources.json"), m.states)
}

// snapshotLocked: 매니페스트(경로·해시) 전체의 SHA-256. 같은 ID = 같은 DB 내용.
func (m *mirror) snapshotLocked() (string, int64, int) {
	paths := make([]string, 0, len(m.files))
	var total int64
	for p, f := range m.files {
		paths = append(paths, p)
		total += f.Size
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, p := range paths {
		fmt.Fprintf(h, "%s %s\n", m.files[p].SHA256, p)
	}
	return hex.EncodeToString(h.Sum(nil)), total, len(paths)
}

// ---------- 접속 창 ----------

func parseHM(s string) (int, error) {
	var h, mi int
	if _, err := fmt.Sscanf(s, "%d:%d", &h, &mi); err != nil || h < 0 || h > 23 || mi < 0 || mi > 59 {
		return 0, fmt.Errorf("시각 형식(HH:MM) 오류: %q", s)
	}
	return h*60 + mi, nil
}

func inWindow(p mirrorPolicy, t time.Time) bool {
	s, _ := parseHM(p.WindowStart)
	e, _ := parseHM(p.WindowEnd)
	t = t.In(kst)
	m := t.Hour()*60 + t.Minute()
	if s == e {
		return true // 하루 종일
	}
	if s < e {
		return m >= s && m < e
	}
	return m >= s || m < e // 자정을 넘는 창
}

// nextWindowAt: t 이후(포함) 처음으로 접속 창 안에 드는 시각.
func nextWindowAt(p mirrorPolicy, t time.Time) time.Time {
	if inWindow(p, t) {
		return t
	}
	s, _ := parseHM(p.WindowStart)
	k := t.In(kst)
	start := time.Date(k.Year(), k.Month(), k.Day(), s/60, s%60, 0, 0, kst)
	if !start.After(k) {
		start = start.AddDate(0, 0, 1)
	}
	return start
}

func parseT(s string) time.Time { t, _ := time.Parse(time.RFC3339, s); return t }

// ---------- 내려받기 ----------

type runCtx struct {
	m        *mirror
	src      *mirrorSource
	upstream string
	minFree  int64
	ctx      context.Context
	touched  map[string]bool
	changed  int
	bytes    int64
}

var errNotFound = errors.New("404")

// localPath: URL → data/ 아래 상대 경로(<호스트>/<경로>). 경로 탈출을 막는다.
func localPath(u string) (string, error) {
	pu, err := url.Parse(u)
	if err != nil || pu.Host == "" {
		return "", fmt.Errorf("URL 오류: %s", u)
	}
	p := path.Clean("/" + pu.Path)
	if strings.Contains(p, "..") || pu.RawQuery != "" {
		return "", fmt.Errorf("허용하지 않는 경로: %s", u)
	}
	return pu.Host + p, nil
}

func (r *runCtx) get(u string) error {
	rel, err := localPath(u)
	if err != nil {
		return err
	}
	return r.fetch(u, rel, nil)
}

// tryGet: 원본에 없는 파일(404)은 건너뛴다(연도별 피드의 빈 연도 등).
func (r *runCtx) tryGet(u string) error {
	if err := r.get(u); err != nil && !errors.Is(err, errNotFound) {
		return err
	}
	return nil
}

func (r *runCtx) readLocal(u string) ([]byte, error) {
	rel, err := localPath(u)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(filepath.Join(r.m.dataDir(), filepath.FromSlash(rel)))
}

func (r *runCtx) readLines(u string) ([]string, error) {
	b, err := r.readLocal(u)
	if err != nil {
		return nil, err
	}
	out := []string{}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.ContainsAny(l, "/\\") {
			out = append(out, l)
		}
	}
	return out, nil
}

func (r *runCtx) readJSON(u string, v any) error {
	b, err := r.readLocal(u)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// latestArchive: <base>archive_latest.txt 가 가리키는 전체 묶음 1개를 받는다.
func (r *runCtx) latestArchive(base string) error {
	if err := r.get(base + "archive_latest.txt"); err != nil {
		return err
	}
	b, err := r.readLocal(base + "archive_latest.txt")
	if err != nil {
		return err
	}
	name := strings.TrimSpace(string(b))
	if name == "" || strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
		return errors.New("archive_latest.txt 형식이 예상과 다름")
	}
	return r.get(base + name)
}

// ociLayer: 공개 OCI 이미지(ghcr)의 첫 레이어를 고정 경로에 받는다. 상위 미러 모드면 그 경로를 그대로 받는다.
func (r *runCtx) ociLayer(repo, tag, rel string) error {
	if r.upstream != "" {
		return r.fetch("", rel, nil)
	}
	var tok struct{ Token string }
	if err := r.getJSONDirect("https://ghcr.io/token?scope=repository:"+repo+":pull", nil, &tok); err != nil {
		return err
	}
	auth := map[string]string{"Authorization": "Bearer " + tok.Token}
	var man struct {
		Layers []struct{ Digest string } `json:"layers"`
	}
	h := map[string]string{"Authorization": auth["Authorization"], "Accept": "application/vnd.oci.image.manifest.v1+json"}
	if err := r.getJSONDirect("https://ghcr.io/v2/"+repo+"/manifests/"+tag, h, &man); err != nil {
		return err
	}
	if len(man.Layers) == 0 || !strings.HasPrefix(man.Layers[0].Digest, "sha256:") {
		return errors.New("OCI 매니페스트에 레이어가 없음")
	}
	return r.fetch("https://ghcr.io/v2/"+repo+"/blobs/"+man.Layers[0].Digest, rel, auth)
}

func (r *runCtx) getJSONDirect(u string, hdr map[string]string, v any) error {
	req, _ := http.NewRequestWithContext(r.ctx, "GET", u, nil)
	req.Header.Set("User-Agent", mirrorUA)
	for k, x := range hdr {
		req.Header.Set(k, x)
	}
	resp, err := r.m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(v)
}

func diskFree(dir string) (free, total int64) {
	var st syscall.Statfs_t
	if syscall.Statfs(dir, &st) != nil {
		return -1, -1
	}
	return int64(st.Bavail) * int64(st.Bsize), int64(st.Blocks) * int64(st.Bsize)
}

// fetch: 조건부 GET(ETag·Last-Modified) → 바뀐 경우만 임시 파일에 받아 해시 계산 후 교체.
func (r *runCtx) fetch(src, rel string, hdr map[string]string) error {
	m := r.m
	if r.upstream != "" {
		src, hdr = strings.TrimRight(r.upstream, "/")+"/"+rel, nil
	}
	dst := filepath.Join(m.dataDir(), filepath.FromSlash(rel))
	r.touched[rel] = true
	m.mu.Lock()
	prev := m.files[rel]
	m.mu.Unlock()
	req, err := http.NewRequestWithContext(r.ctx, "GET", src, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", mirrorUA)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if _, err := os.Stat(dst); err == nil && prev != nil {
		if prev.ETag != "" {
			req.Header.Set("If-None-Match", prev.ETag)
		}
		if prev.LastMod != "" {
			req.Header.Set("If-Modified-Since", prev.LastMod)
		}
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %v", rel, err)
	}
	defer resp.Body.Close()
	now := time.Now().UTC().Format(time.RFC3339)
	if resp.StatusCode == http.StatusNotModified {
		m.mu.Lock()
		prev.Checked = now
		m.mu.Unlock()
		return nil
	}
	if resp.StatusCode == 404 {
		delete(r.touched, rel)
		return fmt.Errorf("%s: %w", rel, errNotFound)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s: HTTP %d", rel, resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if free, _ := diskFree(m.dataDir()); free >= 0 && free-max64(resp.ContentLength, 0) < r.minFree {
		return fmt.Errorf("디스크 여유 부족: 남은 %s, 받을 크기 %s, 최소 여유 %s — 받지 않음",
			human(free), human(resp.ContentLength), human(r.minFree))
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".part-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	// 받는 도중에도 여유 공간을 지킨다(크기를 모르는 응답 대비)
	n, err := io.Copy(io.MultiWriter(tmp, h), &freeGuard{r: resp.Body, dir: m.dataDir(), min: r.minFree})
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("%s: %v", rel, err)
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	m.mu.Lock()
	if prev == nil || prev.SHA256 != sum {
		r.changed++
	}
	fetched := now
	if prev != nil && prev.SHA256 == sum {
		fetched = prev.Fetched
	}
	m.files[rel] = &fileEntry{Path: rel, Source: r.src.ID, Size: n, SHA256: sum, ETag: resp.Header.Get("ETag"),
		LastMod: resp.Header.Get("Last-Modified"), Fetched: fetched, Checked: now}
	m.mu.Unlock()
	r.bytes += n
	return nil
}

type freeGuard struct {
	r   io.Reader
	dir string
	min int64
	n   int64
}

func (g *freeGuard) Read(p []byte) (int, error) {
	k, err := g.r.Read(p)
	g.n += int64(k)
	if g.n > 256<<20 { // 256MB 마다 확인
		g.n = 0
		if free, _ := diskFree(g.dir); free >= 0 && free < g.min {
			return k, fmt.Errorf("받는 중 디스크 여유가 최소치(%s) 아래로 내려가 중단", human(g.min))
		}
	}
	return k, err
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func human(n int64) string {
	if n < 0 {
		return "?"
	}
	f := float64(n)
	for _, u := range []string{"B", "KB", "MB", "GB"} {
		if f < 1024 {
			return fmt.Sprintf("%.1f%s", f, u)
		}
		f /= 1024
	}
	return fmt.Sprintf("%.1fTB", f)
}

// runSource: 한 출처를 받는다. 성공하면 이번에 다루지 않은 이전 파일(예: 지난주 묶음)을 지운다.
func (m *mirror) runSource(id, trigger string) {
	src := sourceByID(id)
	if src == nil {
		return
	}
	m.runMu.Lock()
	defer m.runMu.Unlock()
	m.mu.Lock()
	pol := m.policy
	if pol.Mode == "offline" {
		m.mu.Unlock()
		return
	}
	st := m.states[id]
	if st == nil {
		st = &sourceState{}
		m.states[id] = st
	}
	start := time.Now().UTC()
	st.LastAttempt, st.Status, st.Error = start.Format(time.RFC3339), "running", ""
	m.running = id
	m.saveStateLocked()
	m.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
	defer cancel()
	r := &runCtx{m: m, src: src, upstream: pol.Upstream, minFree: int64(pol.MinFreeGB) << 30, ctx: ctx, touched: map[string]bool{}}
	err := src.run(r)

	m.mu.Lock()
	m.running = ""
	st.Changed = r.changed
	if err != nil {
		st.Status, st.Error = "error", err.Error()
	} else {
		st.Status, st.LastSuccess = "ok", time.Now().UTC().Format(time.RFC3339)
		for p, f := range m.files {
			if f.Source == id && !r.touched[p] {
				_ = os.Remove(filepath.Join(m.dataDir(), filepath.FromSlash(p)))
				delete(m.files, p)
				r.changed++
			}
		}
	}
	snap, _, _ := m.snapshotLocked()
	m.saveStateLocked()
	m.mu.Unlock()
	rec := runRecord{ID: id, Trigger: trigger, Start: start.Format(time.RFC3339), End: time.Now().UTC().Format(time.RFC3339),
		Status: st.Status, Error: st.Error, Changed: r.changed, Bytes: r.bytes, Snapshot: snap}
	if f, err := os.OpenFile(m.statePath("runs.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640); err == nil {
		b, _ := json.Marshal(rec)
		_, _ = f.Write(append(b, '\n'))
		f.Close()
	}
	log.Printf("mirror %s (%s): %s changed=%d bytes=%s %s", id, trigger, rec.Status, r.changed, human(r.bytes), rec.Error)
}

// due: 정기 접속 대상인지(주기 경과, 실패 후 재시도는 1시간 간격).
func (m *mirror) dueLocked(id string, now time.Time) bool {
	sp := m.policy.Sources[id]
	if !sp.Enabled {
		return false
	}
	st := m.states[id]
	if st == nil {
		return true
	}
	if st.Status == "error" && now.Sub(parseT(st.LastAttempt)) < time.Hour {
		return false
	}
	return now.Sub(parseT(st.LastSuccess)) >= time.Duration(sp.IntervalH)*time.Hour
}

func (m *mirror) scheduler() {
	for {
		now := time.Now()
		m.mu.Lock()
		var due []string
		if m.policy.Mode == "scheduled" && inWindow(m.policy, now) && m.running == "" {
			for _, s := range mirrorCatalog {
				if m.dueLocked(s.ID, now) {
					due = append(due, s.ID)
				}
			}
		}
		m.mu.Unlock()
		for _, id := range due {
			m.mu.Lock()
			ok := m.policy.Mode == "scheduled" && inWindow(m.policy, time.Now())
			m.mu.Unlock()
			if !ok {
				break // 창이 닫히면 다음 창에서 이어 받는다
			}
			m.runSource(id, "schedule")
		}
		time.Sleep(time.Minute)
	}
}

// ---------- 상태 API ----------

type sourceView struct {
	mirrorSource
	Enabled     bool   `json:"enabled"`
	IntervalH   int    `json:"intervalH"`
	StaleH      int    `json:"staleH"`
	State       string `json:"status"`
	Error       string `json:"error,omitempty"`
	LastSuccess string `json:"lastSuccess,omitempty"`
	LastAttempt string `json:"lastAttempt,omitempty"`
	LocalAsOf   string `json:"localAsOf,omitempty"` // 로컬 데이터가 원본과 같았던 마지막 시각
	NextAccess  string `json:"nextAccess,omitempty"`
	Stale       bool   `json:"stale"`
	Files       int    `json:"files"`
	Bytes       int64  `json:"bytes"`
}

type mirrorStatus struct {
	Now          string       `json:"now"`
	Policy       mirrorPolicy `json:"policy"`
	InWindow     bool         `json:"inWindow"`
	NextWindow   string       `json:"nextWindow,omitempty"`
	Running      string       `json:"running,omitempty"`
	Snapshot     string       `json:"snapshot"`
	TotalBytes   int64        `json:"totalBytes"`
	FileCount    int          `json:"fileCount"`
	DiskFree     int64        `json:"diskFree"`
	DiskTotal    int64        `json:"diskTotal"`
	AllowedHosts []string     `json:"allowedHosts"`
	Sources      []sourceView `json:"sources"`
	Runs         []runRecord  `json:"runs"`
}

func (m *mirror) status() mirrorStatus {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	snap, total, count := m.snapshotLocked()
	free, tot := diskFree(m.dataDir())
	out := mirrorStatus{Now: now.UTC().Format(time.RFC3339), Policy: m.policy, InWindow: inWindow(m.policy, now), Running: m.running,
		Snapshot: snap, TotalBytes: total, FileCount: count, DiskFree: free, DiskTotal: tot}
	if m.policy.Mode == "scheduled" {
		out.NextWindow = nextWindowAt(m.policy, now).UTC().Format(time.RFC3339)
	}
	hosts := map[string]bool{}
	per := map[string][2]int64{}
	for _, f := range m.files {
		v := per[f.Source]
		per[f.Source] = [2]int64{v[0] + 1, v[1] + f.Size}
	}
	for _, s := range mirrorCatalog {
		sp := m.policy.Sources[s.ID]
		st := m.states[s.ID]
		if st == nil {
			st = &sourceState{Status: "never"}
		}
		v := sourceView{mirrorSource: s, Enabled: sp.Enabled, IntervalH: sp.IntervalH, StaleH: sp.IntervalH*2 + 24,
			State: st.Status, Error: st.Error, LastSuccess: st.LastSuccess, LastAttempt: st.LastAttempt,
			LocalAsOf: st.LastSuccess, Files: int(per[s.ID][0]), Bytes: per[s.ID][1]}
		if v.State == "" {
			v.State = "never"
		}
		if st.LastSuccess != "" && now.Sub(parseT(st.LastSuccess)) > time.Duration(v.StaleH)*time.Hour {
			v.Stale = true
		}
		if sp.Enabled && m.policy.Mode == "scheduled" {
			due := parseT(st.LastSuccess).Add(time.Duration(sp.IntervalH) * time.Hour)
			if due.Before(now) {
				due = now
			}
			v.NextAccess = nextWindowAt(m.policy, due).UTC().Format(time.RFC3339)
		}
		if sp.Enabled {
			for _, h := range s.Hosts {
				hosts[h] = true
			}
		}
		out.Sources = append(out.Sources, v)
	}
	if m.policy.Upstream != "" {
		hosts = map[string]bool{}
		if u, err := url.Parse(m.policy.Upstream); err == nil {
			hosts[u.Host] = true
		}
	}
	for h := range hosts {
		out.AllowedHosts = append(out.AllowedHosts, h)
	}
	sort.Strings(out.AllowedHosts)
	out.Runs = m.lastRuns(30)
	return out
}

func (m *mirror) lastRuns(n int) []runRecord {
	f, err := os.Open(m.statePath("runs.jsonl"))
	if err != nil {
		return []runRecord{}
	}
	defer f.Close()
	all := []runRecord{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r runRecord
		if json.Unmarshal(sc.Bytes(), &r) == nil {
			all = append(all, r)
		}
	}
	if len(all) > n {
		all = all[len(all)-n:]
	}
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}
	return all
}

func (m *mirror) authorized(r *http.Request) bool {
	return m.key != "" && r.Header.Get("X-Mirror-Key") == m.key
}

func (m *mirror) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /_api/status", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, m.status()) })
	mux.HandleFunc("GET /_api/manifest", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		list := make([]*fileEntry, 0, len(m.files))
		for _, f := range m.files {
			list = append(list, f)
		}
		snap, _, _ := m.snapshotLocked()
		m.mu.Unlock()
		sort.Slice(list, func(i, j int) bool { return list[i].Path < list[j].Path })
		writeJSON(w, 200, map[string]any{"snapshot": snap, "files": list})
	})
	mux.HandleFunc("PUT /_api/policy", func(w http.ResponseWriter, r *http.Request) {
		if !m.authorized(r) {
			writeJSON(w, 403, map[string]string{"error": "forbidden"})
			return
		}
		var p mirrorPolicy
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&p); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if p.Mode != "scheduled" && p.Mode != "offline" {
			writeJSON(w, 400, map[string]string{"error": "mode 는 scheduled 또는 offline"})
			return
		}
		for _, t := range []string{p.WindowStart, p.WindowEnd} {
			if _, err := parseHM(t); err != nil {
				writeJSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
		}
		if p.Upstream != "" {
			if u, err := url.Parse(p.Upstream); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				writeJSON(w, 400, map[string]string{"error": "상위 미러 주소는 http(s)://호스트[:포트] 형식"})
				return
			}
		}
		if p.MinFreeGB < 5 {
			writeJSON(w, 400, map[string]string{"error": "최소 여유 공간은 5GB 이상"})
			return
		}
		m.mu.Lock()
		m.policy = mergePolicy(p)
		err := writeJSONFile(m.statePath("policy.json"), m.policy)
		m.mu.Unlock()
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, m.status())
	})
	mux.HandleFunc("POST /_api/sync/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !m.authorized(r) {
			writeJSON(w, 403, map[string]string{"error": "forbidden"})
			return
		}
		id := r.PathValue("id")
		m.mu.Lock()
		mode, running := m.policy.Mode, m.running
		m.mu.Unlock()
		if mode == "offline" {
			writeJSON(w, 409, map[string]string{"error": "폐쇄망 모드에서는 외부 접속을 하지 않습니다"})
			return
		}
		if running != "" {
			writeJSON(w, 409, map[string]string{"error": "다른 DB 를 받는 중: " + running})
			return
		}
		ids := []string{id}
		if id == "all" {
			ids = nil
			m.mu.Lock()
			for _, s := range mirrorCatalog {
				if m.policy.Sources[s.ID].Enabled {
					ids = append(ids, s.ID)
				}
			}
			m.mu.Unlock()
		} else if sourceByID(id) == nil {
			writeJSON(w, 404, map[string]string{"error": "없는 출처: " + id})
			return
		}
		go func() {
			for _, x := range ids {
				m.runSource(x, "manual")
			}
		}()
		writeJSON(w, 202, map[string]any{"queued": ids})
	})
	// 데이터: /<호스트>/<경로> (디렉터리 목록 포함). 내부망 전용.
	fs := http.FileServer(http.Dir(m.dataDir()))
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(filepath.Base(r.URL.Path), ".part-") {
			http.NotFound(w, r)
			return
		}
		fs.ServeHTTP(w, r)
	})
	return mux
}

func runMirror() {
	m := &mirror{dir: env("MIRROR_DIR", "/mirror"), client: &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment, ResponseHeaderTimeout: 2 * time.Minute, IdleConnTimeout: time.Minute}}}
	if err := m.load(); err != nil {
		log.Fatalf("미러 초기화 실패: %v", err)
	}
	go m.scheduler()
	addr := env("MIRROR_ADDR", ":8090")
	log.Printf("vuln-mirror %s (mode=%s, window=%s-%s KST, dir=%s)", addr, m.policy.Mode, m.policy.WindowStart, m.policy.WindowEnd, m.dir)
	log.Fatal(http.ListenAndServe(addr, m.handler()))
}
