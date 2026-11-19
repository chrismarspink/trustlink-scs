package main

// VEX 대응(remediation) 근거 — 미러 사본만 쓰는 규칙 계산. AI 는 이 결과를 인용해 대응 계획 문장만 쓴다.
//  - OSV: purl 의 생태계 all.zip 에서 해당 취약점(ID·별칭)의 영향 범위·수정 버전을 찾고,
//         현재 버전이 범위 안인지, 올려야 할 최소 버전(target)을 규칙으로 계산한다.
//  - 공개 익스플로잇: Exploit-DB(CSV)·Metasploit(모듈 메타)·Nuclei(cves.json) 에서 CVE 로 찾는다.
//  - 기한: KEV 등재면 KEV dueDate. 그 밖의 기한은 정책이 정할 일이라 만들지 않는다.

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------- purl ----------

type purlParts struct{ Type, Namespace, Name, Version string }

func parsePurl(p string) (purlParts, bool) {
	if !strings.HasPrefix(p, "pkg:") {
		return purlParts{}, false
	}
	p = strings.TrimPrefix(p, "pkg:")
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	var out purlParts
	if i := strings.LastIndex(p, "@"); i > 0 {
		out.Version, _ = url.PathUnescape(p[i+1:])
		p = p[:i]
	}
	seg := strings.Split(p, "/")
	if len(seg) < 2 {
		return purlParts{}, false
	}
	out.Type = strings.ToLower(seg[0])
	for i := range seg {
		seg[i], _ = url.PathUnescape(seg[i])
	}
	out.Name = seg[len(seg)-1]
	out.Namespace = strings.Join(seg[1:len(seg)-1], "/")
	return out, true
}

// osvTarget: purl → (OSV 생태계 디렉터리, OSV 패키지 이름). 배포판 패키지는 판 정보가 필요해 제외.
func osvTarget(pp purlParts) (string, string) {
	join := func(sep string) string {
		if pp.Namespace == "" {
			return pp.Name
		}
		return pp.Namespace + sep + pp.Name
	}
	switch pp.Type {
	case "npm":
		return "npm", join("/")
	case "pypi":
		return "PyPI", strings.ToLower(pypiSep.ReplaceAllString(pp.Name, "-"))
	case "maven":
		return "Maven", join(":")
	case "golang":
		return "Go", join("/")
	case "cargo":
		return "crates.io", pp.Name
	case "gem":
		return "RubyGems", pp.Name
	case "nuget":
		return "NuGet", pp.Name
	case "composer":
		return "Packagist", join("/")
	case "hex":
		return "Hex", pp.Name
	case "pub":
		return "Pub", pp.Name
	}
	return "", ""
}

func osvPkgEqual(eco, a, b string) bool {
	if eco == "PyPI" {
		return strings.EqualFold(pypiSep.ReplaceAllString(a, "-"), pypiSep.ReplaceAllString(b, "-"))
	}
	if eco == "NuGet" || eco == "Packagist" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// ---------- 버전 비교(생태계 공통 근사) ----------

var (
	verTok  = regexp.MustCompile(`\d+|[A-Za-z]+`)
	pypiSep = regexp.MustCompile(`[-_.]+`)
)

// osvCmpVersion: a<b → -1. 숫자 토큰은 수로, 문자 토큰은 사전순, 프리릴리스(문자)는 같은 자리 숫자보다 앞.
func osvCmpVersion(a, b string) int {
	ta := verTok.FindAllString(strings.TrimPrefix(strings.ToLower(a), "v"), -1)
	tb := verTok.FindAllString(strings.TrimPrefix(strings.ToLower(b), "v"), -1)
	for i := 0; i < len(ta) || i < len(tb); i++ {
		if i >= len(ta) { // a 가 짧음: b 의 남은 토큰이 문자면(프리릴리스) a 가 더 큼
			if _, err := strconv.Atoi(tb[i]); err != nil && !isFinal(tb[i]) {
				return 1
			}
			return -1
		}
		if i >= len(tb) {
			if _, err := strconv.Atoi(ta[i]); err != nil && !isFinal(ta[i]) {
				return -1
			}
			return 1
		}
		na, ea := strconv.Atoi(ta[i])
		nb, eb := strconv.Atoi(tb[i])
		switch {
		case ea == nil && eb == nil:
			if na != nb {
				if na < nb {
					return -1
				}
				return 1
			}
		case ea == nil: // 숫자 > 문자(프리릴리스)
			return 1
		case eb == nil:
			return -1
		default:
			if ta[i] != tb[i] {
				if ta[i] < tb[i] {
					return -1
				}
				return 1
			}
		}
	}
	return 0
}

// isFinal: Maven 의 정식 릴리스 표기(1.0.Final, 2.0.RELEASE)는 프리릴리스가 아니다.
func isFinal(t string) bool { return t == "final" || t == "release" || t == "ga" }

// ---------- OSV 별칭 색인(생태계별, all.zip 수정 시각 기준 캐시) ----------

type osvIdx struct {
	mtime time.Time
	byKey map[string][]string // ID·별칭(대문자) → zip 항목 이름
}

var (
	osvMu   sync.Mutex
	osvIdxs = map[string]*osvIdx{}
)

func osvZipPath(eco string) string {
	return filepath.Join(env("MIRROR_DIR", "/mirror"), "data", "osv-vulnerabilities.storage.googleapis.com", eco, "all.zip")
}

func osvIndex(eco string) (*osvIdx, *zip.ReadCloser, bool) {
	p := osvZipPath(eco)
	fi, err := os.Stat(p)
	if err != nil {
		return nil, nil, false
	}
	zr, err := zip.OpenReader(p)
	if err != nil {
		return nil, nil, false
	}
	osvMu.Lock()
	defer osvMu.Unlock()
	if ix := osvIdxs[eco]; ix != nil && ix.mtime.Equal(fi.ModTime()) {
		return ix, zr, true
	}
	ix := &osvIdx{mtime: fi.ModTime(), byKey: map[string][]string{}}
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "MAL-") { // 악성 패키지 항목은 CVE 별칭이 없다
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		var h struct {
			ID      string   `json:"id"`
			Aliases []string `json:"aliases"`
		}
		_ = json.NewDecoder(rc).Decode(&h)
		rc.Close()
		for _, k := range append([]string{h.ID}, h.Aliases...) {
			k = strings.ToUpper(k)
			if k != "" {
				ix.byKey[k] = append(ix.byKey[k], f.Name)
			}
		}
	}
	osvIdxs[eco] = ix
	return ix, zr, true
}

type osvRemedy struct {
	Checked  bool     `json:"checked"`           // OSV 사본으로 확인했는가
	Source   string   `json:"source,omitempty"`  // 근거 OSV 항목 ID
	InRange  string   `json:"inRange,omitempty"` // yes / no / unknown
	Fixed    []string `json:"fixed,omitempty"`   // 수정 버전(오름차순)
	Target   string   `json:"target,omitempty"`  // 현재 버전보다 높은 최소 수정 버전
	Ranges   []string `json:"ranges,omitempty"`  // 사람이 읽는 영향 범위
	Ecosys   string   `json:"ecosystem,omitempty"`
	NoReason string   `json:"noReason,omitempty"` // 확인 못한 이유
}

// osvLookup: purl·버전·취약점 ID 목록 → 수정 버전 판단(규칙).
func osvLookup(purl, version string, ids []string) osvRemedy {
	pp, ok := parsePurl(purl)
	if !ok {
		return osvRemedy{NoReason: "purl 없음"}
	}
	if version == "" {
		version = pp.Version
	}
	eco, name := osvTarget(pp)
	if eco == "" {
		return osvRemedy{NoReason: "OSV 대조 미지원 유형(" + pp.Type + ")"}
	}
	ix, zr, ok := osvIndex(eco)
	if !ok {
		return osvRemedy{Ecosys: eco, NoReason: "미러에 OSV " + eco + " 사본 없음"}
	}
	defer zr.Close()
	names := map[string]bool{}
	for _, id := range ids {
		for _, n := range ix.byKey[strings.ToUpper(id)] {
			names[n] = true
		}
	}
	if len(names) == 0 {
		return osvRemedy{Ecosys: eco, NoReason: "OSV " + eco + " 에 해당 항목 없음"}
	}
	files := map[string]*zip.File{}
	for _, f := range zr.File {
		if names[f.Name] {
			files[f.Name] = f
		}
	}
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	sort.Strings(keys) // GHSA 가 PYSEC 등보다 앞 — 결정적 순서
	res := osvRemedy{Checked: true, Ecosys: eco, InRange: "unknown"}
	fixedSet := map[string]bool{}
	for _, k := range keys {
		rc, err := files[k].Open()
		if err != nil {
			continue
		}
		var v struct {
			ID       string `json:"id"`
			Affected []struct {
				Package struct {
					Ecosystem string `json:"ecosystem"`
					Name      string `json:"name"`
				} `json:"package"`
				Ranges []struct {
					Type   string              `json:"type"`
					Events []map[string]string `json:"events"`
				} `json:"ranges"`
				Versions []string `json:"versions"`
			} `json:"affected"`
		}
		_ = json.NewDecoder(io.LimitReader(rc, 8<<20)).Decode(&v)
		rc.Close()
		for _, a := range v.Affected {
			if !osvPkgEqual(eco, a.Package.Name, name) {
				continue
			}
			if res.Source == "" {
				res.Source = v.ID
			}
			for _, ver := range a.Versions {
				if ver == version {
					res.InRange = "yes"
				}
			}
			for _, rg := range a.Ranges {
				if rg.Type == "GIT" {
					continue
				}
				intro, end, endKind := "", "", ""
				flush := func() {
					desc := firstNonEmpty(intro, "0") + " 이상"
					if end != "" {
						if endKind == "fixed" {
							desc += " " + end + " 미만"
						} else {
							desc += " " + end + " 이하"
						}
					}
					if !inList(desc, res.Ranges) {
						res.Ranges = append(res.Ranges, desc)
					}
					if version != "" && res.InRange != "yes" {
						in := intro == "" || intro == "0" || osvCmpVersion(version, intro) >= 0
						if end != "" {
							c := osvCmpVersion(version, end)
							if endKind == "fixed" {
								in = in && c < 0
							} else {
								in = in && c <= 0
							}
						}
						if in {
							res.InRange = "yes"
						} else if res.InRange == "unknown" {
							res.InRange = "no"
						}
					}
					intro, end, endKind = "", "", ""
				}
				for _, ev := range rg.Events {
					switch {
					case ev["introduced"] != "":
						if intro != "" || end != "" {
							flush()
						}
						intro = ev["introduced"]
					case ev["fixed"] != "":
						end, endKind = ev["fixed"], "fixed"
						fixedSet[end] = true
						flush()
					case ev["last_affected"] != "":
						end, endKind = ev["last_affected"], "last"
						flush()
					}
				}
				if intro != "" {
					flush()
				}
			}
		}
	}
	if res.Source == "" {
		return osvRemedy{Ecosys: eco, NoReason: "OSV 항목에 이 패키지(" + name + ")가 없음"}
	}
	for f := range fixedSet {
		res.Fixed = append(res.Fixed, f)
	}
	sort.Slice(res.Fixed, func(i, j int) bool { return osvCmpVersion(res.Fixed[i], res.Fixed[j]) < 0 })
	for _, f := range res.Fixed {
		if version != "" && osvCmpVersion(f, version) > 0 {
			res.Target = f
			break
		}
	}
	if len(res.Ranges) > 6 {
		res.Ranges = append(res.Ranges[:6], "…")
	}
	return res
}

// ---------- 공개 익스플로잇 ----------

type exploitInfo struct {
	EDB     []string `json:"edb,omitempty"`    // Exploit-DB ID
	MSF     []string `json:"msf,omitempty"`    // Metasploit 모듈
	Nuclei  bool     `json:"nuclei,omitempty"` // Nuclei 탐지 템플릿
	Checked bool     `json:"checked"`          // 하나 이상 사본이 있었는가
}

func (e exploitInfo) Any() bool { return len(e.EDB) > 0 || len(e.MSF) > 0 || e.Nuclei }

var edbCache, msfCache, nucleiCache fileCache

func edbIndex() (map[string][]string, bool) {
	v, _, ok := cachedLoad(&edbCache, mirrorDataPath("gitlab.com", "/exploit-database/exploitdb/-/raw/main/files_exploits.csv"),
		func(b []byte) (any, error) {
			r := csv.NewReader(bytes.NewReader(b))
			r.FieldsPerRecord = -1
			r.LazyQuotes = true
			head, err := r.Read()
			if err != nil {
				return nil, err
			}
			ci := -1
			for i, h := range head {
				if h == "codes" {
					ci = i
				}
			}
			m := map[string][]string{}
			for {
				rec, err := r.Read()
				if err == io.EOF {
					break
				}
				if err != nil || ci < 0 || ci >= len(rec) {
					continue
				}
				for _, c := range strings.Split(rec[ci], ";") {
					if c = strings.ToUpper(strings.TrimSpace(c)); strings.HasPrefix(c, "CVE-") {
						m[c] = append(m[c], rec[0])
					}
				}
			}
			return m, nil
		})
	if !ok {
		return nil, false
	}
	return v.(map[string][]string), true
}

func msfIndex() (map[string][]string, bool) {
	v, _, ok := cachedLoad(&msfCache, mirrorDataPath("raw.githubusercontent.com", "/rapid7/metasploit-framework/master/db/modules_metadata_base.json"),
		func(b []byte) (any, error) {
			var d map[string]struct {
				Fullname   string   `json:"fullname"`
				References []string `json:"references"`
			}
			if err := json.Unmarshal(b, &d); err != nil {
				return nil, err
			}
			m := map[string][]string{}
			for _, mod := range d {
				for _, ref := range mod.References {
					if ref = strings.ToUpper(ref); strings.HasPrefix(ref, "CVE-") {
						m[ref] = append(m[ref], mod.Fullname)
					}
				}
			}
			for k := range m {
				sort.Strings(m[k])
			}
			return m, nil
		})
	if !ok {
		return nil, false
	}
	return v.(map[string][]string), true
}

func nucleiIndex() (map[string]bool, bool) {
	v, _, ok := cachedLoad(&nucleiCache, mirrorDataPath("raw.githubusercontent.com", "/projectdiscovery/nuclei-templates/main/cves.json"),
		func(b []byte) (any, error) {
			m := map[string]bool{}
			sc := bufio.NewScanner(bytes.NewReader(b))
			sc.Buffer(make([]byte, 1<<20), 8<<20)
			for sc.Scan() {
				var l struct{ ID string }
				if json.Unmarshal(sc.Bytes(), &l) == nil && l.ID != "" {
					m[strings.ToUpper(l.ID)] = true
				}
			}
			return m, nil
		})
	if !ok {
		return nil, false
	}
	return v.(map[string]bool), true
}

func exploitsFor(ids []string) exploitInfo {
	var out exploitInfo
	edb, ok1 := edbIndex()
	msf, ok2 := msfIndex()
	nuc, ok3 := nucleiIndex()
	out.Checked = ok1 || ok2 || ok3
	seenE, seenM := map[string]bool{}, map[string]bool{}
	for _, id := range ids {
		id = strings.ToUpper(id)
		for _, e := range edb[id] {
			if !seenE[e] {
				seenE[e] = true
				out.EDB = append(out.EDB, e)
			}
		}
		for _, m := range msf[id] {
			if !seenM[m] {
				seenM[m] = true
				out.MSF = append(out.MSF, m)
			}
		}
		if nuc[id] {
			out.Nuclei = true
		}
	}
	return out
}

func exploitText(e exploitInfo) string {
	if !e.Checked {
		return "공개 익스플로잇: 확인 불가(미러에 사본 없음)"
	}
	if !e.Any() {
		return "공개 익스플로잇: Exploit-DB·Metasploit·Nuclei 사본에서 찾지 못함"
	}
	parts := []string{}
	if n := len(e.EDB); n > 0 {
		parts = append(parts, "Exploit-DB "+itoa(n)+"건(ID "+strings.Join(head(e.EDB, 3), ",")+")")
	}
	if n := len(e.MSF); n > 0 {
		parts = append(parts, "Metasploit 모듈 "+itoa(n)+"개("+strings.Join(head(e.MSF, 2), ", ")+")")
	}
	if e.Nuclei {
		parts = append(parts, "Nuclei 탐지 템플릿 있음")
	}
	return "공개 익스플로잇: " + strings.Join(parts, " · ")
}

func head(l []string, n int) []string {
	if len(l) > n {
		return l[:n]
	}
	return l
}

func remedyText(r osvRemedy, version string) string {
	if !r.Checked {
		return "수정 버전(OSV): 확인 불가 — " + r.NoReason
	}
	t := "수정 버전(OSV " + r.Source + "): 영향 범위 " + strings.Join(r.Ranges, " / ")
	switch r.InRange {
	case "yes":
		t += "; 현재 버전 " + version + " 은 영향 범위 안"
	case "no":
		t += "; 현재 버전 " + version + " 은 OSV 영향 범위 밖"
	}
	if r.Target != "" {
		t += "; 올려야 할 최소 수정 버전 " + r.Target
	} else if len(r.Fixed) == 0 {
		t += "; 수정 버전 미공개"
	}
	return t
}
