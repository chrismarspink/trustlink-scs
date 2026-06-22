package main

// 대시보드 통계: 제품(repo)별 "버전 진행에 따른 추이" 집계.
//   버전(tag) 오름차순으로 SBOM 컴포넌트 수 / 취약점 수 / 영향있음 / 수정됨 의 변화를 본다.
// 데이터 출처: SBOM 컴포넌트=CycloneDX referrer(실데이터), 취약점=zot CVE 스캔(Image.Vulnerabilities),
//   영향있음/수정됨=OpenVEX 상태. 실데이터가 없으면(스캔 0 등) 결정적 더미로 채우고 synthetic=true 로 표시한다.
// admins 전용(guard). 전체 집계라 svc-bff 자격으로 조회.

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

func (s *Server) zotGetSvc(p, accept string) (*http.Response, error) {
	req, _ := http.NewRequest("GET", s.cfg.ZotAPIURL+p, nil)
	req.Header.Set("X-ZOT-API-CLIENT", "zot-ui")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if s.cfg.ZotAdminUser != "" {
		req.SetBasicAuth(s.cfg.ZotAdminUser, s.cfg.ZotAdminPass)
	}
	return s.http.Do(req)
}

func (s *Server) svcCatalog() []string {
	resp, err := s.zotGetSvc("/v2/_catalog?n=1000", "")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var c struct {
		Repositories []string `json:"repositories"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&c)
	sort.Strings(c.Repositories)
	return c.Repositories
}

func (s *Server) svcTags(repo string) []string {
	resp, err := s.zotGetSvc("/v2/"+repo+"/tags/list", "")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var t struct {
		Tags []string `json:"tags"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&t)
	return t.Tags
}

// referrer 첫 레이어 blob(SBOM/VEX 문서) 원문.
func (s *Server) svcReferrerBlob(repo, refDigest string) []byte {
	mr, err := s.zotGetSvc("/v2/"+repo+"/manifests/"+refDigest, acceptManifest)
	if err != nil || mr.StatusCode != 200 {
		if mr != nil {
			mr.Body.Close()
		}
		return nil
	}
	var m ociManifest
	_ = json.NewDecoder(mr.Body).Decode(&m)
	mr.Body.Close()
	if len(m.Layers) == 0 {
		return nil
	}
	br, err := s.zotGetSvc("/v2/"+repo+"/blobs/"+m.Layers[0].Digest, "")
	if err != nil || br.StatusCode != 200 {
		if br != nil {
			br.Body.Close()
		}
		return nil
	}
	defer br.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(br.Body, 32<<20))
	return data
}

func countSBOMComponents(blob []byte) int {
	var d struct {
		Components []json.RawMessage `json:"components"`
	}
	if json.Unmarshal(blob, &d) != nil {
		return 0
	}
	return len(d.Components)
}

// OpenVEX(statements[].status) 우선, CycloneDX VEX(vulnerabilities[].analysis.state) 폴백 → 상태별 카운트.
func countVEXByStatus(blob []byte) map[string]int {
	by := map[string]int{}
	var ov struct {
		Statements []struct {
			Status string `json:"status"`
		} `json:"statements"`
	}
	if json.Unmarshal(blob, &ov) == nil && len(ov.Statements) > 0 {
		for _, st := range ov.Statements {
			by[normVexStatus(st.Status)]++
		}
		return by
	}
	var cdx struct {
		Vulnerabilities []struct {
			Analysis struct {
				State string `json:"state"`
			} `json:"analysis"`
		} `json:"vulnerabilities"`
	}
	if json.Unmarshal(blob, &cdx) == nil {
		for _, v := range cdx.Vulnerabilities {
			by[normVexStatus(v.Analysis.State)]++
		}
	}
	return by
}

func normVexStatus(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "not_affected", "false_positive", "not_set":
		return "not_affected"
	case "affected", "exploitable":
		return "affected"
	case "fixed", "resolved", "resolved_with_pedigree":
		return "fixed"
	default:
		return "under_investigation"
	}
}

// 실데이터: SBOM 컴포넌트 수 + VEX 상태별 카운트.
func (s *Server) referrerStats(repo, tag string) (components int, byStatus map[string]int) {
	byStatus = map[string]int{}
	mr, err := s.zotGetSvc("/v2/"+repo+"/manifests/"+tag, acceptManifest)
	if err != nil || mr.StatusCode != 200 {
		if mr != nil {
			mr.Body.Close()
		}
		return
	}
	dig := mr.Header.Get("Docker-Content-Digest")
	mr.Body.Close()
	if dig == "" {
		return
	}
	rr, err := s.zotGetSvc("/v2/"+repo+"/referrers/"+dig, "")
	if err != nil || rr.StatusCode != 200 {
		if rr != nil {
			rr.Body.Close()
		}
		return
	}
	var idx ociIndex
	_ = json.NewDecoder(rr.Body).Decode(&idx)
	rr.Body.Close()
	// 종류별 "최신"(created 주석 기준) referrer 1건만 집계한다.
	// 재발행은 새 referrer 로 누적되므로(원본 불변), 합산하면 과거 발행분까지 더해져
	// 값이 부풀고 재발행이 교체가 아니라 가산처럼 보인다 → 최신 1건만 반영.
	var sbomDigest, sbomAt, vexDigest, vexAt string
	for _, ref := range idx.Manifests {
		created := ref.Annotations["org.opencontainers.image.created"] // RFC3339(UTC) → 문자열 비교로 정렬 가능
		switch kindDir(ref.ArtifactType, "") {
		case "sbom":
			if sbomDigest == "" || created > sbomAt {
				sbomDigest, sbomAt = ref.Digest, created
			}
		case "vex":
			if vexDigest == "" || created > vexAt {
				vexDigest, vexAt = ref.Digest, created
			}
		}
	}
	if sbomDigest != "" {
		if blob := s.svcReferrerBlob(repo, sbomDigest); blob != nil {
			components = countSBOMComponents(blob)
		}
	}
	if vexDigest != "" {
		if blob := s.svcReferrerBlob(repo, vexDigest); blob != nil {
			byStatus = countVEXByStatus(blob)
		}
	}
	return
}

// zot CVE 스캔 취약점 수(Image.Vulnerabilities.Count). 스캐너 미구성 시 0.
func (s *Server) svcVulnCount(repo, tag string) int {
	gql := fmt.Sprintf(`{ Image(image:%q){ Vulnerabilities{ Count } } }`, repo+":"+tag)
	resp, err := s.zotGetSvc("/v2/_zot/ext/search?query="+url.QueryEscape(gql), "")
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	var d struct {
		Data struct {
			Image struct {
				Vulnerabilities struct {
					Count int `json:"Count"`
				} `json:"Vulnerabilities"`
			} `json:"Image"`
		} `json:"data"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&d)
	return d.Data.Image.Vulnerabilities.Count
}

func fnv32(s string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return int(h.Sum32())
}

// 결정적 더미(실 취약점/VEX 데이터 부재 시): 버전 진행에 따라 취약점↓·수정됨↑ 추세.
func synthSecurity(repo, tag string, idx, comp int) (vuln, affected, fixed int) {
	base := 8 + fnv32(repo)%8 // 8..15
	vuln = base - idx*2 + fnv32(tag)%3
	if vuln < 1 {
		vuln = 1 + comp%3
	}
	fixed = idx*2 + fnv32(repo)%2 // 버전 올라갈수록 수정 누적
	if fixed > vuln {
		fixed = vuln
	}
	affected = vuln - fixed
	if affected < 0 {
		affected = 0
	}
	return
}

func synthComponents(repo string, idx int) int {
	return 4 + idx*2 + fnv32(repo)%4 // 실 SBOM(데모) 규모에 맞춰 작게, 버전 올라갈수록 소폭 증가
}

// 결정적 더미 VEX 상태별 추이(실 VEX 문서 부재 시): 버전 진행에 따라 조사중↓·수정됨/영향없음↑.
func synthVex(repo, tag string, idx int) map[string]int {
	base := 4 + fnv32(repo)%4 // 4..7
	investigating := base - idx*2
	if investigating < 0 {
		investigating = 0
	}
	affected := base - idx + fnv32(tag)%2
	if affected < 0 {
		affected = 0
	}
	fixed := idx + fnv32(repo)%2          // 버전 올라갈수록 수정 누적
	notAffected := 1 + (idx+fnv32(tag))%3 // 영향없음(오탐 처리) 소폭 증가
	return map[string]int{
		"affected":            affected,
		"not_affected":        notAffected,
		"fixed":               fixed,
		"under_investigation": investigating,
	}
}

// 버전 비교(숫자 시퀀스 우선, 동률이면 원문). "latest" 등 비버전은 호출 전 제거.
func cmpVersion(a, b string) int {
	pa, pb := verParts(a), verParts(b)
	for i := 0; i < len(pa) && i < len(pb); i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	if len(pa) != len(pb) {
		if len(pa) < len(pb) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

func verParts(v string) []int {
	parts := []int{}
	cur := ""
	flush := func() {
		if cur != "" {
			n, _ := strconv.Atoi(cur)
			parts = append(parts, n)
			cur = ""
		}
	}
	for _, r := range v {
		if r >= '0' && r <= '9' {
			cur += string(r)
		} else {
			flush()
		}
	}
	flush()
	return parts
}

func sortedVersions(tags []string) []string {
	out := []string{}
	for _, t := range tags {
		if t != "latest" { // latest 는 별칭 → 추이 축에서 제외
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return cmpVersion(out[i], out[j]) < 0 })
	return out
}

type versionStat struct {
	Tag             string         `json:"tag"`
	Components      int            `json:"components"`
	Vulnerabilities int            `json:"vulnerabilities"`
	Affected        int            `json:"affected"`
	Fixed           int            `json:"fixed"`
	Vex             map[string]int `json:"vex"`       // VEX 상태별 카운트(affected/not_affected/fixed/under_investigation)
	Synthetic       bool           `json:"synthetic"` // 취약점/VEX(또는 컴포넌트)가 더미면 true
}

type productStat struct {
	Repo     string        `json:"repo"`
	Versions []versionStat `json:"versions"`
}

// GET /api/stats — 제품별 버전 추이.
func (s *Server) apiStats(w http.ResponseWriter, r *http.Request) {
	products := []productStat{}
	for _, repo := range s.svcCatalog() {
		versions := []versionStat{}
		for idx, tag := range sortedVersions(s.svcTags(repo)) {
			comp, byStatus := s.referrerStats(repo, tag)
			vs := versionStat{Tag: tag, Components: comp}
			// 취약점 수: DT(SBOM 분석) 우선 → zot Trivy(컨테이너 이미지) → 더미.
			//   데모 제품은 oras 바이너리(octet-stream)라 Trivy 스캔 불가 → DT 가 실질 소스.
			vuln, vulnReal := s.dtVulnCount(repo, tag)
			if !vulnReal {
				if z := s.svcVulnCount(repo, tag); z > 0 {
					vuln, vulnReal = z, true
				}
			}
			if vulnReal {
				vs.Vulnerabilities = vuln
				vs.Affected = byStatus["affected"]
				vs.Fixed = byStatus["fixed"]
			} else {
				// 실 취약점 데이터 없음 → 더미 추이
				vs.Vulnerabilities, vs.Affected, vs.Fixed = synthSecurity(repo, tag, idx, comp)
				vs.Synthetic = true
			}
			if vs.Components == 0 { // SBOM 없는 버전 → 컴포넌트도 더미
				vs.Components = synthComponents(repo, idx)
				vs.Synthetic = true
			}
			if len(byStatus) > 0 { // 실 VEX 문서 존재 → 상태별 실데이터
				vs.Vex = byStatus
			} else { // VEX 문서 없음 → 더미 추이
				vs.Vex = synthVex(repo, tag, idx)
				vs.Synthetic = true
			}
			versions = append(versions, vs)
		}
		if len(versions) > 0 {
			products = append(products, productStat{Repo: repo, Versions: versions})
		}
	}
	writeJSON(w, 200, map[string]any{"products": products})
}
