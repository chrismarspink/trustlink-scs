package main

// 아티팩트 다운로드: 단일 파일(referrer 내용) + 전체 zip 번들(바이너리 + SBOM/VEX/서명).
// 모두 BFF가 zot(내부)에서 받아 스트리밍 → 단일 오리진에서 클릭 한 번으로 다운로드.

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"strings"
)

type ociPlatform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
}
type ociDesc struct {
	MediaType    string            `json:"mediaType"`
	ArtifactType string            `json:"artifactType"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	Platform     *ociPlatform      `json:"platform"`
	Annotations  map[string]string `json:"annotations"`
}
type ociManifest struct {
	ArtifactType string    `json:"artifactType"`
	Config       ociDesc   `json:"config"`
	Layers       []ociDesc `json:"layers"`
}
type ociIndex struct {
	Manifests []ociDesc `json:"manifests"`
}

const acceptManifest = "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json"

// zotGet 은 호출자(브라우저)의 자격을 zot 로 그대로 전달한다.
// → svc-bff 관리자 자격으로 우회하지 않고 zot 이 사용자별 RBAC 를 직접 강제한다.
func (s *Server) zotGet(caller *http.Request, path, accept string) (*http.Response, error) {
	req, _ := http.NewRequest("GET", s.cfg.ZotAPIURL+path, nil)
	req.Header.Set("X-ZOT-API-CLIENT", "zot-ui") // 네이티브 Basic 팝업 억제
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if c := caller.Header.Get("Cookie"); c != "" {
		req.Header.Set("Cookie", c) // zot OIDC 세션 쿠키
	}
	if a := caller.Header.Get("Authorization"); a != "" {
		req.Header.Set("Authorization", a) // Basic/Bearer (CLI·API 클라이언트)
	}
	return s.http.Do(req)
}

func (s *Server) fetchManifest(caller *http.Request, repo, ref string) (*ociManifest, string, error) {
	resp, err := s.zotGet(caller, "/v2/"+repo+"/manifests/"+ref, acceptManifest)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, "", &zotStatusErr{resp.StatusCode}
	}
	dig := resp.Header.Get("Docker-Content-Digest")
	var m ociManifest
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, dig, err
	}
	return &m, dig, nil
}

// zotStatusErr 은 zot 의 비정상 상태코드를 보존해 RBAC(401/403) 를 클라이언트로 그대로 전달한다.
type zotStatusErr struct{ code int }

func (e *zotStatusErr) Error() string { return fmt.Sprintf("zot status %d", e.code) }

// httpStatus 는 RBAC 거부(401/403)는 그대로, 그 외는 502 로 매핑한다.
func httpStatus(err error) int {
	if se, ok := err.(*zotStatusErr); ok {
		if se.code == http.StatusUnauthorized || se.code == http.StatusForbidden || se.code == http.StatusNotFound {
			return se.code
		}
	}
	return http.StatusBadGateway
}

// fetchIndexManifests 는 ref 가 이미지 인덱스면 자식(플랫폼별) 매니페스트 목록을 돌려준다.
func (s *Server) fetchIndexManifests(caller *http.Request, repo, ref string) []ociDesc {
	resp, err := s.zotGet(caller, "/v2/"+repo+"/manifests/"+ref, acceptManifest)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return nil
	}
	defer resp.Body.Close()
	var idx ociIndex
	_ = json.NewDecoder(resp.Body).Decode(&idx)
	return idx.Manifests
}

func platformDir(d ociDesc) string {
	if d.Platform != nil && d.Platform.OS != "" {
		if d.Platform.Architecture != "" {
			return d.Platform.OS + "-" + d.Platform.Architecture
		}
		return d.Platform.OS
	}
	return strings.ReplaceAll(d.Digest, ":", "_")[:19]
}

func (s *Server) fetchReferrers(caller *http.Request, repo, digest string) []ociDesc {
	resp, err := s.zotGet(caller, "/v2/"+repo+"/referrers/"+digest, "")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var idx ociIndex
	_ = json.NewDecoder(resp.Body).Decode(&idx)
	return idx.Manifests
}

var nonName = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func layerFilename(d ociDesc) string {
	if t := d.Annotations["org.opencontainers.image.title"]; t != "" {
		return path.Base(t)
	}
	ext := ".bin"
	if strings.Contains(d.MediaType, "json") {
		ext = ".json"
	}
	return strings.ReplaceAll(d.Digest, ":", "_") + ext
}

func kindDir(artifactType, mediaType string) string {
	t := artifactType
	if t == "" {
		t = mediaType
	}
	switch {
	case strings.Contains(t, "spdx"), strings.Contains(t, "cyclonedx") && !strings.Contains(t, "vex"):
		return "sbom"
	case strings.Contains(t, "vex"):
		return "vex"
	case strings.Contains(t, "sigstore"), strings.Contains(t, "cosign"), strings.Contains(t, "signature"):
		return "signature"
	case strings.Contains(t, "guide"), strings.Contains(t, "manual"), strings.Contains(t, "markdown"), strings.Contains(t, "pdf"):
		return "docs" // 매뉴얼·가이드 referrer → 번들 zip 의 docs/ 로 (전체 다운로드에 포함)
	default:
		return "other"
	}
}

// GET /api/artifact/blob?repo=&digest=&name=  — referrer 1건 내용(layer blob) 다운로드
func (s *Server) apiArtifactBlob(w http.ResponseWriter, r *http.Request) {
	repo := r.URL.Query().Get("repo")
	dg := r.URL.Query().Get("digest")
	if repo == "" || dg == "" {
		writeJSON(w, 400, map[string]string{"error": "repo, digest 필수"})
		return
	}
	m, _, err := s.fetchManifest(r, repo, dg)
	if err != nil {
		writeJSON(w, httpStatus(err), map[string]string{"error": "매니페스트 조회 실패(권한 또는 미존재)"})
		return
	}
	if len(m.Layers) == 0 {
		writeJSON(w, 502, map[string]string{"error": "레이어 없음"})
		return
	}
	layer := m.Layers[0]
	br, err := s.zotGet(r, "/v2/"+repo+"/blobs/"+layer.Digest, "")
	if err != nil || br.StatusCode != 200 {
		writeJSON(w, 502, map[string]string{"error": "blob 조회 실패"})
		return
	}
	defer br.Body.Close()
	name := r.URL.Query().Get("name")
	if name == "" {
		name = layerFilename(layer)
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename="+nonName.ReplaceAllString(name, "_"))
	io.Copy(w, br.Body)
}

// GET /api/artifact/bundle?repo=&tag=  — 바이너리 + 모든 referrer 를 zip 한 번에
func (s *Server) apiArtifactBundle(w http.ResponseWriter, r *http.Request) {
	repo := r.URL.Query().Get("repo")
	tag := r.URL.Query().Get("tag")
	if repo == "" || tag == "" {
		writeJSON(w, 400, map[string]string{"error": "repo, tag 필수"})
		return
	}
	subj, subjDigest, err := s.fetchManifest(r, repo, tag)
	if err != nil {
		// zip 스트림을 시작하기 전에 RBAC(401/403)/미존재를 그대로 전달
		writeJSON(w, httpStatus(err), map[string]string{"error": "매니페스트 조회 실패(권한 또는 미존재)"})
		return
	}
	base := nonName.ReplaceAllString(path.Base(repo)+"-"+tag, "_")
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename="+base+".zip")
	s.writeBundleZip(r, repo, tag, subj, subjDigest, w)
}

// writeBundleZip: 바이너리 + 모든 referrer(SBOM/VEX/서명)를 zip 으로 w 에 쓴다.
// caller 의 자격으로 zot 에서 받는다(RBAC). apiArtifactBundle(브라우저)·패키지(svc) 양쪽이 재사용.
func (s *Server) writeBundleZip(caller *http.Request, repo, tag string, subj *ociManifest, subjDigest string, w io.Writer) {
	zw := zip.NewWriter(w)
	defer zw.Close()

	add := func(dir string, layer ociDesc) {
		br, err := s.zotGet(caller, "/v2/"+repo+"/blobs/"+layer.Digest, "")
		if err != nil || br.StatusCode != 200 {
			return
		}
		defer br.Body.Close()
		fw, err := zw.Create(dir + "/" + layerFilename(layer))
		if err != nil {
			return
		}
		io.Copy(fw, br.Body)
	}

	// 바이너리(subject layers; 인덱스면 각 플랫폼 매니페스트의 layers)
	if len(subj.Layers) > 0 {
		for _, l := range subj.Layers {
			add("binary", l)
		}
	} else {
		for _, child := range s.fetchIndexManifests(caller, repo, tag) {
			cm, _, err := s.fetchManifest(caller, repo, child.Digest)
			if err != nil {
				continue
			}
			for _, l := range cm.Layers {
				add("binary/"+platformDir(child), l)
			}
		}
	}
	// referrers (SBOM/VEX/서명)
	for _, ref := range s.fetchReferrers(caller, repo, subjDigest) {
		rm, _, err := s.fetchManifest(caller, repo, ref.Digest)
		if err != nil {
			continue
		}
		dir := kindDir(ref.ArtifactType, rm.ArtifactType)
		for _, l := range rm.Layers {
			add(dir, l)
		}
	}
}
