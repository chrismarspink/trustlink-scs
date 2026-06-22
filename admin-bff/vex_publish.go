package main

// VEX 발행: Dependency-Track 에서 추출한 CycloneDX VEX 를 zot 에 "새 OCI referrer" 로 부착한다.
//   - 원본 SBOM/VEX 는 절대 덮어쓰지 않는다(새 digest 의 referrer 로 누적, 이력 보존).
//   - push 는 호출자(브라우저)의 zot 세션을 그대로 전달 → zot 이 레포 쓰기 RBAC 를 직접 강제한다.
//   - oras 바이너리 없이(BFF 이미지는 distroless) OCI distribution HTTP API 로 직접 push.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

const (
	vexArtifactType = "application/vnd.cyclonedx.vex+json" // dt-verify.sh 규약과 동일
	ociManifestType = "application/vnd.oci.image.manifest.v1+json"
	ociEmptyType    = "application/vnd.oci.empty.v1+json"
)

func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// applyCaller: zot 요청에 호출자 자격(세션 쿠키/Authorization)을 전달하고 Basic 팝업을 억제한다.
func applyCaller(caller, req *http.Request) {
	req.Header.Set("X-ZOT-API-CLIENT", "zot-ui")
	if c := caller.Header.Get("Cookie"); c != "" {
		req.Header.Set("Cookie", c)
	}
	if a := caller.Header.Get("Authorization"); a != "" {
		req.Header.Set("Authorization", a)
	}
}

// pushBlob: 2단계(POST uploads → PUT ?digest=) 모놀리식 업로드. digest 반환.
func (s *Server) pushBlob(caller *http.Request, repo string, data []byte) (string, error) {
	dg := "sha256:" + sha256hex(data)
	initReq, _ := http.NewRequest("POST", s.cfg.ZotAPIURL+"/v2/"+repo+"/blobs/uploads/", nil)
	applyCaller(caller, initReq)
	resp, err := s.http.Do(initReq)
	if err != nil {
		return "", err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusCreated {
		return dg, nil // 이미 존재(혹은 즉시 생성)
	}
	if resp.StatusCode != http.StatusAccepted {
		return "", &zotStatusErr{resp.StatusCode}
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return "", fmt.Errorf("upload location 없음")
	}
	u := loc
	if strings.HasPrefix(loc, "/") {
		u = s.cfg.ZotAPIURL + loc
	}
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	u += sep + "digest=" + url.QueryEscape(dg)
	putReq, _ := http.NewRequest("PUT", u, bytes.NewReader(data))
	applyCaller(caller, putReq)
	putReq.Header.Set("Content-Type", "application/octet-stream")
	presp, err := s.http.Do(putReq)
	if err != nil {
		return "", err
	}
	io.Copy(io.Discard, presp.Body)
	presp.Body.Close()
	if presp.StatusCode != http.StatusCreated {
		return "", &zotStatusErr{presp.StatusCode}
	}
	return dg, nil
}

// subjectDescriptor: subject(이미지/인덱스) 의 digest·size·mediaType.
func (s *Server) subjectDescriptor(caller *http.Request, repo, ref string) (ociDesc, error) {
	resp, err := s.zotGet(caller, "/v2/"+repo+"/manifests/"+ref, acceptManifest)
	if err != nil {
		return ociDesc{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ociDesc{}, &zotStatusErr{resp.StatusCode}
	}
	body, _ := io.ReadAll(resp.Body)
	var mt struct {
		MediaType string `json:"mediaType"`
	}
	_ = json.Unmarshal(body, &mt)
	dg := resp.Header.Get("Docker-Content-Digest")
	if dg == "" {
		dg = "sha256:" + sha256hex(body)
	}
	if mt.MediaType == "" {
		mt.MediaType = ociManifestType
	}
	return ociDesc{MediaType: mt.MediaType, Digest: dg, Size: int64(len(body))}, nil
}

// POST /api/vex/publish {repo, tag, project, version}
//
//	repo:tag = zot subject, project/version = DT 프로젝트. DT VEX 추출 → 새 referrer 부착.
func (s *Server) apiVexPublish(w http.ResponseWriter, r *http.Request) {
	if !s.requireDT(w) {
		return
	}
	var in struct{ Repo, Tag, Project, Version string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Repo == "" || in.Tag == "" {
		writeJSON(w, 400, map[string]string{"error": "repo, tag 필수"})
		return
	}
	if in.Project == "" {
		in.Project = path.Base(in.Repo)
	}
	if in.Version == "" {
		in.Version = in.Tag
	}

	// 1) DT 프로젝트 보장(없으면 SBOM referrer 자동 적재) → VEX 추출
	uuid, err := s.ensureDTProject(r, in.Repo, in.Tag, in.Project, in.Version)
	if err != nil {
		writeJSON(w, httpStatus(err), map[string]string{"error": err.Error()})
		return
	}
	if uuid == "" {
		writeJSON(w, 404, map[string]string{"error": "DT 프로젝트 없음 (SBOM referrer 확인)"})
		return
	}
	vex, code, err := s.dtExportVEX(uuid)
	if err != nil || code != 200 {
		writeJSON(w, 502, map[string]string{"error": "DT VEX 추출 실패"})
		return
	}

	// 2) subject 확인 (호출자 권한으로). 권한 없으면 zot 이 401/403.
	subj, err := s.subjectDescriptor(r, in.Repo, in.Tag)
	if err != nil {
		writeJSON(w, httpStatus(err), map[string]string{"error": "subject 조회 실패(권한 또는 미존재)"})
		return
	}

	// 3) blob push: 빈 config + VEX layer (호출자 권한 → zot 쓰기 RBAC 강제)
	cfgDigest, err := s.pushBlob(r, in.Repo, []byte("{}"))
	if err != nil {
		writeJSON(w, httpStatus(err), map[string]string{"error": "config blob push 실패(쓰기 권한 필요)"})
		return
	}
	vexDigest, err := s.pushBlob(r, in.Repo, vex)
	if err != nil {
		writeJSON(w, httpStatus(err), map[string]string{"error": "VEX blob push 실패"})
		return
	}

	// 4) referrer 매니페스트(subject 지정) push → 원본 불변, 새 digest 누적
	created := time.Now().UTC().Format(time.RFC3339)
	author := w.Header().Get("X-User")
	title := fmt.Sprintf("%s-%s.vex.cdx.json", path.Base(in.Repo), in.Tag)
	manifest := map[string]any{
		"schemaVersion": 2,
		"mediaType":     ociManifestType,
		"artifactType":  vexArtifactType,
		"config": map[string]any{
			"mediaType": ociEmptyType,
			"digest":    cfgDigest,
			"size":      2,
			"data":      "e30=",
		},
		"layers": []any{map[string]any{
			"mediaType":   "application/json",
			"digest":      vexDigest,
			"size":        len(vex),
			"annotations": map[string]string{"org.opencontainers.image.title": title},
		}},
		"subject": map[string]any{
			"mediaType": subj.MediaType,
			"digest":    subj.Digest,
			"size":      subj.Size,
		},
		"annotations": map[string]string{
			"org.opencontainers.image.created": created,
			"com.trustlink.vex.author":         author,
			"com.trustlink.vex.source":         "trustlink-triage",
		},
	}
	mBytes, _ := json.Marshal(manifest)
	mDigest := "sha256:" + sha256hex(mBytes)
	putReq, _ := http.NewRequest("PUT", s.cfg.ZotAPIURL+"/v2/"+in.Repo+"/manifests/"+mDigest, bytes.NewReader(mBytes))
	applyCaller(r, putReq)
	putReq.Header.Set("Content-Type", ociManifestType)
	presp, err := s.http.Do(putReq)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	pb, _ := io.ReadAll(presp.Body)
	presp.Body.Close()
	if presp.StatusCode != http.StatusCreated {
		writeJSON(w, httpStatus(&zotStatusErr{presp.StatusCode}), map[string]string{"error": "manifest push 실패", "detail": string(pb)})
		return
	}
	writeJSON(w, 200, map[string]any{
		"status":   "published",
		"digest":   mDigest,
		"author":   author,
		"created":  created,
		"artifact": vexArtifactType,
	})
}
