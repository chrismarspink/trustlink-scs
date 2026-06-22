package main

// sbom.go: TrustLink 자체 SBOM 생성 — SBOM 이 없는 아티팩트를 syft 로 스캔해 CycloneDX 로
// 부착한다. 두 소스:
//   - source="self"  : TrustLink 자기 자신(실행 중인 BFF 바이너리)을 스캔 → TrustLink 자체 SBOM
//   - source="" (기본): 대상 아티팩트의 바이너리 레이어를 zot 에서 받아 디렉토리 스캔
// 생성물은 application/vnd.cyclonedx+json referrer 로 subject 에 부착(svc 권한). 원본 불변·누적.
// "없는 의존성을 지어내지 않는다" — SBOM 품질 = 스캔 대상에 실제로 있는 정보만큼.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"time"
)

const sbomArtifactType = "application/vnd.cyclonedx+json"

// runSyft: target(파일/디렉토리/`dir:` 등)을 스캔해 CycloneDX(JSON) 바이트 + 컴포넌트 수 반환.
func runSyft(target string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "syft", target, "-o", "cyclonedx-json", "-q")
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return nil, 0, fmt.Errorf("syft %s: %v: %s", target, err, errb.String())
	}
	b := out.Bytes()
	var doc struct {
		Components []json.RawMessage `json:"components"`
	}
	_ = json.Unmarshal(b, &doc)
	return b, len(doc.Components), nil
}

// downloadBinaries: subject(이미지/인덱스)의 바이너리 레이어를 dir 에 받는다(svc 권한). 받은 파일 수 반환.
func (s *Server) downloadBinaries(caller *http.Request, repo, tag, dir string) int {
	n := 0
	save := func(layer ociDesc) {
		br, err := s.zotGet(caller, "/v2/"+repo+"/blobs/"+layer.Digest, "")
		if err != nil || br.StatusCode != 200 {
			return
		}
		defer br.Body.Close()
		f, err := os.Create(filepath.Join(dir, layerFilename(layer)))
		if err != nil {
			return
		}
		defer f.Close()
		if _, err := io.Copy(f, br.Body); err == nil {
			n++
		}
	}
	subj, _, err := s.fetchManifest(caller, repo, tag)
	if err != nil {
		return 0
	}
	if len(subj.Layers) > 0 {
		for _, l := range subj.Layers {
			save(l)
		}
	} else {
		for _, child := range s.fetchIndexManifests(caller, repo, tag) {
			cm, _, err := s.fetchManifest(caller, repo, child.Digest)
			if err != nil {
				continue
			}
			for _, l := range cm.Layers {
				save(l)
			}
		}
	}
	return n
}

// attachSBOM: CycloneDX SBOM 을 subject 에 referrer 로 부착(svc 권한). referrer digest 반환.
func (s *Server) attachSBOM(repo, tag string, sbom []byte, generator string) (string, error) {
	caller := s.svcCaller()
	subj, err := s.subjectDescriptor(caller, repo, tag)
	if err != nil {
		return "", err
	}
	cfgDigest, err := s.pushBlob(caller, repo, []byte("{}"))
	if err != nil {
		return "", fmt.Errorf("config blob: %w", err)
	}
	sbomDigest, err := s.pushBlob(caller, repo, sbom)
	if err != nil {
		return "", fmt.Errorf("sbom blob: %w", err)
	}
	manifest := map[string]any{
		"schemaVersion": 2,
		"mediaType":     ociManifestType,
		"artifactType":  sbomArtifactType,
		"config":        map[string]any{"mediaType": ociEmptyType, "digest": cfgDigest, "size": 2, "data": "e30="},
		"layers": []any{map[string]any{
			"mediaType":   sbomArtifactType,
			"digest":      sbomDigest,
			"size":        len(sbom),
			"annotations": map[string]string{"org.opencontainers.image.title": fmt.Sprintf("%s-%s.sbom.cdx.json", path.Base(repo), tag)},
		}},
		"subject": map[string]any{"mediaType": subj.MediaType, "digest": subj.Digest, "size": subj.Size},
		"annotations": map[string]string{
			"org.opencontainers.image.created": time.Now().UTC().Format(time.RFC3339),
			"com.trustlink.sbom.generator":     generator,
			"com.trustlink.sbom.provenance":    "trustlink-analyzed", // 자체 분석(빌드 증명 아님)
		},
	}
	mBytes, _ := json.Marshal(manifest)
	mDigest := "sha256:" + sha256hex(mBytes)
	putReq, _ := http.NewRequest("PUT", s.cfg.ZotAPIURL+"/v2/"+repo+"/manifests/"+mDigest, bytes.NewReader(mBytes))
	applyCaller(caller, putReq)
	putReq.Header.Set("Content-Type", ociManifestType)
	presp, err := s.http.Do(putReq)
	if err != nil {
		return "", err
	}
	presp.Body.Close()
	if presp.StatusCode != http.StatusCreated {
		return "", &zotStatusErr{presp.StatusCode}
	}
	return mDigest, nil
}

// POST /api/sbom/generate {repo, tag, source}
//   source="self": TrustLink 자기 자신(BFF 바이너리) 스캔. 그 외: 대상 아티팩트 스캔.
//   생성한 CycloneDX SBOM 을 subject 에 referrer 로 부착.
func (s *Server) apiSBOMGenerate(w http.ResponseWriter, r *http.Request) {
	var in struct{ Repo, Tag, Source string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Repo == "" || in.Tag == "" {
		writeJSON(w, 400, map[string]string{"error": "repo, tag 필수"})
		return
	}

	var sbom []byte
	var comps int
	var generator, target string

	if in.Source == "self" {
		// TrustLink 자기 자신 = 실행 중인 BFF 컨테이너 루트파일시스템(실제 배포 산출물의
		// 전체 공급망: alpine OS 패키지 + 임베드 바이너리(openssl·step·syft)의 Go 모듈 +
		// trustlink-admin). BFF 바이너리만 스캔하면 stdlib 전용이라 빈약 → rootfs 스캔.
		target = "dir:/"
		generator = "syft (self: container rootfs)"
		b, n, err := runSyft(target)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "syft 실패: " + err.Error()})
			return
		}
		sbom, comps = b, n
	} else {
		// 대상 아티팩트의 바이너리 레이어를 받아 디렉토리 스캔.
		dir, err := os.MkdirTemp("", "tl-sbom-*")
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		defer os.RemoveAll(dir)
		got := s.downloadBinaries(s.svcCaller(), in.Repo, in.Tag, dir)
		if got == 0 {
			writeJSON(w, 502, map[string]string{"error": "스캔할 바이너리 레이어 없음(아티팩트 미존재/권한)"})
			return
		}
		b, n, err := runSyft("dir:" + dir)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "syft 실패: " + err.Error()})
			return
		}
		sbom, comps, generator = b, n, fmt.Sprintf("syft (artifact: %d files)", got)
	}

	refDigest, err := s.attachSBOM(in.Repo, in.Tag, sbom, generator)
	if err != nil {
		writeJSON(w, httpStatus(err), map[string]string{"error": "SBOM 부착 실패: " + err.Error()})
		return
	}
	_ = s.sor.append(SoREvent{Actor: w.Header().Get("X-User"), Action: "sbom-generate", Repo: in.Repo, Tag: in.Tag,
		Status: "attached", Detail: map[string]any{"components": comps, "generator": generator, "referrer": refDigest}})
	writeJSON(w, 200, map[string]any{
		"status": "generated", "repo": in.Repo, "tag": in.Tag,
		"components": comps, "generator": generator, "referrer": refDigest,
	})
}
