package main

// SBOM 자동 적재(ingest): zot 의 CycloneDX SBOM referrer 를 Dependency-Track 으로 올려 분석 프로젝트를 만든다.
//   - DT 는 "바이너리"가 아니라 "SBOM(부품표)"을 입력으로 받아 컴포넌트↔CVE 를 대조한다.
//   - 따라서 분석/발행 전, 해당 제품@태그의 SBOM referrer 를 DT 프로젝트로 보장한다.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var urnUUID = regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// sanitizeBOM: DT 의 엄격한 CycloneDX 스키마 검증을 통과하도록 "전송용 복사본"을 최소 정규화한다.
//   - 잘못된 serialNumber(선택 필드) 제거. 원본 referrer(zot)는 불변.
func sanitizeBOM(b []byte) []byte {
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return b // JSON 아니면(SPDX 등) 그대로
	}
	if sn, ok := m["serialNumber"].(string); ok && !urnUUID.MatchString(sn) {
		delete(m, "serialNumber")
		if out, err := json.Marshal(m); err == nil {
			return out
		}
	}
	return b
}

// isSBOM: CycloneDX SBOM referrer 판별(VEX 제외).
func isSBOM(artifactType string) bool {
	t := strings.ToLower(artifactType)
	return strings.Contains(t, "cyclonedx") && !strings.Contains(t, "vex")
}

// fetchBlob: referrer layer blob 바이트.
func (s *Server) fetchBlob(caller *http.Request, repo, digest string) ([]byte, error) {
	resp, err := s.zotGet(caller, "/v2/"+repo+"/blobs/"+digest, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, &zotStatusErr{resp.StatusCode}
	}
	return io.ReadAll(resp.Body)
}

// ensureDTProject: (제품@태그) DT 프로젝트 uuid 보장. 없으면 SBOM referrer 를 적재 후 분석 완료까지 대기.
func (s *Server) ensureDTProject(caller *http.Request, repo, tag, name, version string) (string, error) {
	if uuid, _ := s.dtLookupProject(name, version); uuid != "" {
		return uuid, nil
	}
	// 1) subject → referrers 에서 CycloneDX SBOM 찾기
	_, subjDigest, err := s.fetchManifest(caller, repo, tag)
	if err != nil {
		return "", err
	}
	var sbomLayer *ociDesc
	for _, ref := range s.fetchReferrers(caller, repo, subjDigest) {
		if !isSBOM(ref.ArtifactType) {
			continue
		}
		rm, _, err := s.fetchManifest(caller, repo, ref.Digest)
		if err != nil || len(rm.Layers) == 0 {
			continue
		}
		l := rm.Layers[0]
		sbomLayer = &l
		break
	}
	if sbomLayer == nil {
		return "", fmt.Errorf("CycloneDX SBOM referrer 없음 (먼저 SBOM 첨부 필요)")
	}
	// 2) SBOM blob → DT 업로드(autoCreate)
	blob, err := s.fetchBlob(caller, repo, sbomLayer.Digest)
	if err != nil {
		return "", fmt.Errorf("SBOM blob 조회 실패: %w", err)
	}
	token, err := s.dtUploadBOM(name, version, base64.StdEncoding.EncodeToString(sanitizeBOM(blob)))
	if err != nil {
		return "", fmt.Errorf("DT 업로드 실패: %w", err)
	}
	// 3) 분석 완료 폴링 (최대 ~40s)
	for i := 0; i < 40; i++ {
		processing, err := s.dtBomProcessing(token)
		if err == nil && !processing {
			break
		}
		time.Sleep(1 * time.Second)
	}
	// 4) uuid 재조회
	uuid, err := s.dtLookupProject(name, version)
	if err != nil {
		return "", err
	}
	if uuid == "" {
		return "", fmt.Errorf("적재 후에도 DT 프로젝트 미생성 (분석 지연 가능, 잠시 후 재시도)")
	}
	return uuid, nil
}
