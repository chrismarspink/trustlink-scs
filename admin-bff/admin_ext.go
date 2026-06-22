package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
)

// ---------- 시스템 상태 / 헬스 ----------

func (s *Server) apiHealth(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{}
	// zot: /v2/ 가 200/401 이면 살아있음
	out["zot"] = s.ping(s.cfg.ZotAPIURL+"/v2/", true)
	// keycloak realm
	out["keycloak"] = s.ping(fmt.Sprintf("%s/realms/%s", s.cfg.KCInternal, s.cfg.Realm), false)
	writeJSON(w, 200, out)
}

func (s *Server) ping(url string, auth401ok bool) bool {
	req, _ := http.NewRequest("GET", url, nil)
	resp, err := s.http.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return true
	}
	return auth401ok && resp.StatusCode == 401
}

// ---------- 레지스트리 관리 (repo/tag, 삭제) ----------

func (s *Server) zotReq(method, path string) (*http.Response, error) {
	req, _ := http.NewRequest(method, s.cfg.ZotAPIURL+path, nil)
	if s.cfg.ZotAdminUser != "" {
		req.SetBasicAuth(s.cfg.ZotAdminUser, s.cfg.ZotAdminPass)
	}
	return s.http.Do(req)
}

func (s *Server) apiRepos(w http.ResponseWriter, r *http.Request) {
	resp, err := s.zotReq("GET", "/v2/_catalog?n=1000")
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	var cat struct {
		Repositories []string `json:"repositories"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&cat)
	out := []map[string]any{}
	for _, repo := range cat.Repositories {
		tags := s.repoTags(repo)
		out = append(out, map[string]any{"repo": repo, "tags": tags, "tagCount": len(tags)})
	}
	writeJSON(w, 200, out)
}

func (s *Server) repoTags(repo string) []string {
	resp, err := s.zotReq("GET", "/v2/"+repo+"/tags/list")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var t struct {
		Tags []string `json:"tags"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&t)
	sort.Strings(t.Tags)
	return t.Tags
}

func (s *Server) apiDeleteTag(w http.ResponseWriter, r *http.Request) {
	var in struct{ Repo, Tag string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Repo == "" || in.Tag == "" {
		writeJSON(w, 400, map[string]string{"error": "repo, tag 필수"})
		return
	}
	// 태그 → digest 조회 (zot 는 digest 로 삭제)
	req, _ := http.NewRequest("GET", s.cfg.ZotAPIURL+"/v2/"+in.Repo+"/manifests/"+in.Tag, nil)
	req.Header.Set("Accept", "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json")
	if s.cfg.ZotAdminUser != "" {
		req.SetBasicAuth(s.cfg.ZotAdminUser, s.cfg.ZotAdminPass)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	digest := resp.Header.Get("Docker-Content-Digest")
	resp.Body.Close()
	if digest == "" {
		writeJSON(w, 404, map[string]string{"error": "매니페스트/digest 조회 실패"})
		return
	}
	del, err := s.zotReq("DELETE", "/v2/"+in.Repo+"/manifests/"+digest)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	defer del.Body.Close()
	if del.StatusCode != 202 && del.StatusCode != 200 {
		writeJSON(w, del.StatusCode, map[string]string{"error": fmt.Sprintf("삭제 실패(status %d) — 권한(delete) 확인", del.StatusCode)})
		return
	}
	writeJSON(w, 200, map[string]string{"repo": in.Repo, "tag": in.Tag, "digest": digest, "status": "deleted"})
}

// ---------- 리텐션 dryRun 결과 (로그에서 파싱) ----------

func (s *Server) apiRetention(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(s.cfg.LogFile)
	if err != nil {
		writeJSON(w, 200, map[string]any{"candidates": []any{}, "note": "로그 없음"})
		return
	}
	type cand struct{ Repository, Reference, Reason string }
	seen := map[string]bool{}
	cands := []cand{}
	for _, ln := range strings.Split(string(data), "\n") {
		if !strings.Contains(ln, `"decision":"delete"`) {
			continue
		}
		var m struct {
			Repository string `json:"repository"`
			Reference  string `json:"reference"`
			Reason     string `json:"reason"`
			DryRun     bool   `json:"dry-run"`
		}
		if json.Unmarshal([]byte(ln), &m) != nil {
			continue
		}
		key := m.Repository + "|" + m.Reference
		if seen[key] {
			continue
		}
		seen[key] = true
		cands = append(cands, cand{m.Repository, m.Reference, m.Reason})
	}
	writeJSON(w, 200, map[string]any{
		"candidates": cands,
		"count":      len(cands),
		"note":       "dryRun 기준 삭제 예정 목록. 실제 삭제는 config의 retention.dryRun=false 전환 + 재기동으로 적용됩니다.",
	})
}

// ---------- 권한 매트릭스 (config accessControl 읽기) ----------

func (s *Server) apiACL(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(s.cfg.ConfigFile)
	if err != nil {
		writeJSON(w, 200, map[string]any{"error": "config 읽기 실패: " + err.Error()})
		return
	}
	var cfg map[string]any
	if json.Unmarshal(data, &cfg) != nil {
		writeJSON(w, 200, map[string]any{"error": "config 파싱 실패"})
		return
	}
	ac := dig(cfg, "http", "accessControl")
	writeJSON(w, 200, map[string]any{"accessControl": ac})
}

// ---------- 설정 관리 ▸ 오브젝트 스토리지(확장용) ----------

func (s *Server) apiStorageGet(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(s.cfg.ConfigFile)
	if err != nil {
		writeJSON(w, 200, map[string]any{"error": "config 읽기 실패: " + err.Error()})
		return
	}
	var cfg map[string]any
	_ = json.Unmarshal(data, &cfg)
	st, _ := cfg["storage"].(map[string]any)
	driver := "local (filesystem)"
	if sd, ok := st["storageDriver"].(map[string]any); ok {
		if n, ok := sd["name"].(string); ok {
			driver = n
		}
	}
	writeJSON(w, 200, map[string]any{
		"driver":        driver,
		"rootDirectory": st["rootDirectory"],
		"dedupe":        st["dedupe"],
		"gc":            st["gc"],
		"retention":     st["retention"] != nil,
	})
}

// apiStoragePreview: S3/MinIO 파라미터 → 적용할 zot storage 설정 블록 생성(전환은 운영 절차).
func (s *Server) apiStoragePreview(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Endpoint  string `json:"endpoint"`
		Region    string `json:"region"`
		Bucket    string `json:"bucket"`
		AccessKey string `json:"accessKey"`
		SecretKey string `json:"secretKey"`
		Secure    bool   `json:"secure"`
		RootDir   string `json:"rootDirectory"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Bucket == "" {
		writeJSON(w, 400, map[string]string{"error": "bucket 필수"})
		return
	}
	if in.Region == "" {
		in.Region = "us-east-1"
	}
	if in.RootDir == "" {
		in.RootDir = "/registry"
	}
	block := map[string]any{
		"storage": map[string]any{
			"rootDirectory": in.RootDir,
			"dedupe":        false, // S3 는 서버측 중복제거 권장 off (드라이버/캐시 의존)
			"gc":            true,
			"storageDriver": map[string]any{
				"name":           "s3",
				"region":         in.Region,
				"regionendpoint": in.Endpoint,
				"bucket":         in.Bucket,
				"accesskey":      in.AccessKey,
				"secretkey":      in.SecretKey,
				"secure":         in.Secure,
				"rootdirectory":  in.RootDir,
			},
			"cacheDriver": map[string]any{
				"name": "redis", "url": "redis://redis:6379", "keyprefix": "zot",
			},
		},
	}
	pretty, _ := json.MarshalIndent(block, "", "  ")
	writeJSON(w, 200, map[string]any{
		"configBlock": string(pretty),
		"steps": []string{
			"1) 오브젝트 스토리지(MinIO/S3) 버킷 생성 및 자격증명 준비",
			"2) 위 storage 블록을 zot config에 반영(로컬 storageDriver 제거)",
			"3) 기존 로컬 데이터 → 버킷으로 1회 마이그레이션(rclone/mc)",
			"4) 다중 인스턴스면 cacheDriver(redis) 공유 설정",
			"5) zot 재기동 후 catalog/pull 검증",
		},
		"note": "확장(온프레→SaaS) 전환용. 현재는 로컬 스토리지를 유지합니다. 자세한 절차는 STORAGE-SCALING.md 참고.",
	})
}

func dig(m map[string]any, keys ...string) any {
	var cur any = m
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}
