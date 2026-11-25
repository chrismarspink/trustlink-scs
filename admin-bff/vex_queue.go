package main

// vex_queue.go: VEX 판단 대기열 — 감시 중인 모든 제품·버전의 미판단 취약점을 한 화면에 모은다.
// 보안·개발·관리자(vexEditors)용. 관리자가 아니면 읽기 권한이 있는 제품만 보인다.
// 행마다 미판단 수(심각도별)·KEV·AI 일괄 판정 상태를 주고, 판단은 제품 화면(VexPanel)에서 한다.

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type vexQueueRow struct {
	Repo        string `json:"repo"`
	Tag         string `json:"tag"`
	Project     string `json:"project"` // DT 프로젝트 UUID(AI 일괄 판정 키)
	Total       int    `json:"total"`
	Analyzed    int    `json:"analyzed"`
	Pending     int    `json:"pending"`
	PendCrit    int    `json:"pendCritical"`
	PendHigh    int    `json:"pendHigh"`
	PendKEV     int    `json:"pendKev"`
	Affected    int    `json:"affected"`           // 영향 있음(조치 필요)
	Imported    int64  `json:"imported,omitempty"` // 이 버전의 SBOM 을 받은 때(ms) — 화면이 제품별 최신 버전을 가린다
	Demo        bool   `json:"demo,omitempty"`     // 시연용 제품(REAL_REPO_PREFIX 를 정했을 때 그 밖의 제품)
	BatchState  string `json:"batchState,omitempty"`
	BatchDone   int    `json:"batchDone,omitempty"`
	BatchTotal  int    `json:"batchTotal,omitempty"`
	BatchPhase  string `json:"batchPhase,omitempty"` // enrich = 판정은 끝났고 권고문 요약을 덧붙이는 중
	EnrichDone  int    `json:"enrichDone,omitempty"`
	EnrichTotal int    `json:"enrichTotal,omitempty"`
	BatchDrafts int    `json:"batchDrafts,omitempty"` // 저장 대기 중인 AI 초안 수
	BatchAt     string `json:"batchAt,omitempty"`
	BatchAuto   int    `json:"batchAuto,omitempty"` // 그중 자동 초안(KEV·치명) 수
}

var vexQueueCache struct {
	sync.Mutex
	at      time.Time
	rows    []vexQueueRow
	idx     map[string][]vulnHit // 취약점 ID(대문자) → 그 취약점이 있는 제품·버전("묻고 찾기"용)
	skipped int                  // 취약점 분석기가 답하지 않아 집계에서 빠진 제품·버전 수(화면이 "일부만 표시"를 알린다)
}

// vulnHit: 어느 제품·버전의 어느 구성요소에 그 취약점이 있는가.
type vulnHit struct {
	Repo, Tag, Component, Severity, State string
	Project                               string // 분석 엔진의 프로젝트 UUID
	Found                                 int64  // 이 버전에서 처음 발견된 때(epoch ms, 없으면 0)
}

// vexQueueRows: 전 제품 집계(1분 캐시). 권한 필터는 호출 쪽에서.
func (s *Server) vexQueueRows(refresh bool) []vexQueueRow {
	vexQueueCache.Lock()
	defer vexQueueCache.Unlock()
	if !refresh && vexQueueCache.rows != nil && time.Since(vexQueueCache.at) < time.Minute {
		return vexQueueCache.rows
	}
	n := s.notify
	projects := map[string]string{}
	if n != nil {
		n.mu.Lock()
		for k, v := range n.st.Projects {
			projects[k] = v
		}
		n.mu.Unlock()
	}
	kev, _, _ := kevIndex()
	rows := []vexQueueRow{}
	idx := map[string][]vulnHit{}
	skipped := 0
	for key, repo := range projects {
		name, tag, ok := strings.Cut(key, "@")
		if !ok {
			continue
		}
		uuid, err := s.dtLookupProject(name, tag)
		if err != nil {
			skipped++
		}
		if err != nil || uuid == "" {
			continue
		}
		row := vexQueueRow{Repo: repo, Tag: tag, Project: uuid}
		if v, ok := dtImported.Load(uuid); ok {
			row.Imported, _ = v.(int64)
		}
		row.Demo = isDemoRepo(repo)
		var fs []dtFinding
		if b, err := s.dtFindings(uuid); err == nil {
			_ = json.Unmarshal(b, &fs)
		} else {
			skipped++
			continue // 취약점을 못 받은 제품을 "0건"으로 보여 주지 않는다
		}
		for _, f := range fs {
			if f.Analysis.IsSuppressed {
				continue
			}
			id := strings.ToUpper(f.Vulnerability.VulnID)
			idx[id] = append(idx[id], vulnHit{Repo: repo, Tag: tag, Component: strings.TrimSpace(f.Component.Name + " " + f.Component.Version),
				Severity: strings.ToUpper(f.Vulnerability.Severity), State: f.Analysis.State, Project: uuid, Found: f.Attribution.AttributedOn})
			row.Total++
			if !pendingState(f.Analysis.State) {
				row.Analyzed++
				if strings.EqualFold(f.Analysis.State, "EXPLOITABLE") {
					row.Affected++
				}
				continue
			}
			row.Pending++
			switch strings.ToUpper(f.Vulnerability.Severity) {
			case "CRITICAL":
				row.PendCrit++
			case "HIGH":
				row.PendHigh++
			}
			if _, hit := kev[strings.ToUpper(f.Vulnerability.VulnID)]; hit {
				row.PendKEV++
			}
		}
		if b := vexBatchGet(uuid); b != nil {
			row.BatchState, row.BatchDone, row.BatchTotal = b.State, b.Done, b.Total
			if b.State == "running" && b.Phase == "enrich" {
				row.BatchPhase, row.EnrichDone, row.EnrichTotal = "enrich", b.EnrichDone, b.EnrichTotal
			}
			row.BatchDrafts, row.BatchAt = len(b.Results), firstNonEmpty(b.Finished, b.Started)
			vexBatchMu.Lock() // 진행 중인 일괄 판정이 Results 에 쓰는 중일 수 있다
			for _, r := range b.Results {
				if r != nil && r.Auto {
					row.BatchAuto++
				}
			}
			vexBatchMu.Unlock()
		}
		rows = append(rows, row)
	}
	// 급한 순: KEV → 미판단 치명 → 높음 → 미판단 수
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.PendKEV != b.PendKEV {
			return a.PendKEV > b.PendKEV
		}
		if a.PendCrit != b.PendCrit {
			return a.PendCrit > b.PendCrit
		}
		if a.PendHigh != b.PendHigh {
			return a.PendHigh > b.PendHigh
		}
		if a.Pending != b.Pending {
			return a.Pending > b.Pending
		}
		return a.Repo+a.Tag < b.Repo+b.Tag
	})
	vexQueueCache.rows, vexQueueCache.at, vexQueueCache.idx, vexQueueCache.skipped = rows, time.Now(), idx, skipped
	return rows
}

// vexBatchGet: 진행 중이면 메모리, 아니면 마지막 결과 파일.
func vexBatchGet(project string) *vexBatch {
	vexBatchMu.Lock()
	b := vexBatches[project]
	vexBatchMu.Unlock()
	if b != nil {
		return b
	}
	var fb vexBatch
	if readJSONFile(vexBatchPath(project), &fb) == nil {
		if fb.State == "running" { // 메모리에 없는데 파일이 "진행 중" = 재시작으로 끊긴 작업. 계속 진행 중으로 보이지 않게 한다
			fb.State, fb.Error = "cancelled", "서비스 재시작으로 중단됨"
		}
		return &fb
	}
	return nil
}

// GET /api/vex/queue[?refresh=1] — VEX 판단 대기열(보안·개발·관리자).
func (s *Server) apiVexQueue(w http.ResponseWriter, r *http.Request) {
	if !s.dtEnabled() {
		writeJSON(w, 200, map[string]any{"dt": false, "rows": []vexQueueRow{}})
		return
	}
	sess, _ := s.sessionOf(r)
	all := s.vexQueueRows(r.URL.Query().Get("refresh") == "1")
	rows := []vexQueueRow{}
	for _, row := range all {
		if contains(sess.Groups, "admins") || s.access == nil || s.access.allowed(sess.Username, sess.Groups, row.Repo, "read") {
			rows = append(rows, row)
		}
	}
	vexQueueCache.Lock()
	skipped := vexQueueCache.skipped
	vexQueueCache.Unlock()
	sum := map[string]int{}
	for _, row := range rows {
		sum["pending"] += row.Pending
		sum["pendCritical"] += row.PendCrit
		sum["pendHigh"] += row.PendHigh
		sum["pendKev"] += row.PendKEV
		sum["affected"] += row.Affected
		sum["total"] += row.Total
		sum["drafts"] += row.BatchDrafts
		if row.BatchState == "running" {
			sum["running"]++
		}
	}
	writeJSON(w, 200, map[string]any{"dt": true, "rows": rows, "summary": sum, "ai": aiEnabled(), "generated": time.Now().UTC().Format(time.RFC3339), "skipped": skipped})
}

// isDemoRepo: REAL_REPO_PREFIX(쉼표로 여러 개)를 정해 두면 그 접두어로 시작하지 않는 제품을 시연용으로 본다. 비어 있으면 나누지 않는다.
func isDemoRepo(repo string) bool {
	real := strings.TrimSpace(env("REAL_REPO_PREFIX", ""))
	if real == "" {
		return false
	}
	for _, p := range strings.Split(real, ",") {
		if p = strings.TrimSpace(p); p != "" && strings.HasPrefix(repo, p) {
			return false
		}
	}
	return true
}
