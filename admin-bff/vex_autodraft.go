package main

// vex_autodraft.go: KEV·치명 자동 초안.
// 새 취약점 통보(notify.go sendVulnNotice)가 나가면, AI(VEX 용도)가 켜져 있을 때 그 제품·버전의
// 미분석 항목 중 KEV 등재 또는 CRITICAL 만 골라 AI 일괄 판정(ai_vex.go)을 자동으로 건다.
//   - 최대 AI_AUTODRAFT_MAX 건(기본 10), 끄기 AI_AUTODRAFT=off(기본 on).
//   - 그 제품·버전의 일괄 판정이 이미 진행 중이면 걸지 않는다.
//   - 이미 초안이 있는 항목은 다시 만들지 않고, 이전 초안은 새 결과에 이어 붙인다(DT 가 알림을 나눠 보내도 초안이 사라지지 않게).
//   - 초안은 수동 일괄 판정과 같다 — DT 에 쓰지 않고, 사람이 화면에서 확인·저장해야 기록된다.
//   - 원장(SoR)에 "ai-autodraft" 로 남긴다.

import (
	"log"
	"path"
	"strconv"
	"strings"
)

const autoDraftActor = "trustlink-auto"

func autoDraftOn() bool {
	switch strings.ToLower(strings.TrimSpace(env("AI_AUTODRAFT", "on"))) {
	case "off", "false", "0", "no":
		return false
	}
	return true
}

func autoDraftMax() int {
	n, err := strconv.Atoi(strings.TrimSpace(env("AI_AUTODRAFT_MAX", "10")))
	if err != nil || n <= 0 {
		return 10
	}
	if n > 50 {
		n = 50
	}
	return n
}

// autoDraftPick: 미분석 항목 중 KEV 등재·CRITICAL 만, 일괄 판정과 같은 우선순위 순으로 최대 n 개.
// skip 에 있는 키(컴포넌트UUID|취약점UUID)는 이미 초안이 있어 건너뛴다.
func autoDraftPick(fs []dtFindingFull, n int, skip map[string]*vexDraftResult) (picks []dtFindingFull, kev, critical int) {
	idx, _, _ := kevIndex()
	for _, f := range vexBatchPick(fs, len(fs)) {
		if len(picks) >= n {
			break
		}
		if skip[f.Component.UUID+"|"+f.Vulnerability.UUID] != nil {
			continue
		}
		isKEV := false
		for _, id := range vulnIDs(f) {
			if _, hit := idx[id]; hit {
				isKEV = true
				break
			}
		}
		if !isKEV && !strings.EqualFold(f.Vulnerability.Severity, "CRITICAL") {
			continue
		}
		picks = append(picks, f)
		if isKEV {
			kev++
		} else {
			critical++
		}
	}
	return picks, kev, critical
}

// maybeAutoDraft: 통보 직후 호출. 켜져 있을 때만 백그라운드로 자동 초안을 건다.
func (s *Server) maybeAutoDraft(repo, tag string) {
	if !autoDraftOn() || !aiEnabledFor("vex") || !s.dtEnabled() {
		return
	}
	go func() {
		if st := s.autoDraft(repo, tag); st != "started" {
			log.Printf("자동 초안 %s:%s — %s", repo, tag, st)
		}
	}()
}

// autoDraft: 자동 초안을 건다. 결과 요약을 돌려준다(started / off / ai-off / dt-off / no-project / running / none / error: …).
func (s *Server) autoDraft(repo, tag string) string {
	if !autoDraftOn() {
		return "off"
	}
	if !aiEnabledFor("vex") {
		return "ai-off"
	}
	if !s.dtEnabled() {
		return "dt-off"
	}
	project, err := s.dtLookupProject(path.Base(repo), tag)
	if err != nil {
		return "error: " + err.Error()
	}
	if !dtUUIDRe.MatchString(project) {
		return "no-project"
	}
	prev := vexBatchGet(project)
	if prev != nil && prev.State == "running" {
		return "running"
	}
	fs, err := s.projectFindings(project)
	if err != nil {
		return "error: " + err.Error()
	}
	var keep map[string]*vexDraftResult
	if prev != nil {
		keep = prev.Results
	}
	max := autoDraftMax()
	picks, kev, crit := autoDraftPick(fs, max, keep)
	if len(picks) == 0 {
		return "none"
	}
	b, err := s.startVexBatch(project, repo, tag, autoDraftActor, "auto", "", picks, keep)
	if err != nil {
		return "running"
	}
	ids := make([]string, 0, len(picks))
	for _, f := range picks {
		ids = append(ids, f.Vulnerability.VulnID)
	}
	if s.sor != nil {
		_ = s.sor.append(SoREvent{Actor: "trustlink", Action: "ai-autodraft", Repo: repo, Tag: tag, Status: "started",
			Detail: map[string]any{"project": project, "total": b.Total, "kev": kev, "critical": crit, "max": max, "vulns": ids, "kept": len(keep)}})
	}
	return "started"
}
