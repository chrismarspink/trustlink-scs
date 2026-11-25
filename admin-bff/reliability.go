package main

// reliability.go: 조용히 잘못되는 것을 드러낸다 — 저장·감사 기록 실패 횟수, 디스크 여유, 외부 구성요소 상태.
// 이 숫자는 시스템 상태 화면(/api/health)과 에이전트의 관리자 제안에 쓰인다.

import (
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

var relStat struct {
	sync.Mutex
	StoreFails int    // 상태 파일 저장 실패(서버를 켠 뒤)
	SorFails   int    // 감사 기록 추가 실패
	Last       string // 마지막 실패 내용
	LastAt     string
}

// storeFailed: 저장 실패를 세고 로그에 남긴다. kind: store(상태 파일) / sor(감사 기록).
func storeFailed(kind, where string, err error) {
	relStat.Lock()
	if kind == "sor" {
		relStat.SorFails++
	} else {
		relStat.StoreFails++
	}
	relStat.Last, relStat.LastAt = filepath.Base(where)+": "+err.Error(), time.Now().UTC().Format(time.RFC3339)
	relStat.Unlock()
	log.Printf("저장 실패(%s) %s: %v", kind, where, err)
}

const (
	diskWarnPct = 80 // 경고
	diskCritPct = 90 // 급함
)

type diskInfo struct {
	Path    string `json:"path"`
	UsedPct int    `json:"usedPct"`
	FreeGB  int    `json:"freeGB"`
	TotalGB int    `json:"totalGB"`
}

func diskOf(path string) (diskInfo, bool) {
	var fs syscall.Statfs_t
	if err := syscall.Statfs(path, &fs); err != nil || fs.Blocks == 0 {
		return diskInfo{}, false
	}
	total, free := fs.Blocks*uint64(fs.Bsize), fs.Bavail*uint64(fs.Bsize)
	return diskInfo{Path: path, UsedPct: int(float64(total-free)/float64(total)*100 + 0.5), FreeGB: int(free >> 30), TotalGB: int(total >> 30)}, true
}

// relDisks: 서버가 쓰는 자료 폴더들의 디스크(같은 크기·여유면 같은 디스크로 보고 하나만).
func (s *Server) relDisks() []diskInfo {
	out, seen := []diskInfo{}, map[string]bool{}
	for _, p := range []string{s.cfg.DataDir, filepath.Dir(aiConfigPath())} {
		if d, ok := diskOf(p); ok {
			if k := fmt.Sprint(d.TotalGB, "/", d.FreeGB); !seen[k] {
				seen[k] = true
				out = append(out, d)
			}
		}
	}
	return out
}

// relHealth: 건강 점검에 더하는 항목.
func (s *Server) relHealth(out map[string]any) {
	out["ai"] = aiEnabled() // 설정 여부(응답 속도는 AI 성능 화면)
	out["mail"] = s.mail != nil
	if u := mirrorBase(); u != "" {
		out["mirror"] = s.ping(u+"/_api/status", false)
	}
	if u := gotenbergURL(); u != "" {
		out["pdf"] = s.ping(u+"/health", false)
	}
	out["disks"] = s.relDisks()
	relStat.Lock()
	out["storeFails"], out["sorFails"], out["lastFail"], out["lastFailAt"] = relStat.StoreFails, relStat.SorFails, relStat.Last, relStat.LastAt
	relStat.Unlock()
	vexQueueCache.Lock()
	out["dtSkipped"] = vexQueueCache.skipped
	vexQueueCache.Unlock()
}

// relTasks: 관리자에게 알릴 운영 문제(에이전트 제안).
func (s *Server) relTasks() []agentTask {
	out := []agentTask{}
	for _, d := range s.relDisks() {
		if d.UsedPct >= diskWarnPct {
			out = append(out, agentTask{ID: "rel:disk:" + d.Path, Kind: "rel", Grade: "go", Urgent: d.UsedPct >= diskCritPct, Link: "/admin/capacity",
				Title: fmt.Sprintf("디스크 사용률 %d%% — 여유 %dGB", d.UsedPct, d.FreeGB), Why: "가득 차면 저장과 감사 기록이 실패합니다.",
				Steps: []string{"용량 화면에서 무엇이 차지하는지 봅니다", "오래된 버전·보고서를 정리하거나 디스크를 늘립니다"}})
		}
	}
	relStat.Lock()
	sf, af, last := relStat.StoreFails, relStat.SorFails, relStat.Last
	relStat.Unlock()
	if sf+af > 0 {
		out = append(out, agentTask{ID: "rel:fails", Kind: "rel", Grade: "go", Urgent: true, Link: "/admin/system",
			Title: fmt.Sprintf("저장 실패 %d건 · 감사 기록 실패 %d건", sf, af), Why: "서버를 켠 뒤 저장하지 못한 것이 있습니다. 마지막: " + last,
			Steps: []string{"시스템 상태에서 디스크와 구성요소를 확인합니다", "실패한 동안의 변경·기록은 남지 않았을 수 있습니다"}})
	}
	return out
}

// reqHTTPS: 이 요청이 암호화 연결로 들어왔는가(앞단 프록시가 TLS 를 끊어도 X-Forwarded-Proto 로 알린다).
func reqHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	p := r.Header.Get("X-Forwarded-Proto")
	if i := strings.IndexByte(p, ','); i >= 0 { // 프록시가 여럿이면 맨 앞이 원래 값
		p = p[:i]
	}
	return strings.EqualFold(strings.TrimSpace(p), "https")
}

// uiCacheHeader: 이름에 해시가 붙은 빌드 파일은 오래 보관하고, 첫 문서는 매번 확인한다.
func uiCacheHeader(w http.ResponseWriter, hashed bool) {
	if hashed {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
}
