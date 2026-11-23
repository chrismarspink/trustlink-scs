package main

import (
	"errors"
	"testing"
)

func TestAIVerdict(t *testing.T) {
	// 오늘 서버 실측과 비슷한 값: 초당 6.4토큰, 메모리 여유 48%, 스왑 90%
	lv, _, rs := aiVerdict(aiVerdictIn{LocalTPS: 6.4, VexP50: 90000, MemAvailPct: 48, SwapPct: 90, CPUBusy: 30})
	if lv != "hybrid" || len(rs) < 3 {
		t.Fatalf("느린 로컬은 혼합이어야 함: %s %v", lv, rs)
	}
	if lv, _, _ := aiVerdict(aiVerdictIn{LocalTPS: 30, MemAvailPct: 60}); lv != "local" {
		t.Fatalf("빠르고 여유 있으면 로컬: %s", lv)
	}
	if lv, _, _ := aiVerdict(aiVerdictIn{LocalTPS: 6, LocalFailRate: 30, MemAvailPct: 60}); lv != "external" {
		t.Fatalf("실패가 많으면 외부: %s", lv)
	}
	if lv, _, _ := aiVerdict(aiVerdictIn{MemAvailPct: 60}); lv != "local" {
		t.Fatalf("측정 전에는 자료 없음만으로 기울지 않음: %s", lv)
	}
	if lv, _, _ := aiVerdict(aiVerdictIn{LocalTPS: 30, MemAvailPct: 5}); lv != "external" {
		t.Fatalf("메모리가 모자라면 외부: %s", lv)
	}
}

func TestAICallFill(t *testing.T) {
	var r aiCall
	r.fill("gemma", 33700, aiUsage{PromptTok: 256, GenTok: 146, PromptMs: 10858, GenMs: 22626}, "stop", nil)
	if r.GenTPS != 6.5 || r.PromptTPS != 23.6 || !r.OK || r.Fail != "" {
		t.Fatalf("llama timings 계산: %+v", r)
	}
	r = aiCall{}
	r.fill("", 360000, aiUsage{}, "", errors.New("AI 서버 응답 없음: context deadline exceeded (Client.Timeout exceeded)"))
	if r.OK || r.Fail != "timeout" {
		t.Fatalf("시간 초과 분류: %+v", r)
	}
	if parseMemLimit("24g") != 24<<30 || parseMemLimit("512m") != 512<<20 || parseMemLimit("") != 0 {
		t.Fatal("메모리 한도 해석")
	}
}

func TestAIFeatureName(t *testing.T) {
	if f := aiFeature(); f != "기타" { // 테스트 파일에서 부르면 이름표 없음
		t.Fatalf("got %s", f)
	}
}
