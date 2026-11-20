package main

import (
	"testing"
	"time"
)

// 직접 요청이 있는 동안 일괄 판정은 다음 건으로 넘어가지 않는다.
func TestAIYield(t *testing.T) {
	b := &vexBatch{Current: "CVE-1 · x"}
	done := aiInteractive()
	finished := make(chan struct{})
	go func() { aiYield(b); close(finished) }()
	time.Sleep(100 * time.Millisecond)
	vexBatchMu.Lock()
	waiting := b.Current
	vexBatchMu.Unlock()
	select {
	case <-finished:
		t.Fatal("직접 요청 중에는 기다려야 함")
	default:
	}
	done()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("직접 요청이 끝나면 이어서 진행")
	}
	if b.Current != "CVE-1 · x" || waiting == "CVE-1 · x" {
		t.Fatalf("대기 사유 표시 후 원래대로: %q → %q", waiting, b.Current)
	}
}
