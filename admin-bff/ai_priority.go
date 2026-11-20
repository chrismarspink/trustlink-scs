package main

// ai_priority.go: 로컬 LLM 은 한 번에 하나만 돌린다(aiMu). 자동·일괄 판정이 줄줄이 잡고 있으면
// 사람이 화면에서 직접 요청한 AI(단건 VEX 초안·고객 통지 설명)가 수십 분 기다리게 된다.
// 직접 요청이 들어오면 일괄 판정은 지금 하던 한 건만 끝내고, 직접 요청이 끝날 때까지 다음 건을 미룬다.

import (
	"sync/atomic"
	"time"
)

var aiWaiting atomic.Int32 // 진행·대기 중인 직접 요청 수

// aiInteractive: 직접 요청 표시. defer aiInteractive()() 로 쓴다.
func aiInteractive() func() {
	aiWaiting.Add(1)
	return func() { aiWaiting.Add(-1) }
}

// aiYield: 일괄 판정 루프가 다음 건 전에 부른다. 기다리는 동안 화면에 사유를 보인다.
func aiYield(b *vexBatch) {
	if aiWaiting.Load() == 0 {
		return
	}
	vexBatchMu.Lock()
	cur := b.Current
	b.Current = "사람이 요청한 AI 작업 먼저 처리 중 — 끝나면 이어서(" + cur + ")"
	vexBatchMu.Unlock()
	for aiWaiting.Load() > 0 {
		time.Sleep(2 * time.Second)
	}
	vexBatchMu.Lock()
	b.Current = cur
	vexBatchMu.Unlock()
}
