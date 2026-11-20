package main

import "testing"

// AI 가 "조치" 칸에 식별자 같은 값을 넣으면 그 칸만 규칙 문구로 바꾼다.
func TestFixCustFields(t *testing.T) {
	rule := &custAIText{Summary: "규칙 요약 문장입니다 충분히 길게", Impact: "규칙 영향 문장입니다 충분히 길게", Action: "innopouch 11.1 버전으로 업그레이드해 주십시오."}
	ai := &custAIText{Summary: "이 취약점은 nginx 에서 숫자를 처리하는 과정의 오류입니다", Impact: "서비스가 중단되거나 원격 코드 실행 위험이 있습니다", Action: "customer_notice"}
	fixCustFields(ai, rule, "ko")
	if ai.Action != rule.Action || ai.Summary == rule.Summary || len(ai.Warnings) != 1 {
		t.Fatalf("조치 칸만 교체: %+v", ai)
	}
	en := &custAIText{Summary: "A critical integer underflow in nginx.", Impact: "Attackers may crash the worker process.", Action: "Upgrade to 11.1 now."}
	fixCustFields(en, rule, "en")
	if len(en.Warnings) != 0 {
		t.Fatalf("정상 영문은 그대로: %+v", en)
	}
}
