package main

import (
	"strings"
	"testing"
)

// 용어·사용법 답은 AI 없이 장면 글자를 규칙으로 채운다(즉시).
func TestSceneStaticHowto(t *testing.T) {
	a := &askAnswer{Intent: "howto", Title: "VEX",
		Lead: "VEX 는 '이 취약점이 우리 제품에 실제로 영향이 있는가'에 대한 판단 문서입니다. 영향 있음·영향 없음·조사 중으로 적습니다."}
	tx, ok := sceneStatic(a)
	if !ok {
		t.Fatal("howto 는 정적 장면이어야 한다")
	}
	if tx.Lead != "VEX" || tx.Model != "내장 도움말" {
		t.Errorf("lead/model: %q %q", tx.Lead, tx.Model)
	}
	if len(tx.Notes) != 1 || !strings.HasSuffix(tx.Notes[0], "판단 문서입니다.") {
		t.Errorf("첫 문장만 캡션으로: %q", tx.Notes)
	}
	if scenes := sceneBuild(a, tx); len(scenes) == 0 || scenes[0].Tab != "답" {
		t.Errorf("장면이 만들어져야 한다: %+v", scenes)
	}
	// 그 밖의 유형은 AI 경로를 탄다
	if _, ok := sceneStatic(&askAnswer{Intent: "vuln"}); ok {
		t.Error("vuln 은 정적 장면이 아니다")
	}
}
