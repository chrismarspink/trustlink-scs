package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// 대체 연결: 주 연결이 응답하지 않으면 다른 연결이 대신한다(켰을 때만). 전송 정책은 우회하지 않는다.
func TestAIFallback(t *testing.T) {
	t.Setenv("AI_CONFIG", filepath.Join(t.TempDir(), "ai-config.json"))
	t.Setenv("AI_URL", "")
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "down", 503) }))
	defer down.Close()
	hits := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			hits++
		}
		w.Write([]byte(`{"model":"ext-1","choices":[{"message":{"content":"{\"answer\":\"ok\"}"},"finish_reason":"stop"}]}`))
	}))
	defer up.Close()
	s := &Server{}
	schema := map[string]any{"type": "object", "properties": map[string]any{"answer": map[string]any{"type": "string"}}}
	draft := func(use string) (aiMeta, string, error) {
		var out struct{ Answer string }
		m, err := s.aiDraftFor(use, "ko", []aiFact{{ID: "F1", Text: "x"}}, "t", schema, 50, &out)
		return m, out.Answer, err
	}
	save := func(in aiConfigIn) {
		c, err := mergeAIConf(aiConf(), in)
		if err != nil {
			t.Fatal(err)
		}
		if err := saveAIConf(c); err != nil {
			t.Fatal(err)
		}
	}
	ext := aiExternalIn{Provider: "openai", URL: up.URL + "/v1", Model: "ext-1"}

	// 꺼 두면 넘어가지 않는다
	save(aiConfigIn{Mode: "local", URL: down.URL, External: ext})
	if _, _, err := draft("vex"); err == nil || hits != 0 {
		t.Fatalf("대체 연결을 켜지 않았는데 넘어감: %v hits=%d", err, hits)
	}
	// 켜면 로컬 실패 → 외부가 대신하고, 어느 쪽이 실패했는지 남는다
	save(aiConfigIn{Mode: "local", URL: down.URL, External: ext, Fallback: true})
	m, ans, err := draft("vex")
	if err != nil || ans != "ok" || m.FallbackFrom != "local" || m.Model != "ext-1" || m.Provider != "openai" {
		t.Fatalf("대체 실패: %v %q %+v", err, ans, m)
	}
	// 보고서 용도는 체크리스트 전송을 허용하지 않았으면 외부로 넘기지 않는다
	before := hits
	if _, _, err := draft("report"); err == nil || hits != before {
		t.Fatalf("전송을 허용하지 않았는데 보고서가 외부로 넘어감: %v", err)
	}
	save(aiConfigIn{Mode: "local", URL: down.URL, External: ext, Fallback: true, SendChecklist: true})
	if m, _, err := draft("report"); err != nil || m.FallbackFrom != "local" {
		t.Fatalf("허용했는데 넘어가지 않음: %v", err)
	}
	// 반대 방향: 외부 실패 → 로컬
	save(aiConfigIn{Mode: "external", URL: up.URL, External: aiExternalIn{Provider: "openai", URL: down.URL + "/v1", Model: "x"}, Fallback: true})
	if m, ans, err := draft("vex"); err != nil || ans != "ok" || m.FallbackFrom != "external" {
		t.Fatalf("외부→로컬 대체 실패: %v %+v", err, m)
	}
	// 한쪽만 설정돼 있으면 켤 수 없다
	if _, err := mergeAIConf(aiConf(), aiConfigIn{Mode: "local", URL: up.URL, Fallback: true}); err == nil {
		t.Fatal("외부 연결 없이 대체 연결을 켬")
	}
}
