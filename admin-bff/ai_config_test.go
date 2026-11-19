package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAIConfigExternal(t *testing.T) {
	t.Setenv("AI_CONFIG", filepath.Join(t.TempDir(), "ai-config.json"))
	t.Setenv("AI_URL", "")
	if aiEnabled() {
		t.Fatal("설정 없으면 꺼짐")
	}
	var got map[string]any
	var auth, path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, path = r.Header.Get("Authorization"), r.URL.Path
		if r.Method == "GET" {
			w.Write([]byte(`{"data":[]}`))
			return
		}
		json.NewDecoder(r.Body).Decode(&got)
		w.Write([]byte("{\"model\":\"ext-1\",\"choices\":[{\"message\":{\"content\":\"```json\\n{\\\"status\\\":\\\"affected\\\"}\\n```\"},\"finish_reason\":\"stop\"}]}"))
	}))
	defer srv.Close()

	c, err := mergeAIConf(aiConf(), aiConfigIn{Mode: "external", URL: srv.URL + "/v1beta/openai", Model: "ext-1", APIKey: "sk-secret-123456"})
	if err != nil {
		t.Fatal(err)
	}
	if err := saveAIConf(c); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(aiConfigPath()); fi.Mode().Perm() != 0o600 {
		t.Fatalf("키 파일 권한 0600: %v", fi.Mode())
	}
	// 키를 비워 다시 저장하면 기존 키 유지, 화면에는 끝 4자리만
	c2, _ := mergeAIConf(aiConf(), aiConfigIn{Mode: "external", URL: c.URL, Model: "ext-1"})
	v := viewAIConf(c2)
	if c2.APIKey != "sk-secret-123456" || v.APIKey != "" || v.KeyHint != "…3456" || !v.HasKey {
		t.Fatalf("키 유지·가림: %+v", v)
	}
	b, _ := json.Marshal(v)
	if strings.Contains(string(b), "secret") {
		t.Fatal("응답에 키 노출")
	}

	s := &Server{sor: newSoR(filepath.Join(t.TempDir(), "sor.jsonl"))}
	var d struct{ Status string }
	meta, err := s.aiDraft([]aiFact{{ID: "C1", Text: "x"}}, "작업", map[string]any{"type": "object"}, 50, &d)
	if err != nil || d.Status != "affected" || meta.Model != "ext-1" {
		t.Fatalf("외부 LLM 초안(코드 울타리 제거): %v %+v %+v", err, d, meta)
	}
	if auth != "Bearer sk-secret-123456" || path != "/v1beta/openai/chat/completions" {
		t.Fatalf("인증·경로: %q %q", auth, path)
	}
	if _, ok := got["chat_template_kwargs"]; ok {
		t.Fatal("외부 API 에 로컬 전용 필드를 보내면 안 됨")
	}
	if got["model"] != "ext-1" {
		t.Fatal("모델 이름 누락")
	}
	if st := s.aiStatusNow(); !st.Reachable || st.Mode != "external" || path != "/v1beta/openai/models" {
		t.Fatalf("상태 확인: %+v %s", st, path)
	}
	// 검증
	if _, err := mergeAIConf(aiConfig{}, aiConfigIn{Mode: "external", URL: "ftp://x"}); err == nil {
		t.Fatal("잘못된 주소 거부")
	}
	if _, err := mergeAIConf(aiConfig{}, aiConfigIn{Mode: "external", URL: "https://x"}); err == nil {
		t.Fatal("외부는 모델 필수")
	}
	if aiAPIBase(aiConfig{URL: "http://trustlink-ai:8080"}) != "http://trustlink-ai:8080/v1" {
		t.Fatal("경로 없으면 /v1")
	}
}
