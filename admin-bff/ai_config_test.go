package main

import (
	"encoding/json"
	"io"
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
	if aiEnabled() || aiEnabledFor("report") {
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

	in := aiConfigIn{Mode: "external", External: aiExternalIn{Provider: "openai", URL: srv.URL + "/v1beta/openai", Model: "ext-1", APIKey: "sk-secret-123456"}}
	c, err := mergeAIConf(aiConf(), in)
	if err != nil {
		t.Fatal(err)
	}
	if c.ReportMode != "external" {
		t.Fatal("보고서 용도 비우면 VEX 와 같음")
	}
	if err := saveAIConf(c); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(aiConfigPath()); fi.Mode().Perm() != 0o600 {
		t.Fatalf("키 파일 권한 0600: %v", fi.Mode())
	}
	// 키를 비워 다시 저장하면 기존 키 유지, 화면에는 끝 4자리만
	in.External.APIKey = ""
	c2, _ := mergeAIConf(aiConf(), in)
	v := viewAIConf(c2)
	if c2.External.APIKey != "sk-secret-123456" || v.External.APIKey != "" || v.External.KeyHint != "…3456" || !v.External.HasKey {
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
	if _, err := mergeAIConf(aiConfig{}, aiConfigIn{Mode: "external", External: aiExternalIn{Provider: "openai", URL: "ftp://x", Model: "m"}}); err == nil {
		t.Fatal("잘못된 주소 거부")
	}
	if _, err := mergeAIConf(aiConfig{}, aiConfigIn{Mode: "external", External: aiExternalIn{Provider: "openai", Model: "m"}}); err == nil {
		t.Fatal("OpenAI 호환은 주소 필수")
	}
	if _, err := mergeAIConf(aiConfig{}, aiConfigIn{Mode: "external", External: aiExternalIn{Provider: "anthropic"}}); err == nil {
		t.Fatal("Claude 는 키 필수")
	}
	if _, err := mergeAIConf(aiConfig{}, aiConfigIn{Mode: "local"}); err == nil {
		t.Fatal("로컬은 주소 필수")
	}
	if aiAPIBase(aiEndpoint{URL: "http://trustlink-ai:8080"}) != "http://trustlink-ai:8080/v1" {
		t.Fatal("경로 없으면 /v1")
	}
}

// 이전 형식(mode=external 에 url·model·apiKey 한 벌) 설정 파일을 새 형식으로 읽는다.
func TestAIConfigLegacy(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ai-config.json")
	t.Setenv("AI_CONFIG", p)
	os.WriteFile(p, []byte(`{"mode":"external","url":"https://x.example/v1","model":"m1","apiKey":"sk-old-abcdef","jsonSchema":false}`), 0o600)
	c := aiConf()
	if c.External.Provider != "openai" || c.External.URL != "https://x.example/v1" || c.External.APIKey != "sk-old-abcdef" || c.URL != "" || c.APIKey != "" {
		t.Fatalf("이전 형식 이전: %+v", c)
	}
	if e := c.endpoint("report"); e.Kind != "external" || e.Model != "m1" || e.JSONSchema {
		t.Fatalf("보고서도 같은 연결: %+v", e)
	}
}

// 로컬(Gemma)은 VEX, Claude 는 보고서 — 용도별로 다른 연결을 쓴다. Claude 는 공식 SDK 로 Messages API 호출.
func TestAIConfigAnthropicSplit(t *testing.T) {
	t.Setenv("AI_CONFIG", filepath.Join(t.TempDir(), "ai-config.json"))
	var body map[string]any
	var hdr http.Header
	var paths []string
	claude := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		hdr = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" {
			w.Write([]byte(`{"id":"claude-opus-5-5","type":"model","display_name":"Claude Opus 5.5","created_at":"2026-01-01T00:00:00Z"}`))
			return
		}
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-5-5","stop_reason":"end_turn",
			"content":[{"type":"text","text":"{\"headline\":\"EU CRA reporting applies now [G1]\",\"points\":[\"a\"],\"priority\":[\"b\"],\"citations\":[\"G1\",\"X9\"]}"}],
			"usage":{"input_tokens":10,"output_tokens":20}}`))
	}))
	defer claude.Close()
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"model":"gemma","choices":[{"message":{"content":"{\"status\":\"affected\"}"},"finish_reason":"stop"}]}`))
	}))
	defer local.Close()

	c, err := mergeAIConf(aiConfig{}, aiConfigIn{Mode: "local", ReportMode: "external", URL: local.URL,
		External: aiExternalIn{Provider: "anthropic", URL: claude.URL, APIKey: "sk-ant-test-0000abcd", Effort: "low"}})
	if err != nil {
		t.Fatal(err)
	}
	if c.External.Model != anthropicDefaultModel {
		t.Fatal("Claude 모델 기본값")
	}
	if err := saveAIConf(c); err != nil {
		t.Fatal(err)
	}
	s := &Server{sor: newSoR(filepath.Join(t.TempDir(), "sor.jsonl"))}
	var d struct{ Status string }
	if m, err := s.aiDraft([]aiFact{{ID: "C1", Text: "x"}}, "작업", map[string]any{"type": "object"}, 50, &d); err != nil || m.Provider != "llama" || d.Status != "affected" {
		t.Fatalf("VEX 는 로컬: %v %+v", err, m)
	}
	if len(paths) != 0 {
		t.Fatal("VEX 요청이 Claude 로 가면 안 됨")
	}
	rep := &regReport{Lang: "en", AudienceKo: "Sales", RegionNames: regRegionEn,
		Regs: []regReportReg{{regulation: regulation{ID: "eu-cra", NameKo: "EU Cyber Resilience Act", Region: "EU", Binding: "Mandatory", Status: "In force"}}}}
	s.regReportAI(rep)
	if rep.Summary == nil || rep.AIMeta.Model != "claude-opus-5-5" || rep.AIMeta.Provider != "anthropic" {
		t.Fatalf("보고서 요약: %+v %s", rep.Summary, rep.AIError)
	}
	if strings.Join(rep.Summary.Citations, ",") != "G1" {
		t.Fatalf("없는 근거 ID 는 버림: %v", rep.Summary.Citations)
	}
	if (hdr.Get("X-Api-Key") != "sk-ant-test-0000abcd" && hdr.Get("Authorization") != "Bearer sk-ant-test-0000abcd") || hdr.Get("Anthropic-Version") == "" {
		t.Fatalf("Claude 인증 헤더: %v", hdr)
	}
	if !strings.Contains(hdr.Get("Anthropic-Beta"), "server-side-fallback") {
		t.Fatal("거절 대체(fallbacks) beta")
	}
	if body["model"] != "claude-opus-5-5" || body["fallbacks"] != "default" {
		t.Fatalf("요청 본문: %v", body)
	}
	oc, _ := body["output_config"].(map[string]any)
	f, _ := oc["format"].(map[string]any)
	sc, _ := f["schema"].(map[string]any)
	if oc["effort"] != "low" || f["type"] != "json_schema" || sc["additionalProperties"] != false {
		t.Fatalf("구조화 출력: %v", oc)
	}
	bs, _ := json.Marshal(sc)
	if strings.Contains(string(bs), "maxLength") || strings.Contains(string(bs), "maxItems") {
		t.Fatalf("받지 않는 제약 제거: %s", bs)
	}
	sys, _ := body["system"].([]any)
	if len(sys) == 0 || !strings.Contains(sys[0].(map[string]any)["text"].(string), "English") {
		t.Fatal("영문 보고서는 영문 지시")
	}
	if _, ok := body["temperature"]; ok {
		t.Fatal("Claude 에 temperature 보내지 않음")
	}
	// 상태: 모델 조회
	if st := s.aiStatusFor("report"); !st.Reachable || st.Provider != "anthropic" {
		t.Fatalf("Claude 상태: %+v", st)
	}
	if st := s.aiStatusFor("vex"); st.Provider != "llama" {
		t.Fatalf("VEX 상태는 로컬: %+v", st)
	}
	// 화면 응답에 키가 나가지 않음
	b, _ := json.Marshal(viewAIConf(aiConf()))
	if strings.Contains(string(b), "sk-ant-test") {
		t.Fatal("키 노출")
	}
}
