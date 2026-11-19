package main

// AI 연결 설정(관리 콘솔 › AI 연결) — 로컬 LLM(llama.cpp·vLLM 등)과 외부 LLM(OpenAI 호환 API) 모두 지원.
//  - 저장: /var/lib/trustlink/ai-config.json (0600, tl-sor 볼륨). API 키는 화면·API 응답에 다시 내보내지 않는다(끝 4자리만).
//  - 설정 파일이 없으면 기존처럼 환경변수 AI_URL 을 로컬 LLM 으로 쓴다(하위 호환).
//  - URL 규칙: 경로가 없으면 <URL>/v1 을 API 기준으로 쓰고, 경로가 있으면(예: https://host/v1beta/openai) 그대로 쓴다.
//    요청은 <기준>/chat/completions, 연결 확인은 <기준>/models.
//  - 외부 LLM 은 입력 사실(구성요소·취약점·사용 맥락)이 외부로 나간다. 대외비 체크리스트 내용은
//    "체크리스트 외부 전송 허용"을 켠 경우에만 규제 보고서 AI 에 쓴다.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type aiConfig struct {
	Mode          string `json:"mode"`             // off / local / external
	URL           string `json:"url"`              // API 주소
	Model         string `json:"model,omitempty"`  // 요청에 넣을 모델 이름(외부 LLM 필수)
	APIKey        string `json:"apiKey,omitempty"` // 외부 LLM 키(파일에만 저장)
	JSONSchema    bool   `json:"jsonSchema"`       // response_format json_schema 지원 여부
	SendChecklist bool   `json:"sendChecklist"`    // 외부 LLM 에 체크리스트 내용 전송 허용
	UpdatedBy     string `json:"updatedBy,omitempty"`
	UpdatedAt     string `json:"updatedAt,omitempty"`
}

var (
	aiCfgMu    sync.Mutex
	aiCfgCache *aiConfig
	aiCfgMtime time.Time
)

func aiConfigPath() string { return env("AI_CONFIG", "/var/lib/trustlink/ai-config.json") }

// aiConf: 현재 설정(파일 우선, 없으면 AI_URL 환경변수). 파일이 바뀌면 다시 읽는다.
func aiConf() aiConfig {
	p := aiConfigPath()
	fi, err := os.Stat(p)
	if err != nil {
		if u := strings.TrimRight(os.Getenv("AI_URL"), "/"); u != "" {
			return aiConfig{Mode: "local", URL: u, JSONSchema: true}
		}
		return aiConfig{Mode: "off", JSONSchema: true}
	}
	aiCfgMu.Lock()
	defer aiCfgMu.Unlock()
	if aiCfgCache != nil && fi.ModTime().Equal(aiCfgMtime) {
		return *aiCfgCache
	}
	var c aiConfig
	if b, err := os.ReadFile(p); err == nil && json.Unmarshal(b, &c) == nil {
		aiCfgCache, aiCfgMtime = &c, fi.ModTime()
		return c
	}
	return aiConfig{Mode: "off", JSONSchema: true}
}

func saveAIConf(c aiConfig) error {
	p := aiConfigPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	aiCfgMu.Lock()
	aiCfgCache = nil
	aiCfgMu.Unlock()
	return nil
}

// aiAPIBase: 요청 기준 주소(…/v1 등).
func aiAPIBase(c aiConfig) string {
	u := strings.TrimRight(c.URL, "/")
	if pu, err := url.Parse(u); err == nil && (pu.Path == "" || pu.Path == "/") {
		return u + "/v1"
	}
	return u
}

// aiRoot: 경로를 뺀 주소(llama.cpp /props 용).
func aiRoot(c aiConfig) string {
	pu, err := url.Parse(c.URL)
	if err != nil {
		return strings.TrimRight(c.URL, "/")
	}
	return pu.Scheme + "://" + pu.Host
}

func validAIURL(s string) bool {
	pu, err := url.Parse(s)
	return err == nil && (pu.Scheme == "http" || pu.Scheme == "https") && pu.Host != "" && pu.User == nil
}

// aiChat: 설정에 맞춰 chat/completions 요청 본문을 만들고 보낸다. 반환: 응답 본문.
func aiChat(c aiConfig, messages []map[string]string, schema map[string]any, maxTokens int, timeout time.Duration) (string, string, string, error) {
	req := map[string]any{
		"messages":    messages,
		"temperature": 0.2,
		"max_tokens":  maxTokens,
	}
	if c.Model != "" {
		req["model"] = c.Model
	}
	if schema != nil && c.JSONSchema {
		req["response_format"] = map[string]any{"type": "json_schema",
			"json_schema": map[string]any{"name": "draft", "strict": true, "schema": schema}}
	} else if schema != nil {
		req["response_format"] = map[string]any{"type": "json_object"}
	}
	if c.Mode == "local" { // llama.cpp·vLLM: 생각(thinking) 출력 끄기. 외부 API 는 모르는 필드를 거부할 수 있어 넣지 않음
		req["chat_template_kwargs"] = map[string]any{"enable_thinking": false}
	}
	body, _ := json.Marshal(req)
	hr, _ := http.NewRequest("POST", aiAPIBase(c)+"/chat/completions", bytes.NewReader(body))
	hr.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		hr.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	resp, err := (&http.Client{Timeout: timeout}).Do(hr)
	if err != nil {
		return "", "", "", errors.New("AI 서버 응답 없음: " + redactKey(err.Error(), c.APIKey))
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return "", "", "", errors.New("AI 서버 " + itoa(resp.StatusCode) + ": " + truncate(redactKey(string(rb), c.APIKey), 300))
	}
	var cr struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(rb, &cr); err != nil || len(cr.Choices) == 0 {
		return "", "", "", errors.New("AI 응답 형식 오류")
	}
	return stripFence(cr.Choices[0].Message.Content), firstNonEmpty(cr.Model, c.Model), cr.Choices[0].FinishReason, nil
}

// stripFence: json_schema 를 지원하지 않는 API 가 ```json … ``` 으로 감싸 보낸 경우 벗긴다.
func stripFence(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		s = strings.TrimPrefix(s, "```json")
		s = strings.TrimPrefix(s, "```")
		s = strings.TrimSuffix(strings.TrimSpace(s), "```")
	}
	return strings.TrimSpace(s)
}

func redactKey(s, key string) string {
	if key == "" {
		return s
	}
	return strings.ReplaceAll(s, key, "****")
}

// ---------- 관리 API ----------

type aiConfigView struct {
	aiConfig
	HasKey  bool   `json:"hasKey"`
	KeyHint string `json:"keyHint,omitempty"` // 끝 4자리
	FromEnv bool   `json:"fromEnv"`           // 설정 파일 없이 AI_URL 환경변수 사용 중
}

func viewAIConf(c aiConfig) aiConfigView {
	v := aiConfigView{aiConfig: c, HasKey: c.APIKey != ""}
	if n := len(c.APIKey); n >= 8 {
		v.KeyHint = "…" + c.APIKey[n-4:]
	}
	v.APIKey = ""
	if _, err := os.Stat(aiConfigPath()); err != nil && c.Mode == "local" {
		v.FromEnv = true
	}
	return v
}

// GET /api/ai/config
func (s *Server) apiAIConfigGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"config": viewAIConf(aiConf()), "status": s.aiStatusNow()})
}

type aiConfigIn struct {
	Mode          string `json:"mode"`
	URL           string `json:"url"`
	Model         string `json:"model"`
	APIKey        string `json:"apiKey"`   // 빈 값이면 기존 키 유지
	ClearKey      bool   `json:"clearKey"` // 키 삭제
	JSONSchema    *bool  `json:"jsonSchema"`
	SendChecklist bool   `json:"sendChecklist"`
}

func mergeAIConf(old aiConfig, in aiConfigIn) (aiConfig, error) {
	c := aiConfig{Mode: in.Mode, URL: strings.TrimSpace(in.URL), Model: strings.TrimSpace(in.Model),
		APIKey: old.APIKey, JSONSchema: true, SendChecklist: in.SendChecklist}
	if in.JSONSchema != nil {
		c.JSONSchema = *in.JSONSchema
	}
	if k := strings.TrimSpace(in.APIKey); k != "" {
		c.APIKey = k
	}
	if in.ClearKey {
		c.APIKey = ""
	}
	switch c.Mode {
	case "off":
	case "local", "external":
		if !validAIURL(c.URL) {
			return c, errors.New("주소는 http:// 또는 https:// 로 시작해야 합니다")
		}
		if c.Mode == "external" && c.Model == "" {
			return c, errors.New("외부 LLM 은 모델 이름이 필요합니다")
		}
	default:
		return c, errors.New("mode 는 off / local / external 중 하나")
	}
	if c.Mode != "external" {
		c.SendChecklist = false
	}
	return c, nil
}

// PUT /api/ai/config
func (s *Server) apiAIConfigPut(w http.ResponseWriter, r *http.Request) {
	var in aiConfigIn
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "잘못된 요청"})
		return
	}
	c, err := mergeAIConf(aiConf(), in)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	c.UpdatedBy, c.UpdatedAt = w.Header().Get("X-User"), time.Now().UTC().Format(time.RFC3339)
	if err := saveAIConf(c); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	host := ""
	if pu, err := url.Parse(c.URL); err == nil {
		host = pu.Host
	}
	_ = s.sor.append(SoREvent{Actor: c.UpdatedBy, Action: "ai-config", Status: c.Mode,
		Detail: map[string]any{"host": host, "model": c.Model, "hasKey": c.APIKey != "", "sendChecklist": c.SendChecklist}})
	writeJSON(w, 200, map[string]any{"config": viewAIConf(c), "status": s.aiStatusNow()})
}

// POST /api/ai/test — 저장 전 입력값(키 비우면 저장된 키)으로 짧은 JSON 요청을 보내 본다.
func (s *Server) apiAITest(w http.ResponseWriter, r *http.Request) {
	var in aiConfigIn
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "잘못된 요청"})
		return
	}
	c, err := mergeAIConf(aiConf(), in)
	if err == nil && c.Mode == "off" {
		err = errors.New("사용 안 함 상태입니다")
	}
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	schema := map[string]any{"type": "object", "properties": map[string]any{"answer": map[string]any{"type": "string", "maxLength": 40}},
		"required": []string{"answer"}}
	t0 := time.Now()
	content, model, _, err := aiChat(c, []map[string]string{{"role": "user", "content": "연결 시험이다. answer 에 '정상'이라고만 써라."}},
		schema, 60, 2*time.Minute)
	ms := time.Since(t0).Milliseconds()
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error(), "elapsedMs": ms})
		return
	}
	var out struct {
		Answer string `json:"answer"`
	}
	jsonOK := json.Unmarshal([]byte(content), &out) == nil
	writeJSON(w, 200, map[string]any{"ok": jsonOK, "model": model, "answer": truncate(firstNonEmpty(out.Answer, content), 80),
		"elapsedMs": ms, "error": map[bool]string{true: "", false: "응답이 JSON 형식이 아닙니다 — 'JSON 스키마 지원'을 끄고 다시 시험하세요"}[jsonOK]})
}
