package main

// AI 연결 설정(관리 콘솔 › AI 연결) — 로컬 LLM 과 외부 LLM 을 함께 등록하고, 용도별로 골라 쓴다.
//  - 로컬 LLM: llama.cpp·vLLM 등 OpenAI 호환 서버(예: Gemma 4 26B-A4B). 데이터가 밖으로 나가지 않는다.
//  - 외부 LLM: Anthropic(Claude) 공식 SDK, 또는 OpenAI 호환 API.
//  - 용도: vex(취약점 판정·대응 초안) / report(규제 보고서·체크리스트 요약·규제 탐색). 용도마다 off / local / external.
//  - 저장: /var/lib/trustlink/ai-config.json (0600, tl-sor 볼륨). API 키는 화면·API 응답에 다시 내보내지 않는다(끝 4자리만).
//  - 설정 파일이 없으면 기존처럼 환경변수 AI_URL 을 로컬 LLM 으로 쓴다(하위 호환).
//  - OpenAI 호환 URL 규칙: 경로가 없으면 <URL>/v1 을 기준으로, 경로가 있으면 그대로. 요청은 <기준>/chat/completions.
//  - 외부 LLM 은 입력 사실(구성요소·취약점·사용 맥락)이 외부로 나간다. 대외비 체크리스트 내용은
//    "체크리스트 외부 전송 허용"을 켠 경우에만 체크리스트 AI 요약에 쓴다.

import (
	"bytes"
	"context"
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

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"
)

const anthropicDefaultModel = "claude-opus-5-5"

type aiExternal struct {
	Provider   string `json:"provider"`         // anthropic / openai
	URL        string `json:"url,omitempty"`    // openai: 필수 / anthropic: 비우면 공식 주소
	Model      string `json:"model,omitempty"`  // 요청에 넣을 모델 이름
	APIKey     string `json:"apiKey,omitempty"` // 파일에만 저장
	JSONSchema bool   `json:"jsonSchema"`       // openai: response_format json_schema 지원 여부
	Effort     string `json:"effort,omitempty"` // anthropic: low / medium / high
}

type aiConfig struct {
	Mode          string     `json:"mode"`                 // VEX 판정·대응: off / local / external
	ReportMode    string     `json:"reportMode,omitempty"` // 보고서·규제: off / local / external (비우면 mode 와 같음)
	URL           string     `json:"url"`                  // 로컬 LLM 주소
	Model         string     `json:"model,omitempty"`      // 로컬 LLM 모델 이름(선택)
	JSONSchema    bool       `json:"jsonSchema"`           // 로컬 LLM json_schema 지원
	APIKey        string     `json:"apiKey,omitempty"`     // (이전 형식) 외부 LLM 키 — 읽을 때 External 로 옮긴다
	External      aiExternal `json:"external"`
	SendChecklist bool       `json:"sendChecklist"`      // 외부 LLM 에 체크리스트 내용 전송 허용
	Fallback      bool       `json:"fallback,omitempty"` // 지정한 연결이 응답하지 않으면 다른 연결(로컬↔외부)로 대신한다
	UpdatedBy     string     `json:"updatedBy,omitempty"`
	UpdatedAt     string     `json:"updatedAt,omitempty"`
}

// aiEndpoint: 용도에 맞춰 고른 실제 연결 대상.
type aiEndpoint struct {
	Kind       string // off / local / external
	Provider   string // local: llama / external: anthropic·openai
	URL        string
	Model      string
	APIKey     string
	JSONSchema bool
	Effort     string
}

var (
	aiCfgMu    sync.Mutex
	aiCfgCache *aiConfig
	aiCfgMtime time.Time
)

func aiConfigPath() string { return env("AI_CONFIG", "/var/lib/trustlink/ai-config.json") }

// normalizeAIConf: 이전 형식(mode=external 에 url·model·apiKey 한 벌)을 새 형식으로 옮긴다.
func normalizeAIConf(c aiConfig) aiConfig {
	if c.External.Provider == "" && (c.Mode == "external" || c.APIKey != "") {
		c.External = aiExternal{Provider: "openai", URL: c.URL, Model: c.Model, APIKey: c.APIKey, JSONSchema: c.JSONSchema}
		c.URL, c.Model = "", ""
	}
	c.APIKey = ""
	if c.Mode == "" {
		c.Mode = "off"
	}
	return c
}

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
		c = normalizeAIConf(c)
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

// useMode: 용도(vex / report)에 지정된 연결.
func (c aiConfig) useMode(use string) string {
	if use == "report" && c.ReportMode != "" {
		return c.ReportMode
	}
	return c.Mode
}

func (c aiConfig) endpointOf(kind string) aiEndpoint {
	switch kind {
	case "local":
		return aiEndpoint{Kind: "local", Provider: "llama", URL: c.URL, Model: c.Model, JSONSchema: c.JSONSchema}
	case "external":
		x := c.External
		return aiEndpoint{Kind: "external", Provider: x.Provider, URL: x.URL, Model: x.Model, APIKey: x.APIKey, JSONSchema: x.JSONSchema, Effort: x.Effort}
	}
	return aiEndpoint{Kind: "off"}
}

func (c aiConfig) endpoint(use string) aiEndpoint { return c.endpointOf(c.useMode(use)) }

// fallback: 용도의 주 연결이 실패했을 때 대신 쓸 연결. 꺼져 있거나 대신할 연결이 없으면 Kind=off.
// 로컬 → 외부로 넘어가면 입력이 외부 서비스로 나가므로 관리자가 켠 경우에만 하고,
// 보고서 용도는 체크리스트 전송을 허용하지 않았으면 외부로 넘기지 않는다(전송 정책을 우회하지 않게).
func (c aiConfig) fallback(use string) aiEndpoint {
	if !c.Fallback {
		return aiEndpoint{Kind: "off"}
	}
	other := map[string]string{"local": "external", "external": "local"}[c.useMode(use)]
	if other == "" || (other == "external" && use == "report" && !c.SendChecklist) {
		return aiEndpoint{Kind: "off"}
	}
	if e := c.endpointOf(other); e.ready() {
		return e
	}
	return aiEndpoint{Kind: "off"}
}

func (e aiEndpoint) ready() bool {
	switch {
	case e.Kind == "local":
		return e.URL != ""
	case e.Kind == "external" && e.Provider == "anthropic":
		return e.APIKey != "" && e.Model != ""
	case e.Kind == "external":
		return e.URL != "" && e.Model != ""
	}
	return false
}

// aiAPIBase: OpenAI 호환 요청 기준 주소(…/v1 등).
func aiAPIBase(e aiEndpoint) string {
	u := strings.TrimRight(e.URL, "/")
	if pu, err := url.Parse(u); err == nil && (pu.Path == "" || pu.Path == "/") {
		return u + "/v1"
	}
	return u
}

// aiRoot: 경로를 뺀 주소(llama.cpp /props 용).
func aiRoot(e aiEndpoint) string {
	pu, err := url.Parse(e.URL)
	if err != nil {
		return strings.TrimRight(e.URL, "/")
	}
	return pu.Scheme + "://" + pu.Host
}

func validAIURL(s string) bool {
	pu, err := url.Parse(s)
	return err == nil && (pu.Scheme == "http" || pu.Scheme == "https") && pu.Host != "" && pu.User == nil
}

// aiChat: 연결 종류에 맞춰 요청한다. 반환: 응답 본문(JSON 문자열), 모델 이름, 종료 사유.
func aiChat(e aiEndpoint, system, user string, schema map[string]any, maxTokens int, timeout time.Duration) (string, string, string, error) {
	c, m, f, _, err := aiChatU(e, system, user, schema, maxTokens, timeout)
	return c, m, f, err
}

// aiChatU: aiChat + 토큰 수·처리 속도(성능 측정용). 로컬(llama.cpp)이 도는 동안은 aiLocalBusy 가 0 보다 크다.
func aiChatU(e aiEndpoint, system, user string, schema map[string]any, maxTokens int, timeout time.Duration) (string, string, string, aiUsage, error) {
	if e.Kind == "external" && e.Provider == "anthropic" {
		return anthropicChat(e, system, user, schema, timeout)
	}
	if e.Kind == "local" {
		aiLocalBusy.Add(1)
		aiBusySeen.Store(true)
		defer aiLocalBusy.Add(-1)
	}
	return openaiChat(e, system, user, schema, maxTokens, timeout)
}

func openaiChat(e aiEndpoint, system, user string, schema map[string]any, maxTokens int, timeout time.Duration) (string, string, string, aiUsage, error) {
	var u aiUsage
	msgs := []map[string]string{}
	if system != "" {
		msgs = append(msgs, map[string]string{"role": "system", "content": system})
	}
	msgs = append(msgs, map[string]string{"role": "user", "content": user})
	req := map[string]any{"messages": msgs, "temperature": 0.2, "max_tokens": maxTokens}
	if e.Model != "" {
		req["model"] = e.Model
	}
	if schema != nil && e.JSONSchema {
		req["response_format"] = map[string]any{"type": "json_schema",
			"json_schema": map[string]any{"name": "draft", "strict": true, "schema": schema}}
	} else if schema != nil {
		req["response_format"] = map[string]any{"type": "json_object"}
	}
	if e.Kind == "local" { // llama.cpp·vLLM: 생각(thinking) 출력 끄기. 외부 API 는 모르는 필드를 거부할 수 있어 넣지 않음
		req["chat_template_kwargs"] = map[string]any{"enable_thinking": false}
		req["cache_prompt"] = true // 앞부분이 직전 요청과 같으면 다시 읽지 않는다
	}
	body, _ := json.Marshal(req)
	hr, _ := http.NewRequest("POST", aiAPIBase(e)+"/chat/completions", bytes.NewReader(body))
	hr.Header.Set("Content-Type", "application/json")
	if e.APIKey != "" {
		hr.Header.Set("Authorization", "Bearer "+e.APIKey)
	}
	resp, err := (&http.Client{Timeout: timeout}).Do(hr)
	if err != nil {
		return "", "", "", u, errors.New("AI 서버 응답 없음: " + redactKey(err.Error(), e.APIKey))
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return "", "", "", u, errors.New("AI 서버 " + itoa(resp.StatusCode) + ": " + truncate(redactKey(string(rb), e.APIKey), 300))
	}
	var cr struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			Prompt     int `json:"prompt_tokens"`
			Completion int `json:"completion_tokens"`
		} `json:"usage"`
		Timings *struct { // llama.cpp 만 준다
			PromptMs    float64 `json:"prompt_ms"`
			PredictedMs float64 `json:"predicted_ms"`
			PromptN     int     `json:"prompt_n"`
			CacheN      int     `json:"cache_n"`
		} `json:"timings"`
	}
	if err := json.Unmarshal(rb, &cr); err != nil || len(cr.Choices) == 0 {
		return "", "", "", u, errors.New("AI 응답 형식 오류")
	}
	u.PromptTok, u.GenTok = cr.Usage.Prompt, cr.Usage.Completion
	if cr.Timings != nil {
		u.PromptMs, u.GenMs = cr.Timings.PromptMs, cr.Timings.PredictedMs
		u.EvalTok, u.CacheTok = cr.Timings.PromptN, cr.Timings.CacheN
	}
	model := firstNonEmpty(cr.Model, e.Model)
	if strings.HasSuffix(model, ".gguf") { // llama.cpp 는 모델 파일 경로를 돌려준다 → 이름만
		model = strings.TrimSuffix(filepath.Base(model), ".gguf")
	}
	return stripFence(cr.Choices[0].Message.Content), model, cr.Choices[0].FinishReason, u, nil
}

func anthropicClient(e aiEndpoint, timeout time.Duration) anthropic.Client {
	opts := []option.RequestOption{option.WithAPIKey(e.APIKey), option.WithRequestTimeout(timeout), option.WithMaxRetries(2)}
	if e.URL != "" {
		opts = append(opts, option.WithBaseURL(e.URL))
	}
	return anthropic.NewClient(opts...)
}

// anthropicFallbackOK: 서버 측 거절 대체(fallbacks)를 받는 모델.
func anthropicFallbackOK(model string) bool {
	for _, p := range []string{"claude-fable-5-2", "claude-fable-5-1", "claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5"} {
		if model == p {
			return true
		}
	}
	return false
}

// anthropicChat: Claude Messages API(공식 SDK). 구조화 출력(output_config.format)으로 JSON 을 강제한다.
// 생각(adaptive thinking)이 출력 토큰을 함께 쓰므로 max_tokens 는 넉넉히 잡는다.
func anthropicChat(e aiEndpoint, system, user string, schema map[string]any, timeout time.Duration) (string, string, string, aiUsage, error) {
	var u aiUsage
	cl := anthropicClient(e, timeout)
	p := anthropic.BetaMessageNewParams{
		Model:     anthropic.Model(e.Model),
		MaxTokens: 16000,
		System:    []anthropic.BetaTextBlockParam{{Text: system}},
		Messages:  []anthropic.BetaMessageParam{anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(user))},
	}
	if eff := firstNonEmpty(e.Effort, "medium"); eff != "" {
		p.OutputConfig.Effort = anthropic.BetaOutputConfigEffort(eff)
	}
	if schema != nil {
		p.OutputConfig.Format = anthropic.BetaJSONOutputFormatParam{Schema: anthropicSchema(schema)}
	}
	if anthropicFallbackOK(e.Model) { // 정책 거절 시 서버가 대체 모델로 다시 답한다
		p.Betas = []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01}
		p.Fallbacks = anthropic.BetaFallbacksParamOfDefault()
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout+30*time.Second)
	defer cancel()
	resp, err := cl.Beta.Messages.New(ctx, p)
	if err != nil {
		var apierr *anthropic.Error
		if errors.As(err, &apierr) {
			msg := map[int]string{401: "API 키가 올바르지 않습니다", 403: "권한 없음", 404: "모델을 찾을 수 없습니다", 429: "요청 한도 초과 — 잠시 후 다시"}[apierr.StatusCode]
			return "", "", "", u, errors.New("Claude API " + itoa(apierr.StatusCode) + ": " + firstNonEmpty(msg, truncate(redactKey(apierr.Message, e.APIKey), 300)))
		}
		return "", "", "", u, errors.New("Claude API 응답 없음: " + truncate(redactKey(err.Error(), e.APIKey), 300))
	}
	model := string(resp.Model)
	u.PromptTok, u.GenTok = int(resp.Usage.InputTokens), int(resp.Usage.OutputTokens)
	if resp.StopReason == anthropic.BetaStopReasonRefusal {
		return "", model, "refusal", u, errors.New("Claude 가 요청을 거절했습니다(" + firstNonEmpty(string(resp.StopDetails.Category), "분류 없음") + ")")
	}
	var b strings.Builder
	for _, blk := range resp.Content {
		if t, ok := blk.AsAny().(anthropic.BetaTextBlock); ok {
			b.WriteString(t.Text)
		}
	}
	finish := string(resp.StopReason)
	if resp.StopReason == anthropic.BetaStopReasonMaxTokens {
		finish = "length"
	}
	return stripFence(b.String()), model, finish, u, nil
}

// anthropicSchema: 구조화 출력이 받지 않는 제약(길이·개수·수치 범위)을 빼고 모든 object 에 additionalProperties:false 를 붙인다.
// 빠진 제약은 각 기능의 후처리(guard·truncate)가 맡는다.
func anthropicSchema(s map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range s {
		switch k {
		case "maxLength", "minLength", "maxItems", "minItems", "minimum", "maximum", "multipleOf", "exclusiveMinimum", "exclusiveMaximum", "pattern":
			continue
		}
		switch x := v.(type) {
		case map[string]any:
			if k == "properties" {
				pp := map[string]any{}
				for pk, pv := range x {
					if m, ok := pv.(map[string]any); ok {
						pp[pk] = anthropicSchema(m)
					} else {
						pp[pk] = pv
					}
				}
				out[k] = pp
			} else {
				out[k] = anthropicSchema(x)
			}
		case []any:
			arr := make([]any, len(x))
			for i, it := range x {
				if m, ok := it.(map[string]any); ok {
					arr[i] = anthropicSchema(m)
				} else {
					arr[i] = it
				}
			}
			out[k] = arr
		default:
			out[k] = v
		}
	}
	if out["type"] == "object" {
		out["additionalProperties"] = false
		if _, ok := out["properties"]; !ok {
			out["properties"] = map[string]any{}
		}
	}
	return out
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

type aiExternalView struct {
	aiExternal
	HasKey  bool   `json:"hasKey"`
	KeyHint string `json:"keyHint,omitempty"` // 끝 4자리
}

type aiConfigView struct {
	Mode          string         `json:"mode"`
	ReportMode    string         `json:"reportMode"`
	URL           string         `json:"url"`
	Model         string         `json:"model,omitempty"`
	JSONSchema    bool           `json:"jsonSchema"`
	External      aiExternalView `json:"external"`
	SendChecklist bool           `json:"sendChecklist"`
	Fallback      bool           `json:"fallback"`
	UpdatedBy     string         `json:"updatedBy,omitempty"`
	UpdatedAt     string         `json:"updatedAt,omitempty"`
	FromEnv       bool           `json:"fromEnv"` // 설정 파일 없이 AI_URL 환경변수 사용 중
}

func viewAIConf(c aiConfig) aiConfigView {
	v := aiConfigView{Mode: c.Mode, ReportMode: c.useMode("report"), URL: c.URL, Model: c.Model, JSONSchema: c.JSONSchema,
		SendChecklist: c.SendChecklist, Fallback: c.Fallback, UpdatedBy: c.UpdatedBy, UpdatedAt: c.UpdatedAt,
		External: aiExternalView{aiExternal: c.External, HasKey: c.External.APIKey != ""}}
	if n := len(c.External.APIKey); n >= 8 {
		v.External.KeyHint = "…" + c.External.APIKey[n-4:]
	}
	v.External.APIKey = ""
	if _, err := os.Stat(aiConfigPath()); err != nil && c.Mode == "local" {
		v.FromEnv = true
	}
	return v
}

// GET /api/ai/config
func (s *Server) apiAIConfigGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"config": viewAIConf(aiConf()), "status": s.aiStatusFor("vex"), "reportStatus": s.aiStatusFor("report")})
}

type aiExternalIn struct {
	Provider   string `json:"provider"`
	URL        string `json:"url"`
	Model      string `json:"model"`
	APIKey     string `json:"apiKey"`   // 빈 값이면 기존 키 유지
	ClearKey   bool   `json:"clearKey"` // 키 삭제
	JSONSchema *bool  `json:"jsonSchema"`
	Effort     string `json:"effort"`
}

type aiConfigIn struct {
	Mode          string       `json:"mode"`
	ReportMode    string       `json:"reportMode"`
	URL           string       `json:"url"`
	Model         string       `json:"model"`
	JSONSchema    *bool        `json:"jsonSchema"`
	External      aiExternalIn `json:"external"`
	SendChecklist bool         `json:"sendChecklist"`
	Fallback      bool         `json:"fallback"`
}

func validMode(m string) bool { return m == "off" || m == "local" || m == "external" }

func mergeAIConf(old aiConfig, in aiConfigIn) (aiConfig, error) {
	c := aiConfig{Mode: in.Mode, ReportMode: firstNonEmpty(in.ReportMode, in.Mode), URL: strings.TrimSpace(in.URL), Model: strings.TrimSpace(in.Model),
		JSONSchema: true, SendChecklist: in.SendChecklist, Fallback: in.Fallback}
	if in.JSONSchema != nil {
		c.JSONSchema = *in.JSONSchema
	}
	x := in.External
	c.External = aiExternal{Provider: firstNonEmpty(x.Provider, "anthropic"), URL: strings.TrimRight(strings.TrimSpace(x.URL), "/"),
		Model: strings.TrimSpace(x.Model), APIKey: old.External.APIKey, JSONSchema: true, Effort: x.Effort}
	if x.JSONSchema != nil {
		c.External.JSONSchema = *x.JSONSchema
	}
	if k := strings.TrimSpace(x.APIKey); k != "" {
		c.External.APIKey = k
	}
	if x.ClearKey {
		c.External.APIKey = ""
	}
	if c.External.Provider == "anthropic" && c.External.Model == "" {
		c.External.Model = anthropicDefaultModel
	}
	if !validMode(c.Mode) || !validMode(c.ReportMode) {
		return c, errors.New("용도별 연결은 off / local / external 중 하나")
	}
	if c.External.Provider != "anthropic" && c.External.Provider != "openai" {
		return c, errors.New("외부 LLM 종류는 anthropic / openai")
	}
	if c.External.Effort != "" && !inList(c.External.Effort, []string{"low", "medium", "high"}) {
		return c, errors.New("추론 수준은 low / medium / high")
	}
	uses := c.Mode + " " + c.ReportMode
	if c.URL != "" || strings.Contains(uses, "local") {
		if !validAIURL(c.URL) {
			return c, errors.New("로컬 LLM 주소는 http:// 또는 https:// 로 시작해야 합니다")
		}
	}
	if c.External.URL != "" && !validAIURL(c.External.URL) {
		return c, errors.New("외부 LLM 주소는 http:// 또는 https:// 로 시작해야 합니다")
	}
	if strings.Contains(uses, "external") {
		switch {
		case c.External.Provider == "openai" && c.External.URL == "":
			return c, errors.New("OpenAI 호환 외부 LLM 은 주소가 필요합니다")
		case c.External.Model == "":
			return c, errors.New("외부 LLM 은 모델 이름이 필요합니다")
		case c.External.Provider == "anthropic" && c.External.APIKey == "":
			return c, errors.New("Claude API 키가 필요합니다")
		}
	}
	if c.Fallback && !(c.endpointOf("local").ready() && c.endpointOf("external").ready()) {
		return c, errors.New("대체 연결을 켜려면 로컬 LLM 과 외부 LLM 이 모두 설정돼 있어야 합니다")
	}
	if !strings.Contains(uses, "external") && !c.Fallback {
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
	host := func(u string) string {
		if pu, err := url.Parse(u); err == nil {
			return pu.Host
		}
		return ""
	}
	_ = s.sor.append(SoREvent{Actor: c.UpdatedBy, Action: "ai-config", Status: c.Mode + "/" + c.ReportMode,
		Detail: map[string]any{"vex": c.Mode, "report": c.ReportMode, "localHost": host(c.URL), "external": c.External.Provider,
			"externalHost": host(c.External.URL), "externalModel": c.External.Model, "hasKey": c.External.APIKey != "", "sendChecklist": c.SendChecklist, "fallback": c.Fallback}})
	writeJSON(w, 200, map[string]any{"config": viewAIConf(c), "status": s.aiStatusFor("vex"), "reportStatus": s.aiStatusFor("report")})
}

// POST /api/ai/test {target: local|external, ...설정} — 저장 전 입력값(키 비우면 저장된 키)으로 짧은 JSON 요청을 보내 본다.
func (s *Server) apiAITest(w http.ResponseWriter, r *http.Request) {
	var in struct {
		aiConfigIn
		Target string `json:"target"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "잘못된 요청"})
		return
	}
	// 시험 대상만 쓰도록 용도를 맞춰 검증한다
	if in.Target != "local" && in.Target != "external" {
		writeJSON(w, 400, map[string]string{"error": "target 은 local / external"})
		return
	}
	in.Mode, in.ReportMode = in.Target, in.Target
	c, err := mergeAIConf(aiConf(), in.aiConfigIn)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	e := c.endpointOf(in.Target)
	schema := map[string]any{"type": "object", "properties": map[string]any{"answer": map[string]any{"type": "string", "maxLength": 40}},
		"required": []string{"answer"}}
	t0 := time.Now()
	content, model, _, err := aiChat(e, "", "연결 시험이다. answer 에 '정상'이라고만 써라.", schema, 60, 2*time.Minute)
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
