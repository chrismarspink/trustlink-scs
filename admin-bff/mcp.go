package main

// mcp.go: MCP 서버(시범) — Claude 같은 AI 도구가 TrustLink 에 직접 묻게 한다.
//
//   POST /api/mcp                 MCP(Streamable HTTP, JSON-RPC 2.0). 조회 도구만 있다 — 보내기·저장·판정은 없다.
//   GET/POST /api/mcp/tokens      내 연결 토큰 목록 / 새로 만들기(값은 만든 직후 한 번만 보인다)
//   DELETE /api/mcp/tokens/{id}   토큰 끊기(본인 것, 관리자는 누구 것이든)
//
// 인증: 화면 로그인(쿠키)이 아니라 "연결 토큰"(Authorization: Bearer). 토큰은 만든 사람의 계정에 묶이고,
// 답은 그 사람이 화면에서 볼 수 있는 범위 그대로다(묻고 찾기와 같은 함수로 답한다).
// 토큰 원문은 저장하지 않고 SHA-256 만 둔다. 계정이 꺼지거나 지워지면 다음 확인(5분 이내) 때 토큰도 막힌다.
// 누가 어떤 도구로 무엇을 물었는지는 감사 원장에 남긴다.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type mcpToken struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	User     string   `json:"user"`
	Groups   []string `json:"groups"` // 만든 때의 그룹. 쓸 때 Keycloak 에서 다시 읽어 맞춘다
	Hash     string   `json:"hash,omitempty"`
	Created  string   `json:"created"`
	Expires  string   `json:"expires"`
	LastUsed string   `json:"lastUsed,omitempty"`
	Uses     int      `json:"uses"`
}

const (
	mcpMaxTokens  = 5  // 한 사람이 가질 수 있는 토큰
	mcpRatePerMin = 60 // 토큰 하나의 분당 요청
	mcpPrefix     = "tlmcp_"
	mcpRecheck    = 5 * time.Minute
)

var mcpStore = struct {
	sync.Mutex
	path    string
	tokens  []*mcpToken
	checked map[string]time.Time // 토큰 ID → 계정을 마지막으로 확인한 때
	hits    map[string][]time.Time
}{checked: map[string]time.Time{}, hits: map[string][]time.Time{}}

// 잠근 채로 부른다. 저장 파일이 바뀌면(시험) 다시 읽는다.
func mcpLoad() {
	p := env("MCP_STORE", "/var/lib/trustlink/mcp-tokens.json")
	if mcpStore.path == p {
		return
	}
	mcpStore.path, mcpStore.tokens = p, nil
	mcpStore.checked, mcpStore.hits = map[string]time.Time{}, map[string][]time.Time{}
	if b, err := os.ReadFile(p); err == nil {
		_ = json.Unmarshal(b, &mcpStore.tokens)
	}
}

func mcpSave() {
	b, _ := json.MarshalIndent(mcpStore.tokens, "", " ")
	_ = os.MkdirAll(filepath.Dir(mcpStore.path), 0o700)
	tmp := mcpStore.path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, mcpStore.path)
	}
}

func mcpHash(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

func mcpURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") == "" && (strings.HasPrefix(r.Host, "localhost") || strings.HasPrefix(r.Host, "127.")) {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

// ---------- 토큰 관리(화면 로그인 필요) ----------

func mcpPublic(t *mcpToken) map[string]any {
	return map[string]any{"id": t.ID, "name": t.Name, "user": t.User, "created": t.Created, "expires": t.Expires, "lastUsed": t.LastUsed, "uses": t.Uses,
		"expired": t.Expires < time.Now().UTC().Format(time.RFC3339)}
}

// GET /api/mcp/tokens — 내 토큰(관리자는 전체)
func (s *Server) apiMcpTokens(w http.ResponseWriter, r *http.Request) {
	sess, _ := s.sessionOf(r)
	admin := contains(sess.Groups, "admins")
	mcpStore.Lock()
	mcpLoad()
	out := []map[string]any{}
	for _, t := range mcpStore.tokens {
		if t.User == sess.Username || admin {
			out = append(out, mcpPublic(t))
		}
	}
	mcpStore.Unlock()
	writeJSON(w, 200, map[string]any{"url": mcpURL(r) + "/api/mcp", "tokens": out, "max": mcpMaxTokens, "user": sess.Username})
}

// POST /api/mcp/tokens {name, days} — 값은 이 응답에서만 볼 수 있다
func (s *Server) apiMcpTokenCreate(w http.ResponseWriter, r *http.Request) {
	sess, _ := s.sessionOf(r)
	var in struct {
		Name string `json:"name"`
		Days int    `json:"days"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&in)
	in.Name = truncate(strings.TrimSpace(in.Name), 40)
	if in.Name == "" {
		in.Name = "AI 도구"
	}
	if in.Days <= 0 || in.Days > 365 {
		in.Days = 90
	}
	mcpStore.Lock()
	mcpLoad()
	n := 0
	for _, t := range mcpStore.tokens {
		if t.User == sess.Username {
			n++
		}
	}
	if n >= mcpMaxTokens {
		mcpStore.Unlock()
		writeJSON(w, 409, map[string]string{"error": fmt.Sprintf("토큰은 %d개까지 만들 수 있습니다. 쓰지 않는 것을 끊고 다시 만드세요.", mcpMaxTokens)})
		return
	}
	raw, id := make([]byte, 24), make([]byte, 5)
	_, _ = rand.Read(raw)
	_, _ = rand.Read(id)
	tok := mcpPrefix + hex.EncodeToString(raw)
	now := time.Now().UTC()
	t := &mcpToken{ID: "m-" + hex.EncodeToString(id), Name: in.Name, User: sess.Username, Groups: append([]string(nil), sess.Groups...), Hash: mcpHash(tok),
		Created: now.Format(time.RFC3339), Expires: now.AddDate(0, 0, in.Days).Format(time.RFC3339)}
	mcpStore.tokens = append(mcpStore.tokens, t)
	mcpStore.checked[t.ID] = now
	mcpSave()
	mcpStore.Unlock()
	if s.sor != nil {
		_ = s.sor.append(SoREvent{Actor: sess.Username, Action: "mcp-token-create", Subject: t.ID, Detail: map[string]any{"name": t.Name, "days": in.Days}})
	}
	out := mcpPublic(t)
	out["token"], out["url"] = tok, mcpURL(r)+"/api/mcp"
	writeJSON(w, 200, out)
}

// DELETE /api/mcp/tokens/{id}
func (s *Server) apiMcpTokenDelete(w http.ResponseWriter, r *http.Request) {
	sess, _ := s.sessionOf(r)
	id := r.PathValue("id")
	mcpStore.Lock()
	mcpLoad()
	found := false
	for i, t := range mcpStore.tokens {
		if t.ID == id && (t.User == sess.Username || contains(sess.Groups, "admins")) {
			mcpStore.tokens = append(mcpStore.tokens[:i], mcpStore.tokens[i+1:]...)
			found = true
			break
		}
	}
	if found {
		mcpSave()
	}
	mcpStore.Unlock()
	if !found {
		writeJSON(w, 404, map[string]string{"error": "토큰을 찾지 못했습니다"})
		return
	}
	if s.sor != nil {
		_ = s.sor.append(SoREvent{Actor: sess.Username, Action: "mcp-token-revoke", Subject: id})
	}
	writeJSON(w, 200, map[string]string{"status": "revoked"})
}

// mcpAuth: Bearer 토큰 → 그 사람의 세션. 계정 상태와 그룹은 mcpRecheck 마다 Keycloak 에서 다시 읽는다.
func (s *Server) mcpAuth(r *http.Request) (Session, *mcpToken, int, string) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") || !strings.HasPrefix(strings.TrimSpace(h[7:]), mcpPrefix) {
		return Session{}, nil, 401, "연결 토큰이 필요합니다"
	}
	hash := mcpHash(strings.TrimSpace(h[7:]))
	now := time.Now().UTC()
	mcpStore.Lock()
	mcpLoad()
	var t *mcpToken
	for _, x := range mcpStore.tokens {
		if x.Hash == hash {
			t = x
		}
	}
	if t == nil || t.Expires < now.Format(time.RFC3339) {
		mcpStore.Unlock()
		return Session{}, nil, 401, "토큰이 없거나 기한이 지났습니다"
	}
	hits := mcpStore.hits[t.ID][:0]
	for _, x := range mcpStore.hits[t.ID] {
		if now.Sub(x) < time.Minute {
			hits = append(hits, x)
		}
	}
	if len(hits) >= mcpRatePerMin {
		mcpStore.hits[t.ID] = hits
		mcpStore.Unlock()
		return Session{}, nil, 429, "요청이 너무 많습니다. 잠시 뒤에 다시 하세요"
	}
	mcpStore.hits[t.ID] = append(hits, now)
	recheck := now.Sub(mcpStore.checked[t.ID]) > mcpRecheck
	user := t.User
	mcpStore.Unlock()

	if recheck {
		gone, groups := s.mcpAccount(user)
		mcpStore.Lock()
		mcpStore.checked[t.ID] = now
		if gone {
			mcpStore.Unlock()
			return Session{}, nil, 401, "계정이 꺼져 있거나 없어 토큰을 쓸 수 없습니다"
		}
		if groups != nil {
			t.Groups = groups
		}
		mcpStore.Unlock()
	}
	mcpStore.Lock()
	t.LastUsed, t.Uses = now.Format(time.RFC3339), t.Uses+1
	if t.Uses%20 == 1 {
		mcpSave()
	}
	sess := Session{Username: t.User, Groups: append([]string(nil), t.Groups...), Expiry: now.Add(time.Minute)}
	mcpStore.Unlock()
	return sess, t, 0, ""
}

// mcpAccount: Keycloak 에서 계정을 확인한다. gone=true 는 계정이 없거나 꺼짐. Keycloak 에 닿지 않으면 (false, nil) — 저장된 그룹을 그대로 쓴다.
func (s *Server) mcpAccount(username string) (gone bool, groups []string) {
	resp, err := s.kcAdmin("GET", "/users?exact=true&username="+url.QueryEscape(username), nil)
	if err != nil {
		return false, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false, nil
	}
	var users []kcUser
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&users) != nil {
		return false, nil
	}
	if len(users) == 0 || !users[0].Enabled {
		return true, nil
	}
	return false, s.userGroupNames(users[0].ID)
}

// ---------- MCP(JSON-RPC) ----------

var mcpVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

type mcpTool struct {
	Name        string         `json:"name"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations map[string]any `json:"annotations"`
}

func mcpSchema(props map[string]any, required ...string) map[string]any {
	if required == nil {
		required = []string{}
	}
	return map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}
}

var mcpReadOnly = map[string]any{"readOnlyHint": true, "destructiveHint": false, "openWorldHint": false}

var mcpTools = []mcpTool{
	{"trustlink_ask", "TrustLink 에 묻기", "TrustLink(소프트웨어 공급망 신뢰 장부)에 한국어 문장으로 묻는다. 취약점 번호, 구성요소 이름, 제품 이름, 현황, 급한 것, 할 일, 용어를 물을 수 있다. 답은 토큰 주인의 권한 범위 안에서만 나온다. 조회만 하며 아무것도 바꾸지 않는다.",
		mcpSchema(map[string]any{"question": map[string]any{"type": "string", "description": "질문. 예: 'CVE-2026-1234 가 어디에 걸리나?', '취약점 몇 건이야?', '급한 것부터'", "maxLength": 300}}, "question"), mcpReadOnly},
	{"trustlink_vulnerability", "취약점 영향 조회", "취약점 번호(CVE 또는 GHSA) 하나가 어느 제품·버전에 있는지, 판단 상태가 무엇인지 조회한다. 관리자 토큰이면 그 버전을 설치한 고객도 답한다.",
		mcpSchema(map[string]any{"id": map[string]any{"type": "string", "description": "예: CVE-2026-1234"}}, "id"), mcpReadOnly},
	{"trustlink_component", "구성요소가 든 제품 찾기", "구성요소(라이브러리) 이름으로 그것이 들어 있는 제품과 버전을 SBOM 에서 찾는다.",
		mcpSchema(map[string]any{"name": map[string]any{"type": "string", "description": "예: log4j, spring-webmvc"}}, "name"), mcpReadOnly},
	{"trustlink_status", "현황 요약", "감시 중인 제품·버전 수와 판단 대기 취약점 수(실제 악용·치명·높음)를 요약한다. 고객 계정이면 자기 설치 버전에서 조치할 것을 답한다.",
		mcpSchema(map[string]any{}), mcpReadOnly},
	{"trustlink_urgent", "급한 취약점", "실제 악용이 확인됐거나 치명 등급인 판단 대기 취약점이 남은 제품·버전을 급한 순으로 보여 준다.",
		mcpSchema(map[string]any{}), mcpReadOnly},
}

type mcpReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func mcpReply(w http.ResponseWriter, id json.RawMessage, result any) {
	writeJSON(w, 200, map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func mcpErr(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	if id == nil {
		id = json.RawMessage("null")
	}
	writeJSON(w, 200, map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": msg}})
}

// POST /api/mcp
func (s *Server) apiMcp(w http.ResponseWriter, r *http.Request) {
	sess, tok, code, msg := s.mcpAuth(r)
	if code != 0 {
		if code == 401 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="TrustLink MCP"`)
		}
		writeJSON(w, code, map[string]string{"error": msg})
		return
	}
	var req mcpReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil || req.JSONRPC != "2.0" || req.Method == "" {
		mcpErr(w, nil, -32600, "JSON-RPC 2.0 요청 하나를 보내 주세요")
		return
	}
	if req.ID == nil { // 알림(notifications/initialized 등) — 답이 없다
		w.WriteHeader(http.StatusAccepted)
		return
	}
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		v := mcpVersions[0]
		if inList(p.ProtocolVersion, mcpVersions) {
			v = p.ProtocolVersion
		}
		mcpReply(w, req.ID, map[string]any{
			"protocolVersion": v,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "trustlink", "title": "TrustLink", "version": "1.0"},
			"instructions":    "TrustLink 는 납품 소프트웨어의 SBOM·취약점·VEX·고객 통지를 기록하는 장부다. 이 서버는 조회만 한다. 답은 토큰 주인(" + sess.Username + ")의 권한 범위 안의 기록이다. 답에 없는 내용은 추측하지 말고 없다고 답하라.",
		})
	case "ping":
		mcpReply(w, req.ID, map[string]any{})
	case "tools/list":
		mcpReply(w, req.ID, map[string]any{"tools": mcpTools})
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if json.Unmarshal(req.Params, &p) != nil {
			mcpErr(w, req.ID, -32602, "도구 이름과 인자를 확인해 주세요")
			return
		}
		arg := func(k string) string { v, _ := p.Arguments[k].(string); return truncate(strings.TrimSpace(v), 300) }
		a, bad := s.mcpCall(sess, p.Name, arg)
		if a == nil && bad == "" {
			mcpErr(w, req.ID, -32602, "없는 도구입니다: "+truncate(p.Name, 60))
			return
		}
		if s.sor != nil {
			st := "ok"
			if bad != "" {
				st = "bad-input"
			}
			_ = s.sor.append(SoREvent{Actor: sess.Username, Action: "mcp", Status: st, Subject: tok.ID,
				Detail: map[string]any{"tool": p.Name, "q": truncate(arg("question")+arg("id")+arg("name"), 200)}})
		}
		if bad != "" {
			mcpReply(w, req.ID, map[string]any{"content": []map[string]string{{"type": "text", "text": bad}}, "isError": true})
			return
		}
		mcpReply(w, req.ID, map[string]any{"content": []map[string]string{{"type": "text", "text": mcpText(a, mcpURL(r))}}, "isError": false})
	default:
		mcpErr(w, req.ID, -32601, "지원하지 않는 요청입니다: "+truncate(req.Method, 60))
	}
}

// mcpCall: 도구 → 묻고 찾기의 조회 함수. (nil, "") 이면 없는 도구, bad 가 있으면 입력 오류.
func (s *Server) mcpCall(sess Session, name string, arg func(string) string) (*askAnswer, string) {
	mine := s.myProducts(sess)
	isCustomer := len(mine) > 0 && !contains(sess.Groups, "admins")
	var a *askAnswer
	switch name {
	case "trustlink_ask":
		if arg("question") == "" {
			return nil, "question 에 질문을 적어 주세요"
		}
		a = s.askQuery(sess, arg("question"))
	case "trustlink_vulnerability":
		id := strings.ToUpper(askVulnRe.FindString(arg("id")))
		if id == "" {
			return nil, "id 에 CVE-2026-1234 같은 취약점 번호를 적어 주세요"
		}
		a = s.askVuln(sess, id, mine, isCustomer)
	case "trustlink_component":
		if arg("name") == "" {
			return nil, "name 에 구성요소 이름을 적어 주세요"
		}
		if isCustomer {
			a = &askAnswer{Title: "구성요소 찾기", Lead: "고객 계정은 구성요소 검색을 쓸 수 없습니다. 설치하신 제품의 상태는 현황 요약으로 확인하세요."}
		} else {
			a = s.askComponent(sess, arg("name"))
		}
	case "trustlink_status", "trustlink_urgent":
		switch {
		case isCustomer:
			a = askMine(mine)
		case !s.dtEnabled():
			a = &askAnswer{Title: "현황", Lead: "취약점 분석이 꺼져 있어 답할 수 없습니다."}
		case name == "trustlink_urgent":
			a = s.askUrgent(sess)
		default:
			a = s.askStatus(sess)
		}
	default:
		return nil, ""
	}
	return a, ""
}

// mcpText: 답을 AI 도구가 읽을 글로 만든다(링크는 전체 주소로).
func mcpText(a *askAnswer, base string) string {
	var b strings.Builder
	if a.Title != "" {
		b.WriteString("# " + a.Title + "\n\n")
	}
	b.WriteString(a.Lead + "\n")
	for _, r := range a.Rows {
		b.WriteString("\n- " + r.Title)
		if r.Detail != "" {
			b.WriteString(" — " + r.Detail)
		}
		if strings.HasPrefix(r.Link, "/") {
			b.WriteString(" (" + base + r.Link + ")")
		}
	}
	if a.More > 0 {
		fmt.Fprintf(&b, "\n- 그 밖에 %d건이 더 있습니다.", a.More)
	}
	if len(a.Sources) > 0 {
		src := append([]string(nil), a.Sources...)
		sort.Strings(src)
		b.WriteString("\n\n출처: " + strings.Join(src, " · "))
	}
	return b.String()
}
