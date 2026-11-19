package main

// 관리 콘솔 ↔ 취약점 DB 미러(vuln-mirror) 연결.
//  - 상태·정책 화면은 미러의 내부 API 를 그대로 보여 준다. 쓰기(정책·즉시 받기)는 미러 볼륨의 api.key 로 인증.
//  - DT 연결: DT 의 vuln-source *.url 설정 중 미러가 가진 호스트만 미러 주소로 바꾼다(되돌리기용 원래 값 보관).
//    기본은 바꾸지 않는다(관리자가 화면에서 명시적으로 전환).
//  - 정책 변경·즉시 받기·DT 전환은 원장(SoR)에 남긴다.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

func mirrorBase() string { return strings.TrimRight(os.Getenv("MIRROR_URL"), "/") }

func mirrorKey() string {
	b, _ := os.ReadFile(env("MIRROR_KEY_FILE", "/mirror/_state/api.key"))
	return strings.TrimSpace(string(b))
}

func (s *Server) mirrorCall(method, p string, body []byte) (int, []byte, error) {
	req, err := http.NewRequest(method, mirrorBase()+p, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if method != "GET" {
		req.Header.Set("X-Mirror-Key", mirrorKey())
	}
	c := &http.Client{Timeout: 15 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp.StatusCode, b, err
}

type dtMirrorProp struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	MirrorValue string `json:"mirrorValue,omitempty"` // 전환 시 값(미러가 그 호스트를 가진 경우)
	UsingMirror bool   `json:"usingMirror"`
	Original    string `json:"original,omitempty"`
}

func (s *Server) dtOrigPath() string {
	return env("MIRROR_DT_ORIG", "/var/lib/trustlink/mirror-dt-orig.json")
}

// dtMirrorProps: DT vuln-source 의 URL 설정과, 미러가 가진 호스트 기준 전환 후보.
func (s *Server) dtMirrorProps(hosts map[string]bool) ([]dtMirrorProp, func(string, string, string) (int, []byte, error), error) {
	call, err := s.dtAdminCaller()
	if err != nil {
		return nil, nil, err
	}
	cfg, err := s.dtConfig(call)
	if err != nil {
		return nil, nil, err
	}
	orig := map[string]string{}
	_ = readJSONFile(s.dtOrigPath(), &orig)
	base := mirrorBase()
	out := []dtMirrorProp{}
	for k, v := range cfg {
		if !strings.HasSuffix(k, ".url") || v == "" || v == "null" {
			continue
		}
		p := dtMirrorProp{Name: k, Value: v, Original: orig[k]}
		if strings.HasPrefix(v, base+"/") {
			p.UsingMirror = true
		} else if u, err := url.Parse(v); err == nil && hosts[u.Host] {
			p.MirrorValue = base + "/" + u.Host + u.Path
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, call, nil
}

// mirroredHosts: 미러에 파일이 있는 출처의 호스트.
func mirroredHosts(st map[string]any) map[string]bool {
	hosts := map[string]bool{}
	srcs, _ := st["sources"].([]any)
	for _, x := range srcs {
		m, _ := x.(map[string]any)
		if n, _ := m["files"].(float64); n > 0 {
			hs, _ := m["hosts"].([]any)
			for _, h := range hs {
				if hv, ok := h.(string); ok {
					hosts[hv] = true
				}
			}
		}
	}
	return hosts
}

// GET /api/mirror
func (s *Server) apiMirror(w http.ResponseWriter, r *http.Request) {
	if mirrorBase() == "" {
		writeJSON(w, 200, map[string]any{"installed": false})
		return
	}
	code, b, err := s.mirrorCall("GET", "/_api/status", nil)
	if err != nil || code != 200 {
		writeJSON(w, 200, map[string]any{"installed": true, "reachable": false, "error": fmt.Sprintf("미러 응답 없음: %v %d", err, code)})
		return
	}
	var st map[string]any
	_ = json.Unmarshal(b, &st)
	out := map[string]any{"installed": true, "reachable": true, "status": st, "mirrorUrl": mirrorBase()}
	if props, _, err := s.dtMirrorProps(mirroredHosts(st)); err != nil {
		out["dtError"] = err.Error()
	} else {
		out["dt"] = props
	}
	writeJSON(w, 200, out)
}

// PUT /api/mirror/policy
func (s *Server) apiMirrorPolicy(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	code, b, err := s.mirrorCall("PUT", "/_api/policy", body)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	if code == 200 {
		var p map[string]any
		_ = json.Unmarshal(body, &p)
		delete(p, "sources")
		_ = s.sor.append(SoREvent{Actor: w.Header().Get("X-User"), Action: "mirror-policy", Status: "updated", Detail: p})
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(b)
}

// POST /api/mirror/sync/{id}  (id=all 이면 켠 출처 전부)
func (s *Server) apiMirrorSync(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	code, b, err := s.mirrorCall("POST", "/_api/sync/"+url.PathEscape(id), nil)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	if code == 202 {
		_ = s.sor.append(SoREvent{Actor: w.Header().Get("X-User"), Action: "mirror-sync", Status: "queued", Detail: map[string]any{"source": id}})
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(b)
}

// PUT /api/mirror/dt {use:bool} — DT 가 미러를 보게 하거나 원래 주소로 되돌린다.
func (s *Server) apiMirrorDT(w http.ResponseWriter, r *http.Request) {
	var in struct{ Use bool }
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<10)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	code, b, err := s.mirrorCall("GET", "/_api/status", nil)
	if err != nil || code != 200 {
		writeJSON(w, 502, map[string]string{"error": "미러 응답 없음"})
		return
	}
	var st map[string]any
	_ = json.Unmarshal(b, &st)
	props, call, err := s.dtMirrorProps(mirroredHosts(st))
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	orig := map[string]string{}
	_ = readJSONFile(s.dtOrigPath(), &orig)
	changed := map[string]string{}
	for _, p := range props {
		var val string
		switch {
		case in.Use && p.MirrorValue != "":
			orig[p.Name], val = p.Value, p.MirrorValue
		case !in.Use && p.UsingMirror && p.Original != "":
			val = p.Original
		default:
			continue
		}
		body, _ := json.Marshal(map[string]any{"groupName": vsGroup, "propertyName": p.Name, "propertyValue": val})
		if c, rb, err := call("POST", "/api/v1/configProperty", string(body)); err != nil || c != 200 {
			writeJSON(w, 502, map[string]string{"error": fmt.Sprintf("DT 설정 저장 실패(%s %d): %v %s", p.Name, c, err, rb)})
			return
		}
		changed[p.Name] = val
		if !in.Use {
			delete(orig, p.Name)
		}
	}
	if err := writeJSONFile(s.dtOrigPath(), orig); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_ = s.sor.append(SoREvent{Actor: w.Header().Get("X-User"), Action: "mirror-dt", Status: map[bool]string{true: "use-mirror", false: "use-origin"}[in.Use],
		Detail: map[string]any{"changed": changed}})
	writeJSON(w, 200, map[string]any{"changed": changed})
}
