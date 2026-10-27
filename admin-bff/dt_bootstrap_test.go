package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 가짜 DT: admin 비밀번호 변경 → 로그인 → 팀 생성 → 권한 → 키 발급 흐름.
func fakeDT(t *testing.T, pw string) (*httptest.Server, *int) {
	keys := 0
	changed := false
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/version", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"version":"4.14.3"}`)) })
	mux.HandleFunc("POST /api/v1/user/forceChangePassword", func(w http.ResponseWriter, r *http.Request) {
		if !changed && r.FormValue("password") == "admin" {
			changed = true
			return
		}
		w.WriteHeader(401)
	})
	mux.HandleFunc("POST /api/v1/user/login", func(w http.ResponseWriter, r *http.Request) {
		if changed && r.FormValue("password") == pw {
			w.Write([]byte("eyJfake"))
			return
		}
		w.WriteHeader(401)
	})
	authed := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer eyJfake" {
				w.WriteHeader(401)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("GET /api/v1/team", authed(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`[]`)) }))
	mux.HandleFunc("PUT /api/v1/team", authed(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		w.Write([]byte(`{"uuid":"team-1","name":"trustlink-bff"}`))
	}))
	mux.HandleFunc("POST /api/v1/permission/{p}/team/{u}", authed(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("PUT /api/v1/team/{u}/key", authed(func(w http.ResponseWriter, r *http.Request) {
		keys++
		w.WriteHeader(201)
		w.Write([]byte(`{"key":"odt_secret123","maskedKey":"odt_****"}`))
	}))
	return httptest.NewServer(mux), &keys
}

func TestDTBootstrapPersistsKey(t *testing.T) {
	dt, keys := fakeDT(t, "s3cret")
	defer dt.Close()
	keyFile := filepath.Join(t.TempDir(), "sub", "dt-api-key")
	cfg := Config{DTBaseURL: dt.URL, DTAdminPassword: "s3cret", DTKeyFile: keyFile}

	s := &Server{cfg: cfg, http: &http.Client{Timeout: 5 * time.Second}}
	s.initDTKey()
	for i := 0; i < 50 && !s.dtEnabled(); i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if s.dtAPIKey() != "odt_secret123" {
		t.Fatalf("key = %q", s.dtAPIKey())
	}
	b, err := os.ReadFile(keyFile)
	if err != nil || strings.TrimSpace(string(b)) != "odt_secret123" {
		t.Fatalf("키 파일: %q %v", b, err)
	}

	// 재기동: 파일에서 읽고 새 키를 발급하지 않는다(업데이트해도 연동 유지)
	s2 := &Server{cfg: cfg, http: &http.Client{Timeout: 5 * time.Second}}
	s2.initDTKey()
	if s2.dtAPIKey() != "odt_secret123" || *keys != 1 {
		t.Fatalf("재기동 key=%q 발급횟수=%d", s2.dtAPIKey(), *keys)
	}
}

func TestDTKeyEnvWins(t *testing.T) {
	s := &Server{cfg: Config{DTBaseURL: "http://x", DTApiKey: "from-env"}}
	s.initDTKey()
	if s.dtAPIKey() != "from-env" {
		t.Fatal(s.dtAPIKey())
	}
}
