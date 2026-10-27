package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestStripSecure(t *testing.T) {
	cases := map[string]string{
		"state=abc; Path=/; Max-Age=900; HttpOnly; Secure; SameSite=Lax": "state=abc; Path=/; Max-Age=900; HttpOnly; SameSite=Lax",
		"pkce=x; Path=/; secure; SameSite=None":                          "pkce=x; Path=/; SameSite=Lax",
		"session=1; Path=/; HttpOnly":                                    "session=1; Path=/; HttpOnly",
	}
	for in, want := range cases {
		if got := stripSecure(in); got != want {
			t.Errorf("stripSecure(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

func TestStripSecureCookiesOnHTTP(t *testing.T) {
	mk := func(r *http.Request) *http.Response {
		h := http.Header{}
		h.Add("Set-Cookie", "a=1; Secure")
		h.Add("Set-Cookie", "b=2; Path=/; Secure")
		return &http.Response{Header: h, Request: r}
	}
	plain, _ := http.NewRequest("GET", "http://x/zot/auth/login", nil)
	resp := mk(plain)
	_ = stripSecureCookiesOnHTTP(resp)
	if got := resp.Header.Values("Set-Cookie"); len(got) != 2 || got[0] != "a=1" || got[1] != "b=2; Path=/" {
		t.Fatalf("HTTP: %q", got)
	}

	tlsReq, _ := http.NewRequest("GET", "https://x/zot/auth/login", nil)
	tlsReq.TLS = &tls.ConnectionState{}
	resp = mk(tlsReq)
	_ = stripSecureCookiesOnHTTP(resp)
	if got := resp.Header.Values("Set-Cookie"); got[0] != "a=1; Secure" {
		t.Fatalf("HTTPS 는 보존해야 함: %q", got)
	}

	fwd, _ := http.NewRequest("GET", "http://x/zot/auth/login", nil)
	fwd.Header.Set("X-Forwarded-Proto", "https")
	resp = mk(fwd)
	_ = stripSecureCookiesOnHTTP(resp)
	if got := resp.Header.Values("Set-Cookie"); got[0] != "a=1; Secure" {
		t.Fatalf("X-Forwarded-Proto=https 는 보존해야 함: %q", got)
	}
}

func TestServeUISPAFallback(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("INDEX"), 0o644)
	os.MkdirAll(filepath.Join(dir, "assets"), 0o755)
	os.WriteFile(filepath.Join(dir, "assets", "app.js"), []byte("JS"), 0o644)
	s := &Server{cfg: Config{UIDir: dir}}
	for path, want := range map[string]int{
		"/":                                   200,
		"/artifact/products%2Finnopouch/10.0": 200, // 버전의 점 → SPA
		"/admin/users":                        200,
		"/assets/app.js":                      200,
		"/assets/missing.js":                  404,
	} {
		rec := httptest.NewRecorder()
		s.serveUI(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != want {
			t.Errorf("%s: got %d want %d", path, rec.Code, want)
		}
	}
}
