package main

import (
	"crypto/tls"
	"net/http"
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
