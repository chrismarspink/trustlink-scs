package main

// 단일 프론트도어: BFF가 신규 UI(dist)를 서빙하고, /v2·/zot·/oci → zot, /auth → keycloak 로 리버스 프록시.
// 이로써 외부 노출은 TrustLink(BFF) 단일 진입점만 두고 zot/keycloak/DT 포트는 내부 전용으로 닫는다.

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func mustProxy(target string) *httputil.ReverseProxy {
	u, err := url.Parse(target)
	if err != nil {
		panic("bad proxy target: " + target)
	}
	p := httputil.NewSingleHostReverseProxy(u)
	// Host 헤더를 타깃으로 (zot/keycloak 가 Host 기반 로직을 쓸 수 있어 보존)
	orig := p.Director
	p.Director = func(r *http.Request) {
		orig(r)
		r.Host = u.Host
	}
	return p
}

// registerFrontDoor: 프록시 + 정적 UI 라우트 등록. (admin/api/auth 콜백은 main 에서 먼저 등록)
func (s *Server) registerFrontDoor(mux *http.ServeMux) {
	zotProxy := mustProxy(s.cfg.ZotAPIURL) // 예: http://zot:5000
	zotProxy.ModifyResponse = stripSecureCookiesOnHTTP
	kcProxy := mustProxy(s.cfg.KCProxyTarget) // 예: http://keycloak:8085 (relative-path /auth, 경로 보존)

	// 레지스트리/zot UI 보조 경로 → zot
	for _, p := range []string{"/v2/", "/oci/", "/zot/"} {
		mux.Handle(p, zotProxy)
	}
	// Keycloak (relative path /auth) → keycloak. 브라우저 authorize/token/jwks 모두 이 경로로.
	mux.Handle("/auth/", kcProxy)

	// 그 외 모든 경로 → 신규 UI(dist), SPA 폴백.
	mux.HandleFunc("/", s.serveUI)
}

// stripSecureCookiesOnHTTP: 공식 zot 은 OIDC state/PKCE 쿠키를 항상 Secure 로 내려준다.
// 평문 HTTP 접속이면 브라우저가 Secure 쿠키를 버려 콜백에서 "failed to get state" 가 나므로
// 프론트도어에서 Secure 속성만 제거한다(zot 무수정). HTTPS 접속이면 손대지 않는다.
func stripSecureCookiesOnHTTP(resp *http.Response) error {
	req := resp.Request
	if req == nil || req.TLS != nil || strings.EqualFold(req.Header.Get("X-Forwarded-Proto"), "https") {
		return nil
	}
	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) == 0 {
		return nil
	}
	resp.Header.Del("Set-Cookie")
	for _, c := range cookies {
		resp.Header.Add("Set-Cookie", stripSecure(c))
	}
	return nil
}

func stripSecure(cookie string) string {
	parts := strings.Split(cookie, ";")
	out := parts[:1]
	for _, p := range parts[1:] {
		a := strings.TrimSpace(p)
		switch {
		case strings.EqualFold(a, "Secure"):
			continue
		case strings.EqualFold(a, "SameSite=None"): // None 은 Secure 필수 → Lax 로
			p = " SameSite=Lax"
		}
		out = append(out, p)
	}
	return strings.Join(out, ";")
}

func (s *Server) serveUI(w http.ResponseWriter, r *http.Request) {
	dir := s.cfg.UIDir
	if dir == "" {
		http.Error(w, "UI not configured", http.StatusNotImplemented)
		return
	}
	// 경로 정규화 후 dist 내 파일 탐색, 없으면 index.html (SPA 라우팅)
	clean := filepath.Clean(r.URL.Path)
	fp := filepath.Join(dir, clean)
	if fi, err := os.Stat(fp); err == nil && !fi.IsDir() {
		http.ServeFile(w, r, fp)
		return
	}
	// 빌드 자산(/assets/*)인데 없으면 404. 그 외는 SPA 경로 — /artifact/x/10.0 처럼 버전의 점을 확장자로 오인하지 않게.
	if strings.HasPrefix(clean, "/assets/") {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, filepath.Join(dir, "index.html"))
}
