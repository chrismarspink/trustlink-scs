package main

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 큰 SBOM 은 multipart(POST), 작은 것은 기존 JSON(PUT).
func TestDTUploadBOMMultipart(t *testing.T) {
	var method, ctype, name, bom string
	dt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, ctype = r.Method, r.Header.Get("Content-Type")
		if strings.HasPrefix(ctype, "multipart/") {
			_ = r.ParseMultipartForm(1 << 20)
			name = r.FormValue("projectName")
			f, _, _ := r.FormFile("bom")
			b, _ := io.ReadAll(f)
			bom = string(b)
		}
		w.Write([]byte(`{"token":"t1"}`))
	}))
	defer dt.Close()
	s := &Server{cfg: Config{DTBaseURL: dt.URL}, http: dt.Client()}
	s.dtKey.Store("k")
	old := dtMultipartLimit
	dtMultipartLimit = 10
	defer func() { dtMultipartLimit = old }()
	tok, err := s.dtUploadBOM("p", "1.0", base64.StdEncoding.EncodeToString([]byte(`{"bomFormat":"CycloneDX"}`)))
	if err != nil || tok != "t1" || method != "POST" || !strings.HasPrefix(ctype, "multipart/") || name != "p" || !strings.Contains(bom, "CycloneDX") {
		t.Fatalf("multipart: %v %s %s %s %q", err, tok, method, ctype, bom)
	}
	dtMultipartLimit = old
	if _, err := s.dtUploadBOM("p", "1.0", "e30="); err != nil || method != "PUT" || ctype != "application/json" {
		t.Fatalf("작은 SBOM 은 JSON: %v %s %s", err, method, ctype)
	}
}
