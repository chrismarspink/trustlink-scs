package main

// customer_status.go: 고객(회사) 사용/중지와 로고.
//   - 중지 사유: 폐업·관계 종료·계약 해지·기타. 중지된 회사는 고객 통지·만료 알림·내 제품에서 빠진다.
//     계정·제품 권한은 자동으로 바꾸지 않는다(필요하면 관리자가 따로) — 화면에서 남은 권한을 알려 준다.
//   - 로고: PNG·JPEG·WebP·GIF 만(SVG 는 스크립트를 품을 수 있어 받지 않음), 512KB 이하, 서버 데이터(logos/)에만 둔다.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var custDisableReasons = map[string]string{"closed": "폐업", "ended": "관계 종료", "terminated": "계약 해지", "other": "기타"}

// activeCustomers: 사용 중인 회사만.
func activeCustomers(cs []Customer) []Customer {
	out := make([]Customer, 0, len(cs))
	for _, c := range cs {
		if !c.Disabled {
			out = append(out, c)
		}
	}
	return out
}

func (c *custStore) logoDir() string { return filepath.Join(filepath.Dir(c.path), "logos") }

// update: 고객 한 명을 잠근 채 바꾸고 저장.
func (c *custStore) updateOne(id string, fn func(x *Customer)) (Customer, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.d.Customers {
		if c.d.Customers[i].ID == id {
			fn(&c.d.Customers[i])
			return c.d.Customers[i], true, c.saveLocked()
		}
	}
	return Customer{}, false, nil
}

// PUT /api/customers/{id}/status {enabled, reason, note}
func (s *Server) apiCustomerStatus(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled bool   `json:"enabled"`
		Reason  string `json:"reason"`
		Note    string `json:"note"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<14)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "요청 형식 오류"})
		return
	}
	if !in.Enabled && custDisableReasons[in.Reason] == "" {
		writeJSON(w, 400, map[string]string{"error": "중지 사유를 고르세요(폐업·관계 종료·계약 해지·기타)"})
		return
	}
	actor := w.Header().Get("X-User")
	c := s.cust()
	x, ok, err := c.updateOne(r.PathValue("id"), func(x *Customer) {
		if in.Enabled {
			x.Disabled, x.DisabledReason, x.DisabledNote, x.DisabledAt, x.DisabledBy = false, "", "", "", ""
			return
		}
		x.Disabled, x.DisabledReason, x.DisabledNote = true, in.Reason, truncate(strings.TrimSpace(in.Note), 300)
		x.DisabledAt, x.DisabledBy = c.now().UTC().Format(time.RFC3339), actor
	})
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "고객 없음"})
		return
	}
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	action := map[bool]string{true: "customer-enable", false: "customer-disable"}[in.Enabled]
	_ = s.sor.append(SoREvent{Actor: actor, Action: action, Subject: x.ID, Detail: map[string]any{"name": x.Name, "reason": in.Reason, "note": x.DisabledNote}})
	writeJSON(w, 200, x)
}

var logoTypes = map[string]string{"image/png": ".png", "image/jpeg": ".jpg", "image/webp": ".webp", "image/gif": ".gif"}
var logoFileRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.(png|jpg|webp|gif)$`)

// PUT /api/customers/{id}/logo (본문 = 이미지 그대로)
func (s *Server) apiCustomerLogoPut(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c := s.cust()
	if _, ok := c.find(id); !ok || !logoFileRe.MatchString(id+".png") {
		writeJSON(w, 404, map[string]string{"error": "고객 없음"})
		return
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 512<<10+1))
	if err != nil || len(b) == 0 || len(b) > 512<<10 {
		writeJSON(w, 400, map[string]string{"error": "로고는 512KB 이하 이미지여야 합니다"})
		return
	}
	ext := logoTypes[http.DetectContentType(b)] // 내용으로 판별(보낸 Content-Type 은 믿지 않음)
	if ext == "" {
		writeJSON(w, 400, map[string]string{"error": "PNG·JPEG·WebP·GIF 만 받습니다(SVG 는 안 됨)"})
		return
	}
	dir := c.logoDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	for e := range strings.SplitSeq(".png .jpg .webp .gif", " ") { // 이전 형식 파일 정리
		_ = os.Remove(filepath.Join(dir, id+e))
	}
	if err := os.WriteFile(filepath.Join(dir, id+ext), b, 0o640); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	sum := sha256.Sum256(b)
	x, _, err := c.updateOne(id, func(x *Customer) { x.Logo = id + ext + "?v=" + hex.EncodeToString(sum[:4]) })
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_ = s.sor.append(SoREvent{Actor: w.Header().Get("X-User"), Action: "customer-logo", Subject: id, Detail: map[string]any{"name": x.Name, "bytes": len(b)}})
	writeJSON(w, 200, x)
}

// DELETE /api/customers/{id}/logo
func (s *Server) apiCustomerLogoDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c := s.cust()
	x, ok, err := c.updateOne(id, func(x *Customer) { x.Logo = "" })
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "고객 없음"})
		return
	}
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	for e := range strings.SplitSeq(".png .jpg .webp .gif", " ") {
		_ = os.Remove(filepath.Join(c.logoDir(), id+e))
	}
	writeJSON(w, 200, x)
}

// GET /api/customer-logo/{file} — 로그인한 사용자(고객 포함)가 볼 수 있다. 로고는 민감 정보가 아니다.
func (s *Server) apiCustomerLogoGet(w http.ResponseWriter, r *http.Request) {
	f := r.PathValue("file")
	if !logoFileRe.MatchString(f) {
		http.NotFound(w, r)
		return
	}
	b, err := os.ReadFile(filepath.Join(s.cust().logoDir(), f))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", http.DetectContentType(b))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	w.Header().Set("Cache-Control", "private, max-age=86400")
	_, _ = w.Write(b)
}
