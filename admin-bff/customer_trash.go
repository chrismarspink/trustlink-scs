package main

// customer_trash.go: 고객 휴지통(되살리기·완전 삭제)과 고객 정보 백업·복원.
//   - 삭제는 표시만(customers.go apiCustomerDelete). 휴지통에서 되살리거나, 이름을 그대로 입력해 확인한 뒤에만 완전 삭제.
//   - 백업: 고객(휴지통 포함)·제품 버전 정책·설정·로고를 JSON 파일 하나로 받는다.
//   - 복원: 그 파일을 올리면 지금 상태를 서버에 먼저 따로 저장해 두고(되돌릴 수 있게) 고객·정책·설정·로고를 바꾼다.
//     통지 이력·만료 알림 기록은 건드리지 않는다.

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// POST /api/customers/{id}/restore — 휴지통에서 되살리기
func (s *Server) apiCustomerUndelete(w http.ResponseWriter, r *http.Request) {
	c := s.cust()
	x, ok, err := c.updateOne(r.PathValue("id"), func(x *Customer) { x.Deleted, x.DeletedAt, x.DeletedBy = false, "", "" })
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "고객 없음"})
		return
	}
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_ = s.sor.append(SoREvent{Actor: w.Header().Get("X-User"), Action: "customer-undelete", Subject: x.ID, Detail: map[string]any{"name": x.Name}})
	writeJSON(w, 200, x)
}

// DELETE /api/customers/{id}/purge {confirm: "<고객 이름 그대로>"} — 휴지통에 있는 고객만 완전 삭제
func (s *Server) apiCustomerPurge(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Confirm string `json:"confirm"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&in)
	id := r.PathValue("id")
	c := s.cust()
	c.mu.Lock()
	idx := -1
	for i, x := range c.d.Customers {
		if x.ID == id {
			idx = i
		}
	}
	if idx < 0 {
		c.mu.Unlock()
		writeJSON(w, 404, map[string]string{"error": "고객 없음"})
		return
	}
	x := c.d.Customers[idx]
	if !x.Deleted {
		c.mu.Unlock()
		writeJSON(w, 409, map[string]string{"error": "먼저 삭제(휴지통으로)해야 완전 삭제할 수 있습니다"})
		return
	}
	if strings.TrimSpace(in.Confirm) != x.Name {
		c.mu.Unlock()
		writeJSON(w, 400, map[string]string{"error": "확인용으로 고객 이름을 그대로 입력하세요"})
		return
	}
	c.d.Customers = append(c.d.Customers[:idx:idx], c.d.Customers[idx+1:]...)
	err := c.saveLocked()
	c.mu.Unlock()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	for e := range strings.SplitSeq(".png .jpg .webp .gif", " ") {
		_ = os.Remove(filepath.Join(c.logoDir(), id+e))
	}
	_ = s.sor.append(SoREvent{Actor: w.Header().Get("X-User"), Action: "customer-purge", Subject: id, Detail: map[string]any{"name": x.Name}})
	writeJSON(w, 200, map[string]any{"purged": id})
}

type custBackup struct {
	Format     string                 `json:"format"` // trustlink-customers
	Version    int                    `json:"version"`
	ExportedAt string                 `json:"exportedAt"`
	ExportedBy string                 `json:"exportedBy,omitempty"`
	Customers  []Customer             `json:"customers"`
	Products   map[string][]VerPolicy `json:"products"`
	Settings   custSettings           `json:"settings"`
	Logos      map[string]string      `json:"logos,omitempty"` // 파일 이름 → base64
}

// GET /api/customers-backup — 내려받기(JSON)
func (s *Server) apiCustomersBackup(w http.ResponseWriter, r *http.Request) {
	c := s.cust()
	d := c.snapshot()
	b := custBackup{Format: "trustlink-customers", Version: 1, ExportedAt: c.now().UTC().Format(time.RFC3339), ExportedBy: w.Header().Get("X-User"),
		Customers: d.Customers, Products: d.Products, Settings: d.Settings, Logos: map[string]string{}}
	for _, x := range d.Customers {
		if f := strings.SplitN(x.Logo, "?", 2)[0]; f != "" && logoFileRe.MatchString(f) {
			if raw, err := os.ReadFile(filepath.Join(c.logoDir(), f)); err == nil {
				b.Logos[f] = base64.StdEncoding.EncodeToString(raw)
			}
		}
	}
	_ = s.sor.append(SoREvent{Actor: w.Header().Get("X-User"), Action: "customer-backup", Detail: map[string]any{"customers": len(b.Customers), "logos": len(b.Logos)}})
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="trustlink-customers-`+c.now().Format("20060102-1504")+`.json"`)
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	_ = enc.Encode(b)
}

// POST /api/customers-restore (본문 = 백업 JSON) — 지금 상태를 먼저 서버에 따로 저장하고 바꾼다.
func (s *Server) apiCustomersRestore(w http.ResponseWriter, r *http.Request) {
	var b custBackup
	if err := json.NewDecoder(io.LimitReader(r.Body, 32<<20)).Decode(&b); err != nil || b.Format != "trustlink-customers" || b.Version != 1 {
		writeJSON(w, 400, map[string]string{"error": "TrustLink 고객 백업 파일이 아닙니다"})
		return
	}
	seen := map[string]bool{}
	for i := range b.Customers {
		if err := normalizeCustomer(&b.Customers[i]); err != nil {
			writeJSON(w, 400, map[string]string{"error": "고객 " + b.Customers[i].Name + ": " + err.Error()})
			return
		}
		if seen[b.Customers[i].ID] {
			writeJSON(w, 400, map[string]string{"error": "같은 ID 가 두 번 있음: " + b.Customers[i].ID})
			return
		}
		seen[b.Customers[i].ID] = true
	}
	logos := map[string][]byte{}
	for f, enc := range b.Logos {
		raw, err := base64.StdEncoding.DecodeString(enc)
		if !logoFileRe.MatchString(f) || err != nil || len(raw) > 512<<10 || logoTypes[http.DetectContentType(raw)] == "" {
			writeJSON(w, 400, map[string]string{"error": "로고 파일이 올바르지 않음: " + f})
			return
		}
		logos[f] = raw
	}
	c := s.cust()
	actor := w.Header().Get("X-User")
	c.mu.Lock()
	// 되돌릴 수 있게 지금 상태를 먼저 저장
	prev, _ := json.MarshalIndent(c.d, "", "  ")
	keep := c.path + ".before-restore-" + c.now().UTC().Format("20060102-150405")
	if err := os.WriteFile(keep, prev, 0o600); err != nil {
		c.mu.Unlock()
		writeJSON(w, 500, map[string]string{"error": "복원 전 사본 저장 실패: " + err.Error()})
		return
	}
	c.d.Customers, c.d.Settings = b.Customers, b.Settings
	if b.Products != nil {
		c.d.Products = b.Products
	}
	err := c.saveLocked()
	c.mu.Unlock()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_ = os.MkdirAll(c.logoDir(), 0o750)
	for f, raw := range logos {
		_ = os.WriteFile(filepath.Join(c.logoDir(), f), raw, 0o640)
	}
	_ = s.sor.append(SoREvent{Actor: actor, Action: "customer-restore", Detail: map[string]any{"customers": len(b.Customers), "logos": len(logos),
		"exportedAt": b.ExportedAt, "previousCopy": filepath.Base(keep)}})
	writeJSON(w, 200, map[string]any{"customers": len(b.Customers), "logos": len(logos), "previousCopy": filepath.Base(keep)})
}
