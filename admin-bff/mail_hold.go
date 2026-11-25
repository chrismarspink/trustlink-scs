package main

// mail_hold.go: 고객에게 자동으로 나가던 메일(VEX 발행 통보·계약 만료 안내)을 바로 보내지 않고 승인을 기다리게 한다.
//
//   만들어짐(waiting) → 관리자가 승인 → 발송함에서 잠깐 대기(취소 가능) → 발송
//                     → 반려 → 보내지 않고 사유를 남김
//
// 내부로 가는 메일(영업·지원 담당, 개발자 통보)은 지금처럼 바로 나간다 — 고객에게 가는 것만 붙든다.
// 내용(본문·로고)은 서버 데이터에 두어 BFF 가 다시 떠도 승인 대기가 남는다.
//
//   GET  /api/mail/hold               기다리는 메일 + 최근 처리 기록
//   GET  /api/mail/hold/{id}/preview  메일 내용 미리보기(HTML)
//   POST /api/mail/hold/{id}/approve  {delay} → 발송함으로
//   POST /api/mail/hold/{id}/reject   {reason}

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type mailHold struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"` // vex(VEX 발행 통보) / expiry(계약 만료 안내)
	Label      string   `json:"label"`
	Ref        string   `json:"ref,omitempty"`
	Recipients []string `json:"recipients"`
	Subject    string   `json:"subject"`
	CreatedAt  string   `json:"createdAt"`
	Status     string   `json:"status"` // waiting / approved / rejected
	DoneAt     string   `json:"doneAt,omitempty"`
	DoneBy     string   `json:"doneBy,omitempty"`
	Reason     string   `json:"reason,omitempty"`
	OutboxID   string   `json:"outboxId,omitempty"`
}

const holdKeepDone = 60 // 처리한 기록은 최근 이만큼만(기다리는 것은 지우지 않는다)

var (
	holdIDRe = regexp.MustCompile(`^h-[0-9a-f]{12}$`)
	holds    = struct {
		sync.Mutex
		path  string
		items []mailHold
	}{}
)

func holdPath() string { return filepath.Join(filepath.Dir(aiConfigPath()), "mail-hold.json") }
func holdBodyPath(id string) string {
	return filepath.Join(filepath.Dir(aiConfigPath()), "mail-hold-body", id+".json")
}

func holdLoad() { // holds 잠근 채로
	if p := holdPath(); holds.path != p {
		holds.path, holds.items = p, nil
		if b, err := os.ReadFile(p); err == nil {
			_ = json.Unmarshal(b, &holds.items)
		}
	}
}

func holdSave() { // holds 잠근 채로
	done, drop := 0, map[string]bool{}
	for i := len(holds.items) - 1; i >= 0; i-- { // 최근 것부터 세어 오래된 처리 기록을 버린다
		if h := holds.items[i]; h.Status != "waiting" {
			if done++; done > holdKeepDone {
				drop[h.ID] = true
				_ = os.Remove(holdBodyPath(h.ID))
			}
		}
	}
	kept := make([]mailHold, 0, len(holds.items))
	for _, h := range holds.items {
		if !drop[h.ID] {
			kept = append(kept, h)
		}
	}
	holds.items = kept
	b, _ := json.MarshalIndent(holds.items, "", " ")
	_ = os.MkdirAll(filepath.Dir(holds.path), 0o750)
	tmp := holds.path + ".tmp"
	if os.WriteFile(tmp, b, 0o640) == nil {
		_ = os.Rename(tmp, holds.path)
	}
}

// holdMail: 고객에게 갈 메일을 승인 대기로 둔다.
func (s *Server) holdMail(kind, label, ref string, to []string, subject string, content mailContent) mailHold {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	h := mailHold{ID: "h-" + hex.EncodeToString(b), Kind: kind, Label: label, Ref: ref, Recipients: to, Subject: subject,
		CreatedAt: time.Now().UTC().Format(time.RFC3339), Status: "waiting"}
	if body, err := json.Marshal(content); err == nil {
		_ = os.MkdirAll(filepath.Dir(holdBodyPath(h.ID)), 0o750)
		_ = os.WriteFile(holdBodyPath(h.ID), body, 0o640)
	}
	holds.Lock()
	holdLoad()
	holds.items = append(holds.items, h)
	holdSave()
	holds.Unlock()
	if s.sor != nil {
		_ = s.sor.append(SoREvent{Actor: "trustlink", Action: "mail-hold", Subject: h.ID, Detail: map[string]any{"kind": kind, "ref": ref, "to": to, "subject": subject}})
	}
	return h
}

func holdContent(id string) (mailContent, bool) {
	var c mailContent
	b, err := os.ReadFile(holdBodyPath(id))
	if err != nil || json.Unmarshal(b, &c) != nil {
		return c, false
	}
	return c, true
}

func holdWaiting() []mailHold {
	holds.Lock()
	defer holds.Unlock()
	holdLoad()
	out := []mailHold{}
	for _, h := range holds.items {
		if h.Status == "waiting" {
			out = append(out, h)
		}
	}
	return out
}

// holdTake: 기다리는 메일을 처리 상태로 바꾼다(한 번만).
func holdTake(id, status, by, reason string) (mailHold, bool) {
	holds.Lock()
	defer holds.Unlock()
	holdLoad()
	for i := range holds.items {
		if holds.items[i].ID == id && holds.items[i].Status == "waiting" {
			holds.items[i].Status, holds.items[i].DoneBy, holds.items[i].Reason = status, by, reason
			holds.items[i].DoneAt = time.Now().UTC().Format(time.RFC3339)
			holdSave()
			return holds.items[i], true
		}
	}
	return mailHold{}, false
}

// GET /api/mail/hold
func (s *Server) apiMailHold(w http.ResponseWriter, r *http.Request) {
	holds.Lock()
	holdLoad()
	items := append([]mailHold(nil), holds.items...)
	holds.Unlock()
	sort.SliceStable(items, func(i, j int) bool {
		if (items[i].Status == "waiting") != (items[j].Status == "waiting") {
			return items[i].Status == "waiting"
		}
		return items[i].CreatedAt > items[j].CreatedAt
	})
	if len(items) > 40 {
		items = items[:40]
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

// GET /api/mail/hold/{id}/preview
func (s *Server) apiMailHoldPreview(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, ok := holdContent(id)
	if !holdIDRe.MatchString(id) || !ok {
		http.Error(w, "메일 내용을 찾지 못했습니다", 404)
		return
	}
	h := c.HTML
	if h == "" {
		h = "<pre style=\"font:14px/1.6 sans-serif;white-space:pre-wrap\">" + html.EscapeString(c.Text) + "</pre>"
	}
	if len(c.Inline) > 0 {
		h = strings.Replace(h, "cid:"+mailLogoCID, "data:"+c.Inline[0].Type+";base64,"+b64(c.Inline[0].Data), 1)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; img-src data:; style-src 'unsafe-inline'")
	_, _ = io.WriteString(w, h)
}

var holdOutboxKind = map[string]string{"vex": "notify", "expiry": "expiry"}

// POST /api/mail/hold/{id}/approve {delay}
func (s *Server) apiMailHoldApprove(w http.ResponseWriter, r *http.Request) {
	id, actor := r.PathValue("id"), w.Header().Get("X-User")
	var in struct {
		Delay int `json:"delay"`
	}
	in.Delay = 30
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<10)).Decode(&in)
	c, ok := holdContent(id)
	if !holdIDRe.MatchString(id) || !ok {
		writeJSON(w, 404, map[string]string{"error": "메일 내용을 찾지 못했습니다"})
		return
	}
	if !s.mail.Configured() {
		writeJSON(w, 409, map[string]string{"error": "메일 서버가 설정되지 않아 보낼 수 없습니다"})
		return
	}
	h, ok := holdTake(id, "approved", actor, "")
	if !ok {
		writeJSON(w, 409, map[string]string{"error": "이미 처리된 메일입니다"})
		return
	}
	it := s.enqueueMail(holdOutboxKind[h.Kind], h.Label, h.Ref, actor, h.Recipients, h.Subject, c, outboxDelay(in.Delay), nil)
	holds.Lock()
	for i := range holds.items {
		if holds.items[i].ID == id {
			holds.items[i].OutboxID = it.ID
			h = holds.items[i]
		}
	}
	holdSave()
	holds.Unlock()
	_ = s.sor.append(SoREvent{Actor: actor, Action: "mail-hold-approve", Subject: id, Detail: map[string]any{"kind": h.Kind, "ref": h.Ref, "to": h.Recipients, "outbox": it.ID}})
	writeJSON(w, 200, map[string]any{"hold": h, "outbox": it})
}

// POST /api/mail/hold/{id}/reject {reason}
func (s *Server) apiMailHoldReject(w http.ResponseWriter, r *http.Request) {
	id, actor := r.PathValue("id"), w.Header().Get("X-User")
	var in struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&in)
	h, ok := holdTake(id, "rejected", actor, truncate(strings.TrimSpace(in.Reason), 200))
	if !ok {
		writeJSON(w, 409, map[string]string{"error": "이미 처리됐거나 없는 메일입니다"})
		return
	}
	_ = os.Remove(holdBodyPath(id))
	_ = s.sor.append(SoREvent{Actor: actor, Action: "mail-hold-reject", Subject: id, Detail: map[string]any{"kind": h.Kind, "ref": h.Ref, "to": h.Recipients, "reason": h.Reason}})
	writeJSON(w, 200, h)
}
