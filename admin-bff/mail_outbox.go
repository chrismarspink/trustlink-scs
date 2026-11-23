package main

// mail_outbox.go: 발송함 — "보내기"를 누르면 바로 보내지 않고 잠깐(기본 30초) 기다렸다가 보낸다.
// 그 사이에는 "보내기 취소"로 막을 수 있다. 이미 SMTP 로 나간 메일은 되돌릴 수 없기 때문이다.
//   - 현황 메일(mail_digest.go)과 고객 통지(custnotify.go)가 쓴다.
//   - 메일 내용(첨부 포함)은 메모리에만 둔다. 기다리는 중에 서버가 다시 시작되면 그 메일은 보내지 않고
//     "재시작으로 보내지 못함"으로 남긴다(몰래 나가거나 조용히 사라지지 않게).
//   - 기록(받는 사람·제목·결과)은 파일(mail-outbox.json, 최근 200건)에 남는다.

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type outboxItem struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`  // digest(현황 메일) / custnotify(고객 통지)
	Label      string   `json:"label"` // 화면 표시용(고객 이름 등)
	Ref        string   `json:"ref,omitempty"`
	Recipients []string `json:"recipients"`
	Subject    string   `json:"subject"`
	CreatedBy  string   `json:"createdBy"`
	CreatedAt  string   `json:"createdAt"`
	SendAt     string   `json:"sendAt"`
	Status     string   `json:"status"` // pending / sent / blocked / failed / cancelled / lost
	Sent       []string `json:"sent,omitempty"`
	Dropped    []string `json:"dropped,omitempty"`
	Error      string   `json:"error,omitempty"`
	DoneAt     string   `json:"doneAt,omitempty"`
	DoneBy     string   `json:"doneBy,omitempty"` // 취소한 사람
	Attach     int      `json:"attachments,omitempty"`
}

type outboxJob struct {
	content mailContent
	timer   *time.Timer
	onDone  func(it outboxItem) // 보낸 뒤·취소 뒤 호출(고객 통지 결과 반영)
}

var outbox = struct {
	sync.Mutex
	items  []outboxItem
	jobs   map[string]*outboxJob
	loaded bool
	path   string
}{jobs: map[string]*outboxJob{}}

const outboxKeep = 200

// 기다리는 시간(초): 0(바로), 10, 30, 60, 120
func outboxDelay(sec int) time.Duration {
	switch sec {
	case 0, 10, 30, 60, 120:
		return time.Duration(sec) * time.Second
	}
	return 30 * time.Second
}

func newOutboxID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "m-" + hex.EncodeToString(b)
}

// outboxLoad: 처음 한 번 기록을 읽는다. 기다리던 메일(pending)은 내용이 없으므로 lost 로 바꾼다.
func outboxLoad() { // outbox 잠근 채로
	if outbox.loaded {
		return
	}
	outbox.loaded = true
	outbox.path = filepath.Join(filepath.Dir(aiConfigPath()), "mail-outbox.json")
	_ = readJSONFile(outbox.path, &outbox.items)
	for i := range outbox.items {
		if outbox.items[i].Status == "pending" {
			outbox.items[i].Status, outbox.items[i].Error = "lost", "기다리는 중에 서버가 다시 시작되어 보내지 않았습니다 — 다시 보내 주세요"
			outbox.items[i].DoneAt = time.Now().UTC().Format(time.RFC3339)
		}
	}
}

func outboxSaveLocked() {
	if n := len(outbox.items); n > outboxKeep {
		// 오래된 끝난 항목부터 버린다(기다리는 것은 남김)
		keep := []outboxItem{}
		for i, it := range outbox.items {
			if it.Status == "pending" || i >= n-outboxKeep {
				keep = append(keep, it)
			}
		}
		outbox.items = keep
	}
	_ = writeJSONFile(outbox.path, outbox.items)
}

func outboxSet(id string, fn func(it *outboxItem)) (outboxItem, bool) { // outbox 잠근 채로
	for i := range outbox.items {
		if outbox.items[i].ID == id {
			fn(&outbox.items[i])
			return outbox.items[i], true
		}
	}
	return outboxItem{}, false
}

// enqueueMail: 발송함에 넣는다. delay 뒤에 보내고, 끝나면 onDone(선택)을 부른다.
func (s *Server) enqueueMail(kind, label, ref, actor string, to []string, subject string, content mailContent, delay time.Duration, onDone func(outboxItem)) outboxItem {
	now := time.Now().UTC()
	it := outboxItem{ID: newOutboxID(), Kind: kind, Label: label, Ref: ref, Recipients: to, Subject: subject, CreatedBy: actor,
		CreatedAt: now.Format(time.RFC3339), SendAt: now.Add(delay).Format(time.RFC3339), Status: "pending", Attach: len(content.Attachments)}
	outbox.Lock()
	outboxLoad()
	outbox.items = append(outbox.items, it)
	job := &outboxJob{content: content, onDone: onDone}
	outbox.jobs[it.ID] = job
	outboxSaveLocked()
	job.timer = time.AfterFunc(delay, func() { s.outboxSend(it.ID) })
	outbox.Unlock()
	return it
}

func (s *Server) outboxSend(id string) {
	outbox.Lock()
	job := outbox.jobs[id]
	it, ok := outboxSet(id, func(x *outboxItem) {})
	if job == nil || !ok || it.Status != "pending" {
		outbox.Unlock()
		return
	}
	delete(outbox.jobs, id)
	outbox.Unlock()

	sent, dropped, err := s.mail.SendRich(it.Recipients, it.Subject, job.content)
	status := "sent"
	switch {
	case err != nil:
		status = "failed"
	case len(sent) == 0:
		status = "blocked"
	}
	outbox.Lock()
	it, _ = outboxSet(id, func(x *outboxItem) {
		x.Status, x.Sent, x.Dropped, x.Error, x.DoneAt = status, sent, dropped, errString(err), time.Now().UTC().Format(time.RFC3339)
	})
	outboxSaveLocked()
	outbox.Unlock()
	_ = s.sor.append(SoREvent{Actor: it.CreatedBy, Action: "mail-send", Status: status, Subject: it.ID,
		Detail: map[string]any{"kind": it.Kind, "ref": it.Ref, "to": it.Recipients, "sent": sent, "dropped": dropped, "subject": it.Subject, "error": errString(err)}})
	if job.onDone != nil {
		job.onDone(it)
	}
}

// GET /api/mail/outbox — 기다리는 메일과 최근 기록(최근순)
func (s *Server) apiMailOutbox(w http.ResponseWriter, r *http.Request) {
	outbox.Lock()
	outboxLoad()
	items := append([]outboxItem(nil), outbox.items...)
	outbox.Unlock()
	sort.SliceStable(items, func(i, j int) bool { return items[i].CreatedAt > items[j].CreatedAt })
	if len(items) > 50 {
		items = items[:50]
	}
	writeJSON(w, 200, map[string]any{"items": items, "now": time.Now().UTC().Format(time.RFC3339)})
}

// DELETE /api/mail/outbox/{id} — 보내기 취소(아직 기다리는 중일 때만)
func (s *Server) apiMailOutboxCancel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	actor := w.Header().Get("X-User")
	outbox.Lock()
	outboxLoad()
	job := outbox.jobs[id]
	cur, ok := outboxSet(id, func(x *outboxItem) {})
	if !ok {
		outbox.Unlock()
		writeJSON(w, 404, map[string]string{"error": "발송함에 없는 메일"})
		return
	}
	if cur.Status != "pending" || job == nil || !job.timer.Stop() {
		outbox.Unlock()
		writeJSON(w, 409, map[string]string{"error": "이미 보냈거나 처리된 메일이라 취소할 수 없습니다"})
		return
	}
	delete(outbox.jobs, id)
	it, _ := outboxSet(id, func(x *outboxItem) {
		x.Status, x.DoneAt, x.DoneBy = "cancelled", time.Now().UTC().Format(time.RFC3339), actor
	})
	outboxSaveLocked()
	outbox.Unlock()
	_ = s.sor.append(SoREvent{Actor: actor, Action: "mail-cancel", Subject: id, Detail: map[string]any{"kind": it.Kind, "ref": it.Ref, "to": it.Recipients, "subject": it.Subject}})
	if job.onDone != nil {
		job.onDone(it)
	}
	writeJSON(w, 200, it)
}
