package main

// SoR (System of Record) — 발급·폐기·서명·바인딩 행위의 append-only 감사 기록.
// 단순·내구성 우선: JSONL 파일에 한 줄씩 추가(파일 락 + fsync). 누가·언제·무엇을(§7).
// 외부 의존성 없이 stdlib 만 사용.

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SoREvent — 한 건의 감사 이벤트. action: issue|revoke|sign|bind.
type SoREvent struct {
	Time     string         `json:"time"`
	Actor    string         `json:"actor"`
	Action   string         `json:"action"`
	Serial   string         `json:"serial,omitempty"`
	Subject  string         `json:"subject,omitempty"`
	NotAfter string         `json:"notAfter,omitempty"`
	Repo     string         `json:"repo,omitempty"`
	Tag      string         `json:"tag,omitempty"`
	Status   string         `json:"status,omitempty"`
	Detail   map[string]any `json:"detail,omitempty"`
}

type SoR struct {
	mu   sync.Mutex
	path string
}

func newSoR(path string) *SoR { return &SoR{path: path} }

// append: 이벤트 1건을 JSONL 로 추가(생성·append·fsync). Time 미설정 시 현재시각.
func (s *SoR) append(ev SoREvent) error {
	if ev.Time == "" {
		ev.Time = time.Now().UTC().Format(time.RFC3339)
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// list: 전체 이벤트(시간순). 파일 없으면 빈 슬라이스.
func (s *SoR) list() ([]SoREvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return []SoREvent{}, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []SoREvent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		b := sc.Bytes()
		if len(b) == 0 {
			continue
		}
		var ev SoREvent
		if json.Unmarshal(b, &ev) == nil {
			out = append(out, ev)
		}
	}
	return out, sc.Err()
}
