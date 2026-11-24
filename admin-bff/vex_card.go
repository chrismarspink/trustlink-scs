package main

// vex_card.go: 권고문 요약 카드 — 영어 권고문을 한국어로 정리한 것(AI 생성).
// 취약점마다 한 번만 만들어 서버 데이터(vex-cards/)에 두고, 그 취약점이 있는 모든 제품·버전의 판정 초안이 같이 쓴다.
// 권고문 내용이 바뀌면(설명 해시가 달라지면) 다시 만든다.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type vulnCard struct {
	VulnID     string `json:"vulnId"`
	Summary    string `json:"summary"`    // 무엇이 문제이고 어떤 피해가 나는지
	Condition  string `json:"condition"`  // 악용에 필요한 조건
	Workaround string `json:"workaround"` // 권고문에 적힌 임시 완화
	Model      string `json:"model"`
	At         string `json:"at"`
	ElapsedMs  int64  `json:"elapsedMs"`
}

const cardTask = `아래 취약점 권고문(V3)을 한국어로 정리한다.
- summary: 무엇이 문제이고 악용되면 어떤 피해가 나는지 한 문장(90자 안팎).
- condition: 악용에 필요한 조건(설정·기능·공격자 위치) 한 문장. 권고문에 없으면 빈 문자열.
- workaround: 권고문에 적힌 임시 완화책 한 문장. 권고문에 없으면 빈 문자열.
- 권고문에 없는 버전·수치·설정 값을 지어내지 않는다. 사실 ID([V3] 같은 표시)는 붙이지 않는다.`

var cardSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"summary":    map[string]any{"type": "string", "maxLength": 150},
		"condition":  map[string]any{"type": "string", "maxLength": 100},
		"workaround": map[string]any{"type": "string", "maxLength": 100},
	},
	"required": []string{"summary", "condition", "workaround"},
}

var cardUnsafe = regexp.MustCompile(`[^A-Za-z0-9._-]`)

func cardDir() string { return filepath.Join(filepath.Dir(aiConfigPath()), "vex-cards") }

// 파일 이름: 취약점 ID + 설명 해시 앞 8자(권고문이 바뀌면 새 카드)
func cardPath(f dtFindingFull) string {
	v := f.Vulnerability
	return filepath.Join(cardDir(), cardUnsafe.ReplaceAllString(v.VulnID, "_")+"-"+sha256hex([]byte(v.Description))[:8]+".json")
}

func cardGet(f dtFindingFull) *vulnCard {
	var c vulnCard
	if readJSONFile(cardPath(f), &c) != nil || c.VulnID == "" {
		return nil
	}
	return &c
}

func cardFacts(f dtFindingFull) []aiFact {
	v := f.Vulnerability
	t := "취약점: " + v.VulnID
	if v.CweID > 0 {
		t += " (CWE-" + itoa(v.CweID) + " " + v.CweName + ")"
	}
	return []aiFact{{ID: "V1", Text: t}, {ID: "V3", Text: "권고문 설명: " + truncate(v.Description, 600), Untrusted: true}}
}

var cardMu sync.Mutex // 같은 카드를 두 번 만들지 않게

// cardMake: 카드를 만들어 저장한다(이미 있으면 그것). 로컬 LLM 한 번 호출.
func (s *Server) cardMake(f dtFindingFull) (*vulnCard, error) {
	cardMu.Lock()
	defer cardMu.Unlock()
	if c := cardGet(f); c != nil {
		return c, nil
	}
	return s.cardBuild(f, true)
}

func (s *Server) cardBuild(f dtFindingFull, save bool) (*vulnCard, error) {
	var c vulnCard
	meta, err := s.aiDraftOpt("vex", "ko", cardFacts(f), cardTask, cardSchema, 180, &c, true)
	if err != nil {
		return nil, err
	}
	// 권고문에 없는 버전 표기가 들어간 칸은 비운다(지어낸 버전 방지)
	desc := f.Vulnerability.Description
	clean := func(t string) string {
		for _, v := range verLike.FindAllString(t, -1) {
			if !strings.Contains(desc, v) {
				return ""
			}
		}
		return strings.TrimSpace(citeTag.ReplaceAllString(t, "")) // 모델이 붙인 [V3] 같은 표시는 뗀다(초안이 따로 붙인다)
	}
	c.Summary, c.Condition, c.Workaround = clean(c.Summary), clean(c.Condition), clean(c.Workaround)
	c.VulnID, c.Model, c.At, c.ElapsedMs = f.Vulnerability.VulnID, meta.Model, time.Now().UTC().Format(time.RFC3339), meta.ElapsedMs
	if save && os.MkdirAll(cardDir(), 0o750) == nil {
		_ = writeJSONFile(cardPath(f), c)
	}
	return &c, nil
}

// ---------- 뒤에서 만들기(사람이 기다리지 않게) ----------

var cardQ = struct {
	sync.Mutex
	items   []dtFindingFull
	queued  map[string]bool
	running bool
}{queued: map[string]bool{}}

const cardQueueMax = 300

// cardQueue: 카드가 없는 취약점을 줄에 넣는다. 사람이 요청한 AI 작업이 있으면 그 뒤로 미룬다.
func (s *Server) cardQueue(f dtFindingFull) {
	if !aiEnabledFor("vex") || f.Vulnerability.Description == "" {
		return
	}
	p := cardPath(f)
	cardQ.Lock()
	defer cardQ.Unlock()
	if cardQ.queued[p] || len(cardQ.items) >= cardQueueMax {
		return
	}
	cardQ.queued[p] = true
	cardQ.items = append(cardQ.items, f)
	if !cardQ.running {
		cardQ.running = true
		go s.cardWorker()
	}
}

func (s *Server) cardWorker() {
	for {
		cardQ.Lock()
		if len(cardQ.items) == 0 {
			cardQ.running = false
			cardQ.Unlock()
			return
		}
		f := cardQ.items[0]
		cardQ.items = cardQ.items[1:]
		cardQ.Unlock()
		for aiWaiting.Load() > 0 { // 사람이 요청한 작업 먼저
			time.Sleep(2 * time.Second)
		}
		_, _ = s.cardMake(f)
		cardQ.Lock()
		delete(cardQ.queued, cardPath(f))
		cardQ.Unlock()
	}
}

func cardQueueLen() int {
	cardQ.Lock()
	defer cardQ.Unlock()
	return len(cardQ.items)
}
