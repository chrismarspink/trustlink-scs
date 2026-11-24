package main

// vex_bench.go: VEX 판정 방식별 속도 측정(관리자). 실제 취약점 몇 건을 방식마다 돌려 걸린 시간·토큰·판정을 나란히 남긴다.
// 원장에 기록하지 않고 초안도 저장하지 않는다(측정 전용).

import (
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"time"
)

type vexBenchRow struct {
	Variant   string  `json:"variant"`
	VulnID    string  `json:"vulnId"`
	Component string  `json:"component"`
	Ms        int64   `json:"ms"`
	PromptTok int     `json:"promptTok"`
	EvalTok   int     `json:"evalTok"`  // 실제로 읽은 입력 토큰
	CacheTok  int     `json:"cacheTok"` // 접두 캐시로 건너뛴 입력 토큰
	GenTok    int     `json:"genTok"`
	PromptMs  float64 `json:"promptMs"`
	GenMs     float64 `json:"genMs"`
	Status    string  `json:"status,omitempty"`
	Just      string  `json:"justification,omitempty"`
	Conf      string  `json:"confidence,omitempty"`
	Text      string  `json:"text,omitempty"`
	Warn      int     `json:"warnings,omitempty"`
	Error     string  `json:"error,omitempty"`
}

var vexBench = struct {
	sync.Mutex
	Running bool          `json:"running"`
	Started string        `json:"started,omitempty"`
	Current string        `json:"current,omitempty"`
	Rows    []vexBenchRow `json:"rows"`
}{}

const vexBenchCtx = "이 제품은 해당 구성요소를 내부망에서만 쓰고, 문제의 기능(모듈)은 설정에서 꺼 두었다."

var vexBenchVariants = []string{"full", "full-tf", "slim-raw", "card", "ctx-card", "ctx-raw", "rule"}

// POST /api/ai-perf/vex-bench {project, n, variants[]} · GET → 진행·결과
func (s *Server) apiVexBench(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		vexBench.Lock()
		defer vexBench.Unlock()
		writeJSON(w, 200, map[string]any{"running": vexBench.Running, "started": vexBench.Started, "current": vexBench.Current, "rows": vexBench.Rows})
		return
	}
	var in struct {
		Project  string   `json:"project"`
		N        int      `json:"n"`
		Variants []string `json:"variants"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&in); err != nil || !dtUUIDRe.MatchString(in.Project) {
		writeJSON(w, 400, map[string]string{"error": "project(DT UUID) 필수"})
		return
	}
	if in.N <= 0 || in.N > 12 {
		in.N = 4
	}
	if len(in.Variants) == 0 {
		in.Variants = vexBenchVariants
	}
	fs, err := s.projectFindings(in.Project)
	if err != nil || len(fs) == 0 {
		writeJSON(w, 502, map[string]string{"error": "취약점을 읽지 못했습니다"})
		return
	}
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Vulnerability.VulnID < fs[j].Vulnerability.VulnID })
	picks := []dtFindingFull{}
	for i := 0; i < in.N; i++ { // 고르게 뽑는다
		picks = append(picks, fs[i*len(fs)/in.N])
	}
	vexBench.Lock()
	if vexBench.Running {
		vexBench.Unlock()
		writeJSON(w, 409, map[string]string{"error": "측정이 진행 중입니다"})
		return
	}
	vexBench.Running, vexBench.Started, vexBench.Rows = true, time.Now().UTC().Format(time.RFC3339), nil
	vexBench.Unlock()
	go func() {
		defer func() {
			_ = recover()
			vexBench.Lock()
			vexBench.Running, vexBench.Current = false, ""
			vexBench.Unlock()
		}()
		for _, v := range in.Variants {
			for _, f := range picks {
				vexBench.Lock()
				vexBench.Current = v + " · " + f.Vulnerability.VulnID
				vexBench.Unlock()
				for aiWaiting.Load() > 0 {
					time.Sleep(2 * time.Second)
				}
				row := s.vexBenchOne(v, f)
				vexBench.Lock()
				vexBench.Rows = append(vexBench.Rows, row)
				vexBench.Unlock()
			}
		}
	}()
	writeJSON(w, 202, map[string]any{"running": true, "picks": len(picks), "variants": in.Variants})
}

func (s *Server) vexBenchOne(variant string, f dtFindingFull) vexBenchRow {
	row := vexBenchRow{Variant: variant, VulnID: f.Vulnerability.VulnID, Component: f.Component.Name + "@" + f.Component.Version}
	sig := vexSignalsFor(f)
	var (
		d     vexDraft
		facts []aiFact
		meta  aiMeta
		err   error
	)
	t0 := time.Now()
	switch variant {
	case "full": // 예전 방식
		facts = vexFacts(f, "", sig)
		meta, err = s.aiDraftOpt("vex", "ko", facts, vexTask, vexDraftSchema, 1100, &d, false)
	case "full-tf": // 예전 내용 그대로, 지시문만 앞으로
		facts = vexFacts(f, "", sig)
		meta, err = s.aiDraftOpt("vex", "ko", facts, vexTask, vexDraftSchema, 1100, &d, true)
	case "slim-raw": // 지시문 앞 + 출력 축소, 사실은 원문 그대로(사용 맥락 없음)
		facts = vexFacts(f, "", sig)
		var o vexSlimOut
		meta, err = s.aiDraftOpt("vex", "ko", facts, vexSlimTask, vexSlimSchema, 160, &o, true)
		d = o.draft()
		vexSlimFill(&d)
	case "card": // 권고문 요약 카드 만들기(저장함 — 이후 방식이 쓴다)
		var c *vulnCard
		c, err = s.cardBuild(f, true)
		if c != nil {
			row.Text = c.Summary + " | 조건: " + c.Condition + " | 완화: " + c.Workaround
		}
		row.Ms = time.Since(t0).Milliseconds()
		if err != nil {
			row.Error = err.Error()
		}
		return row
	case "ctx-card": // 사용 맥락 + 카드(축약 AI). 저장된 판정은 쓰지 않는다
		facts = vexSlimFacts(f, vexBenchCtx, sig, cardGet(f))
		var o vexSlimOut
		meta, err = s.aiDraftOpt("vex", "ko", facts, vexSlimTask, vexSlimSchema, 160, &o, true)
		d = o.draft()
		vexSlimFill(&d)
	case "ctx-raw": // 사용 맥락 + 권고문 원문(카드 없이)
		facts = vexSlimFacts(f, vexBenchCtx, sig, nil)
		var o vexSlimOut
		meta, err = s.aiDraftOpt("vex", "ko", facts, vexSlimTask, vexSlimSchema, 160, &o, true)
		d = o.draft()
		vexSlimFill(&d)
	case "rule":
		facts = vexFacts(f, "", sig)
		d = vexRuleDraft(f, sig, facts, cardGet(f))
	default:
		row.Error = "모르는 방식"
		return row
	}
	row.Ms = time.Since(t0).Milliseconds()
	if err != nil {
		row.Error = err.Error()
		return row
	}
	u := meta.usage
	row.PromptTok, row.EvalTok, row.CacheTok, row.GenTok, row.PromptMs, row.GenMs = u.PromptTok, u.EvalTok, u.CacheTok, u.GenTok, u.PromptMs, u.GenMs
	row.Warn = len(guardVexDraft(&d, facts, sig))
	row.Status, row.Just, row.Conf, row.Text = d.Status, d.Justification, d.Confidence, d.Detail
	return row
}
