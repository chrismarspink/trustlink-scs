package main

// ai_perf.go: AI 성능·자원 측정과 "외부 LLM 이 필요한가" 판단 — 대시보드 › AI 탭.
//   - 모든 AI 호출(aiDraftFor)을 기능별로 기록: 대기·소요 시간, 토큰 수, 초당 토큰, 실패 종류
//   - 30초마다 서버 CPU·메모리·스왑을 재고, 그 사이 로컬 AI 가 돌았는지 함께 적는다(24시간)
//   - 성능 측정 버튼: 고객 데이터 없는 고정 문장으로 한 번 돌려 속도를 잰다
// BFF 컨테이너의 /proc/stat·/proc/meminfo 는 서버 전체 값이다(컨테이너별 값이 아님).
// AI 컨테이너 자체 메모리는 볼 수 없어(도커 소켓을 열지 않음) 모델 파일 크기로 어림한다.

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type aiUsage struct {
	PromptTok, GenTok int
	PromptMs, GenMs   float64 // llama.cpp 가 준 처리 시간(없으면 0)
}

type aiCall struct {
	At        string  `json:"at"`
	Feature   string  `json:"feature"`
	Use       string  `json:"use"`
	Kind      string  `json:"kind"` // local / external
	Model     string  `json:"model,omitempty"`
	WaitMs    int64   `json:"waitMs"` // 앞 작업이 끝나기를 기다린 시간(로컬은 한 번에 하나)
	Ms        int64   `json:"ms"`
	PromptTok int     `json:"promptTok"`
	GenTok    int     `json:"genTok"`
	PromptTPS float64 `json:"promptTps,omitempty"`
	GenTPS    float64 `json:"genTps,omitempty"`
	OK        bool    `json:"ok"`
	Fail      string  `json:"fail,omitempty"` // timeout / format / error / length(잘림, 결과는 씀)
}

func (r *aiCall) fill(model string, ms int64, u aiUsage, finish string, err error) {
	r.At, r.Model, r.Ms = time.Now().UTC().Format(time.RFC3339), model, ms
	r.PromptTok, r.GenTok = u.PromptTok, u.GenTok
	if u.GenMs > 0 {
		r.GenTPS = round1(float64(u.GenTok) / (u.GenMs / 1000))
	} else if ms > 0 && u.GenTok > 0 { // 외부 API: 처리 시간을 따로 주지 않아 전체 시간으로 어림
		r.GenTPS = round1(float64(u.GenTok) / (float64(ms) / 1000))
	}
	if u.PromptMs > 0 {
		r.PromptTPS = round1(float64(u.PromptTok) / (u.PromptMs / 1000))
	}
	r.OK = err == nil
	switch {
	case err != nil && (strings.Contains(err.Error(), "Timeout") || strings.Contains(err.Error(), "deadline") || strings.Contains(err.Error(), "timeout")):
		r.Fail = "timeout"
	case err != nil:
		r.Fail = "error"
	case finish == "length":
		r.Fail = "length"
	}
}

func round1(f float64) float64 { return float64(int64(f*10+0.5)) / 10 }

// 기능 이름: 호출한 소스 파일로 정한다(호출부마다 이름을 넘기지 않아도 되게).
var aiFeatureByFile = map[string]string{
	"ai_vex.go": "VEX 판단", "custnotify.go": "고객 통지 문안", "compliance.go": "규제 대응 검증",
	"mail_suggest.go": "현황 메일 제안", "regcatalog.go": "규제 보고서", "regdiscover.go": "규제 탐색",
	"reglaw.go": "국내 법규 분석", "upstream_api.go": "공개 저장소 분석", "ai_perf.go": "성능 측정",
}

// aiSensitive: 고객·내부 자료가 들어가는 기능(외부 LLM 으로 보내기 전에 동의·검토가 필요).
var aiSensitive = map[string]string{
	"VEX 판단": "고객 제품의 구성요소·취약점 정보", "고객 통지 문안": "고객 이름·납품 제품",
	"규제 대응 검증": "대외비 체크리스트·제품 증거", "현황 메일 제안": "내부 운영 현황",
}

func aiFeature() string {
	pc := make([]uintptr, 8)
	n := runtime.Callers(3, pc) // runtime.Callers, aiFeature, aiDraftFor 다음부터
	fr := runtime.CallersFrames(pc[:n])
	for {
		f, more := fr.Next()
		b := filepath.Base(f.File)
		if b != "ai.go" {
			if name, ok := aiFeatureByFile[b]; ok {
				return name
			}
			return "기타"
		}
		if !more {
			return "기타"
		}
	}
}

// ---------- 기록(파일 하나, 최근 1000건·측정 30회) ----------

type aiBench struct {
	aiCall
	CPUDuring float64 `json:"cpuDuring"` // 측정하는 동안 서버 전체 CPU 사용률(%)
	Err       string  `json:"err,omitempty"`
	By        string  `json:"by,omitempty"`
}

var (
	aiLocalBusy atomic.Int32 // 지금 로컬 AI 요청 수
	aiBusySeen  atomic.Bool  // 마지막 표본 이후 로컬 AI 가 돈 적 있음
	aiPerfMu    sync.Mutex
	aiPerfData  struct {
		Calls   []aiCall  `json:"calls"`
		Benches []aiBench `json:"benches"`
	}
	aiPerfLoaded bool
	aiBenchState struct {
		Running bool   `json:"running"`
		Started string `json:"started,omitempty"`
		Target  string `json:"target,omitempty"`
	}
)

func aiPerfPath() string { return filepath.Join(filepath.Dir(aiConfigPath()), "ai-perf.json") }

func aiPerfLoad() { // aiPerfMu 잡은 채로
	if !aiPerfLoaded {
		aiPerfLoaded = true
		_ = readJSONFile(aiPerfPath(), &aiPerfData)
	}
}

func recordAICall(r aiCall) {
	aiPerfMu.Lock()
	defer aiPerfMu.Unlock()
	aiPerfLoad()
	aiPerfData.Calls = append(aiPerfData.Calls, r)
	if n := len(aiPerfData.Calls); n > 1000 {
		aiPerfData.Calls = aiPerfData.Calls[n-1000:]
	}
	_ = writeJSONFile(aiPerfPath(), aiPerfData)
}

// ---------- 서버 자원 표본(30초, 24시간) ----------

type sysSample struct {
	T    int64   `json:"t"`    // unix 초
	CPU  float64 `json:"cpu"`  // 서버 전체 CPU %
	Mem  float64 `json:"mem"`  // 메모리 사용 %(캐시 제외 = 1 - MemAvailable/MemTotal)
	Swap float64 `json:"swap"` // 스왑 사용 %
	AI   bool    `json:"ai"`   // 이 구간에 로컬 AI 가 돌았음
}

var (
	sysMu      sync.Mutex
	sysSamples []sysSample
)

func readCPUStat() (total, idle uint64) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if sc.Scan() {
		fs := strings.Fields(sc.Text())
		for i, v := range fs[1:] {
			n, _ := strconv.ParseUint(v, 10, 64)
			total += n
			if i == 3 || i == 4 { // idle, iowait
				idle += n
			}
		}
	}
	return
}

func cpuPct(t0, i0, t1, i1 uint64) float64 {
	if t1 <= t0 {
		return 0
	}
	return round1(100 * (1 - float64(i1-i0)/float64(t1-t0)))
}

func readMeminfo() map[string]int64 { // 바이트
	m := map[string]int64{}
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) >= 2 {
			n, _ := strconv.ParseInt(fs[1], 10, 64)
			m[strings.TrimSuffix(fs[0], ":")] = n * 1024
		}
	}
	return m
}

func pctOf(a, b int64) float64 {
	if b <= 0 {
		return 0
	}
	return round1(100 * float64(a) / float64(b))
}

func (s *Server) aiSysLoop() {
	t0, i0 := readCPUStat()
	if t0 == 0 {
		return // /proc 가 없는 환경(맥 개발 등)
	}
	for range time.Tick(30 * time.Second) {
		t1, i1 := readCPUStat()
		m := readMeminfo()
		smp := sysSample{T: time.Now().Unix(), CPU: cpuPct(t0, i0, t1, i1),
			Mem:  pctOf(m["MemTotal"]-m["MemAvailable"], m["MemTotal"]),
			Swap: pctOf(m["SwapTotal"]-m["SwapFree"], m["SwapTotal"]),
			AI:   aiBusySeen.Swap(false) || aiLocalBusy.Load() > 0}
		t0, i0 = t1, i1
		sysMu.Lock()
		sysSamples = append(sysSamples, smp)
		if n := len(sysSamples); n > 2880 {
			sysSamples = sysSamples[n-2880:]
		}
		sysMu.Unlock()
	}
}

// ---------- 성능 측정(고정 문장, 고객 데이터 없음) ----------

const aiBenchPrompt = `구성요소 openssl 3.0.2 에 CVE-2022-3602(X.509 인증서 이름 검증 중 스택 버퍼 오버플로) 가 있다.
이 제품은 TLS 서버로만 동작하고 클라이언트 인증서 검증을 쓰지 않는다. 설정 파일에 verify_client off 가 있다.
VEX 상태(affected / not_affected), 근거(justification), 설명(3문장)을 한국어 JSON 으로 써라.`

var aiBenchSchema = map[string]any{"type": "object", "properties": map[string]any{
	"status":        map[string]any{"type": "string", "enum": []string{"affected", "not_affected"}},
	"justification": map[string]any{"type": "string"}, "detail": map[string]any{"type": "string"}},
	"required": []string{"status", "justification", "detail"}}

func (s *Server) runAIBench(target, by string) {
	e := aiConf().endpointOf(target)
	b := aiBench{By: by}
	b.Feature, b.Use, b.Kind = "성능 측정", "bench", e.Kind
	if e.Kind == "local" {
		aiMu.Lock()
	}
	aiBusySeen.Store(e.Kind == "local")
	t0, i0 := readCPUStat()
	st := time.Now()
	content, model, finish, u, err := aiChatU(e, "You are a security analyst.", aiBenchPrompt, aiBenchSchema, 500, 6*time.Minute)
	ms := time.Since(st).Milliseconds()
	t1, i1 := readCPUStat()
	if e.Kind == "local" {
		aiMu.Unlock()
	}
	b.fill(model, ms, u, finish, err)
	if t0 > 0 {
		b.CPUDuring = cpuPct(t0, i0, t1, i1)
	}
	if err != nil {
		b.Err = truncate(err.Error(), 200)
	} else if json.Unmarshal([]byte(content), &map[string]any{}) != nil {
		b.OK, b.Fail, b.Err = false, "format", "응답이 JSON 형식이 아님"
	}
	recordAICall(b.aiCall)
	aiPerfMu.Lock()
	aiPerfData.Benches = append(aiPerfData.Benches, b)
	if n := len(aiPerfData.Benches); n > 30 {
		aiPerfData.Benches = aiPerfData.Benches[n-30:]
	}
	_ = writeJSONFile(aiPerfPath(), aiPerfData)
	aiBenchState.Running = false
	aiPerfMu.Unlock()
}

// POST /api/ai-perf/bench {target: local|external}
func (s *Server) apiAIPerfBench(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Target string `json:"target"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&in)
	if in.Target != "local" && in.Target != "external" {
		writeJSON(w, 400, map[string]string{"error": "target 은 local / external"})
		return
	}
	if !aiConf().endpointOf(in.Target).ready() {
		writeJSON(w, 400, map[string]string{"error": map[string]string{"local": "로컬 AI 가 연결되지 않았습니다", "external": "외부 LLM 이 설정되지 않았습니다"}[in.Target]})
		return
	}
	aiPerfMu.Lock()
	aiPerfLoad()
	if aiBenchState.Running {
		aiPerfMu.Unlock()
		writeJSON(w, 409, map[string]string{"error": "이미 측정 중입니다"})
		return
	}
	aiBenchState.Running, aiBenchState.Started, aiBenchState.Target = true, time.Now().UTC().Format(time.RFC3339), in.Target
	aiPerfMu.Unlock()
	go s.runAIBench(in.Target, w.Header().Get("X-User"))
	writeJSON(w, 202, map[string]any{"started": true})
}

// ---------- 요약·판단 ----------

type aiFeatStat struct {
	Feature   string  `json:"feature"`
	Kind      string  `json:"kind"` // 지금 이 기능이 쓰는 연결
	Sensitive string  `json:"sensitive,omitempty"`
	Count     int     `json:"count"`
	Fails     int     `json:"fails"`
	Timeouts  int     `json:"timeouts"`
	P50       int64   `json:"p50Ms"`
	P90       int64   `json:"p90Ms"`
	AvgWait   int64   `json:"avgWaitMs"`
	GenTPS    float64 `json:"genTps"`
	LastAt    string  `json:"lastAt"`
	Recommend string  `json:"recommend"` // local / external / either
	Why       string  `json:"why"`
}

type aiReason struct {
	Tone string `json:"tone"` // ok / warn / crit
	Text string `json:"text"`
}

func pctl(xs []int64, p float64) int64 {
	if len(xs) == 0 {
		return 0
	}
	ys := append([]int64(nil), xs...)
	sort.Slice(ys, func(i, j int) bool { return ys[i] < ys[j] })
	return ys[int(float64(len(ys)-1)*p+0.5)]
}

func median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	ys := append([]float64(nil), xs...)
	sort.Float64s(ys)
	return ys[len(ys)/2]
}

// 기능이 지금 쓰는 용도(vex / report / 규제 탐색은 보고서용이 꺼지면 일반)
var aiFeatureUse = map[string]string{
	"VEX 판단": "vex", "고객 통지 문안": "vex", "규제 대응 검증": "report", "현황 메일 제안": "report",
	"규제 보고서": "report", "규제 탐색": "discover", "국내 법규 분석": "report", "공개 저장소 분석": "report",
}

type aiVerdictIn struct {
	LocalTPS      float64 // 로컬 생성 속도(초당 토큰)
	LocalFailRate float64 // %
	VexP50        int64   // ms
	MemAvailPct   float64 // 서버 메모리 여유 %
	SwapPct       float64
	CPUBusy       float64 // AI 가 도는 동안 서버 CPU 평균 %
}

// aiVerdict: 로컬 유지 / 혼합(민감 자료는 로컬, 공개 정보 기능은 외부) / 외부 필요.
func aiVerdict(v aiVerdictIn) (level, title string, reasons []aiReason) {
	add := func(t, s string) { reasons = append(reasons, aiReason{t, s}) }
	crit, warn := 0, 0
	switch {
	case v.LocalTPS == 0:
		add("warn", "아직 측정 자료가 없습니다 — 아래 '성능 측정'을 한 번 눌러 주세요")
		warn++
	case v.LocalTPS < 3:
		add("crit", "글 쓰는 속도가 초당 "+numStr(v.LocalTPS)+"토큰으로 매우 느립니다(긴 보고서는 수십 분)")
		crit++
	case v.LocalTPS < 12:
		add("warn", "글 쓰는 속도가 초당 "+numStr(v.LocalTPS)+"토큰입니다 — VEX 한 건은 쓸 만하지만 긴 보고서는 10분 넘게 걸립니다")
		warn++
	default:
		add("ok", "글 쓰는 속도가 초당 "+numStr(v.LocalTPS)+"토큰으로 충분합니다")
	}
	if v.VexP50 > 0 {
		t := "ok"
		if v.VexP50 > 120000 {
			t = "warn"
			warn++
		}
		add(t, "VEX 판단 한 건에 보통 "+fmtDur(v.VexP50)+" 걸립니다(일괄 처리 100건이면 약 "+fmtDur(v.VexP50*100)+")")
	}
	switch {
	case v.LocalFailRate >= 25:
		add("crit", "로컬 AI 요청의 "+numStr(v.LocalFailRate)+"% 가 실패했습니다(시간 초과·형식 오류)")
		crit++
	case v.LocalFailRate >= 10:
		add("warn", "로컬 AI 요청의 "+numStr(v.LocalFailRate)+"% 가 실패했습니다")
		warn++
	}
	switch {
	case v.MemAvailPct > 0 && v.MemAvailPct < 10:
		add("crit", "서버 메모리 여유가 "+numStr(v.MemAvailPct)+"% 뿐입니다 — AI 가 상주하며 다른 서비스를 압박합니다")
		crit++
	case v.MemAvailPct > 0 && v.MemAvailPct < 20:
		add("warn", "서버 메모리 여유가 "+numStr(v.MemAvailPct)+"% 입니다")
		warn++
	}
	if v.SwapPct >= 50 {
		add("warn", "스왑을 "+numStr(v.SwapPct)+"% 쓰고 있습니다(서버 전체 — 같은 서버의 다른 서비스 포함)")
		warn++
	}
	if v.CPUBusy >= 85 {
		add("warn", "AI 가 도는 동안 서버 CPU 가 평균 "+numStr(v.CPUBusy)+"% 까지 오릅니다 — 다른 서비스가 느려질 수 있습니다")
		warn++
	}
	switch {
	case crit > 0:
		return "external", "외부 LLM 이 필요합니다", reasons
	case warn > 0:
		return "hybrid", "혼합을 권장합니다 — 민감 자료는 로컬, 공개 정보 기능은 외부", reasons
	}
	return "local", "로컬 AI 로 충분합니다", reasons
}

func numStr(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

func fmtDur(ms int64) string {
	s := ms / 1000
	switch {
	case s < 60:
		return strconv.FormatInt(s, 10) + "초"
	case s < 3600:
		return strconv.FormatInt(s/60, 10) + "분 " + strconv.FormatInt(s%60, 10) + "초"
	}
	return strconv.FormatInt(s/3600, 10) + "시간 " + strconv.FormatInt(s%3600/60, 10) + "분"
}

func parseMemLimit(s string) int64 { // "24g" / "512m" → 바이트
	s = strings.ToLower(strings.TrimSpace(s))
	mul := int64(1)
	switch {
	case strings.HasSuffix(s, "g"):
		mul, s = 1<<30, strings.TrimSuffix(s, "g")
	case strings.HasSuffix(s, "m"):
		mul, s = 1<<20, strings.TrimSuffix(s, "m")
	}
	n, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return int64(n * float64(mul))
}

// GET /api/ai-perf
func (s *Server) apiAIPerf(w http.ResponseWriter, r *http.Request) {
	c := aiConf()
	aiPerfMu.Lock()
	aiPerfLoad()
	calls := append([]aiCall(nil), aiPerfData.Calls...)
	benches := append([]aiBench(nil), aiPerfData.Benches...)
	bench := aiBenchState
	aiPerfMu.Unlock()

	since := time.Now().Add(-7 * 24 * time.Hour).UTC().Format(time.RFC3339)
	type acc struct {
		ms, wait []int64
		tps      []float64
		st       aiFeatStat
	}
	by := map[string]*acc{}
	var localTPS, extTPS []float64
	localN, localFail := 0, 0
	for _, x := range calls {
		if x.At < since {
			continue
		}
		if x.Kind == "local" && x.GenTPS > 0 && x.GenTok >= 20 {
			localTPS = append(localTPS, x.GenTPS)
		}
		if x.Kind == "external" && x.GenTPS > 0 {
			extTPS = append(extTPS, x.GenTPS)
		}
		if x.Kind == "local" && x.Use != "bench" {
			localN++
			if !x.OK {
				localFail++
			}
		}
		if x.Use == "bench" {
			continue
		}
		a := by[x.Feature]
		if a == nil {
			a = &acc{st: aiFeatStat{Feature: x.Feature}}
			by[x.Feature] = a
		}
		a.st.Count++
		if !x.OK {
			a.st.Fails++
		}
		if x.Fail == "timeout" {
			a.st.Timeouts++
		}
		if x.OK {
			a.ms = append(a.ms, x.Ms)
		}
		a.wait = append(a.wait, x.WaitMs)
		if x.GenTPS > 0 {
			a.tps = append(a.tps, x.GenTPS)
		}
		if x.At > a.st.LastAt {
			a.st.LastAt = x.At
		}
	}
	// 최근 측정(벤치)도 로컬 속도에 넣는다
	for _, b := range benches {
		if b.Kind == "local" && b.OK && b.At >= since && b.GenTPS > 0 {
			localTPS = append(localTPS, b.GenTPS)
		}
	}
	// 기록이 없는 기능도 표에 보이게
	for f := range aiFeatureUse {
		if by[f] == nil {
			by[f] = &acc{st: aiFeatStat{Feature: f}}
		}
	}

	// 서버 자원
	m := readMeminfo()
	memTotal, memAvail := m["MemTotal"], m["MemAvailable"]
	sysMu.Lock()
	samples := append([]sysSample(nil), sysSamples...)
	sysMu.Unlock()
	var busySum, idleSum float64
	var busyN, idleN int
	for _, x := range samples {
		if x.AI {
			busySum += x.CPU
			busyN++
		} else {
			idleSum += x.CPU
			idleN++
		}
	}
	avg := func(s float64, n int) float64 {
		if n == 0 {
			return 0
		}
		return round1(s / float64(n))
	}
	// 그래프용: 5분 단위(표본 10개)로 묶음
	type pt struct {
		T   int64   `json:"t"`
		CPU float64 `json:"cpu"`
		Mem float64 `json:"mem"`
		AI  bool    `json:"ai"`
	}
	series := []pt{}
	for i := 0; i < len(samples); i += 10 {
		j := min(i+10, len(samples))
		p := pt{T: samples[i].T}
		for _, x := range samples[i:j] {
			p.CPU += x.CPU
			p.Mem += x.Mem
			p.AI = p.AI || x.AI
		}
		p.CPU, p.Mem = round1(p.CPU/float64(j-i)), round1(p.Mem/float64(j-i))
		series = append(series, p)
	}
	modelDir := env("AI_MODEL_DIR", "/ai-models")
	var modelFile string
	var modelBytes int64
	if ents, err := os.ReadDir(modelDir); err == nil {
		for _, e := range ents {
			if fi, err := e.Info(); err == nil && strings.HasSuffix(e.Name(), ".gguf") && fi.Size() > modelBytes {
				modelFile, modelBytes = e.Name(), fi.Size()
			}
		}
	}
	type disk struct {
		Label string `json:"label"`
		Free  int64  `json:"free"`
		Total int64  `json:"total"`
	}
	disks := []disk{}
	for _, d := range []struct{ label, path string }{{"AI 모델 저장소", modelDir}, {"TrustLink 데이터", filepath.Dir(aiConfigPath())}} {
		if f, t := diskFree(d.path); t > 0 {
			if n := len(disks); n > 0 && disks[n-1].Total == t && disks[n-1].Free/(1<<30) == f/(1<<30) { // 같은 디스크면 한 줄로
				disks[n-1].Label += " · " + d.label
				continue
			}
			disks = append(disks, disk{d.label, f, t})
		}
	}

	// 로컬 AI 서버 상태(llama.cpp /slots: 대화 길이·지금 처리 중인지)
	live := map[string]any{"configured": c.URL != ""}
	if c.URL != "" {
		var slots []struct {
			NCtx         int  `json:"n_ctx"`
			IsProcessing bool `json:"is_processing"`
		}
		resp, err := (&http.Client{Timeout: 3 * time.Second}).Get(aiRoot(c.endpointOf("local")) + "/slots")
		if err == nil {
			_ = json.NewDecoder(resp.Body).Decode(&slots)
			resp.Body.Close()
		}
		live["reachable"] = err == nil && len(slots) > 0
		if len(slots) > 0 {
			live["nCtx"], live["busy"], live["slots"] = slots[0].NCtx, slots[0].IsProcessing, len(slots)
		}
	}

	// 판단
	vin := aiVerdictIn{LocalTPS: round1(median(localTPS)), MemAvailPct: pctOf(memAvail, memTotal),
		SwapPct: pctOf(m["SwapTotal"]-m["SwapFree"], m["SwapTotal"]), CPUBusy: avg(busySum, busyN)}
	if localN > 0 {
		vin.LocalFailRate = pctOf(int64(localFail), int64(localN))
	}
	if a := by["VEX 판단"]; a != nil {
		vin.VexP50 = pctl(a.ms, 0.5)
	}
	level, title, reasons := aiVerdict(vin)
	feats := []aiFeatStat{}
	for _, a := range by {
		st := a.st
		use := aiFeatureUse[st.Feature]
		if use == "discover" {
			use = discoverAIUse()
		}
		if use != "" {
			st.Kind = c.useMode(use)
		}
		st.P50, st.P90 = pctl(a.ms, 0.5), pctl(a.ms, 0.9)
		if len(a.wait) > 0 {
			var sum int64
			for _, x := range a.wait {
				sum += x
			}
			st.AvgWait = sum / int64(len(a.wait))
		}
		st.GenTPS = round1(median(a.tps))
		st.Sensitive = aiSensitive[st.Feature]
		switch {
		case st.Sensitive != "":
			st.Recommend, st.Why = "local", "보내는 자료에 "+st.Sensitive+" 포함 — 외부로 보내려면 고객 동의·계약 확인"
		case level == "local":
			st.Recommend, st.Why = "either", "공개 정보만 보냄 — 지금 속도면 로컬로 충분"
		default:
			st.Recommend, st.Why = "external", "공개 정보만 보내고 글이 길어 외부 LLM 이 훨씬 빠름(인터넷이 되는 설치 환경일 때)"
		}
		feats = append(feats, st)
	}
	sort.Slice(feats, func(i, j int) bool {
		if feats[i].Count != feats[j].Count {
			return feats[i].Count > feats[j].Count
		}
		return feats[i].Feature < feats[j].Feature
	})
	if len(benches) > 10 {
		benches = benches[len(benches)-10:]
	}
	ext := ""
	if c.External.Model != "" {
		ext = firstNonEmpty(c.External.Provider, "openai") + " · " + c.External.Model
	}
	writeJSON(w, 200, map[string]any{
		"config":   map[string]any{"mode": c.Mode, "reportMode": firstNonEmpty(c.ReportMode, c.Mode), "localUrl": c.URL != "", "external": ext, "externalReady": c.endpointOf("external").ready()},
		"live":     live,
		"verdict":  map[string]any{"level": level, "title": title, "reasons": reasons},
		"local":    map[string]any{"genTps": vin.LocalTPS, "calls": localN, "fails": localFail, "failRate": vin.LocalFailRate},
		"external": map[string]any{"genTps": round1(median(extTPS)), "calls": len(extTPS)},
		"features": feats,
		"benches":  benches,
		"bench":    bench,
		"system": map[string]any{
			"cpus": runtime.NumCPU(), "aiCpus": env("AI_CPUS", ""), "aiMemLimit": parseMemLimit(env("AI_MEM_LIMIT", "")),
			"memTotal": memTotal, "memAvail": memAvail, "swapTotal": m["SwapTotal"], "swapUsed": m["SwapTotal"] - m["SwapFree"],
			"modelFile": modelFile, "modelBytes": modelBytes, "aiMemEst": modelBytes + modelBytes/5, // 모델 + 작업 메모리 어림(실측: 16GB 모델 → 19.5GB)
			"cpuBusy": avg(busySum, busyN), "cpuIdle": avg(idleSum, idleN), "busySamples": busyN, "samples": len(samples),
			"disks": disks, "series": series,
		},
	})
}
