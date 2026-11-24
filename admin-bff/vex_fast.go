package main

// vex_fast.go: VEX 판정 초안을 빠르게 만드는 경로.
//
// 전에는 건마다 로컬 LLM 에게 판정·이유·대응 계획·확인할 점을 모두 쓰게 해서 건당 2분쯤 걸렸다.
// 그런데 담당자가 사용 맥락을 적지 않은 건은 판정이 미러 데이터(OSV 범위·수정 버전·KEV·익스플로잇)만으로 정해지고,
// AI 가 쓰던 글도 그 사실을 풀어 쓴 것이었다. 그래서 이렇게 나눈다.
//   ① 규칙 초안      — 사용 맥락이 없으면 규칙으로 판정하고 틀에 맞춰 글을 채운다(AI 호출 없음, 즉시).
//   ② 권고문 요약 카드 — 영어 권고문을 한국어 한두 문장으로 정리한 것. 취약점마다 한 번만 만들어 저장하고
//                      모든 제품·버전이 같이 쓴다(vex_card.go).
//   ③ 축약 AI 판정   — 담당자가 사용 맥락을 적은 건만 AI 를 부른다. 고정 지시문을 앞에 두고(접두 캐시),
//                      판정과 이유 두 문장만 받는다. 대응 계획은 규칙이 채운다. 같은 입력의 결과는 저장해 다시 쓴다.
// VEX_DRAFT_MODE=full 이면 예전 방식(전체 AI)으로 돌아간다.

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

func vexFastOn() bool { return strings.ToLower(env("VEX_DRAFT_MODE", "fast")) != "full" }

// ---------- ① 규칙 초안 ----------

func vexCompName(f dtFindingFull) string {
	n := f.Component.Name
	if f.Component.Group != "" {
		n = f.Component.Group + "/" + n
	}
	return strings.TrimSpace(n + " " + f.Component.Version)
}

func hasFact(facts []aiFact, id string) bool {
	for _, f := range facts {
		if f.ID == id {
			return true
		}
	}
	return false
}

// vexUrgency: KEV·익스플로잇·EPSS 가 높으면 긴급성 문장(없으면 "").
func vexUrgency(f dtFindingFull, sig vexSignals) string {
	switch {
	case sig.KEV:
		t := "실제 악용이 확인된 취약점(CISA KEV 등재)입니다"
		if sig.KEVDue != "" {
			t += " — 조치 기한 " + sig.KEVDue
		}
		return t + " [X2]."
	case sig.Exploits.Any():
		return "공개된 익스플로잇이 있어 악용 가능성이 높습니다 [X3]."
	case f.Vulnerability.EpssScore != nil && *f.Vulnerability.EpssScore >= 0.1:
		return "30일 내 악용 확률(EPSS)이 " + ftoa(*f.Vulnerability.EpssScore*100, 1) + "%로 높습니다 [X1]."
	}
	return ""
}

// vexPlanFor: 판정에 맞는 대응 계획(규칙). 버전은 OSV 사본에 있는 것만 쓴다.
func vexPlanFor(status string, f dtFindingFull, sig vexSignals) []string {
	urgent := ""
	if sig.KEV {
		urgent = "긴급: KEV 등재 취약점이므로 조치 기한 안에 처리한다 [X2]."
	} else if sig.Exploits.Any() {
		urgent = "긴급: 공개 익스플로잇이 있으므로 우선 처리한다 [X3]."
	}
	var p []string
	switch status {
	case "affected":
		if sig.OSV.Target != "" {
			p = []string{f.Component.Name + " 을(를) " + sig.OSV.Target + " 이상으로 올린다 [R1].", "제품을 다시 빌드하고 SBOM 을 다시 만든다.", "다시 스캔해 취약점이 사라졌는지 확인하고 VEX 를 갱신한다."}
		} else {
			p = []string{"수정 버전이 공개됐는지 공급자 권고문을 확인한다 [R1].", "그때까지 쓸 임시 완화(기능 끄기·접근 제한)를 정해 적용한다.", "수정 버전이 나오면 올리고 SBOM·VEX 를 갱신한다."}
		}
	case "not_affected":
		p = []string{"영향 없음의 근거(버전·설정·코드 경로)를 기록으로 남긴다.", "구성요소 버전이나 설정이 바뀌면 다시 확인한다."}
	case "fixed":
		p = []string{"수정이 들어간 버전·빌드를 기록한다.", "다시 스캔해 취약점이 사라졌는지 확인한다."}
	default: // under_investigation
		p = []string{"제품이 이 구성요소의 취약한 기능을 쓰는지(설정·코드 경로) 확인한다 [C1].", "공급자 권고문에서 영향 범위와 수정 버전을 확인한다 [R1].", "확인 결과에 따라 판정을 '영향 있음' 또는 '영향 없음'으로 바꾸고 VEX 를 갱신한다."}
	}
	if urgent != "" {
		p = append([]string{urgent}, p...)
	}
	return p
}

// vexRuleDraft: 사용 맥락 없이 규칙만으로 만든 판정 초안. card 가 있으면 권고문 요약을 덧붙인다.
func vexRuleDraft(f dtFindingFull, sig vexSignals, facts []aiFact, card *vulnCard) vexDraft {
	v, o := f.Vulnerability, sig.OSV
	comp := vexCompName(f)
	d := vexDraft{Citations: []string{"C1", "V1", "R1"}}
	head := comp + " 에서 " + v.VulnID + "(" + firstNonEmpty(v.Severity, "심각도 미상") + ")이 발견되었습니다 [C1][V1]."
	var why string
	switch {
	case o.Checked && o.InRange == "no":
		d.Status, d.Justification, d.Confidence = "not_affected", "vulnerable_code_not_present", "medium"
		why = "현재 버전은 OSV 영향 범위(" + strings.Join(o.Ranges, " / ") + ") 밖이어서 취약한 코드가 들어 있지 않은 것으로 판단합니다 [R1]."
		d.Missing = []string{"분석기(Dependency-Track)가 이 버전을 취약하다고 본 이유 — 실제 포함 버전 확인"}
	case o.Checked && o.InRange == "yes" && o.Target != "":
		d.Status, d.Response, d.Confidence = "affected", "update", "medium"
		why = "현재 버전은 OSV 영향 범위 안이고, 수정 버전 " + o.Target + " 이 있습니다 [R1]. 취약한 기능을 쓰지 않는다는 근거가 없으므로 '영향 있음'으로 두고 업데이트를 권합니다."
		d.Missing = []string{"제품이 취약한 기능을 실제로 쓰는지 — 쓰지 않으면 사용 맥락을 적어 '영향 없음'으로 다시 판정"}
	case o.Checked && o.InRange == "yes":
		d.Status, d.Confidence = "under_investigation", "medium"
		why = "현재 버전은 OSV 영향 범위 안이지만 수정 버전이 아직 공개되지 않았습니다 [R1]. 취약한 기능의 사용 여부를 확인하기 전까지 조사 중으로 둡니다."
		d.Missing = []string{"제품이 취약한 기능을 실제로 쓰는지(설정·코드 경로)", "공급자의 수정 버전 공개 일정"}
	default:
		d.Status, d.Confidence = "under_investigation", "low"
		why = "OSV 사본으로 영향 범위와 수정 버전을 확인하지 못했습니다 [R1]. 추가 확인 전까지 조사 중으로 둡니다."
		d.Missing = []string{"이 버전이 영향 범위에 드는지 — 공급자 권고문 확인", "제품이 취약한 기능을 실제로 쓰는지(설정·코드 경로)"}
	}
	parts := []string{head}
	if card != nil && card.Summary != "" && hasFact(facts, "V3") {
		parts = append(parts, card.Summary+" [V3]")
		d.Citations = append(d.Citations, "V3")
		if card.Condition != "" {
			d.Missing = append(d.Missing, "악용 조건에 해당하는지 — "+card.Condition)
		}
		d.Workaround = card.Workaround
	}
	if u := vexUrgency(f, sig); u != "" {
		parts = append(parts, u)
		d.Citations = append(d.Citations, u[strings.LastIndex(u, "[")+1:strings.LastIndex(u, "]")])
	}
	d.Detail = strings.Join(append(parts, why), " ")
	d.Plan = vexPlanFor(d.Status, f, sig)
	if len(d.Missing) > 4 {
		d.Missing = d.Missing[:4]
	}
	return d
}

// ---------- ③ 축약 AI 판정(사용 맥락이 있을 때) ----------

const vexSlimTask = `담당자가 적은 사용 맥락(U1)을 반영해 이 취약점이 제품에 영향을 주는지 VEX 판정을 고른다.
- status: under_investigation / not_affected / affected / fixed.
- not_affected 는 U1 이나 "OSV 영향 범위 밖"(R1)이 근거일 때만 고르고 justification 을 채운다. 그 외에는 justification 은 빈 문자열.
- justification: 취약한 기능을 쓰지 않거나 버전이 범위 밖 → vulnerable_code_not_present, 코드는 있으나 꺼져 있거나 실행되지 않음 → vulnerable_code_not_in_execute_path, 외부 입력이 닿지 않음 → vulnerable_code_cannot_be_controlled_by_adversary, 별도 방어 장치 → inline_mitigations_already_exist, 구성요소 자체가 제품에 없음 → component_not_present.
- response: affected 일 때만. R1 에 수정 버전이 있으면 update, 없고 임시 완화가 가능하면 workaround_available, 둘 다 없으면 can_not_fix. 그 외에는 빈 문자열.
- detail: 판단 이유 한 문장(80자 안팎), 끝에 근거 사실 ID 를 [U1] 처럼 붙인다. 사실에 없는 버전·설정 값을 쓰지 않는다.
- confidence: 근거가 충분하면 high, 일부면 medium, 부족하면 low.`

var vexSlimSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"status":        map[string]any{"type": "string", "enum": vexStates},
		"justification": map[string]any{"type": "string", "enum": vexJusts},
		"response":      map[string]any{"type": "string", "enum": vexResponses},
		"detail":        map[string]any{"type": "string", "maxLength": 160},
		"confidence":    map[string]any{"type": "string", "enum": []string{"low", "medium", "high"}},
	},
	"required": []string{"status", "justification", "response", "detail", "confidence"},
}

var citeTag = regexp.MustCompile(`\[([A-Z]\d(?:\s*,\s*[A-Z]\d)*)\]`)

// vexSlimFill: AI 가 쓰지 않은 칸을 채운다 — 근거 ID 는 이유 문장의 [U1] 표시에서, 확인할 점은 판정에 맞는 틀에서.
func vexSlimFill(d *vexDraft) {
	for _, m := range citeTag.FindAllStringSubmatch(d.Detail, -1) {
		for _, id := range strings.Split(m[1], ",") {
			if id = strings.TrimSpace(id); !inList(id, d.Citations) {
				d.Citations = append(d.Citations, id)
			}
		}
	}
	switch d.Status {
	case "not_affected":
		d.Missing = []string{"사용 맥락에 적은 내용(설정·코드 경로)을 뒷받침하는 근거 자료", "설정이나 구성요소 버전이 바뀌면 다시 판정"}
	case "affected":
		d.Missing = []string{"적용할 수정 버전과 배포 일정", "수정 전까지 쓸 임시 완화"}
	default:
		d.Missing = []string{"제품이 취약한 기능을 실제로 쓰는지(설정·코드 경로)", "공급자 권고문의 영향 범위·수정 버전"}
	}
}

// vexSlimFacts: AI 에 보내는 사실을 줄인다 — 권고문 원문 대신 요약 카드(있으면), CVSS 벡터·EPSS·현재 상태는 뺀다.
func vexSlimFacts(f dtFindingFull, context string, sig vexSignals, card *vulnCard) []aiFact {
	v := f.Vulnerability
	facts := []aiFact{{ID: "C1", Text: "구성요소: " + vexCompName(f)},
		{ID: "V1", Text: "취약점: " + v.VulnID + " (심각도 " + firstNonEmpty(v.Severity, "미상") + ")"}}
	if v.CweID > 0 {
		facts = append(facts, aiFact{ID: "V2", Text: "약점 유형: CWE-" + itoa(v.CweID) + " " + v.CweName})
	}
	switch {
	case card != nil && card.Summary != "":
		facts = append(facts, aiFact{ID: "V3", Text: "권고문 요약: " + strings.TrimSpace(card.Summary+" 악용 조건: "+firstNonEmpty(card.Condition, "권고문에 없음")), Untrusted: true})
	case v.Description != "":
		facts = append(facts, aiFact{ID: "V3", Text: "권고문 설명: " + truncate(v.Description, 500), Untrusted: true})
	}
	if sig.KEV {
		facts = append(facts, aiFact{ID: "X2", Text: "CISA KEV(실제 악용 확인 목록)에 등재됨"})
	}
	if sig.Exploits.Any() {
		facts = append(facts, aiFact{ID: "X3", Text: "공개 익스플로잇 있음"})
	}
	facts = append(facts, aiFact{ID: "R1", Text: remedyText(sig.OSV, f.Component.Version)},
		aiFact{ID: "U1", Text: "담당자가 적은 사용 맥락: " + truncate(strings.TrimSpace(context), 800)})
	return facts
}

// 같은 입력(사실 + 사용 맥락)의 AI 판정은 저장해 다시 쓴다 — 같은 구성요소·취약점이 여러 버전에 있을 때.
var vexSlimCache = struct {
	sync.Mutex
	m      map[string]vexDraft
	loaded bool
}{}

const vexSlimCacheKeep = 500

func vexSlimCachePath() string { return filepath.Join(filepath.Dir(aiConfigPath()), "vex-slim-cache.json") }

func vexSlimCacheGet(key string) (vexDraft, bool) {
	vexSlimCache.Lock()
	defer vexSlimCache.Unlock()
	if !vexSlimCache.loaded {
		vexSlimCache.loaded, vexSlimCache.m = true, map[string]vexDraft{}
		_ = readJSONFile(vexSlimCachePath(), &vexSlimCache.m)
	}
	d, ok := vexSlimCache.m[key]
	return d, ok
}

func vexSlimCachePut(key string, d vexDraft) {
	vexSlimCache.Lock()
	defer vexSlimCache.Unlock()
	if len(vexSlimCache.m) >= vexSlimCacheKeep { // 넘치면 절반을 비운다(순서 없는 단순 정리)
		ks := make([]string, 0, len(vexSlimCache.m))
		for k := range vexSlimCache.m {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks[:len(ks)/2] {
			delete(vexSlimCache.m, k)
		}
	}
	vexSlimCache.m[key] = d
	_ = writeJSONFile(vexSlimCachePath(), vexSlimCache.m)
}

// vexSlimDraft: 사용 맥락이 있는 건의 AI 판정(축약). 대응 계획·임시 완화는 규칙과 카드가 채운다.
func (s *Server) vexSlimDraft(f dtFindingFull, context string, sig vexSignals, card *vulnCard) (vexDraft, []aiFact, aiMeta, error) {
	facts := vexSlimFacts(f, context, sig, card)
	key := factsHash(facts)
	if d, ok := vexSlimCacheGet(key); ok {
		return d, facts, aiMeta{FactsSHA256: key, Use: "vex", Method: "ai-slim", Cached: true, Model: "저장된 판정"}, nil
	}
	var d vexDraft
	meta, err := s.aiDraftOpt("vex", "ko", facts, vexSlimTask, vexSlimSchema, 220, &d, true)
	meta.Method = "ai-slim"
	if err != nil {
		return d, facts, meta, err
	}
	vexSlimFill(&d)
	if card != nil {
		d.Workaround = card.Workaround
	}
	vexSlimCachePut(key, d)
	return d, facts, meta, nil
}

// vexFastDraftFor: 빠른 경로의 한 건. waitCard 면 요약 카드가 없을 때 만들어서(한 번, 수십 초) 넣고,
// 아니면 있는 것만 쓰고 없는 것은 뒤에서 만들도록 줄에 넣는다.
func (s *Server) vexFastDraftFor(actor, repo, tag string, f dtFindingFull, context string, waitCard bool) (*vexDraftResult, error) {
	t0 := time.Now()
	sig := vexSignalsFor(f)
	card := cardGet(f)
	if card == nil && f.Vulnerability.Description != "" {
		if waitCard {
			card, _ = s.cardMake(f) // 실패해도 규칙 초안은 낸다
		} else {
			s.cardQueue(f)
		}
	}
	var (
		d     vexDraft
		facts []aiFact
		meta  aiMeta
	)
	if strings.TrimSpace(context) == "" {
		facts = vexFacts(f, "", sig)
		d = vexRuleDraft(f, sig, facts, card)
		meta = aiMeta{FactsSHA256: factsHash(facts), Use: "vex", Method: "rule", Model: "규칙"}
		if card != nil && card.Summary != "" {
			meta.Method, meta.Model = "rule+card", "규칙 + "+card.Model
		}
	} else {
		var err error
		if d, facts, meta, err = s.vexSlimDraft(f, context, sig, card); err != nil {
			return nil, err
		}
		d.Plan = nil
	}
	warn := guardVexDraft(&d, facts, sig)
	if len(d.Plan) == 0 { // 축약 AI 판정: 안전장치가 고친 최종 판정에 맞춰 계획을 채운다
		d.Plan = vexPlanFor(d.Status, f, sig)
	}
	meta.ElapsedMs = time.Since(t0).Milliseconds()
	meta.Snapshot = s.mirrorSnapshot()
	ob, _ := json.Marshal(d)
	s.aiRecord(actor, "vex", repo, tag, meta, sha256hex(ob),
		map[string]any{"vulnId": f.Vulnerability.VulnID, "component": f.Component.Name + "@" + f.Component.Version, "suggested": d.Status, "response": d.Response, "method": meta.Method, "cached": meta.Cached})
	return &vexDraftResult{
		Component: f.Component.UUID, Vulnerability: f.Vulnerability.UUID, VulnID: f.Vulnerability.VulnID,
		Draft: d, Facts: facts, Warnings: warn, KEV: sig.KEV, Meta: meta, At: time.Now().UTC().Format(time.RFC3339),
		Remedy: vexRemedy{Priority: vexPriority(f, sig), Target: sig.OSV.Target, Fixed: sig.OSV.Fixed, InRange: sig.OSV.InRange,
			Source: sig.OSV.Source, Ranges: sig.OSV.Ranges, OSVNote: sig.OSV.NoReason, DueBy: sig.KEVDue, Exploits: sig.Exploits},
	}, nil
}
