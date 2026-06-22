package main

// CycloneDX VEX 어휘 ↔ Dependency-Track enum 매핑.
// 내부 표준은 CycloneDX. DT 버전별 enum 차이는 dt-verify 로 검증·보정한다.

// status(CycloneDX) → analysisState(DT)
var vexStatusToDT = map[string]string{
	"not_affected":        "NOT_AFFECTED",
	"affected":            "EXPLOITABLE",
	"fixed":               "RESOLVED",
	"under_investigation": "IN_TRIAGE",
}

// analysisState(DT) → status(CycloneDX) (역방향, 최종 산출=CycloneDX)
var dtStateToVEX = map[string]string{
	"NOT_AFFECTED":   "not_affected",
	"EXPLOITABLE":    "affected",
	"RESOLVED":       "fixed",
	"IN_TRIAGE":      "under_investigation",
	"FALSE_POSITIVE": "not_affected",
	"NOT_SET":        "under_investigation",
}

// justification(CycloneDX) → analysisJustification(DT)
var vexJustToDT = map[string]string{
	"component_not_present":                             "CODE_NOT_PRESENT",
	"vulnerable_code_not_present":                       "CODE_NOT_PRESENT",
	"vulnerable_code_not_in_execute_path":               "CODE_NOT_REACHABLE",
	"vulnerable_code_cannot_be_controlled_by_adversary": "REQUIRES_CONFIGURATION",
	"inline_mitigations_already_exist":                  "PROTECTED_BY_MITIGATING_CONTROL",
}

// response(CycloneDX) → analysisResponse(DT)
var vexResponseToDT = map[string]string{
	"can_not_fix":          "CAN_NOT_FIX",
	"will_not_fix":         "WILL_NOT_FIX",
	"update":               "UPDATE",
	"rollback":             "ROLLBACK",
	"workaround_available": "WORKAROUND_AVAILABLE",
}

func mapOr(m map[string]string, k, def string) string {
	if v, ok := m[k]; ok {
		return v
	}
	return def
}
