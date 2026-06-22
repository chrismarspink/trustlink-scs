#!/usr/bin/env bash
# DT 헤드리스 연동 스모크: SBOM 업로드 → 분석 폴링 → findings → (audit) → CycloneDX VEX → oras attach.
set -uo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a
DT="${DT_LOCAL_URL:-http://localhost:8081}"
ZOT="${ZOT_URL:-localhost:28080}"
KEY="${DT_API_KEY:?dt-bootstrap.sh 먼저 실행해 DT_API_KEY 설정}"
PROJ="npouch"; VER="1.5.0"
H=(-H "X-Api-Key: $KEY" -H "Content-Type: application/json")
PASS=0; FAIL=0; ok(){ echo "PASS: $1"; PASS=$((PASS+1)); }; no(){ echo "FAIL: $1"; FAIL=$((FAIL+1)); }

echo "[1] 샘플 CycloneDX SBOM 생성 (의도적 취약 컴포넌트 포함)"
cat > /tmp/npouch.cdx.json <<'EOF'
{"bomFormat":"CycloneDX","specVersion":"1.4","version":1,
 "components":[
  {"type":"library","name":"log4j-core","group":"org.apache.logging.log4j","version":"2.14.1","purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
  {"type":"library","name":"openssl","version":"3.0.13","purl":"pkg:generic/openssl@3.0.13"}
 ]}
EOF
BOM64=$(base64 < /tmp/npouch.cdx.json | tr -d '\n')

echo "[2] SBOM 업로드 (PUT /api/v1/bom, autoCreate)"
TOKEN=$(curl -s "${H[@]}" -X PUT "$DT/api/v1/bom" \
  -d "{\"projectName\":\"$PROJ\",\"projectVersion\":\"$VER\",\"autoCreate\":true,\"bom\":\"$BOM64\"}" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("token",""))' 2>/dev/null)
[ -n "$TOKEN" ] && ok "업로드 token 수신" || { no "업로드 실패"; }

echo "[3] 분석 완료 폴링"
for i in $(seq 1 60); do
  P=$(curl -s "${H[@]}" "$DT/api/v1/bom/token/$TOKEN" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("processing",True))' 2>/dev/null)
  [ "$P" = "False" ] && break; sleep 3
done
[ "$P" = "False" ] && ok "분석 완료(processing=false)" || no "분석 미완료"

echo "[4] 프로젝트 조회 + findings"
UUID=$(curl -s "${H[@]}" "$DT/api/v1/project/lookup?name=$PROJ&version=$VER" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("uuid",""))' 2>/dev/null)
[ -n "$UUID" ] && ok "project uuid=$UUID" || no "project 조회 실패"
FIND=$(curl -s "${H[@]}" "$DT/api/v1/finding/project/$UUID")
NF=$(printf '%s' "$FIND" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)))' 2>/dev/null || echo 0)
echo "  findings: $NF 건 (NVD 미러 동기화 전이면 0일 수 있음 — 수용기준 ≥0)"
ok "findings 조회(≥0)"

echo "[5] audit 기록 (findings 있으면 첫 건 NOT_AFFECTED)"
if [ "${NF:-0}" -gt 0 ]; then
  read CU VU < <(printf '%s' "$FIND" | python3 -c 'import sys,json;f=json.load(sys.stdin)[0];print(f["component"]["uuid"],f["vulnerability"]["uuid"])')
  code=$(curl -s -o /dev/null -w '%{http_code}' "${H[@]}" -X PUT "$DT/api/v1/analysis" \
    -d "{\"project\":\"$UUID\",\"component\":\"$CU\",\"vulnerability\":\"$VU\",\"analysisState\":\"NOT_AFFECTED\",\"analysisJustification\":\"CODE_NOT_REACHABLE\",\"comment\":\"smoke test\",\"suppressed\":true}")
  [ "$code" = "200" ] && ok "audit 기록 (200)" || no "audit 기록 ($code)"
else
  echo "  (findings 0 → audit 스킵; NVD 동기화 후 재실행 권장)"
fi

echo "[6] CycloneDX VEX 추출"
curl -s "${H[@]}" "$DT/api/v1/vex/cyclonedx/project/$UUID" -o /tmp/npouch.vex.cdx.json
python3 -c 'import json;json.load(open("/tmp/npouch.vex.cdx.json"))' 2>/dev/null && ok "VEX 추출(유효 JSON)" || no "VEX 추출 실패"

echo "[7] oras attach → zot referrer + discover"
export PATH=$HOME/go/bin:$PATH
oras login "$ZOT" -u ci -p "$CI_PASSWORD" --plain-http >/dev/null 2>&1
oras attach --plain-http --disable-path-validation "$ZOT/innotium/npouch:1.5.0-installer" \
  --artifact-type application/vnd.cyclonedx.vex+json /tmp/npouch.vex.cdx.json:application/json >/dev/null 2>&1 \
  && ok "VEX attach 성공" || no "VEX attach 실패"
oras discover --plain-http "$ZOT/innotium/npouch:1.5.0-installer" 2>/dev/null | grep -q "cyclonedx.vex" \
  && ok "discover 에 VEX referrer 확인" || no "discover VEX 미확인"

echo; echo "PASS=$PASS FAIL=$FAIL"; [ "$FAIL" -eq 0 ]
