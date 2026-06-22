#!/usr/bin/env bash
# Dependency-Track 헤드리스 초기화: admin 비번 변경 → 팀 생성 → 권한 부여 → 서비스 API 키 발급.
# 발급된 DT_API_KEY 를 .env 에 자동 반영한다. (엔드포인트는 설치 버전 API로 검증·보정)
set -uo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a
DT="${DT_LOCAL_URL:-http://localhost:8081}"
ADMIN_PW="${DT_ADMIN_PASSWORD:-dtrack-admin-pw}"

echo "[1/6] DT API Server 기동 대기 (최초 부팅·마이그레이션은 수 분 소요)..."
for i in $(seq 1 120); do curl -fsS "$DT/api/version" >/dev/null 2>&1 && break; sleep 5; echo -n .; done; echo " ok"
curl -s "$DT/api/version" | head -c 200; echo

echo "[2/6] 초기 admin 비밀번호 변경 (admin/admin → 설정값; 이미 변경됐으면 무시)"
curl -s -o /dev/null -X POST "$DT/api/v1/user/forceChangePassword" \
  --data-urlencode "username=admin" --data-urlencode "password=admin" \
  --data-urlencode "newPassword=$ADMIN_PW" --data-urlencode "confirmPassword=$ADMIN_PW" || true

echo "[3/6] admin 로그인 → JWT"
JWT=$(curl -s -X POST "$DT/api/v1/user/login" \
  --data-urlencode "username=admin" --data-urlencode "password=$ADMIN_PW")
case "$JWT" in eyJ*) : ;; *) echo "로그인 실패: $JWT"; exit 1;; esac
AUTH="Authorization: Bearer $JWT"

echo "[4/6] 팀 생성(trustlink-bff)"
TEAM=$(curl -s -H "$AUTH" -H 'Content-Type: application/json' -X PUT "$DT/api/v1/team" -d '{"name":"trustlink-bff"}')
UUID=$(printf '%s' "$TEAM" | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("uuid",""))
except: print("")')
if [ -z "$UUID" ]; then
  UUID=$(curl -s -H "$AUTH" "$DT/api/v1/team" | python3 -c 'import sys,json
[print(t["uuid"]) for t in json.load(sys.stdin) if t.get("name")=="trustlink-bff"]' | head -1)
fi
[ -n "$UUID" ] || { echo "팀 uuid 획득 실패"; exit 1; }
echo "  team uuid=$UUID"

echo "[5/6] 권한 부여"
for P in BOM_UPLOAD PROJECT_CREATION_UPLOAD VIEW_PORTFOLIO VIEW_VULNERABILITY VULNERABILITY_ANALYSIS PORTFOLIO_MANAGEMENT; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTH" -X POST "$DT/api/v1/permission/$P/team/$UUID")
  echo "  $P → $code"
done

echo "[6/6] API 키 발급"
KEY=$(printf '%s' "$TEAM" | python3 -c 'import sys,json
try:
  d=json.load(sys.stdin); k=d.get("apiKeys") or []
  print(k[0].get("key","") if k else "")
except: print("")')
if [ -z "$KEY" ]; then
  KJSON=$(curl -s -H "$AUTH" -X PUT "$DT/api/v1/team/$UUID/key")
  KEY=$(printf '%s' "$KJSON" | python3 -c 'import sys,json
try:
  d=json.load(sys.stdin); print(d.get("key") or d.get("apiKey") or "")
except: print("")')
fi
[ -n "$KEY" ] || { echo "API 키 발급 실패"; exit 1; }
echo "DT_API_KEY=$KEY"
if grep -q '^DT_API_KEY=' .env; then sed -i.bak "s|^DT_API_KEY=.*|DT_API_KEY=$KEY|" .env && rm -f .env.bak; else echo "DT_API_KEY=$KEY" >> .env; fi
echo "→ .env 에 DT_API_KEY 반영 완료. BFF 재기동 시 주입됩니다."
