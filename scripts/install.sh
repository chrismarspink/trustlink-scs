#!/usr/bin/env bash
# TrustLink SCS 원커맨드 설치 — 통합 compose(docker-compose.deploy.yml) 기반.
#   이미지 pull → 시크릿/htpasswd → Keycloak/CA/DT 기동 → realm 구성 → CA 인증서 추출
#   → zot/BFF 기동 → DT 부트스트랩. (단순 `docker compose up` 으로는 step-ca 인증서 생성 순서를
#   맞출 수 없어 본 스크립트가 단계화한다.)
#
#   사전: docker, docker compose, (htpasswd 또는 docker httpd:2.4), openssl, curl, python3.
#   실행:  bash scripts/install.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export COMPOSE_FILE=docker-compose.deploy.yml
DC="docker compose"

# 0) .env
[ -f .env ] || { cp .env.example .env; echo "[.env] .env.example 복사 — 시크릿을 편집하세요(KC_ADMIN_PASSWORD 등)."; }
set -a; source .env; set +a
: "${FRONT_HOST:=trustlink}"; : "${FRONT_PORT:=28080}"
: "${TRUSTLINK_ADMIN_SECRET:?".env 에 TRUSTLINK_ADMIN_SECRET 설정 필요"}"

# 1) step-ca provisioner 비밀번호(없으면 생성) — step-ca init + BFF 마운트 공용
mkdir -p stepca zot
if [ ! -f stepca/ca-password ]; then
  openssl rand -base64 24 | tr -d '\n' > stepca/ca-password
  echo "[1] stepca/ca-password 생성"
fi

# 2) htpasswd: ci(CLI) + svc-bff(BFF 관리)
hp() { if command -v htpasswd >/dev/null 2>&1; then htpasswd -bBn "$1" "$2"; else docker run --rm httpd:2.4 htpasswd -bBn "$1" "$2"; fi; }
{ hp ci "${CI_PASSWORD}"; hp svc-bff "${SVC_BFF_PASS}"; } > zot/htpasswd
echo "[2] htpasswd(ci, svc-bff) 생성"

# 3) 이미지 다운로드
echo "[3] 이미지 pull..."; $DC pull -q 2>/dev/null || $DC pull

# 4) Keycloak/CA/DT 먼저 기동(인증서·realm 의존 없는 것)
echo "[4] keycloak·step-ca·dtrack 기동..."
$DC up -d keycloak step-ca dtrack-db dtrack-apiserver
echo -n "    Keycloak healthy 대기"
until [ "$($DC ps keycloak --format '{{.Health}}' 2>/dev/null)" = "healthy" ]; do echo -n "."; sleep 3; done; echo " ok"

# 5) realm/clients(zot+trustlink-admin)/groups/users 구성 → zot 시크릿 반영
echo "[5] realm 구성..."
$DC exec -T \
  -e KC_ADMIN="${KC_ADMIN}" -e KC_ADMIN_PASSWORD="${KC_ADMIN_PASSWORD}" \
  -e FRONT_HOST="${FRONT_HOST}" -e FRONT_PORT="${FRONT_PORT}" -e TRUSTLINK_ADMIN_SECRET="${TRUSTLINK_ADMIN_SECRET}" \
  keycloak bash < keycloak/configure-realm.sh | tee /tmp/tl-realm.txt
SECRET=$(grep '^ZOT_OIDC_CLIENT_SECRET=' /tmp/tl-realm.txt | tail -1 | cut -d= -f2-)
[ -n "${SECRET}" ] || { echo "ERROR: zot 클라이언트 시크릿 획득 실패" >&2; exit 1; }
if grep -q '^ZOT_OIDC_CLIENT_SECRET=' .env; then sed -i.bak "s|^ZOT_OIDC_CLIENT_SECRET=.*|ZOT_OIDC_CLIENT_SECRET=${SECRET}|" .env && rm -f .env.bak; else echo "ZOT_OIDC_CLIENT_SECRET=${SECRET}" >> .env; fi
printf '{ "clientid": "zot", "clientsecret": "%s" }\n' "${SECRET}" > zot/oidc-credentials.json
echo "[5] zot OIDC 시크릿 반영"

# 6) step-ca 가 생성한 Root/Intermediate 를 호스트로 추출(BFF 가 마운트 — 다운로드/검증용)
echo "[6] CA 인증서 추출..."
$DC exec -T step-ca cat /home/step/certs/root_ca.crt         > stepca/root_ca.crt
$DC exec -T step-ca cat /home/step/certs/intermediate_ca.crt > stepca/issuer_ca.crt

# 7) zot + BFF 기동(시크릿·인증서 준비 후)
echo "[7] zot·trustlink-admin 기동..."
$DC up -d zot trustlink-admin

# 8) Dependency-Track 부트스트랩(API 키 → .env) 후 BFF 재기동(DT_API_KEY 주입)
echo -n "[8] DT healthy 대기"
until [ "$($DC ps dtrack-apiserver --format '{{.Health}}' 2>/dev/null)" = "healthy" ]; do echo -n "."; sleep 5; done; echo " ok"
bash scripts/dt-bootstrap.sh || echo "WARN: dt-bootstrap 실패(수동 확인). DT 없이도 핵심 기능은 동작."
set -a; source .env; set +a
$DC up -d --force-recreate trustlink-admin

echo
echo "완료. 접속: http://${FRONT_HOST}:${FRONT_PORT}  (/etc/hosts 에 '127.0.0.1 ${FRONT_HOST}')"
echo "로그인: Keycloak(admin1/Passw0rd! 등 PoC). 레지스트리: oras login ${FRONT_HOST}:28081 -u ci -p <CI_PASSWORD> --plain-http"
echo "검증: bash scripts/verify.sh"
