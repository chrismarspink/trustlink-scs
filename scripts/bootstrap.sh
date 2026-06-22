#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || cp .env.example .env
set -a; source .env; set +a

# 1) 기계/CLI용 htpasswd 계정(ci) 생성 (bcrypt).
#    오프라인 보정: httpd:2.4 이미지를 받을 수 없어 호스트의 htpasswd 를 사용한다.
mkdir -p zot
if command -v htpasswd >/dev/null 2>&1; then
  htpasswd -bBn ci "${CI_PASSWORD}" > zot/htpasswd
else
  docker run --rm httpd:2.4 htpasswd -bBn ci "${CI_PASSWORD}" > zot/htpasswd
fi
echo "[1/5] htpasswd(ci) 생성 완료"

# 2) Keycloak 기동(healthcheck 가 통과할 때까지 대기). zot 은 시크릿 반영 후 마지막에 띄운다.
echo "[2/5] Keycloak 기동..."
docker compose up -d keycloak
echo -n "      Keycloak healthy 대기"
until [ "$(docker compose ps keycloak --format '{{.Health}}' 2>/dev/null)" = "healthy" ]; do
  echo -n "."; sleep 3
done
echo " ok"

# 3) realm/client/groups/users 구성
echo "[3/5] realm 구성..."
docker compose exec -T -e KC_ADMIN="${KC_ADMIN}" -e KC_ADMIN_PASSWORD="${KC_ADMIN_PASSWORD}" \
  keycloak bash < keycloak/configure-realm.sh | tee /tmp/realm-out.txt

# 4) 시크릿을 .env 와 zot/config.json 에 반영
SECRET=$(grep '^ZOT_OIDC_CLIENT_SECRET=' /tmp/realm-out.txt | tail -1 | cut -d= -f2-)
if [ -z "${SECRET}" ]; then
  echo "ERROR: 클라이언트 시크릿을 얻지 못했습니다. /tmp/realm-out.txt 확인." >&2
  exit 1
fi
echo "[4/5] 시크릿 반영 (.env, zot/oidc-credentials.json)"
# .env (verify.sh 가 토큰 검증에 사용)
if grep -q '^ZOT_OIDC_CLIENT_SECRET=' .env; then
  sed -i.bak "s|^ZOT_OIDC_CLIENT_SECRET=.*|ZOT_OIDC_CLIENT_SECRET=${SECRET}|" .env && rm -f .env.bak
else
  echo "ZOT_OIDC_CLIENT_SECRET=${SECRET}" >> .env
fi
# zot 가 읽는 OpenID credentialsfile (시크릿을 config.json 에서 분리 → git 커밋 안전).
cat > zot/oidc-credentials.json <<EOF
{ "clientid": "zot", "clientsecret": "${SECRET}" }
EOF

# 5) zot 기동(설정 반영 후)
echo "[5/5] zot 기동..."
docker compose up -d zot

echo
echo "완료. 다음으로 검증: bash scripts/verify.sh"
echo "브라우저 OIDC 로그인 테스트는 /etc/hosts 에 '127.0.0.1 keycloak' 추가 후"
echo "http://localhost:5002/ 접속 (dev1 / Passw0rd!). 자세한 내용은 README.md 참고."
