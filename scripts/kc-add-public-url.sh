#!/usr/bin/env bash
# 이미 설치된 서버에서 PUBLIC_URL(예: https 도메인)을 Keycloak 클라이언트(zot·trustlink-admin)의 리다이렉트 주소에 더한다.
# realm import 는 realm 이 이미 있으면 건너뛰므로 compose 의 redirectUris 변경이 기존 realm 에 반영되지 않는다.
# 기존 주소는 지우지 않는다(전환 기간). 여러 번 실행해도 같다. 서버의 compose 디렉터리(~/trustlink)에서 실행.
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a
: "${PUBLIC_URL:?.env 에 PUBLIC_URL 필요}"

kc() { docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh "$@"; }
docker compose exec -T -e P="$KC_ADMIN_PASSWORD" keycloak sh -c \
  '/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8085/auth --realm master --user "'"${KC_ADMIN:-admin}"'" --password "$P"' >/dev/null

for cid in zot trustlink-admin; do
  json=$(kc get clients -r trustlink -q clientId=$cid --fields id,redirectUris,attributes)
  if [ "$cid" = zot ]; then want="$PUBLIC_URL/zot/auth/callback/oidc $PUBLIC_URL/*"; else want="$PUBLIC_URL/admin/callback"; fi
  # 기존 목록 + 없는 주소만 더한 kcadm -s 인자를 만든다
  args=$(WANT="$want" LOGOUT="$PUBLIC_URL/*" python3 -c '
import json, os, sys
c = json.load(sys.stdin)[0]
uris = c.get("redirectUris", [])
for u in os.environ["WANT"].split():
    if u not in uris: uris.append(u)
print(c["id"]); print(json.dumps(uris))
lo = [u for u in c.get("attributes", {}).get("post.logout.redirect.uris", "").split("##") if u]
if os.environ["LOGOUT"] not in lo: lo.append(os.environ["LOGOUT"])
print("##".join(lo))' <<<"$json")
  id=$(sed -n 1p <<<"$args"); uris=$(sed -n 2p <<<"$args"); logout=$(sed -n 3p <<<"$args")
  kc update clients/$id -r trustlink -s "redirectUris=$uris" -s "attributes.\"post.logout.redirect.uris\"=$logout"
  echo "  $cid: $uris"
done
