#!/usr/bin/env bash
set -euo pipefail
# Keycloak 컨테이너 내부에서 실행된다(bootstrap.sh가 stdin 으로 주입):
#   docker compose exec -T keycloak bash < keycloak/configure-realm.sh
# 대상 버전: Keycloak 26.x (kcadm.sh). 멱등하게 동작하도록 작성.
KC=/opt/keycloak/bin/kcadm.sh
REALM=trustlink
ADMIN="${KC_ADMIN:-admin}"
ADMIN_PW="${KC_ADMIN_PASSWORD:?set KC_ADMIN_PASSWORD}"
FRONT_HOST="${FRONT_HOST:-trustlink}"
FRONT_PORT="${FRONT_PORT:-28080}"
ORIGIN="http://${FRONT_HOST}:${FRONT_PORT}"
ADMIN_SECRET="${TRUSTLINK_ADMIN_SECRET:-}"   # BFF(trustlink-admin) 클라이언트 시크릿(.env)

$KC config credentials --server http://localhost:8085 --realm master --user "$ADMIN" --password "$ADMIN_PW"

# 1) realm
$KC create realms -s realm=$REALM -s enabled=true 2>/dev/null && echo "realm created" || echo "realm exists"

# 2) groups
for g in developers partners customers admins; do
  $KC create groups -r $REALM -s name="$g" 2>/dev/null && echo "group $g created" || echo "group $g exists"
done

# 3) client(zot): confidential + standard flow(+ direct grant: 검증 스크립트의 토큰 발급용, PoC 전용)
CID=$($KC get clients -r $REALM -q clientId=zot --fields id --format csv --noquotes 2>/dev/null | tail -1)
if [ -z "${CID}" ]; then
  CID=$($KC create clients -r $REALM -i \
    -s clientId=zot -s enabled=true -s protocol=openid-connect \
    -s publicClient=false -s standardFlowEnabled=true -s directAccessGrantsEnabled=true \
    -s "redirectUris=[\"${ORIGIN}/zot/auth/callback/oidc\",\"${ORIGIN}/*\",\"http://localhost:28080/*\",\"http://localhost:5002/*\"]" \
    -s 'webOrigins=["+"]')
  echo "client zot created ($CID)"
else
  echo "client zot exists ($CID)"
fi

# 4) group-membership 매퍼: 토큰에 groups 클레임을 full path 없이 싣는다(claim 이름 = groups).
#    클라이언트 dedicated scope 에 추가되므로 별도 'groups' scope 요청 없이 항상 토큰에 포함된다.
$KC create clients/$CID/protocol-mappers/models -r $REALM \
  -s name=groups -s protocol=openid-connect \
  -s protocolMapper=oidc-group-membership-mapper \
  -s 'config."claim.name"=groups' \
  -s 'config."full.path"=false' \
  -s 'config."id.token.claim"=true' \
  -s 'config."access.token.claim"=true' \
  -s 'config."userinfo.token.claim"=true' 2>/dev/null && echo "mapper created" || echo "mapper exists"

# 3-b) client(trustlink-admin = BFF 단일 프론트도어). confidential + standard flow.
#      시크릿은 .env 의 TRUSTLINK_ADMIN_SECRET 로 고정(BFF env 와 일치해야 로그인 성공).
AID=$($KC get clients -r $REALM -q clientId=trustlink-admin --fields id --format csv --noquotes 2>/dev/null | tail -1)
if [ -z "${AID}" ]; then
  AID=$($KC create clients -r $REALM -i \
    -s clientId=trustlink-admin -s enabled=true -s protocol=openid-connect \
    -s publicClient=false -s standardFlowEnabled=true -s directAccessGrantsEnabled=true \
    -s "redirectUris=[\"${ORIGIN}/admin/callback\"]" -s 'webOrigins=["+"]')
  echo "client trustlink-admin created ($AID)"
else
  echo "client trustlink-admin exists ($AID)"
fi
[ -n "${ADMIN_SECRET}" ] && $KC update clients/$AID -r $REALM -s secret="${ADMIN_SECRET}" 2>/dev/null \
  && echo "trustlink-admin secret set" || echo "WARN: TRUSTLINK_ADMIN_SECRET 미설정 — BFF 로그인 실패할 수 있음"
# groups 매퍼(동일 — 토큰에 groups 클레임)
$KC create clients/$AID/protocol-mappers/models -r $REALM \
  -s name=groups -s protocol=openid-connect \
  -s protocolMapper=oidc-group-membership-mapper \
  -s 'config."claim.name"=groups' -s 'config."full.path"=false' \
  -s 'config."id.token.claim"=true' -s 'config."access.token.claim"=true' \
  -s 'config."userinfo.token.claim"=true' 2>/dev/null && echo "admin mapper created" || echo "admin mapper exists"

# 5) 샘플 사용자(역할별 1명) + 그룹 배정
# 컨테이너에 awk 가 없어 csv(id,name) 를 grep/cut 로 파싱한다.
gid_of() { $KC get groups -r $REALM --fields id,name --format csv --noquotes 2>/dev/null | grep ",$1\$" | cut -d, -f1 | tail -1; }
create_user() { # $1 user  $2 group
  # emailVerified/firstName/lastName 미설정 시 declarative user-profile 때문에
  # "Account is not fully set up" 으로 로그인/그랜트가 실패하므로 함께 설정한다.
  $KC create users -r $REALM -s username="$1" -s enabled=true -s emailVerified=true \
    -s email="$1@innotium.local" -s firstName="$1" -s lastName=user 2>/dev/null \
    && echo "user $1 created" || echo "user $1 exists"
  $KC set-password -r $REALM --username "$1" --new-password "Passw0rd!"
  local uid gid
  uid=$($KC get users -r $REALM -q username="$1" --fields id --format csv --noquotes 2>/dev/null | tail -1)
  # 기존 사용자(이전 실행분)도 프로필 필드를 강제해 멱등하게 보정한다.
  [ -n "$uid" ] && $KC update users/$uid -r $REALM \
    -s emailVerified=true -s firstName="$1" -s lastName=user 2>/dev/null || true
  gid=$(gid_of "$2")
  if [ -n "$uid" ] && [ -n "$gid" ]; then
    $KC update users/$uid/groups/$gid -r $REALM -s realm=$REALM -s userId=$uid -s groupId=$gid -n 2>/dev/null \
      && echo "  $1 -> $2 ok" || echo "  $1 -> $2 (already member)"
  else
    echo "  WARN: could not resolve uid/gid for $1 -> $2 (uid=$uid gid=$gid)"
  fi
}
# 역할별 테스트 사용자 (각 그룹 2명) — 공통 비밀번호 Passw0rd! (PoC 전용)
#  developers: README 편집 / VEX 첨부·수정 / 서명 검증 (read+create+update)
#  partners/customers: 조회(read)  |  admins: 전체(+delete) + 관리 콘솔
create_user dev1     developers
create_user dev2     developers
create_user partner1 partners
create_user partner2 partners
create_user acme1    customers
create_user acme2    customers
create_user admin1   admins
create_user admin2   admins

# 6) 클라이언트 시크릿 출력(bootstrap.sh가 .env 와 zot/config.json 에 반영)
SECRET=$($KC get clients/$CID/client-secret -r $REALM --fields value --format csv --noquotes 2>/dev/null | tail -1)
echo "ZOT_OIDC_CLIENT_SECRET=${SECRET}"
echo "done. 샘플 비밀번호: Passw0rd!  (PoC 전용)"
