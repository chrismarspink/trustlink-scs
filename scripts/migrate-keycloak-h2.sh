#!/usr/bin/env bash
# (1회용) 구 구성 → 새 구성 Keycloak 계정 이전.
#   구: Keycloak start-dev + 내장 H2 (볼륨 <project>_kc-data)
#   신: Keycloak start + 전용 Postgres (keycloak-db, 볼륨 <project>_kc-db)
#   realm·사용자·그룹·클라이언트를 공식 kc.sh export/import 로 옮긴다. 비밀번호 해시가 그대로 이전되므로
#   기존 비밀번호가 유지된다. 구 볼륨은 손대지 않고(사본에서 export) 남겨 둔다 → 롤백 가능.
#
# 사용: 새 docker-compose.yaml 과 .env(KC_DB_PASSWORD 등 신규 항목 포함) 준비 후
#   bash scripts/migrate-keycloak-h2.sh
#   - 프로젝트 이름은 compose 기준(name: trustlink, 또는 .env 의 COMPOSE_PROJECT_NAME)
#   - 구 볼륨 이름이 다르면 OLD_VOL=<볼륨> 지정
#   - .env 의 ZOT_OIDC_CLIENT_SECRET·TRUSTLINK_ADMIN_SECRET 은 구 설치 값 그대로 둔다(이전된 클라이언트 시크릿과 일치해야 함)
set -euo pipefail
cd "$(dirname "$0")/.."

PROJECT="$(docker compose config --format json | python3 -c 'import json,sys;print(json.load(sys.stdin)["name"])')"
OLD_VOL="${OLD_VOL:-${PROJECT}_kc-data}"
IMAGE="$(docker compose config --images | grep -m1 keycloak/keycloak)"
STAMP="$(date +%Y%m%d-%H%M%S)"
COPY_VOL="${OLD_VOL}-migrate-${STAMP}"
EXPORT="$(mktemp -d)"; chmod 777 "$EXPORT"
trap 'rm -rf "$EXPORT"' EXIT

docker volume inspect "$OLD_VOL" >/dev/null 2>&1 || { echo "구 H2 볼륨 없음: $OLD_VOL (OLD_VOL=… 로 지정)" >&2; exit 1; }
echo "[1/5] 구 Keycloak 정지 (H2 파일 잠금 해제) — project=$PROJECT vol=$OLD_VOL"
ids="$(docker ps -q --filter "volume=$OLD_VOL")"
[ -n "$ids" ] && docker stop $ids >/dev/null
docker compose stop keycloak >/dev/null 2>&1 || true

echo "[2/5] 구 볼륨 사본 생성 → $COPY_VOL (원본 보존)"
docker volume create "$COPY_VOL" >/dev/null
docker run --rm --user 0 -v "$OLD_VOL":/from:ro -v "$COPY_VOL":/to --entrypoint sh "$IMAGE" -c 'cp -a /from/. /to/'

echo "[3/5] H2 사본에서 trustlink realm export ($IMAGE)"
docker run --rm -v "$COPY_VOL":/opt/keycloak/data -v "$EXPORT":/export --entrypoint /opt/keycloak/bin/kc.sh \
  "$IMAGE" export --db dev-file --dir /export --realm trustlink --users realm_file >/dev/null
ls "$EXPORT"/trustlink-realm.json >/dev/null

echo "[4/5] Postgres(keycloak-db) 로 import (기존 trustlink realm 은 덮어씀)"
docker compose up -d --wait keycloak-db >/dev/null
docker compose run --rm --no-deps -v "$EXPORT":/export keycloak import --dir /export --override true >/dev/null

echo "[5/5] 기동 + BFF 서비스계정 권한 보정(사용자 생성·재설정용 manage-users 등)"
docker compose up -d --wait keycloak >/dev/null
docker compose exec -T keycloak bash -c '
  KC=/opt/keycloak/bin/kcadm.sh
  $KC config credentials --server http://localhost:8085/auth --realm master \
    --user "$KC_BOOTSTRAP_ADMIN_USERNAME" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >/dev/null
  $KC add-roles -r trustlink --uusername service-account-trustlink-admin --cclientid realm-management \
    --rolename view-users --rolename query-users --rolename query-groups --rolename manage-users --rolename view-realm
  echo "  사용자 수: $($KC get users -r trustlink --fields username --format csv --noquotes | wc -l)"'

echo "완료. 나머지 서비스 기동: docker compose up -d"
echo "구 볼륨($OLD_VOL)·사본($COPY_VOL)은 확인 후 수동 삭제: docker volume rm $OLD_VOL $COPY_VOL"
