#!/usr/bin/env sh
# trustlink-admin(BFF+UI) 로컬 빌드·재배포 (개발용).
#  - compose 가 쓰는 이미지 이름(.env TRUSTLINK_ADMIN_IMAGE)으로 태깅한 뒤 BFF 만 재생성한다.
#    개발 PC 의 .env 에는 TRUSTLINK_ADMIN_IMAGE=trustlink-admin:latest 를 권장
#    (Docker Hub 이름을 그대로 쓰면 `docker compose pull` 시 로컬 빌드가 덮어써진다).
#  - go 1.22+ 필요 → 로컬 go 버전 무관하게 golang:1.22 컨테이너로 cross-compile.
set -e
cd "$(dirname "$0")"

ARCH="${ARCH:-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')}"
IMAGE="$(cd .. && docker compose config --images 2>/dev/null | grep trustlink-admin || echo trustlink-admin:latest)"

echo "[1/4] UI 빌드 + ui-dist 동기화"
# package-lock.json 이 설치본보다 새로우면(의존성 변경) npm ci 로 맞춘다
( cd ../trustlink-ui && { [ node_modules/.package-lock.json -nt package-lock.json ] || npm ci; } && npm run build )
rm -rf ui-dist && cp -R ../trustlink-ui/dist ui-dist

echo "[2/4] go 빌드 (linux/$ARCH, golang:1.22)"
docker run --rm -v "$PWD":/src -w /src \
  -e CGO_ENABLED=0 -e GOOS=linux -e "GOARCH=$ARCH" \
  golang:1.22 go build -o trustlink-admin-linux .

echo "[3/4] 이미지 빌드 → $IMAGE"
docker build -t "$IMAGE" .

echo "[4/4] 재배포"
( cd .. && docker compose up -d --no-deps --force-recreate trustlink-admin )
echo "done."
