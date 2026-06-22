#!/usr/bin/env sh
# trustlink-admin(BFF) 빌드·배포.
#  주의: compose 의 trustlink-admin 서비스에는 build: 섹션이 없다(image+pull_policy:never).
#        따라서 `docker compose build` 는 no-op 이며 새 코드가 배포되지 않는다.
#        반드시 아래 순서(바이너리 → 이미지 docker build → recreate)로 배포할 것.
#  go 1.22+ 필요 → 로컬 go 버전 무관하게 golang:1.22 컨테이너로 cross-compile.
set -e
cd "$(dirname "$0")"

ARCH="${ARCH:-arm64}" # zot:latest/호스트 아키텍처에 맞춤(arm64). amd64 면 ARCH=amd64.

echo "[1/4] UI 빌드 + ui-dist 동기화"
( cd ../trustlink-ui && npm run build )
rm -rf ui-dist && cp -R ../trustlink-ui/dist ui-dist

echo "[2/4] go 빌드 (linux/$ARCH, golang:1.22)"
docker run --rm -v "$PWD":/src -w /src \
  -e CGO_ENABLED=0 -e GOOS=linux -e "GOARCH=$ARCH" \
  golang:1.22 go build -o trustlink-admin-linux .

echo "[3/4] 이미지 빌드 (docker build — compose build 아님)"
docker build -t trustlink-admin:latest .

echo "[4/4] 재배포"
( cd .. && docker compose up -d --force-recreate trustlink-admin )
echo "done."
