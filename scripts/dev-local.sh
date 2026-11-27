#!/usr/bin/env bash
# 개발 PC(맥북)에서 TrustLink 를 로컬로 띄운다 — 회사망·상시 서버 없이 개발할 때.
#
#   scripts/dev-local.sh up        UI·BFF 를 빌드해 이미지로 만들고 스택을 띄운다(데이터 볼륨은 그대로)
#   scripts/dev-local.sh build     코드를 고친 뒤 이미지만 다시 만들어 trustlink-admin·vuln-mirror 만 교체
#   scripts/dev-local.sh check|ps|logs [서비스]|down|url
#
# - 설정은 .env 에서 읽는다(이 스크립트는 .env 를 만들거나 고치지 않는다). 필수 항목이 빠져 있으면 check 가 알려 준다.
# - 기본으로 PDF 변환(gotenberg, 이미지 약 1.6GB)과 로컬 AI 는 띄우지 않는다. PDF 가 필요하면 PDF=1, 시연 계정은 DEMO=1.
# - 취약점 DB 미러는 뜨지만 폐쇄망 모드(받지 않음)다. 전체는 10~15GB 라서 디스크가 넉넉할 때만
#   관리 화면에서 작은 출처(KEV·EPSS·EOL 등)만 골라 켠다.
# - go 1.25+ 가 PC 에 있으면 그것으로, 없으면 golang:1.25 컨테이너로 빌드한다.
set -euo pipefail
cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-zot-keycloak}"   # 이 PC 의 기존 볼륨(zot-keycloak_*)을 쓴다
DC=(docker compose)
SVCS=(keycloak-db keycloak zot trustlink-admin dtrack-db dtrack-apiserver vuln-mirror)
[ "${PDF:-0}" = 1 ] && SVCS+=(gotenberg)
if [ "${DEMO:-0}" = 1 ]; then DC+=(--profile demo); SVCS+=(keycloak-demo-users); fi

check() {
  local err free
  if ! err="$("${DC[@]}" config -q 2>&1)"; then
    echo "설정(.env)에 빠진 항목이 있습니다:"; echo "$err" | grep -oE 'required variable [A-Z_]+' | sort -u | sed 's/required variable /  - /'
    echo "  .env 에 추가한 뒤 다시 실행하세요(.env.example 참고)."; return 1
  fi
  free="$(docker run --rm alpine df -m / | awk 'END{print $4}')"
  echo "Docker 디스크 여유: ${free}MB"
  [ "$free" -ge 3000 ] || echo "  ⚠ 3GB 미만입니다. Dependency-Track 이 DB 를 받다가 멈출 수 있습니다 — 안 쓰는 이미지·볼륨을 정리하거나 Docker Desktop 디스크 한도를 늘리세요."
}

build() {
  local arch image go g
  arch="$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"
  image="$("${DC[@]}" config --images | grep trustlink-admin | head -1)"
  echo "[빌드] UI"
  ( cd trustlink-ui && { [ node_modules/.package-lock.json -nt package-lock.json ] || npm ci; } && npm run build >/dev/null )
  rm -rf admin-bff/ui-dist && cp -R trustlink-ui/dist admin-bff/ui-dist
  echo "[빌드] BFF (linux/$arch)"
  go="$(command -v go || true)"; for g in "$HOME"/sdk/go1.*/bin/go; do [ -x "$g" ] && go="$g"; done
  if [ -n "$go" ] && "$go" version | grep -qE 'go1\.(2[5-9]|[3-9][0-9])'; then
    ( cd admin-bff && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "$go" build -o trustlink-admin-linux . )
  else
    docker run --rm -v "$PWD/admin-bff":/src -w /src -e CGO_ENABLED=0 -e GOOS=linux -e "GOARCH=$arch" golang:1.25 go build -o trustlink-admin-linux .
  fi
  echo "[빌드] 이미지 → $image"
  docker build -q -t "$image" admin-bff >/dev/null
}

url() { "${DC[@]}" config --format json | python3 -c "import json,sys; e=json.load(sys.stdin)['services']['trustlink-admin']['environment']; print(e['KC_PUBLIC'].rsplit('/auth',1)[0])"; }

case "${1:-up}" in
  check) check ;;
  up)    check; build; "${DC[@]}" up -d "${SVCS[@]}"; echo "주소: $(url)  (Dependency-Track 은 처음 뜰 때 2~3분 걸립니다)" ;;
  build) check; build; "${DC[@]}" up -d --no-deps --force-recreate trustlink-admin vuln-mirror ;;
  ps)    "${DC[@]}" ps --format 'table {{.Service}}\t{{.Status}}' ;;
  logs)  shift; "${DC[@]}" logs --tail=100 "$@" ;;
  down)  "${DC[@]}" stop ;;   # 컨테이너만 멈춘다(볼륨·데이터 유지)
  url)   url ;;
  *)     echo "사용법: $0 up|build|check|ps|logs [서비스]|down|url"; exit 1 ;;
esac
