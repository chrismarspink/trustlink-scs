#!/usr/bin/env bash
# 상시 서버에 최신 main 을 반영한다. Mac(이 저장소)에서 실행. 원격 ~/trustlink 는 이 저장소의 git clone.
#   1) 원격 작업트리가 깨끗한지 확인 → git pull --ff-only
#   2) BFF 이미지 원격 빌드(admin-bff/build.sh: UI → go → docker build, .env 의 TRUSTLINK_ADMIN_IMAGE 로 태깅)
#   3) docker compose up -d (변경된 서비스만 재생성, 데이터 볼륨 유지)
#   4) 컨테이너 → OIDC issuer(FRONT_HOST) 도달 확인 (NAT 조작 없음 — 방화벽 규칙 1줄로 충족, INSTALL.md 0절)
#
# 최초 1회(구 구성 → 새 구성): 원격 .env 에 새 항목(KC_DB_PASSWORD·TL_ADMIN_* 등, .env.example 참고) 추가 후
#   ssh 로 들어가 `bash scripts/migrate-keycloak-h2.sh` 를 먼저 실행한다(계정 이전).
# SSH 비밀번호는 실행 중 프롬프트로 입력(키 등록 시 생략).
set -euo pipefail

HOST="${HOST:-218.38.12.14}"; PORT="${PORT:-7422}"; RUSER="${RUSER:-innotium}"; RDIR="${RDIR:-trustlink}"
CTRL="/tmp/tl-deploy-$$"   # SSH 연결 재사용(비밀번호 1회 입력)
SSH=(ssh -p "$PORT" -o ControlMaster=auto -o ControlPath="$CTRL" -o ControlPersist=300 "$RUSER@$HOST")
trap 'ssh -o ControlPath="$CTRL" -O exit "$RUSER@$HOST" 2>/dev/null || true' EXIT

echo "[1/4] git pull"
"${SSH[@]}" "set -e; cd ~/$RDIR
  if [ -n \"\$(git status --porcelain --untracked-files=no)\" ]; then
    echo '  원격 작업트리에 커밋 안 된 수정이 있어 중단:'; git status --short --untracked-files=no; exit 1; fi
  git pull --ff-only && git log --oneline -1"

echo "[2/4] BFF 빌드"
"${SSH[@]}" "cd ~/$RDIR && bash admin-bff/build.sh >/dev/null && echo '  ok'"

echo "[3/4] docker compose up -d"
"${SSH[@]}" "cd ~/$RDIR && docker compose up -d --wait --wait-timeout 300 2>&1 | grep -iE 'error|unhealthy' || true; docker compose ps --format '  {{.Service}}\t{{.Status}}'"

echo "[4/4] 컨테이너 → OIDC issuer 도달 확인 (zot 로그인 전제)"
"${SSH[@]}" "cd ~/$RDIR && set -a && . ./.env && set +a
  NET=\$(docker inspect \$(docker compose ps -q zot) --format '{{range \$k,\$v := .NetworkSettings.Networks}}{{\$k}}{{end}}')
  code=\$(docker run --rm --network \$NET curlimages/curl:8.10.1 -s -m 8 -o /dev/null -w '%{http_code}' http://\$FRONT_HOST:\$FRONT_PORT/auth/realms/trustlink/.well-known/openid-configuration)
  echo \"  issuer \$code\"
  [ \"\$code\" = 200 ] || echo '  ✗ 방화벽 확인: sudo ufw allow from 172.16.0.0/12 to any port '\$FRONT_PORT' proto tcp (INSTALL.md 0절)'"
echo "완료. http://$HOST:28080"
