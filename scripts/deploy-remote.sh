#!/usr/bin/env bash
# 상시 서버에 최신 main 을 반영한다. Mac(이 저장소)에서 실행. 원격 ~/trustlink 는 이 저장소의 git clone.
#   1) 원격 작업트리가 깨끗한지 확인 → git pull --ff-only
#   2) BFF 이미지 원격 빌드(admin-bff/build.sh: UI → go → docker build, .env 의 TRUSTLINK_ADMIN_IMAGE 로 태깅)
#   3) docker compose up -d (변경된 서비스만 재생성, 데이터 볼륨 유지)
#   4) BFF 컨테이너 IP 가 바뀌면 hairpin iptables DNAT 갱신(공인 IP 를 FRONT_HOST 로 쓰는 서버 전용)
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

echo "[4/4] hairpin 규칙 확인"
"${SSH[@]}" 'set -e
  C=$(docker ps --filter label=com.docker.compose.service=trustlink-admin -q | head -1)
  IP=$(docker inspect "$C" --format "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}")
  CUR=$(sudo -n iptables -t nat -S PREROUTING | grep -- "--dport 28080" | grep -oE "to-destination [0-9.]+" | cut -d" " -f2 || true)
  echo "  BFF IP=$IP, DNAT=${CUR:-없음}"
  if [ -n "$CUR" ] && [ "$CUR" != "$IP" ]; then   # DNAT + MASQUERADE 둘 다 BFF IP 를 가리켜야 함
    for CH in PREROUTING POSTROUTING; do
      sudo -n iptables -t nat -S $CH | grep -- "--dport 28080" | sed "s/^-A/-D/" | while read -r r; do sudo -n iptables -t nat $r; done
    done
    sudo -n iptables -t nat -I PREROUTING 1 -p tcp -s 172.16.0.0/12 -d '"$HOST"' --dport 28080 -j DNAT --to-destination "$IP:28080"
    sudo -n iptables -t nat -I POSTROUTING 1 -p tcp -s 172.16.0.0/12 -d "$IP" --dport 28080 -j MASQUERADE
    docker compose restart zot >/dev/null   # issuer 도달 실패로 재시작 중이던 zot 복구
    echo "  DNAT·MASQUERADE 갱신 → $IP"
  fi
  sleep 3; curl -s -o /dev/null -w "  healthz %{http_code}\n" http://127.0.0.1:28080/healthz'
echo "완료. http://$HOST:28080"
