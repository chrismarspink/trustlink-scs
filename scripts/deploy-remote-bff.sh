#!/usr/bin/env bash
# 상시 서버(218.38.12.14)에 BFF(trustlink-admin) 변경분을 반영한다. Mac(이 저장소)에서 실행.
#   1) 원격 소스·이미지 백업(롤백용 태그 jkkim7202/trustlink-admin:backup-<날짜>)
#   2) 변경 파일 복사 → 원격 네이티브 빌드(UI → go amd64 → docker build) → 재생성
#   3) BFF 컨테이너 IP 가 바뀌면 hairpin iptables DNAT 규칙 갱신(안 하면 zot OIDC 패닉)
# 롤백: ssh 후 `docker tag jkkim7202/trustlink-admin:backup-<날짜> jkkim7202/trustlink-admin:latest`
#       `cd ~/trustlink && docker compose -f docker-compose.deploy.yml up -d --force-recreate trustlink-admin`
# SSH 비밀번호는 실행 중 프롬프트로 입력(키 등록 시 생략).
set -euo pipefail

HOST="${HOST:-218.38.12.14}"; PORT="${PORT:-7422}"; RUSER="${RUSER:-innotium}"
DIR="$(cd "$(dirname "$0")/.." && pwd)"   # deploy/zot-keycloak
FILES=(
  admin-bff/main.go admin-bff/credentials.go admin-bff/credentials_test.go
  trustlink-ui/src/lib/api.ts
  trustlink-ui/src/pages/admin/Users.tsx trustlink-ui/src/pages/admin/CredentialDialog.tsx
)
STAMP="$(date +%Y%m%d-%H%M%S)"
CTRL="/tmp/tl-deploy-$$"   # SSH 연결 재사용(비밀번호 1회 입력)
SSH=(ssh -p "$PORT" -o ControlMaster=auto -o ControlPath="$CTRL" -o ControlPersist=300 "$RUSER@$HOST")
trap 'ssh -o ControlPath="$CTRL" -O exit "$RUSER@$HOST" 2>/dev/null || true' EXIT

echo "[1/4] 백업 ($STAMP)"
"${SSH[@]}" "cd ~/trustlink && mkdir -p ~/backup && tar czf ~/backup/trustlink-src-$STAMP.tgz ${FILES[*]} 2>/dev/null; \
  docker tag jkkim7202/trustlink-admin:latest jkkim7202/trustlink-admin:backup-$STAMP && echo '  이미지 백업: backup-$STAMP'"

echo "[2/4] 파일 복사"
( cd "$DIR" && tar czf - "${FILES[@]}" ) | "${SSH[@]}" "cd ~/trustlink && tar xzf - && echo '  ${#FILES[@]}개 반영'"

echo "[3/4] 원격 빌드·재생성"
"${SSH[@]}" 'set -e; cd ~/trustlink
  ( cd trustlink-ui && npm run build >/dev/null ) && rm -rf admin-bff/ui-dist && cp -R trustlink-ui/dist admin-bff/ui-dist
  docker run --rm -v "$PWD/admin-bff":/src -w /src -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=amd64 golang:1.22 \
    sh -c "go vet ./... && go test -run TestGenTempPassword ./... && go build -o trustlink-admin-linux ."
  docker build -q -t jkkim7202/trustlink-admin:latest admin-bff
  docker compose -f docker-compose.deploy.yml up -d --force-recreate trustlink-admin'

echo "[4/4] hairpin 규칙 확인"
"${SSH[@]}" 'set -e
  IP=$(docker inspect trustlink-trustlink-admin-1 --format "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}")
  CUR=$(sudo -n iptables -t nat -S PREROUTING | grep -- "--dport 28080" | grep -oE "to-destination [0-9.]+" | cut -d" " -f2 || true)
  echo "  BFF IP=$IP, DNAT=$CUR"
  if [ -n "$CUR" ] && [ "$CUR" != "$IP" ]; then
    sudo -n iptables -t nat -S PREROUTING | grep -- "--dport 28080" | sed "s/^-A/-D/" | while read -r r; do sudo -n iptables -t nat $r; done
    sudo -n iptables -t nat -I PREROUTING 1 -p tcp -s 172.16.0.0/12 -d '"$HOST"' --dport 28080 -j DNAT --to-destination "$IP:28080"
    echo "  DNAT 갱신 → $IP"
  fi
  sleep 3; curl -s -o /dev/null -w "  healthz %{http_code}\n" http://127.0.0.1:28080/healthz'
echo "완료. http://$HOST:28080/admin/users 에서 확인."
