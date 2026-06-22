#!/usr/bin/env bash
# TrustLink 전체 스택을 TrustLink(zot) 에 올린다 — 설치 배포용.
#   각 컨테이너 이미지를 `docker save | gzip` 하여 oras 아티팩트로 push(데몬 insecure 설정 불필요,
#   air-gap 친화, 전 이미지 동일 방식). + 설치 패키지(compose+설정+이미지목록) push 후 CMS 서명(.p7s).
#
# 설치(수신 측):
#   oras pull  trustlink:28081/innotium/trustlink-install:<ver> -o ./install   # 설치 패키지
#   (선택) openssl cms -verify -inform DER -in *.signed.p7s -CAfile root_ca.crt -purpose any  # 서명 검증
#   images.txt 의 각 이미지: oras pull ... -o . && docker load -i <comp>.tar.gz
#   docker compose -f docker-compose.yml up -d
#
# 도구: oras, docker, curl, python3. ci/admin 자격은 PoC 기본값(공개) — 운영은 env 주입.
set -u
VER="${VER:-$(date +%Y%m%d-%H%M%S)}"
REG="${REG:-trustlink:28081}"; BFF="${BFF:-http://trustlink:28080}"; NS="${NS:-innotium}"
CI_USER="${CI_USER:-ci}"; CI_PASS="${CI_PASS:-ci-poc-pw}"
ADMIN_USER="${ADMIN_USER:-admin1}"; ADMIN_PASS="${ADMIN_PASS:-Passw0rd!}"
DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-$(mktemp -d)}"; mkdir -p "$WORK/install"

# 컴포넌트 → 로컬 이미지
IMAGES="
trustlink-admin|trustlink-admin:latest
zot|trustlink:latest
keycloak|quay.io/keycloak/keycloak:latest
step-ca|smallstep/step-ca:latest
dependency-track|dependencytrack/apiserver:latest
postgres|postgres:16
"

echo "TrustLink 스택 push — VER=$VER REG=$REG NS=$NS"
: > "$WORK/install/images.txt"
echo "$IMAGES" | while IFS='|' read -r name image; do
  [ -z "$name" ] && continue
  tar="$name.tar.gz"
  echo "──── [$name] $image → docker save ────"
  docker save "$image" 2>/dev/null | gzip > "$WORK/$tar" || { echo "  save 실패"; continue; }
  sz=$(wc -c < "$WORK/$tar")
  ( cd "$WORK" && oras push --plain-http -u "$CI_USER" -p "$CI_PASS" "$REG/$NS/$name-image:$VER" \
      --artifact-type application/vnd.docker.image-save+gzip \
      --annotation "com.trustlink.image=$image" \
      "$tar":application/gzip >/dev/null 2>&1 ) \
    && echo "  push: $NS/$name-image:$VER ($((sz/1024/1024)) MB)" \
    && echo "$NS/$name-image:$VER  $image  $tar" >> "$WORK/install/images.txt"
  rm -f "$WORK/$tar"
done

# 설치 패키지(경량): compose + 설정 + 이미지 목록 + 설치 안내
cp "$DIR/docker-compose.yml" "$WORK/install/docker-compose.yml"
cp "$DIR/trustlink/config.container.json" "$WORK/install/" 2>/dev/null || true
cat > "$WORK/install/INSTALL.md" <<EOF
# TrustLink 설치 ($VER)
1) 이미지 적재: images.txt 의 각 줄에 대해
   oras pull --plain-http $REG/<ref> -o . && docker load -i <tar>
2) 설정 배치 후: docker compose -f docker-compose.yml up -d
(이 패키지는 .p7s 로 CMS 서명되어 신뢰 앵커(루트)로 검증 가능)
EOF

echo "──── 설치 패키지 push ────"
cfgarg=""; [ -f "$WORK/install/config.container.json" ] && cfgarg="config.container.json:application/json"
( cd "$WORK/install" && oras push --plain-http -u "$CI_USER" -p "$CI_PASS" "$REG/$NS/trustlink-install:$VER" \
    --artifact-type application/vnd.trustlink.install.v1 \
    docker-compose.yml:text/yaml images.txt:text/plain INSTALL.md:text/markdown $cfgarg >/dev/null 2>&1 ) \
  && echo "  push: $NS/trustlink-install:$VER"

# 설치 패키지 CMS 서명(.p7s) — BFF share/sign (admin 세션)
JAR="$WORK/jar"
html=$(curl -s -c "$JAR" -b "$JAR" -L "$BFF/admin/login")
action=$(printf '%s' "$html" | grep -oE 'action="[^"]*login-actions/authenticate[^"]*"' | head -1 | sed -E 's/^action="//; s/"$//; s/&amp;/\&/g')
if [ -n "$action" ]; then
  curl -s -c "$JAR" -b "$JAR" -L --data-urlencode "username=$ADMIN_USER" --data-urlencode "password=$ADMIN_PASS" "$action" -o /dev/null
fi
echo "  서명: $(curl -s -b "$JAR" -u "$CI_USER:$CI_PASS" -H "Content-Type: application/json" \
  -d "{\"repo\":\"$NS/trustlink-install\",\"tag\":\"$VER\"}" "$BFF/api/share/sign" \
  | python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('status',d.get('error')),'verified=',d.get('verified'),'serial=',d.get('serial'))" 2>/dev/null)"

echo "완료. 설치 패키지: $NS/trustlink-install:$VER (+ 이미지 $NS/*-image:$VER)"
echo "다운로드(.p7s): $BFF/api/share/package?repo=$NS/trustlink-install&tag=$VER"
