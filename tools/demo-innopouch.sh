#!/usr/bin/env bash
# innoPouch 시연: 계정·권한 설정 → 1.0~10.0 업로드(바이너리+SBOM+매뉴얼) → DT 분석·VEX → 바로 쓰는 자격·명령 생성
#
#   1) 고객사 acme + 고객 계정(acme1·acme2) 소속 지정
#   2) 제품 권한 products/innopouch: 쓰기=개발자·ci-innopouch, 읽기=고객사 acme·robot-acme
#   3) 기계 계정 ci-innopouch(업로드)·robot-acme(다운로드) 발급(있으면 재발급), 개발자 dev1 의 개인 API 키 발급
#   4) ci-innopouch 로 버전별 업로드 + SBOM·매뉴얼 referrer 첨부
#   5) 버전별 SBOM → Dependency-Track 분석 → VEX 발행(대시보드 통계)
#   6) $OUT/credentials.env · upload.sh · download.sh 생성(바로 실행 가능)
#
# 사용: BFF=http://218.38.12.14:28080 REG=218.38.12.14:28081 ADMIN=admin1 ADMIN_PW='…' bash tools/demo-innopouch.sh
# 필요: curl, python3, oras
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
BFF="${BFF:-http://trustlink:28080}"; REG="${REG:-${BFF#http://}}"; REG="${REG%%:*}:28081"
ADMIN="${ADMIN:-admin1}"; ADMIN_PW="${ADMIN_PW:?ADMIN_PW}"
DEV="${DEV:-dev1}"; DEV_PW="${DEV_PW:-}"
ORG="${ORG:-acme}"; CUSTOMERS="${CUSTOMERS:-acme1 acme2}"
REPO="${REPO:-products/innopouch}"; VERSIONS="${VERSIONS:-10}"
OUT="${OUT:-$PWD/innopouch-demo}"; mkdir -p "$OUT"; chmod 700 "$OUT"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
JAR="$WORK/admin.jar"; JSONH='Content-Type: application/json'

kc_login() { # $1 jar  $2 시작 URL  $3 user  $4 pw
  local html action
  html=$(curl -s -c "$1" -b "$1" -L "$2")
  action=$(printf '%s' "$html" | grep -oE 'action="[^"]*login-actions/authenticate[^"]*"' | head -1 | sed -E 's/^action="//; s/"$//; s/&amp;/\&/g')
  [ -n "$action" ] || { echo "로그인 폼 없음($3)" >&2; return 1; }
  curl -s -c "$1" -b "$1" -L -o /dev/null --data-urlencode "username=$3" --data-urlencode "password=$4" "$action"
}
api() { curl -sf -b "$JAR" -H "$JSONH" "$@"; }
jget() { python3 -c "import json,sys;d=json.load(sys.stdin);print($1)"; }

echo "[1] 관리자 로그인 · 고객사 · 고객 계정"
kc_login "$JAR" "$BFF/admin/login" "$ADMIN" "$ADMIN_PW"
api "$BFF/api/me" | jget 'd["username"], d["groups"]' >/dev/null
curl -s -o /dev/null -b "$JAR" -H "$JSONH" -d "{\"name\":\"$ORG\"}" "$BFF/api/orgs" || true
USERS_JSON=$(api "$BFF/api/users")
for u in $CUSTOMERS; do
  id=$(printf '%s' "$USERS_JSON" | jget "next((x['id'] for x in d if x['username']=='$u'), '')")
  [ -n "$id" ] || { echo "  - $u 없음(건너뜀)"; continue; }
  api -X PUT -d "{\"username\":\"$u\",\"role\":\"users\",\"orgs\":[\"$ORG\"],\"enabled\":true}" "$BFF/api/users/$id" >/dev/null
  echo "  - $u → 외부 사용자, 고객사 $ORG"
done

echo "[2] 기계 계정 (있으면 재발급)"
ROBOTS=$(api "$BFF/api/robots")
issue() { # $1 name $2 kind
  if printf '%s' "$ROBOTS" | jget "any(r['name']=='$1' for r in d)" | grep -q True; then
    api -X POST "$BFF/api/robots/$1/reissue" | jget 'd["password"]'
  else
    api -d "{\"name\":\"$1\",\"kind\":\"$2\",\"products\":[\"$REPO\"],\"days\":365,\"note\":\"innoPouch 시연\"}" "$BFF/api/robots" | jget 'd["password"]'
  fi
}
CI_PASS=$(issue ci-innopouch push); PULL_USER="robot-$ORG"; PULL_PASS=$(issue "$PULL_USER" pull)
echo "  - ci-innopouch(업로드), $PULL_USER(다운로드)"

echo "[3] 제품 권한 $REPO"
api -X PUT -d "{\"repo\":\"$REPO\",\"writers\":[{\"type\":\"group\",\"name\":\"developers\"},{\"type\":\"user\",\"name\":\"ci\"},{\"type\":\"user\",\"name\":\"ci-innopouch\"}],\"readers\":[{\"type\":\"group\",\"name\":\"org-$ORG\"},{\"type\":\"user\",\"name\":\"$PULL_USER\"}]}" "$BFF/api/access/products" >/dev/null
echo "  - 쓰기: 내부 개발자·ci·ci-innopouch / 읽기: 고객사 ${ORG}·${PULL_USER}"

DEV_KEY=""
if [ -n "$DEV_PW" ]; then
  echo "[4] $DEV 개인 API 키(zot 기본 기능)"
  DJ="$WORK/dev.jar"
  kc_login "$DJ" "$BFF/zot/auth/login?provider=oidc&callback_ui=$BFF/" "$DEV" "$DEV_PW"
  DEV_KEY=$(curl -sf -b "$DJ" -H 'X-ZOT-API-CLIENT: zot-ui' -H "$JSONH" \
    -d "{\"label\":\"innoPouch 시연\",\"expirationDate\":\"$(python3 -c 'import datetime as t;print((t.datetime.now(t.timezone.utc)+t.timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ"))')\"}" \
    "$BFF/zot/auth/apikey" | jget 'd["apiKey"]')
fi

echo "[5] 권한 반영 대기"
for i in $(seq 1 120); do
  c=$(curl -s -o /dev/null -w '%{http_code}' -u "ci-innopouch:$CI_PASS" "http://$REG/v2/$REPO/tags/list")
  case "$c" in 200|404) break;; esac; sleep 1
done
echo "  - ci-innopouch 권한 확인($c, ${i}초)"

echo "[6] 1.0~$VERSIONS.0 생성·업로드 (바이너리 + SBOM + 매뉴얼)"
python3 -I "$DIR/demo_innopouch_gen.py" "$WORK/art" "$VERSIONS" >/dev/null
CFG="$WORK/oras.json"; echo '{}' > "$CFG"
printf '%s' "$CI_PASS" | oras login "$REG" -u ci-innopouch --password-stdin --plain-http --registry-config "$CFG" >/dev/null
for n in $(seq 1 "$VERSIONS"); do
  v="$n.0"; cd "$WORK/art/$v"
  dg=$(oras push --plain-http --registry-config "$CFG" "$REG/$REPO:$v" \
        --artifact-type application/vnd.innotium.innopouch.v1 \
        --annotation "org.opencontainers.image.version=$v" \
        "innopouch-$v-linux-amd64.tar.gz:application/gzip" --format go-template='{{.digest}}')
  oras attach --plain-http --registry-config "$CFG" "$REG/$REPO@$dg" --artifact-type application/vnd.cyclonedx+json \
    --annotation "com.innotium.sbom.tool=xscan" "innopouch-$v.cdx.json:application/vnd.cyclonedx+json" >/dev/null
  oras attach --plain-http --registry-config "$CFG" "$REG/$REPO@$dg" --artifact-type application/vnd.trustlink.guide+markdown \
    "innopouch-$v-install-guide.md:text/markdown" >/dev/null
  echo "  - $v 업로드"
done
cd "$OUT"

echo "[7] 취약점 분석(DT) → VEX 발행"
for n in $(seq 1 "$VERSIONS"); do
  v="$n.0"
  f=$(curl -s -m 600 -b "$JAR" "$BFF/api/vex/findings?project=innopouch&version=$v&repo=$REPO&tag=$v" | jget 'len(d) if isinstance(d,list) else d.get("error")')
  p=$(curl -s -m 300 -b "$JAR" -H "$JSONH" -d "{\"repo\":\"$REPO\",\"tag\":\"$v\"}" "$BFF/api/vex/publish" | jget 'd.get("status", d.get("error"))')
  echo "  - $v 취약점 ${f}건, VEX $p"
done

echo "[8] 바로 쓰는 자격·명령 → $OUT"
umask 077
cat > "$OUT/credentials.env" <<EOF
# innoPouch 시연 자격 — 외부 공유 금지
TL_REG=$REG
TL_REPO=$REPO
# 업로드(빌드 서버용 기계 계정)
TL_PUSH_USER=ci-innopouch
TL_PUSH_PASS=$CI_PASS
# 다운로드(고객 $ORG 자동 다운로드용 기계 계정)
TL_PULL_USER=$PULL_USER
TL_PULL_PASS=$PULL_PASS
# 개발자 개인 API 키(${DEV}) — 업로드·다운로드
TL_DEV_USER=$DEV
TL_DEV_KEY=$DEV_KEY
EOF
cat > "$OUT/upload.sh" <<'EOF'
#!/usr/bin/env bash
# 사용: bash upload.sh <버전> <바이너리> <SBOM.cdx.json> [매뉴얼.md]   (파일과 같은 폴더에서 실행)
set -euo pipefail; . "$(dirname "$0")/credentials.env"
V=$1; BIN=$2; SBOM=$3; DOC=${4:-}
printf '%s' "$TL_PUSH_PASS" | oras login "$TL_REG" -u "$TL_PUSH_USER" --password-stdin --plain-http
DG=$(oras push --plain-http "$TL_REG/$TL_REPO:$V" --artifact-type application/vnd.innotium.innopouch.v1 \
      "$BIN:application/gzip" --format go-template='{{.digest}}')
oras attach --plain-http "$TL_REG/$TL_REPO@$DG" --artifact-type application/vnd.cyclonedx+json "$SBOM:application/vnd.cyclonedx+json"
[ -n "$DOC" ] && oras attach --plain-http "$TL_REG/$TL_REPO@$DG" --artifact-type application/vnd.trustlink.guide+markdown "$DOC:text/markdown"
oras discover --plain-http "$TL_REG/$TL_REPO:$V" --format tree
EOF
cat > "$OUT/download.sh" <<'EOF'
#!/usr/bin/env bash
# 사용: bash download.sh [버전=latest 가 없으면 가장 최근] — 바이너리 + SBOM + 매뉴얼을 ./innopouch-<버전>/ 로
set -euo pipefail; . "$(dirname "$0")/credentials.env"
printf '%s' "$TL_PULL_PASS" | oras login "$TL_REG" -u "$TL_PULL_USER" --password-stdin --plain-http >/dev/null
V=${1:-$(oras repo tags --plain-http "$TL_REG/$TL_REPO" | sort -V | tail -1)}
D="innopouch-$V"; mkdir -p "$D"
oras pull --plain-http "$TL_REG/$TL_REPO:$V" -o "$D"
for t in application/vnd.cyclonedx+json application/vnd.trustlink.guide+markdown; do
  for r in $(oras discover --plain-http "$TL_REG/$TL_REPO:$V" --artifact-type "$t" --format go-template='{{range .referrers}}{{.digest}} {{end}}' 2>/dev/null); do
    oras pull --plain-http "$TL_REG/$TL_REPO@$r" -o "$D"
  done
done
ls -la "$D"
EOF
chmod 700 "$OUT/upload.sh" "$OUT/download.sh"
echo "완료. 다운로드 시험: bash $OUT/download.sh 10.0"
