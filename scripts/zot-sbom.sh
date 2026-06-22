#!/usr/bin/env bash
# zot 프로젝트(소스) SBOM 생성·업로드.
#   zot Go 소스(go.mod)를 syft 로 스캔 → CycloneDX SBOM → TrustLink(zot) 에 `innotium/zot-source:<ver>`
#   로 올리고 SBOM referrer 부착 + DT 취약점 분석 + (선택) CMS 서명.
#   이미지 SBOM(dogfood-sbom.sh 의 innotium/zot)과 달리 "소스 의존성" SBOM 이다.
#
# 도구: syft, oras, curl, python3. 자격은 PoC 기본값(공개) — 운영은 env 주입.
set -u
ZOT_SRC="${ZOT_SRC:-/Users/chris/ZOT}"
VER="${VER:-$(date +%Y%m%d-%H%M%S)}"
REG="${REG:-trustlink:28081}"; BFF="${BFF:-http://trustlink:28080}"; NS="${NS:-innotium}"
CI_USER="${CI_USER:-ci}"; CI_PASS="${CI_PASS:-ci-poc-pw}"
ADMIN_USER="${ADMIN_USER:-admin1}"; ADMIN_PASS="${ADMIN_PASS:-Passw0rd!}"
SIGN="${SIGN:-1}"   # 1=설치/공유용 CMS 서명까지
WORK="$(mktemp -d)"
repo="$NS/zot-source"

[ -f "$ZOT_SRC/go.mod" ] || { echo "zot 소스 아님(go.mod 없음): $ZOT_SRC"; exit 1; }
echo "zot 소스 SBOM — src=$ZOT_SRC ver=$VER → $REG/$repo:$VER"

# 1) syft 소스 스캔 → CycloneDX
syft "dir:$ZOT_SRC" -o cyclonedx-json="$WORK/zot-source.cdx.json" -q 2>/dev/null || { echo "syft 실패"; exit 1; }
comps=$(python3 -c "import json;print(len(json.load(open('$WORK/zot-source.cdx.json')).get('components',[])))")
echo "  SBOM: $comps components"

# 2) descriptor 주체 push + SBOM referrer 부착 (상대경로 — oras 절대경로 거부 회피)
cat > "$WORK/desc.json" <<EOF
{"type":"trustlink.component.v1","component":"zot-source","role":"zot 레지스트리 소스(Go 프로젝트)","version":"$VER","sbomGenerator":"syft","sbomFormat":"CycloneDX","scanned":"$ZOT_SRC","components":$comps}
EOF
( cd "$WORK" && oras push --plain-http -u "$CI_USER" -p "$CI_PASS" "$REG/$repo:$VER" \
    --artifact-type application/vnd.trustlink.component.v1+json desc.json:application/json >/dev/null 2>&1 ) && echo "  push: $repo:$VER"
( cd "$WORK" && oras attach --plain-http -u "$CI_USER" -p "$CI_PASS" --artifact-type application/vnd.cyclonedx+json \
    "$REG/$repo:$VER" zot-source.cdx.json:application/vnd.cyclonedx+json >/dev/null 2>&1 ) && echo "  attach: SBOM referrer"

# 3) admin 세션
JAR="$WORK/jar"
H=$(curl -s -c "$JAR" -b "$JAR" -L "$BFF/admin/login")
A=$(printf '%s' "$H" | grep -oE 'action="[^"]*authenticate[^"]*"' | head -1 | sed -E 's/^action="//;s/"$//;s/&amp;/\&/g')
[ -n "$A" ] && curl -s -c "$JAR" -b "$JAR" -L --data-urlencode "username=$ADMIN_USER" --data-urlencode "password=$ADMIN_PASS" "$A" -o /dev/null

# 4) DT 업로드 → 분석 대기 → 취약점
python3 - "$WORK/zot-source.cdx.json" zot-source "$VER" > "$WORK/up.json" <<'PY'
import json,sys,base64
print(json.dumps({'project':sys.argv[2],'version':sys.argv[3],'bomBase64':base64.b64encode(open(sys.argv[1],'rb').read()).decode()}))
PY
tok=$(curl -s -b "$JAR" -H "Content-Type: application/json" --data @"$WORK/up.json" "$BFF/api/vex/upload" | python3 -c "import json,sys;print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
for i in $(seq 1 30); do p=$(curl -s -b "$JAR" "$BFF/api/vex/status?token=$tok" | python3 -c "import json,sys;print(json.load(sys.stdin).get('processing'))" 2>/dev/null); [ "$p" = "False" ] && break; sleep 5; done
echo "  취약점: $(curl -s -b "$JAR" "$BFF/api/vex/findings?project=zot-source&version=$VER" | python3 -c "import json,sys;d=json.load(sys.stdin);print(len(d) if isinstance(d,list) else len(d.get('findings',[])))" 2>/dev/null)"

# 5) VEX 발행 + (선택) CMS 서명
curl -s -b "$JAR" -u "$CI_USER:$CI_PASS" -H "Content-Type: application/json" -d "{\"repo\":\"$repo\",\"tag\":\"$VER\"}" "$BFF/api/vex/publish" \
  | python3 -c "import json,sys;d=json.load(sys.stdin);print('  VEX:',d.get('status',d.get('error')))" 2>/dev/null
if [ "$SIGN" = "1" ]; then
  curl -s -b "$JAR" -H "Content-Type: application/json" -d "{\"repo\":\"$repo\",\"tag\":\"$VER\"}" "$BFF/api/share/sign" \
    | python3 -c "import json,sys;d=json.load(sys.stdin);print('  서명:',d.get('status',d.get('error')),'verified=',d.get('verified'))" 2>/dev/null
fi
echo "완료: $repo:$VER (대시보드에서 확인)"
