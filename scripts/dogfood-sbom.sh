#!/usr/bin/env bash
# TrustLink 자기 dogfooding: 스택 구성요소(자체 + 서브모듈) + 설정을 버전별로 TrustLink(zot)에
# 올리고, 컴포넌트별로 SBOM 생성 → 취약점 분석(DT) → VEX 발행 → CMS 서명까지 수행한다.
#
# 파이프라인(컴포넌트당):
#   syft → CycloneDX SBOM
#   oras push(descriptor 주체) + attach(SBOM referrer)          [ci 자격]
#   BFF /api/vex/upload → DT 분석 → 대기 → /api/vex/publish(VEX) [admin 세션 + ci basic]
#   BFF /api/share/sign → CMS 서명 .p7s referrer 바인딩          [admin 세션]
#
# 필요 도구: syft, oras, curl, python3, docker. 기본값은 PoC 데모 자격.
set -u

VER="${VER:-$(date +%Y%m%d-%H%M%S)}"  # 버전 = 빌드 타임스탬프(YYYYMMDD-HHMMSS, OCI 태그 안전·정렬가능)
REG="${REG:-trustlink:28081}"        # zot 직접(레지스트리)
BFF="${BFF:-http://trustlink:28080}" # BFF 프론트도어(세션/DT/서명)
NS="${NS:-innotium}"                  # 레포 네임스페이스(ci 쓰기 가능)
CI_USER="${CI_USER:-ci}"; CI_PASS="${CI_PASS:-ci-poc-pw}"
ADMIN_USER="${ADMIN_USER:-admin1}"; ADMIN_PASS="${ADMIN_PASS:-Passw0rd!}"
WORK="${WORK:-$(mktemp -d)}"; mkdir -p "$WORK/sbom"
DIR="$(cd "$(dirname "$0")/.." && pwd)"  # deploy/zot-keycloak

# 컴포넌트 → 이미지 (자체 + 서브모듈). 설정 번들은 별도 처리.
COMPONENTS="
trustlink-admin|trustlink-admin:latest|TrustLink BFF (자체)
zot|trustlink:latest|아티팩트 레지스트리 zot (자체 빌드)
keycloak|quay.io/keycloak/keycloak:latest|인증 (Keycloak)
step-ca|smallstep/step-ca:latest|CA (step-ca)
dependency-track|dependencytrack/apiserver:latest|취약점 분석 (Dependency-Track)
postgres|postgres:16|DT 데이터베이스 (PostgreSQL)
"

JAR="$WORK/jar"
oidc_login() {
  local html action
  html=$(curl -s -c "$JAR" -b "$JAR" -L "$BFF/admin/login")
  action=$(printf '%s' "$html" | grep -oE 'action="[^"]*login-actions/authenticate[^"]*"' | head -1 | sed -E 's/^action="//; s/"$//; s/&amp;/\&/g')
  [ -z "$action" ] && { echo "로그인 폼 파싱 실패(이미 세션?)"; return 1; }
  curl -s -c "$JAR" -b "$JAR" -L --data-urlencode "username=$ADMIN_USER" --data-urlencode "password=$ADMIN_PASS" "$action" -o /dev/null
  local me; me=$(curl -s -b "$JAR" "$BFF/api/me")
  echo "$me" | grep -q "$ADMIN_USER" || { echo "로그인 실패: $me"; return 1; }
  echo "admin 로그인: $me"
}

push_component() {
  local name="$1" image="$2" role="$3"
  local repo="$NS/$name" sbom="$name.cdx.json"  # basename — oras 는 상대경로만 허용(절대경로 거부 + pull path-traversal 회피)
  echo "──────── [$name] $image ────────"
  syft "$image" -o cyclonedx-json="$WORK/$sbom" -q 2>/dev/null || { echo "  syft 실패"; return 1; }
  local comps; comps=$(python3 -c "import json;print(len(json.load(open('$WORK/$sbom')).get('components',[])))")
  echo "  SBOM: $comps components"

  cat > "$WORK/desc.json" <<EOF
{"type":"trustlink.component.v1","component":"$name","role":"$role","version":"$VER","image":"$image","sbomGenerator":"syft","sbomFormat":"CycloneDX","components":$comps}
EOF
  ( cd "$WORK" && oras push --plain-http -u "$CI_USER" -p "$CI_PASS" "$REG/$repo:$VER" \
      --artifact-type application/vnd.trustlink.component.v1+json \
      desc.json:application/json >/dev/null 2>&1 ) && echo "  push: $repo:$VER"
  ( cd "$WORK" && oras attach --plain-http -u "$CI_USER" -p "$CI_PASS" --artifact-type application/vnd.cyclonedx+json \
      "$REG/$repo:$VER" "$sbom":application/vnd.cyclonedx+json >/dev/null 2>&1 ) && echo "  attach: SBOM referrer"

  # DT 업로드 → 분석 대기 (base64 는 python 이 파일에서 직접 — argv 길이 한계 회피)
  local tok
  python3 - "$WORK/$sbom" "$name" "$VER" > "$WORK/up.json" <<'PY'
import json,sys,base64
sbom,name,ver=sys.argv[1],sys.argv[2],sys.argv[3]
print(json.dumps({'project':name,'version':ver,'bomBase64':base64.b64encode(open(sbom,'rb').read()).decode()}))
PY
  tok=$(curl -s -b "$JAR" -H "Content-Type: application/json" --data @"$WORK/up.json" "$BFF/api/vex/upload" | python3 -c "import json,sys;print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
  echo "  DT 업로드 token=$tok"
  local i p
  for i in $(seq 1 30); do
    p=$(curl -s -b "$JAR" "$BFF/api/vex/status?token=$tok" | python3 -c "import json,sys;print(json.load(sys.stdin).get('processing'))" 2>/dev/null)
    [ "$p" = "False" ] && break; sleep 5
  done
  local vc
  vc=$(curl -s -b "$JAR" "$BFF/api/vex/findings?project=$name&version=$VER" | python3 -c "import json,sys;d=json.load(sys.stdin);print(len(d) if isinstance(d,list) else len(d.get('findings',[])))" 2>/dev/null)
  echo "  취약점 findings=$vc"

  # VEX 발행 (zot 쓰기는 ci basic 전달)
  curl -s -b "$JAR" -u "$CI_USER:$CI_PASS" -H "Content-Type: application/json" \
    -d "{\"repo\":\"$repo\",\"tag\":\"$VER\"}" "$BFF/api/vex/publish" \
    | python3 -c "import json,sys;d=json.load(sys.stdin);print('  VEX:', d.get('status',d.get('error')))" 2>/dev/null

  # CMS 서명 + referrer 바인딩
  curl -s -b "$JAR" -H "Content-Type: application/json" \
    -d "{\"repo\":\"$repo\",\"tag\":\"$VER\"}" "$BFF/api/share/sign" \
    | python3 -c "import json,sys;d=json.load(sys.stdin);print('  서명:', d.get('status',d.get('error')),'verified=',d.get('verified'),'serial=',d.get('serial'))" 2>/dev/null
}

push_config() {
  local repo="$NS/trustlink-config" tar="config.tar.gz"
  echo "──────── [config] 설정 번들 ────────"
  tar -C "$DIR" -czf "$WORK/$tar" docker-compose.yml trustlink/config.container.json keycloak 2>/dev/null
  ( cd "$WORK" && oras push --plain-http -u "$CI_USER" -p "$CI_PASS" "$REG/$repo:$VER" \
      --artifact-type application/vnd.trustlink.config.v1+tar \
      "$tar":application/gzip >/dev/null 2>&1 ) && echo "  push: $repo:$VER ($(wc -c < "$WORK/$tar") bytes)"
  curl -s -b "$JAR" -H "Content-Type: application/json" \
    -d "{\"repo\":\"$repo\",\"tag\":\"$VER\"}" "$BFF/api/share/sign" \
    | python3 -c "import json,sys;d=json.load(sys.stdin);print('  서명:', d.get('status',d.get('error')),'verified=',d.get('verified'))" 2>/dev/null
}

echo "TrustLink dogfooding — VER=$VER REG=$REG NS=$NS"
oidc_login || exit 1
echo "$COMPONENTS" | while IFS='|' read -r name image role; do
  [ -z "$name" ] && continue
  push_component "$name" "$image" "$role"
done
push_config
echo "완료. 관리 콘솔 대시보드에서 $NS/trustlink-* 버전 $VER 확인."
