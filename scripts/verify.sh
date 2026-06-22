#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/.."; set -a; source .env; set +a

ZOT=http://localhost:5002
KC=http://localhost:8085
REPO=products/verify
PASS=0; FAIL=0
ok(){ echo "PASS: $1"; PASS=$((PASS+1)); }
no(){ echo "FAIL: $1"; FAIL=$((FAIL+1)); }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }   # echo HTTP status

echo "=== 1) 설정/헬스 ==="
# zot config 스키마 검증 (컨테이너 내 zot 바이너리)
# zot 이미지는 distroless(셸 없음)이므로 바이너리를 직접 exec 한다.
if docker compose exec -T zot /usr/bin/zot verify /etc/zot/config.json >/dev/null 2>&1; then
  ok "zot config 유효 (zot verify)"; else no "zot config 유효 (zot verify)"; fi

# zot 서버 살아있음: auth 활성 시 /v2/ 는 200 또는 401
c=$(code "$ZOT/v2/"); [ "$c" = "200" ] || [ "$c" = "401" ] && ok "zot /v2/ 응답 ($c)" || no "zot /v2/ 응답 ($c)"

# Keycloak realm + OIDC discovery
c=$(code "$KC/realms/trustlink"); [ "$c" = "200" ] && ok "keycloak realm trustlink ($c)" || no "keycloak realm trustlink ($c)"
DISC="$KC/realms/trustlink/.well-known/openid-configuration"
c=$(code "$DISC"); [ "$c" = "200" ] && ok "OIDC discovery ($c)" || no "OIDC discovery ($c)"

# UI 로그인용 redirect_uri 가 externalUrl(localhost:5002)로 생성되는지.
# externalUrl 미설정 시 0.0.0.0:5000 으로 생성되어 Keycloak 가 거부 → 브라우저 로그인 화면이 안 뜬다.
LOC=$(curl -s -D - -o /dev/null "$ZOT/zot/auth/login?provider=oidc" | tr -d '\r' | sed -n 's/^[Ll]ocation: //p' | head -1)
case "$LOC" in
  *"redirect_uri=http%3A%2F%2Flocalhost%3A5002"*) ok "OIDC 로그인 redirect_uri 가 externalUrl 사용" ;;
  *) no "OIDC 로그인 redirect_uri origin (externalUrl 확인 필요): $LOC" ;;
esac

echo "=== 2) htpasswd(ci) 인증 + 권한 ==="
# 익명 push 시도는 거부되어야 한다(fail-closed). POST blobs/uploads → 401
c=$(code -X POST "$ZOT/v2/$REPO/blobs/uploads/")
[ "$c" = "401" ] && ok "익명 push 거부 ($c)" || no "익명 push 거부 (got $c, want 401)"

# ci 계정 push (curl 기반 OCI 모놀리식 업로드: layer + 빈 config + manifest)
push_blob(){ # $1=data-file  -> echo digest
  local f="$1" dg loc
  dg="sha256:$(shasum -a 256 "$f" | awk '{print $1}')"
  loc=$(curl -s -u "ci:${CI_PASSWORD}" -X POST -D - -o /dev/null "$ZOT/v2/$REPO/blobs/uploads/" \
        | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}')
  case "$loc" in /*) loc="$ZOT$loc";; esac
  local sep='?'; case "$loc" in *\?*) sep='&';; esac
  curl -s -u "ci:${CI_PASSWORD}" -X PUT -H "Content-Type: application/octet-stream" \
       --data-binary "@$f" "${loc}${sep}digest=${dg}" -o /dev/null
  echo "$dg"
}
TMP=$(mktemp -d); printf 'hello zot\n' > "$TMP/layer"; printf '{}' > "$TMP/config"
LAYER_DG=$(push_blob "$TMP/layer"); LAYER_SZ=$(wc -c < "$TMP/layer" | tr -d ' ')
CFG_DG=$(push_blob "$TMP/config"); CFG_SZ=$(wc -c < "$TMP/config" | tr -d ' ')
cat > "$TMP/manifest.json" <<EOF
{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
 "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"${CFG_DG}","size":${CFG_SZ}},
 "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"${LAYER_DG}","size":${LAYER_SZ}}]}
EOF
c=$(curl -s -o /dev/null -w '%{http_code}' -u "ci:${CI_PASSWORD}" -X PUT \
    -H "Content-Type: application/vnd.oci.image.manifest.v1+json" \
    --data-binary "@$TMP/manifest.json" "$ZOT/v2/$REPO/manifests/v1")
{ [ "$c" = "201" ] || [ "$c" = "200" ]; } && ok "ci push manifest ($c)" || no "ci push manifest ($c)"

# ci pull (manifest GET)
c=$(code -u "ci:${CI_PASSWORD}" -H "Accept: application/vnd.oci.image.manifest.v1+json" "$ZOT/v2/$REPO/manifests/v1")
[ "$c" = "200" ] && ok "ci pull manifest ($c)" || no "ci pull manifest ($c)"

echo "=== 3) OIDC 그룹 클레임 검증 (dev1) ==="
# direct access grant 로 토큰을 받아 groups 클레임에 'developers' 가 있는지 확인(매퍼 동작 검증).
# 토큰 발급/디코드/검사를 단일 python 으로 처리해 셸 변수 확장 이슈를 피한다.
GROUP_CHECK=$(curl -s -X POST "$KC/realms/trustlink/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=zot -d "client_secret=${ZOT_OIDC_CLIENT_SECRET}" \
  -d username=dev1 -d password='Passw0rd!' -d scope=openid \
  | python3 -c '
import sys, json, base64
d = json.load(sys.stdin)
tok = d.get("access_token", "")
if not tok:
    print("NOTOKEN " + d.get("error_description", d.get("error", "")))
    sys.exit(0)
p = tok.split(".")[1]; p += "=" * (-len(p) % 4)
groups = json.loads(base64.urlsafe_b64decode(p)).get("groups", [])
print(("OK " if "developers" in groups else "BAD ") + ",".join(groups))
' 2>/dev/null)
echo "      dev1 groups 클레임: ${GROUP_CHECK#* }"
case "$GROUP_CHECK" in
  OK*) ok "OIDC groups 클레임에 developers 포함" ;;
  *)   no "OIDC groups 클레임에 developers 포함 ($GROUP_CHECK)" ;;
esac

rm -rf "$TMP"
echo
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
