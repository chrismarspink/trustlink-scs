#!/usr/bin/env bash
# innoPouch 웹 스택 시연(docs/DEMO-INNOPOUCH-WEB.md): 11.0(취약 nginx·PHP·Node.js) / 11.1(수정 버전) / 12.0(nginx 1.30.6 — 자동 대응 "패치 없음" 시연) 업로드.
#
#   1) tools/demo_innopouch_gen.py --web 으로 바이너리 + CycloneDX SBOM + 설치 매뉴얼 생성
#   2) products/innopouch:<버전> 업로드 + SBOM·매뉴얼 referrer 첨부 (oras)
#   3) (선택 --sync) 관리자 로그인 → TrustLink 통보 동기화 즉시 실행(10분 주기를 기다리지 않음)
#
# 다시 실행해도 안전: 태그와 SBOM 이 이미 있으면 건너뛰고, 빠진 referrer(SBOM·매뉴얼)만 붙인다.
# 자격 증명은 환경 변수로만 받는다(파일에 쓰지 않음). demo-innopouch.sh 가 만든 credentials.env 를 그대로 써도 된다.
#
# 사용:
#   . innopouch-demo/credentials.env          # TL_REG · TL_REPO · TL_PUSH_USER · TL_PUSH_PASS
#   bash tools/demo-innopouch-web.sh 11.0 --dry-run    # 서버에 접속하지 않고 할 일만 출력
#   bash tools/demo-innopouch-web.sh 11.0              # 업로드
#   bash tools/demo-innopouch-web.sh 11.1              # (시연 뒷부분) 패치 버전 업로드
#   BFF=http://<서버>:28080 ADMIN=admin1 ADMIN_PW='…' bash tools/demo-innopouch-web.sh 11.0 --sync
# 필요: python3, oras(실제 업로드 시), curl(--sync 시)
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"

VER=""; DRY=0; SYNC=0
for a in "$@"; do
  case "$a" in
    11.0|11.1|12.0|12.0.1) VER="$a" ;;
    --dry-run|-n) DRY=1 ;;
    --sync) SYNC=1 ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "알 수 없는 인자: $a (버전 11.0|11.1, --dry-run, --sync)" >&2; exit 2 ;;
  esac
done
[ -n "$VER" ] || { echo "버전을 지정하세요: 11.0 또는 11.1" >&2; exit 2; }

REG="${TL_REG:-${REG:-}}"; REPO="${TL_REPO:-${REPO:-products/innopouch}}"
PUSH_USER="${TL_PUSH_USER:-ci-innopouch}"; PUSH_PASS="${TL_PUSH_PASS:-}"
SBOM_TYPE=application/vnd.cyclonedx+json; GUIDE_TYPE=application/vnd.trustlink.guide+markdown
if [ "$DRY" = 0 ]; then
  [ -n "$REG" ] || { echo "TL_REG(또는 REG)=<서버>:28081 이 필요합니다" >&2; exit 2; }
  [ -n "$PUSH_PASS" ] || { echo "TL_PUSH_PASS 가 필요합니다(업로드 자동화 계정 비밀번호, 환경 변수로만)" >&2; exit 2; }
  command -v oras >/dev/null || { echo "oras 가 필요합니다" >&2; exit 2; }
fi
REG="${REG:-<TL_REG>}"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
python3 -I "$DIR/demo_innopouch_gen.py" "$WORK/art" --web "$VER" >/dev/null
cd "$WORK/art/$VER"
BIN="innopouch-$VER-linux-amd64.tar.gz"; SBOM="innopouch-$VER.cdx.json"; GUIDE="innopouch-$VER-install-guide.md"

echo "[1] innoPouch $VER 생성 — 웹 스택 구성요소(CPE 로 Dependency-Track 이 매칭)"
python3 -I -c '
import json, sys
for c in json.load(open(sys.argv[1]))["components"]:
    if "cpe" in c:
        print("  - {:6} {:8} {}".format(c["name"], c["version"], c["cpe"]))
' "$SBOM"

CFG="$WORK/oras.json"; echo '{}' > "$CFG"
O=(--plain-http --registry-config "$CFG")
run() { # 실행 또는 출력
  if [ "$DRY" = 1 ]; then printf '  $ %s\n' "$*"; else "$@"; fi
}

echo "[2] $REG/$REPO:$VER 업로드 ($([ "$DRY" = 1 ] && echo '시험 실행 — 서버에 접속하지 않음' || echo "계정 $PUSH_USER"))"
if [ "$DRY" = 1 ]; then
  echo "  $ oras login $REG -u $PUSH_USER --password-stdin   (비밀번호: TL_PUSH_PASS 환경 변수)"
  echo "  · 태그가 이미 있고 SBOM 이 붙어 있으면 아무것도 하지 않음(멱등)"
  run oras push "${O[@]}" "$REG/$REPO:$VER" --artifact-type application/vnd.innotium.innopouch.v1 \
    --annotation "org.opencontainers.image.version=$VER" "$BIN:application/gzip"
  run oras attach "${O[@]}" "$REG/$REPO@<digest>" --artifact-type "$SBOM_TYPE" --annotation com.innotium.sbom.tool=xscan "$SBOM:$SBOM_TYPE"
  run oras attach "${O[@]}" "$REG/$REPO@<digest>" --artifact-type "$GUIDE_TYPE" "$GUIDE:text/markdown"
else
  printf '%s' "$PUSH_PASS" | oras login "$REG" -u "$PUSH_USER" --password-stdin "${O[@]}" >/dev/null
  # 하위 명령은 비밀번호를 다시 쓰지 않는다(registry-config 에만, 작업 폴더는 끝나면 지움)
  refs() { # $1 artifactType → 그 유형 referrer digest 목록
    oras discover "${O[@]}" --artifact-type "$1" --format json "$REG/$REPO@$DG" 2>/dev/null |
      python3 -I -c 'import json,sys
d=json.load(sys.stdin)
print(" ".join(m["digest"] for m in (d.get("referrers") or d.get("manifests") or [])))' || true
  }
  if DG=$(oras manifest fetch "${O[@]}" --descriptor "$REG/$REPO:$VER" 2>/dev/null | python3 -I -c 'import json,sys;print(json.load(sys.stdin)["digest"])'); then
    echo "  - 태그 $VER 이미 있음($DG) — 다시 올리지 않음"
  else
    DG=$(oras push "${O[@]}" "$REG/$REPO:$VER" --artifact-type application/vnd.innotium.innopouch.v1 \
          --annotation "org.opencontainers.image.version=$VER" "$BIN:application/gzip" --format go-template='{{.digest}}')
    echo "  - 바이너리 업로드 $DG"
  fi
  if [ -n "$(refs "$SBOM_TYPE")" ]; then
    echo "  - SBOM 이미 첨부됨 — 건너뜀"
  else
    oras attach "${O[@]}" "$REG/$REPO@$DG" --artifact-type "$SBOM_TYPE" --annotation com.innotium.sbom.tool=xscan "$SBOM:$SBOM_TYPE" >/dev/null
    echo "  - SBOM 첨부"
  fi
  if [ -n "$(refs "$GUIDE_TYPE")" ]; then
    echo "  - 매뉴얼 이미 첨부됨 — 건너뜀"
  else
    oras attach "${O[@]}" "$REG/$REPO@$DG" --artifact-type "$GUIDE_TYPE" "$GUIDE:text/markdown" >/dev/null
    echo "  - 매뉴얼 첨부"
  fi
fi

if [ "$SYNC" = 1 ]; then
  BFF="${BFF:-}"; ADMIN="${ADMIN:-admin1}"
  echo "[3] 통보 동기화 즉시 실행 ($BFF/api/notify/sync)"
  if [ "$DRY" = 1 ]; then
    echo "  $ (관리자 $ADMIN 로그인 — ADMIN_PW 환경 변수) POST ${BFF:-<BFF>}/api/notify/sync"
  else
    [ -n "$BFF" ] && [ -n "${ADMIN_PW:-}" ] || { echo "  --sync 에는 BFF · ADMIN_PW 환경 변수가 필요합니다" >&2; exit 2; }
    JAR="$WORK/admin.jar"
    html=$(curl -s -c "$JAR" -b "$JAR" -L "$BFF/admin/login")
    action=$(printf '%s' "$html" | grep -oE 'action="[^"]*login-actions/authenticate[^"]*"' | head -1 | sed -E 's/^action="//; s/"$//; s/&amp;/\&/g')
    [ -n "$action" ] || { echo "  로그인 폼 없음" >&2; exit 1; }
    curl -s -c "$JAR" -b "$JAR" -L -o /dev/null --data-urlencode "username=$ADMIN" --data-urlencode "password=$ADMIN_PW" "$action"
    curl -sf -m 600 -b "$JAR" -X POST "$BFF/api/notify/sync" | python3 -I -c 'import json,sys;print("  -", json.load(sys.stdin).get("message"))'
  fi
else
  echo "[3] 감시 동기화는 10분 주기로 자동(바로 하려면 --sync 또는 관리 › 취약점 통보 › 지금 동기화)"
fi
[ "$DRY" = 1 ] && echo "시험 실행 끝 — 실제로 올리려면 --dry-run 없이 실행하세요." || echo "완료: $REG/$REPO:$VER"
