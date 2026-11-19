#!/bin/sh
# 로컬 AI 모델(GGUF)을 ai-models 볼륨에 받는다 — 허깅페이스가 공개한 LFS SHA-256 과 대조해 검증.
# 인터넷이 되는 곳(서버 또는 DMZ)에서 한 번 실행한다. AI 컨테이너 자체는 외부 망에 붙지 않는다.
#
#   scripts/ai-model-fetch.sh                         # 기본(권장) 모델
#   scripts/ai-model-fetch.sh unsloth/gemma-4-E4B-it-GGUF gemma-4-E4B-it-Q4_K_M.gguf
#
# 폐쇄망: 다른 곳에서 받은 파일을 넣을 때는 LOCAL_FILE=/경로/모델.gguf 로 지정(같은 검증 수행).
set -eu
REPO=${1:-unsloth/gemma-4-26B-A4B-it-GGUF}
FILE=${2:-gemma-4-26B-A4B-it-UD-Q4_K_M.gguf}
VOL=${AI_VOLUME:-trustlink_ai-models}

want=$(curl -fsS "https://huggingface.co/api/models/$REPO/tree/main" | python3 -c "
import sys, json
for f in json.load(sys.stdin):
    if f['path'] == '$FILE':
        print((f.get('lfs') or {}).get('oid', ''))")
[ -n "$want" ] || { echo "SHA-256 을 찾지 못함: $REPO/$FILE" >&2; exit 1; }
echo "기대 SHA-256: $want"

docker volume create "$VOL" >/dev/null
if [ -n "${LOCAL_FILE:-}" ]; then
  src="-v $(cd "$(dirname "$LOCAL_FILE")" && pwd):/src:ro"
  fetch="cp /src/$(basename "$LOCAL_FILE") /m/$FILE.part"
else
  src=""
  fetch="wget -q -c -O /m/$FILE.part https://huggingface.co/$REPO/resolve/main/$FILE"
fi
# shellcheck disable=SC2086
docker run --rm $src -v "$VOL":/m alpine:3.20 sh -c "
  set -e
  $fetch
  got=\$(sha256sum /m/$FILE.part | cut -d' ' -f1)
  if [ \"\$got\" != \"$want\" ]; then echo \"SHA-256 불일치: \$got\" >&2; rm -f /m/$FILE.part; exit 1; fi
  mv /m/$FILE.part /m/$FILE
  echo \"$want  $FILE\" > /m/$FILE.sha256
  ls -la /m"
echo "완료 — .env 에 AI_MODEL_FILE=$FILE, AI_URL=http://trustlink-ai:8080 을 넣고 'docker compose --profile ai up -d'"
