#!/usr/bin/env bash
# 커스텀 이미지(zot 빌드·BFF)를 Docker Hub 에 push → compose-only 설치(docker-compose.deploy.yml) 가능하게 한다.
#
# 사전:
#   1) 이미지 빌드돼 있어야 함: trustlink:latest(zot), trustlink-admin:latest(BFF)  ← admin-bff/build.sh
#   2) Docker Hub 로그인: docker login -u <user>   (네임스페이스 push 권한 필요)
#
# 사용:
#   NS=trustlink-scs bash scripts/push-images.sh          # latest + 타임스탬프 버전 동시 태깅·push
#   NS=myorg TAG=v1.0.0 bash scripts/push-images.sh
set -eu

NS="${NS:-trustlink-scs}"           # Docker Hub 네임스페이스(계정/조직)
TAG="${TAG:-latest}"                # 기본 태그
VER="${VER:-$(date +%Y%m%d-%H%M%S)}" # 함께 붙일 불변 버전 태그

# 로컬 이미지 → Docker Hub repo (docker-compose.deploy.yml 의 참조와 일치)
MAP="
trustlink:latest|$NS/trustlink-zot
trustlink-admin:latest|$NS/trustlink-admin
"

echo "Docker Hub push — NS=$NS TAG=$TAG VER=$VER"

# 로그인 사전점검
if ! docker login >/dev/null 2>&1; then
  if ! docker system info 2>/dev/null | grep -qi username; then
    echo "✗ Docker Hub 미로그인. 먼저: docker login -u <$NS push 권한 계정>" >&2
    # 계속 진행하되 push 단계에서 실패하면 안내
  fi
fi

for line in $MAP; do
  [ -z "$line" ] && continue
  local_img="${line%%|*}"; repo="${line##*|}"
  if ! docker image inspect "$local_img" >/dev/null 2>&1; then
    echo "✗ 로컬 이미지 없음: $local_img (admin-bff/build.sh 로 빌드 필요)" >&2
    exit 1
  fi
  for t in "$TAG" "$VER"; do
    docker tag "$local_img" "$repo:$t"
    echo "  push $repo:$t ..."
    docker push "$repo:$t" >/dev/null && echo "    ✓ $repo:$t" || { echo "    ✗ push 실패($repo:$t) — docker login / 네임스페이스 권한 확인" >&2; exit 1; }
  done
done

echo "완료. 설치측: docker compose -f docker-compose.yml -f docker-compose.deploy.yml up -d"
echo "(deploy.yml 기본 네임스페이스가 $NS 가 아니면 TRUSTLINK_ZOT_IMAGE/TRUSTLINK_ADMIN_IMAGE 로 지정)"
