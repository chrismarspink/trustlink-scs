# TrustLink BFF 이미지.
#   이전: FROM zot:latest(distroless). 변경 사유 — CMS 서명(openssl)·CA 어댑터(step CLI)가
#   실행 바이너리를 필요로 한다. Go 바이너리는 정적(CGO_ENABLED=0)이라 alpine(musl)에서 동작.
#   openssl: CMS SignedData 서명/검증. step: step-ca 연동(소스 무수정, CLI 호출).
#   syft: SBOM 자체 생성(누락 아티팩트 스캔 + TrustLink 자기 자신 스캔). 정적 Go 바이너리.
FROM smallstep/step-cli:latest AS stepcli
FROM anchore/syft:latest AS syft
FROM alpine:3.20
RUN apk add --no-cache openssl ca-certificates
COPY --from=stepcli /usr/local/bin/step /usr/local/bin/step
COPY --from=syft /syft /usr/local/bin/syft
COPY trustlink-admin-linux /usr/bin/trustlink-admin
COPY ui-dist /srv/ui
ENTRYPOINT ["/usr/bin/trustlink-admin"]
