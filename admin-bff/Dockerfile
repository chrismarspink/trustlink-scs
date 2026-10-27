# TrustLink BFF 이미지.
#   Go 바이너리는 정적(CGO_ENABLED=0)이라 alpine(musl)에서 동작.
#   syft: SBOM 자체 생성(누락 아티팩트 스캔). 정적 Go 바이너리.
#   apache2-utils: htpasswd(bcrypt) — 기계 계정·ci 를 zot htpasswd 로 렌더(access.go).
FROM anchore/syft:latest AS syft
FROM alpine:3.20
RUN apk add --no-cache ca-certificates apache2-utils
COPY --from=syft /syft /usr/local/bin/syft
COPY trustlink-admin-linux /usr/bin/trustlink-admin
COPY ui-dist /srv/ui
ENTRYPOINT ["/usr/bin/trustlink-admin"]
