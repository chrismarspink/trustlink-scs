# 오프라인: 로컬 zot:latest(distroless) 베이스에 커스텀 UI 포함 linux 바이너리만 교체
FROM zot:latest
COPY zot-linux-arm64 /usr/bin/zot
ENTRYPOINT ["/usr/bin/zot"]
