# TrustLink 프로토타입 설계 전략 (v2)
ZOT 기반 공급망 보안 산출물 레지스트리 — 단순·독립·유지보수 우선

> v2 변경점: (1) 전제 보강 — 과제 특성상 사용자는 **최종 빌드 바이너리 + SBOM + VEX를 모두 업로드**한다. 즉 SBOM/VEX가 이미 존재할 수 있다. 따라서 TrustLink의 기본 동작은 "생성"이 아니라 **"수용(ingest)·검증·관리"** 이고, 생성은 비어 있을 때의 보조(fallback) 다. (2) GUI 결정 — React 유지 + shadcn/ui + Tailwind.

## 추가 운영 원칙 (이 세션 합의)
- **TrustLink만 전면(front-facing)** 노출. zot·keycloak·dependency-track 등은 **내부 docker 네트워크 전용**으로 두고, 사용자/관리자는 **오직 TrustLink(UI/BFF)** 를 통해서만 접근·관리한다. (단일 진입점/단일 오리진)
- 관리(사용자·용량·로그·레지스트리·취약점/VEX) 행위는 **TrustLink(관리 콘솔/BFF)** 가 백엔드 엔진 API를 호출해 수행한다.

## 0. 한 장 요약 — 설계 3원칙 + 정체성
- ZOT는 바닐라로 두고 옆에 붙인다. 인증·관리·SBOM/VEX 기능은 ZOT 코어를 포크 수정하지 않고 별도 계층(BFF + UI)으로.
- 엔진은 만들지 말고 통합한다. 생성(Syft)·위험분석/VEX(Dependency-Track)·VEX(vexctl)는 검증된 OSS를 백엔드 엔진으로.
- 전부 docker-compose 한 곳에서. 독립 교체·업그레이드 가능.
- 정체성(v2 재정렬): TrustLink의 1차 가치는 **"공급망 산출물의 신뢰할 수 있는 수용·검증·관리·배포 허브"**. 생성은 보조, 자동 생성·AI VEX는 확장.

## 1. 큰 그림 (수용·검증 우선)
```
[GitHub Actions] 빌드 → Sparrow(소스SBOM)·xSCAN(바이너리SBOM) → 서명 → ORAS push (번들)
        │  업로드 산출물 = 바이너리(+서명) [+소스SBOM] [+바이너리SBOM] [+VEX]
        ▼
┌──────────────────── TrustLink (docker-compose) ────────────────────┐
│ [사용자] ─OIDC─► Keycloak (내부)                                    │
│      ▼ (TrustLink 고유 UI: React + shadcn/ui + Tailwind)            │
│  관리시스템 UI ── BFF ─┬─► ZOT (레지스트리, 바닐라+OIDC, referrer)  │
│                        ├─► 검증(서명·SBOM↔바이너리·VEX↔SBOM·스키마)  │
│                        ├─► Syft (SBOM 없을 때만 생성 — 보조)         │
│                        ├─► Dependency-Track API (위험분석+VEX, 헤드리스)│
│                        └─► vexctl (OpenVEX 생성/적용)               │
│  ※ 외부 노출은 TrustLink 단일 진입점만. 나머지는 내부 네트워크 전용. │
└─────────────────────────────────────────────────────────────────────┘
```

## 2. 수용(Ingest) · 검증 흐름 — v2 핵심
업로드는 단건 파일이 아니라 **번들**로 받고, 무엇이 들어왔는지 먼저 분류한다.
```
업로드 번들 도착
 → 분류: 바이너리(+서명) / 소스SBOM / 바이너리SBOM / VEX (각 존재 여부 판별)
 → 검증(수용 게이트):
     · 서명 검증(cosign/Authenticode)
     · SBOM ↔ 바이너리 정합(해시/메타)
     · VEX ↔ SBOM 정합(PURL 매핑·대상 일치)
     · 포맷/스키마 유효성(CycloneDX 등)
 → 분기:
     · SBOM 있음 → 그대로 referrer 결합·보관·표시 (덮어쓰지 않음)
     · SBOM 없음 → "생성" 제안(Syft, 보조)
     · VEX 있음 → 편집기에서 불러와 편집/갱신(원본 보존, doc_version++)
     · VEX 없음 → 스캔 결과로 초안 생성
 → 출처·신뢰등급 표기 + 검증 리포트(통과/경고/실패) + 감사로그
```
원칙: 이미 만들어진 SBOM/VEX는 **절대 덮어쓰지 않는다.** 출처(Sparrow/xSCAN/외부)와 검증 상태를 함께 보관·표시한다.

## 3. 구성요소 (docker-compose 서비스)
| 서비스 | 역할 | 라이선스 | 비고 |
|---|---|---|---|
| zot | OCI 레지스트리(저장·referrer·내장 CVE 스캔) | Apache-2.0 | 바닐라 유지, 설정만. **내부 전용** |
| keycloak (+db) | 인증(IdP), OIDC | Apache-2.0 | 표준 연동. **내부 전용(프록시 경유)** |
| trustlink-bff | 두뇌: 수용·검증·관리 API + 오케스트레이션 + **단일 프론트 프록시** | 자체 | 핵심 자체개발 |
| trustlink-ui | 관리 페이지 — React + shadcn/ui + Tailwind | 자체 | 자체개발 |
| dependency-track-apiserver (+db) | 위험분석 + audit→VEX(헤드리스) | Apache-2.0 | 백엔드 엔진. **내부 전용** |
| syft | SBOM 생성(없을 때 보조) | Apache-2.0 | 온디맨드 |
| vexctl | OpenVEX 생성/적용 | Apache-2.0 | CLI |
| (선택) grype/trivy | 취약점 매핑 | Apache-2.0 | 보조/교차검증 |
| (향후) 오브젝트 스토리지 | 대용량 | MinIO=AGPL-3.0 주의 | 대안 SeaweedFS(Apache-2.0)/zot S3 |

GUI 라이선스: shadcn/ui·Tailwind 모두 MIT 계열. shadcn/ui는 컴포넌트를 저장소에 복사해 소유 → 폐쇄망·커스터마이즈 유리.

## 4. 인증 · 권한
ZOT 기본 인증(htpasswd) → Keycloak OIDC로 일원화(htpasswd는 CLI/CI 보조). 4역할(일반/관리자/파트너/고객) = Keycloak 그룹 → ZOT accessControl.repositories(read/create/update/delete). "Keycloak 콘솔 없이 사용자 관리" = 관리시스템 UI가 **Keycloak Admin API**를 호출해 사용자 CRUD.

## 5. 관리 시스템 (요구 항목별)
| 항목 | 구현 |
|---|---|
| 대시보드/용량관리 | ZOT 스토리지 사용량·디스크·제품/버전 수 집계(metrics 확장) |
| 사용자 관리(Keycloak 최소화) | UI → Keycloak Admin API 래핑 |
| 로그 | 인증·업/다운로드·검증·VEX편집·권한변경 append-only + 해시체인, ZOT events 연동 |
| 레지스트리 관리 | 제품/버전 목록·삭제·리텐션, referrer 조회 (ZOT /v2·search) |
| 시스템 상태 | 컨테이너 헬스·디스크·메모리 |
| 권한 관리 | ZOT accessControl × Keycloak 그룹 UI 매핑 |
| 오브젝트 스토리지(향후) | ZOT S3 백엔드/별도 버킷 용량·객체 관리 |
원칙: 관리시스템은 각 엔진 API를 호출해 보여주는 **얇은 계층**(데이터 재구현·복제 금지).

## 6. SBOM/VEX 기능 (v2 — 수용·검증 우선)
| 기능 | v2 동작 |
|---|---|
| 업로드/다운로드 | ORAS 번들(바이너리·서명·SBOM·VEX) 수용·배포 |
| 검증 | 1급 기능(수용 게이트) — 서명·SBOM↔바이너리·VEX↔SBOM·스키마 |
| SBOM 보기 | 업로드 SBOM 그대로 표시(컴포넌트·라이선스·CVE) |
| 바이너리 SBOM 생성 | SBOM 없을 때만 Syft(보조), 외부 SBOM 보강 옵션 |
| 소스 SBOM | CI(Sparrow) 생성분 보관, 없을 때 소스 지정/업로드 시 생성 |
| 위험분석 | 업로드 SBOM을 DT에 올려 분석(+zot CVE), VEX 적용 잔존위험 |
| VEX | 업로드 VEX 불러와 편집/갱신(원본 보존·doc_version++), 없으면 초안 |
| 출처·신뢰 | TrustLink 생성 vs 업로드 구분 + 검증 상태 표기 |
핵심: 자동 생성은 강제가 아니라 "비어 있을 때 채워주는 보조". 정합성 검증과 출처 표기가 더 중요.

## 7. 데이터 결합 모델 (zot referrers)
```
products/innoecm:1.2.3 (subject = 윈도우 설치 파일, Authenticode)
 ├─ source.cdx.json  (업로드: Sparrow / 없으면 생성)
 ├─ binary.cdx.json  (업로드: xSCAN / 없으면 Syft)
 ├─ vex.cdx.json     (업로드분 편집·승인 / 없으면 초안)
 └─ signature        (cosign/KCDSA)  + 검증리포트·출처 메타
```

## 8. 단계별 로드맵 (단순 → 확장, v2)
| 단계 | 목표 | 내용 |
|---|---|---|
| P1 — 수용·검증(MVP) | "받고·검증하고·본다" | compose(zot+keycloak+bff+ui[React/shadcn]), **단일 프론트 프록시**, 4역할, 번들 업/다운로드, 검증 리포트, SBOM/VEX 보기, 관리 기본(대시보드/용량·사용자·로그·레지스트리) |
| P2 — 분석·VEX | "위험·VEX 관리" | DT 헤드리스 연동, 업로드 VEX 편집·승인, vexctl/CSAF 내보내기, Grype/Trivy 보조 |
| P3 — 생성(보조) | "없으면 만든다" | Syft 바이너리 SBOM 생성, 소스 업로드 시 SW SBOM 생성 |
| P4 — 제품화 | "주요 공급망 도구" | xSCAN/Sparrow 심층기능 흡수, AI 보조 VEX(로컬 LLM 초안+사람 승인), 오브젝트 스토리지, 폐쇄망 어플라이언스 |

## 9. 유지보수 · 단순화 규칙
- ZOT 코어 비수정(BFF/UI로 확장). *예외: 평문 HTTP OIDC 쿠키(WithUnsecure) 등 배포 보정은 최소 패치로 기록.*
- 포맷 CycloneDX 통일.
- 관리시스템 = API를 보여주는 얇은 계층.
- 엔진 교체 가능 인터페이스(Syft↔xSCAN 등).
- 업로드된 SBOM/VEX 불변·출처 보존(절대 덮어쓰지 않음).
- 시크릿 git 금지. 폐쇄망 반입 미러링.

## 10. 다음 액션
1. **단일 프론트(프록시) 통합** — 외부 노출은 TrustLink만, keycloak/zot/DT 포트 미게시.
2. P1 docker-compose 골격(zot OIDC + keycloak + bff + React/shadcn UI).
3. 수용·검증 파이프라인 정의(번들 분류·검증 규칙·분기).
4. Keycloak 4역할 + ZOT accessControl 매핑.
5. Sparrow/xSCAN 실제 CycloneDX 출력 샘플 → 정합 검증·DT 업로드 스키마.
6. DT 헤드리스 연동(P2), Syft 생성(P3).
7. 라이선스 확정(MinIO 대체 여부).

---
## 현재 프로토타입 대비 격차 (착수 메모)
- 현재: zot(28080)·keycloak(8085)·bff(9100) **모두 외부 게시** → v2는 **TrustLink 단일 진입점**으로 통합 필요(프록시).
- 현재 인증은 Keycloak OIDC + htpasswd(CLI). 사용자 관리 BFF(Keycloak Admin API) 구축됨.
- 수용·검증 게이트(서명/SBOM↔바이너리/VEX↔SBOM/스키마)는 **미구현** → P1 핵심으로 구현 대상.
- UI: React+shadcn/ui+Tailwind 자체 UI(trustlink-ui)로 전환 완료. 제품 페이지 + **관리 콘솔(/admin)** 모두 신규 SPA로 구현(구 vanilla-JS 콘솔 page.go 제거). zui(React/MUI)는 연동 패턴 참조용으로만 남김.
