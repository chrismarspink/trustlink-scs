# TrustLink SCS — 제품 설명 및 완성도·리스크 분석

> 대상: `deploy/zot-keycloak/` 의 TrustLink SCS(Supply Chain Security) 프로토타입.
> 목적: 아티팩트(공급망 산출물)를 **수용·검증·관리·배포**하고, 외부 공급망 보안 도구(SBOM/VEX/취약점 분석)와 연계하는 단일 진입점 플랫폼.
> 본 문서는 실제 코드/구성(`docker-compose.yml`, `admin-bff/*.go`, `trustlink-ui/`, `trustlink/config.container.json`, `keycloak/configure-realm.sh`)에 근거한다. 작성 시점 기준 PoC/프로토타입 단계.

---

## 1. 제품 개요

### 1.1 한 줄 정의
**바닐라 OCI 레지스트리(zot)를 코어로 두고, 그 옆에 인증·관리·SBOM/VEX 계층(BFF + 자체 UI)을 붙여, "공급망 산출물의 신뢰할 수 있는 수용·검증·관리·배포 허브"를 지향하는 단일 진입점 시스템.**

### 1.2 목적과 가치
- 빌드 산출물(바이너리 + 서명 + 소스/바이너리 SBOM + VEX)을 **번들로 수용**하고, 출처·신뢰등급·검증 상태와 함께 보관·배포한다.
- 취약점 분석(Dependency-Track)·VEX 작성/발행을 레지스트리와 **연계**한다(아티팩트에 VEX를 referrer로 재부착).
- zot·Keycloak·Dependency-Track 등 검증된 OSS를 **엔진으로 통합**하고, 직접 만든 것은 오케스트레이션 계층(BFF/UI)뿐. 코어는 포크하지 않는다.

### 1.3 아키텍처 (현재 구현)
```
[브라우저] ──(단일 오리진 http://trustlink:28080)──► trustlink-admin (BFF, Go)
                                                       │  = 단일 프론트도어 + 리버스 프록시
                                                       ├─ 정적 서빙: trustlink-ui (React/shadcn/Tailwind)
                                                       ├─ /v2,/oci,/zot  → zot         (내부 전용)
                                                       ├─ /auth          → keycloak    (내부 전용)
                                                       ├─ /api/*         → BFF 핸들러
                                                       │     ├─ Keycloak Admin API (사용자/그룹 CRUD)
                                                       │     ├─ zot /metrics·statfs·catalog (대시보드/용량/레지스트리)
                                                       │     └─ Dependency-Track API (SBOM ingest→분석→VEX)
                                                       └─ 세션: 인메모리(map)
내부 네트워크 전용: zot · keycloak(+postgres) · dependency-track(+postgres)
```

### 1.4 구성요소
| 서비스 | 역할 | 라이선스 | 노출 |
|---|---|---|---|
| zot | OCI 레지스트리(저장·referrer·내장 CVE 스캔) | Apache-2.0 | 내부 전용 |
| keycloak (+postgres) | OIDC IdP, 4그룹 RBAC | Apache-2.0 | 내부 전용 |
| trustlink-admin (BFF) | 프론트도어·프록시·관리/VEX API·UI 서빙 | 자체개발 | **외부 단일 포트** |
| trustlink-ui | 제품 페이지 + 관리 콘솔(8탭) | 자체개발(shadcn/ui MIT, Tailwind MIT) | (BFF가 서빙) |
| dependency-track (+postgres) | 헤드리스 취약점 분석 → VEX | Apache-2.0 | 내부 전용 |
| syft / vexctl | SBOM 생성 / OpenVEX (보조·계획) | Apache-2.0 | 온디맨드 |

라이선스 구성은 전부 **퍼미시브 계열(Apache-2.0/MIT)** 로, 상용·폐쇄망 납품에 유리하다. (단, 대용량 스토리지로 MinIO 채택 시 AGPL-3.0 주의 — 대안 SeaweedFS/zot S3.)

---

## 2. 완성도 평가

### 2.1 기능별 성숙도
| 영역 | 상태 | 비고 |
|---|---|---|
| 단일 프론트도어/프록시 | ✅ 구현 | `frontdoor.go`. zot/keycloak 포트 비공개, 단일 오리진 |
| OIDC 로그인(제품·관리 분리) | ✅ 구현 | zot 세션(쿠키 state) + BFF 세션(서버측 state) |
| 사용자/그룹 관리 | ✅ 구현 | Keycloak Admin API 래핑(생성·그룹변경·단일역할) |
| 대시보드/용량/시스템 상태 | ✅ 구현 | zot /metrics + statfs + 그래프(자체 SVG/CSS) |
| 레지스트리 관리(레포/태그/삭제) | ✅ 구현 | catalog + tag 삭제(digest) |
| 권한 매트릭스(조회) | ✅ 구현 | config accessControl **읽기 전용** (편집 불가) |
| 로그 | 🟡 부분 | zot 로그 **파일 tail**(검색/페이지). 회전·집계·해시체인 미구현 |
| 리텐션 | 🟡 부분 | **dryRun만**(`retention.dryRun=true`). 실삭제는 config 변경+재기동 |
| 취약점 분석/VEX(제품 VexPanel) | 🟡 부분 | DT 연동·triage·VEX 발행(referrer) 동작. DT 미설정 시 비활성 |
| 설정·스토리지(S3 전환) | 🟡 부분 | 설정 블록 **미리보기 생성만**(실시간 전환 아님) |
| **수용·검증 게이트** | ❌ 미구현 | **서명검증·SBOM↔바이너리·VEX↔SBOM·스키마 정합** — 설계상 1급 기능이나 코드 없음(`bundle.go`는 서명 referrer를 *분류*만 함) |
| OIDC 토큰 서명검증 | ❌ 미구현 | `parseToken`이 JWT payload를 **서명검증 없이** 디코드(PoC) |
| TLS | ❌ 없음 | 전 구간 평문 HTTP |
| HA/수평확장 | ❌ 없음 | 전 컴포넌트 단일 인스턴스, 인메모리 상태 |
| 백업/DR·관측성·CI/CD | ❌ 없음 | 수동 빌드/배포, 백업·모니터링 스택 없음 |
| 자동화 테스트 | ❌ 없음 | deploy 컴포넌트에 테스트 없음 |

### 2.2 종합 판정
- **아키텍처 설계 품질: 높음.** "코어 비포크 + 얇은 BFF + 검증된 OSS 엔진 통합 + 단일 진입점"은 유지보수·교체성·보안 경계 면에서 합리적이다. UI도 자체 shadcn/Tailwind로 깔끔하다.
- **기능 완성도: 데모 가능한 PoC 수준(약 50~60%).** "받고·보고·관리하는" 흐름은 동작하나, **제품의 핵심 차별점인 '수용·검증 게이트'가 미구현**이고, VEX/리텐션/스토리지는 데모 수준이다.
- **운영 성숙도: 프로덕션 미달(약 15~20%).** 보안 하드닝·HA·백업·관측성·CI가 전무하다.

> 요약: **설계는 상용 제품의 골격으로 손색없으나, 현재 산출물은 "기능 시연용 프로토타입"이며 그대로 상용/운영에 투입 불가.**

---

## 3. 문제점 (정확하고 폭넓게)

### 3.1 보안 (가장 시급)
1. **OIDC 토큰 서명 미검증** — `parseToken`이 JWT를 base64 디코드만 한다. 위·변조 토큰으로 권한 상승 가능. 백채널 코드교환 응답을 신뢰하는 구조라 즉시 악용은 어렵지만, 표준(JWKS 서명·`exp`·`aud`·`iss` 검증) 부재는 치명적 결함.
2. **전 구간 평문 HTTP / TLS 없음** — 세션 쿠키·자격증명·토큰이 평문 전송. OIDC 쿠키도 `Secure` 불가(WithUnsecure 보정). MITM·세션 탈취에 노출.
3. **인메모리 세션** — `SessionStore{map}`. 재시작 시 전원 로그아웃 + 단일 인스턴스 강제(HA 불가). 세션 고정/탈취 방어, 만료·회전 정책 빈약.
4. **데모 시크릿 하드코딩** — `configure-realm.sh`에 공통 비밀번호 `Passw0rd!`, 서비스 계정. `.env`에 `CLIENT_SECRET` 등 평문. 시크릿 매니저 부재.
5. **수용 게이트(검증) 미구현** — 서명·SBOM↔바이너리 해시·VEX↔SBOM PURL·스키마 정합 검증이 없다. 즉 **신뢰할 수 없는 산출물도 무검증 수용**된다(제품 정체성과 정면 배치).
6. **감사로그 부재** — 인증·업/다운로드·권한변경·VEX편집의 append-only 해시체인 감사로그가 설계엔 있으나 미구현. 현재 "로그"는 zot 로그파일 tail.
7. **CSRF/입력 검증** — BFF 변경 API(POST/PUT)에 CSRF 토큰·오리진 검증·요청 본문 스키마 검증이 약함.

### 3.2 구조적 문제
1. **단일 진입점 = 단일 장애점(SPOF) 겸 단일 확장점** — BFF가 프록시+UI+API+세션을 모두 담당. BFF 다운 시 전체 마비, BFF 1대로 처리량 상한.
2. **인메모리 상태(세션·OAuth state)로 수평확장 불가** — 외부 세션 저장(Redis 등) 없이는 BFF 다중화 불가.
3. **`trustlink` 호스트네임에 강결합** — issuer·redirect_uri·externalUrl·쿠키 오리진이 모두 `trustlink:28080`에 묶여 `/etc/hosts` 등록 필수. 도메인 변경·다중 도메인·로컬 접근이 취약(localhost 접근 시 OIDC 콜백 state 쿠키 불일치로 로그인 실패).
4. **빌드/릴리스 비재현** — `Dockerfile`이 외부에서 빌드한 `trustlink-admin-linux` 바이너리와 `ui-dist`를 **COPY만** 한다. 멀티스테이지 빌드·CI 없음 → 재현성·공급망 무결성(자기 dogfooding) 결여.
5. **BFF의 "얇은 계층" 원칙 침식** — VEX 매핑·ingest·publish·bundle 등 로직이 BFF에 누적. 엔진 교체 인터페이스가 코드로 추상화되어 있지 않음.
6. **API 계약 부재** — BFF `/api/*`에 버전·OpenAPI 스펙·하위호환 정책 없음.

### 3.3 관리/운영 문제 (HA 포함, §5에서 상세)
1. **HA 전무** — zot·keycloak·dtrack·bff·postgres×2 모두 단일 인스턴스.
2. **백업/DR 없음** — 레지스트리 데이터·keycloak DB·dtrack DB 백업/복구 절차 없음.
3. **관측성 부족** — zot `/metrics`를 BFF가 스크랩해 화면 표시만. 중앙 메트릭/로그 집계·트레이싱·알림(예: 디스크 임계) 없음.
4. **용량 리스크 현실화** — 로컬 파일시스템 스토리지, 관측상 디스크 **94% 사용**. 자동 정리(리텐션 실삭제)는 비활성.
5. **헬스체크 불균일** — keycloak/dtrack/DB엔 healthcheck 있으나 **zot·trustlink-admin엔 없음**. 오케스트레이터 자동 복구 어려움.
6. **업그레이드 전략 부재** — zot/keycloak/dtrack 버전 핀 고정·롤링 업그레이드·스키마 마이그레이션 절차 없음.

### 3.4 데이터/스토리지
- 로컬 FS 단일 볼륨(`/var/lib/registry`), `dedupe=true`, `gc=true`(gcInterval 24h). 객체 스토리지/공유 캐시 미적용 → 다중 zot 불가, 용량 수평확장 불가.
- 리텐션은 `dryRun=true`로 **삭제 후보만 산출**, 실제 정리는 수동 config 변경+재기동.

---

## 4. 상업적 목적의 문제점

1. **프로덕션 보안 기준 미달** — TLS·토큰 서명검증·외부 세션·시크릿 관리·감사로그 부재. 공급망 보안 제품이 정작 자체 보안이 PoC 수준이면 **신뢰성·레퍼런스 확보 불가**, 보안 심사/인증(예: 공공·금융 도입 요건) 통과 불가.
2. **핵심 차별점 미완성** — 시장의 zot/Harbor/Artifactory 대비 차별점은 "수용·검증 게이트 + 출처·신뢰등급"인데 이게 미구현이라, 현재로선 **"zot + Keycloak + DT를 묶은 통합 데모"** 이상의 가치 주장이 어렵다.
3. **SLA/HA 불가** — 단일 인스턴스·인메모리 세션으로 가용성 SLA(예: 99.9%) 약정 불가. 상용 고객의 무중단·장애복구 요구 충족 못 함.
4. **멀티테넌시 부재** — 단일 realm·단일 네임스페이스. 고객사/프로젝트 격리, 쿼터, 사용량 과금 단위가 없어 SaaS·다고객 납품 모델 곤란.
5. **유지보수·지원 부담** — 자체 BFF/UI는 곧 유지보수 비용. CI/테스트/문서/버전관리 체계 없이는 인력 의존·회귀버그 위험. (현재 `deploy/`가 git 미추적인 점도 형상관리 공백.)
6. **운영 도구화 부족** — 백업/복구, 모니터링/알림, 업그레이드, 용량관리 자동화가 없어 **TCO(총소유비용)** 가 높고, 폐쇄망 어플라이언스로 납품 시 현장 운영이 어렵다.
7. **확장성 한계로 성장 천장** — 트래픽/저장량 증가 시 수평확장 경로(객체 스토리지·HA·캐시)가 설계만 있고 미구현이라, 초기 고객 규모를 넘기기 어렵다.

> 정리: **PoC로서의 사업 타당성 검증·데모에는 충분하나, 유상 납품/운영 계약에는 보안·HA·차별기능 3축의 완성이 선행되어야 한다.**

---

## 5. HA·관리상 예상 취약 지점 (구체)

| 컴포넌트 | 현재 | HA/운영 리스크 | 해결 방향 |
|---|---|---|---|
| **BFF(trustlink-admin)** | 단일, 인메모리 세션/OAuth state | SPOF, 다중화 불가(세션 분실), 재시작=전원 로그아웃 | **세션을 Redis 등 외부 저장**으로 분리 → N replica + LB. 헬스체크 추가 |
| **zot** | 단일, 로컬 FS | 다중화 불가(공유 스토리지 없음), 용량 천장, 헬스체크 없음 | **S3/SeaweedFS + Redis 캐시드라이버** → 다중 zot. liveness/readiness |
| **Keycloak** | 단일 + postgres | IdP 다운=전체 로그인 불가 | 클러스터(Infinispan) + 공유 DB + 다중 노드 |
| **postgres ×2 (kc, dtrack)** | 단일 | DB SPOF, 백업 없음 | HA(Patroni/운영형 RDS) + 정기 백업/PITR |
| **Dependency-Track** | 단일(Java, 무거움) | 분석 처리량 한계, 자원 과다 | apiserver 스케일 + 작업 큐, 자원 한도 |
| **프론트도어 라우팅** | BFF 내장 프록시 | LB·TLS 종단·레이트리밋 기능 부재 | 앞단에 Ingress/L7 LB(TLS·WAF·rate-limit) 도입 |
| **상태/세션** | 인메모리 | 무상태 확장 불가 | 외부 세션·캐시 일원화(Redis) |
| **데이터 보호** | 백업/DR 없음 | 디스크/DB 손상 시 복구 불가 | 레지스트리·DB 백업, 복구 리허설, 보존정책 |
| **관측성** | 화면 표시만 | 장애 조기탐지/알림 불가 | Prometheus+Grafana+Alertmanager, 로그 집계(Loki/ELK) |
| **시크릿** | .env 평문 | 유출 위험, 회전 불가 | Vault/SOPS/K8s Secret + 회전 |

추가로 **인증서·시크릿 회전**, **로그 회전/보존**, **업그레이드 시 다운타임/마이그레이션** 절차가 운영 공백으로 남아 있다.

---

## 6. 개선 사항 (영역별)

### 6.1 보안 하드닝 (최우선)
- OIDC **토큰 서명검증**(JWKS, `exp`/`aud`/`iss` 검증) — BFF·zot 양쪽.
- **TLS 전 구간**(앞단 LB/Ingress 종단 + 내부 mTLS 옵션). 쿠키 `Secure`/`SameSite` 정상화.
- **세션 외부화**(Redis): 만료·회전·강제 로그아웃, HA 전제.
- **시크릿 매니저**(Vault/SOPS) + 데모 계정 제거/회전, 최소권한 서비스계정.
- **수용·검증 게이트 구현**(제품 정체성): cosign/Authenticode 서명검증, SBOM↔바이너리 해시 정합, VEX↔SBOM PURL 매핑, CycloneDX 스키마 검증 → 통과/경고/실패 리포트 + **fail-closed**.
- **감사로그**: append-only + 해시체인(인증·업/다운·권한·VEX), 변조 탐지.

### 6.2 구조·확장성
- **무상태 BFF + 외부 세션 → N replica + L7 LB.**
- **zot 객체 스토리지(S3/SeaweedFS) + Redis 캐시 → 다중 zot, 용량 수평확장.**
- **호스트네임 결합 제거**: 환경별 도메인/issuer 주입, 다중 도메인·로컬 개발 지원.
- **엔진 어댑터 인터페이스**(SBOM 생성, 취약점 분석, VEX)로 교체성 확보.
- **BFF API 버전·OpenAPI 스펙·계약 테스트.**

### 6.3 운영·배포
- **멀티스테이지 Dockerfile + CI/CD**(빌드·테스트·이미지 서명·SBOM 생성으로 **자기 dogfooding**), 버전 핀 고정.
- **백업/DR**(레지스트리·DB), 복구 리허설, 보존정책. **리텐션 실삭제** 운영 전환.
- **관측성 스택**(메트릭/로그/트레이스/알림 — 디스크 임계 자동 알림 포함), 모든 컴포넌트 헬스체크.
- **형상관리**: `deploy/` git 추적, 환경 분리(dev/stg/prod), IaC.

### 6.4 상업화
- **멀티테넌시**(realm/네임스페이스/쿼터/사용량), RBAC 매트릭스 **편집** UI.
- **K8s Helm 차트**(HA 기본) + 폐쇄망 오프라인 번들(이미지 미러·차트·SBOM).
- 컴플라이언스(감사로그·접근통제·암호화) 문서화로 도입심사 대응.

---

## 7. 개선 전략 (단계별 로드맵)

| 단계 | 목표 | 핵심 작업 | 완료 기준 |
|---|---|---|---|
| **S0 — 보안 기반(필수)** | "안전하게 데모/파일럿" | TLS, OIDC 서명검증, 세션 Redis화, 시크릿 매니저, 데모계정 제거, 모든 컴포넌트 헬스체크 | 외부 보안점검 통과 가능 수준 |
| **S1 — 차별 기능** | "검증하는 허브" | **수용·검증 게이트**(서명/SBOM↔바이너리/VEX↔SBOM/스키마) + 출처·신뢰등급 + 감사로그(해시체인) | 무검증 수용 차단(fail-closed), 검증 리포트 제공 |
| **S2 — HA·확장** | "끊기지 않고 큰다" | 무상태 BFF 다중화+LB, zot 객체스토리지+Redis, Keycloak/DB HA, 백업/DR, 관측성·알림 | 단일 노드 장애 시 무중단, 백업 복구 검증 |
| **S3 — 운영 자동화** | "운영비를 낮춘다" | CI/CD(이미지 서명·SBOM), 리텐션 실운영, 업그레이드/마이그레이션 절차, IaC/Helm | 원클릭 배포·롤백, 정기 백업·업그레이드 |
| **S4 — 상용화** | "다고객·납품형" | 멀티테넌시·쿼터·과금단위, 폐쇄망 오프라인 번들, 컴플라이언스 문서 | SaaS/온프레 납품 가능, 도입심사 대응 |

### 전략 요약
1. **순서가 중요하다**: 보안(S0)을 먼저 닫지 않으면 어떤 기능도 상용 신뢰를 못 얻는다.
2. **차별점(S1)을 빨리 증명**: "검증 게이트 + 출처/신뢰등급"이 경쟁 레지스트리 대비 유일한 차별점이므로, HA보다 먼저(또는 병행) 완성해 가치를 명확히 한다.
3. **HA/확장(S2)은 무상태화 한 번으로 다수 문제를 동시 해결**: 세션 외부화 + 객체 스토리지가 BFF·zot 다중화의 공통 열쇠다.
4. **자기 dogfooding**: 자사 제품을 자사 빌드 파이프라인에 적용(이미지 서명·SBOM·VEX)하면 신뢰성·레퍼런스·차별점을 동시에 확보한다.

---

## 부록 — 근거 파일
- 토폴로지/노출: `docker-compose.yml` (단일 외부 포트, 내부 전용, healthcheck 불균일)
- 프론트도어/프록시: `admin-bff/frontdoor.go`
- 세션·OIDC·토큰: `admin-bff/main.go` (`SessionStore{map}`, `parseToken` 서명 미검증)
- 서명 "분류"만(검증 아님): `admin-bff/bundle.go`
- VEX 연동: `admin-bff/vex_*.go`, 제품 UI `trustlink-ui/src/pages/VexPanel.tsx`
- zot 스토리지/리텐션: `trustlink/config.container.json` (`gc=true`, `retention.dryRun=true`, 로컬 FS)
- 데모 계정/시크릿: `keycloak/configure-realm.sh`, `.env`
- 설계 의도/격차: `DESIGN-STRATEGY-v2.md` (수용·검증 게이트 "미구현" 명시)
