# TrustLink SCS — 설치·설정 가이드 (타 시스템)

zot(OCI 레지스트리) + Keycloak(OIDC) + step-ca(CA) + Dependency-Track(취약점) + TrustLink BFF 로 구성된
공급망 보안(SCS) 스택을 새 시스템에 설치하는 절차.

## 0. 사전 요구
- Docker 24+, Docker Compose v2
- `/etc/hosts` 에 단일 오리진 호스트 등록 (브라우저 OIDC 쿠키·issuer 일치용):
  ```
  127.0.0.1   trustlink
  ```
- 외부 노출 포트: **28080**(웹/관리/OIDC), **28081**(레지스트리 직접 pull/push)

## 1. 시크릿 준비
```bash
cp .env.example .env
# 최소: KC_ADMIN_PASSWORD, CI_PASSWORD, SVC_BFF_PASS, TRUSTLINK_ADMIN_SECRET,
#       DT_DB_PASSWORD, DT_ADMIN_PASSWORD 를 임의 강한 값으로 변경
# (FRONT_HOST=trustlink, FRONT_PORT=28080 기본)
```
> ⚠️ `.env`·`zot/htpasswd`·`zot/oidc-credentials.json`·`stepca/*`·키 파일은 **절대 커밋 금지**(이미 `.gitignore`).

## 2. 원커맨드 설치 [권장]

통합 compose(`docker-compose.deploy.yml`, 자기완결)로 **이미지 다운로드 + 기동 + 초기 설정**을 한 번에:
```bash
bash scripts/install.sh
```
수행 내용(순서 자동화): 이미지 pull → 시크릿/htpasswd(ci·svc-bff) → Keycloak·step-ca·DT 기동 → realm/clients(zot·trustlink-admin)/groups/users 구성 → CA Root/Intermediate 추출 → zot·BFF 기동 → DT 부트스트랩.

- 커스텀 이미지는 Docker Hub `jkkim7202/trustlink-zot`·`jkkim7202/trustlink-admin`(공식 zot + 평문HTTP OIDC 패치 / BFF). 나머지(keycloak·step-ca·postgres·dependency-track)는 **공식 오픈소스 이미지 자동 pull**.
- 이미지 네임스페이스 교체: `TRUSTLINK_ZOT_IMAGE`/`TRUSTLINK_ADMIN_IMAGE` env.

> 왜 스크립트인가: BFF 가 step-ca 가 생성하는 Root/Issuer 인증서를 마운트하므로, 단순 `docker compose up` 한 번으로는 **인증서 생성→추출→BFF 기동 순서**를 맞출 수 없다. install.sh 가 이 순서를 처리한다.

### (대안) 소스 빌드 후 설치
이미지를 직접 빌드해 쓰려면: zot 이미지는 zot 소스에서 빌드(`make`/docker build), BFF 는 `bash admin-bff/build.sh`. 그 후 `TRUSTLINK_*_IMAGE` 를 로컬 태그로 지정하고 `bash scripts/install.sh`.

## 2-b. 통합 인증(Keycloak SSO) 구조

**BFF(trustlink-admin)가 단일 프론트도어**(포트 28080)다. 사용자는 **Keycloak 1회 로그인**으로 전부 접근:
- 제품/관리 UI·zot 레지스트리(`/v2`) → Keycloak OIDC (zot·trustlink-admin 클라이언트)
- Dependency-Track → BFF 가 서버측 API 키로 중개(사용자 직접 로그인 없음, 내부 전용)
- step-ca → BFF 어댑터가 발급/조회 중개(평면2). 검증자는 step-ca(28443)에 직접(평면1)

즉 DT·step-ca 는 외부 비노출·BFF 뒤에 있어 **별도 로그인이 없고**, 사람 인증은 Keycloak 하나로 통일된다. (DT 자체 웹 UI 를 OIDC 로 직접 붙이는 건 본선 비목표 — 필요 시 DT `ALPINE_OIDC_*` 로 별도 구성 가능.)

## 4. 검증
```bash
bash scripts/verify.sh          # 인증/RBAC/엔드포인트 자동 점검 (모두 PASS)
```
- 웹/관리 콘솔: `http://trustlink:28080` → 우측 상단 로그인(Keycloak). `admins` 그룹은 관리 콘솔 접근.
- 레지스트리: `oras login trustlink:28081 -u ci -p <CI_PASSWORD> --plain-http` 후 pull/push.

## 5. 설정 항목 (운영 커스터마이즈)
| 항목 | 위치 | 설명 |
|---|---|---|
| 그룹↔레포 RBAC | `trustlink/config.container.json` `accessControl` | fail-closed, 경로별 read/create/update/delete |
| 사용자/그룹 | Keycloak (또는 관리 콘솔 사용자 탭) | developers/partners/customers/admins |
| CMS 암호 알고리즘 | compose env `CMS_CONTENT_CIPHER`/`CMS_RSA_PADDING` | FIPS 승인값 기본(AES-256-GCM/OAEP) |
| FIPS 검증 모듈 | 배포 OE | alpine→RHEL UBI/Ubuntu Pro FIPS 교체(SPEC §12) |
| 세션 영속 | compose env `SESSIONS_PATH` | 재시작/재배포 로그인 유지 |

## 6. 운영 주의
- **PoC 기본 비밀번호**(`docs/DEMO-ACCOUNTS.md`)는 시연용 — 운영 전 **전부 교체 + 계정 정리 + TLS 적용**.
- TLS 미적용(평문 HTTP) 배포에서는 OIDC 쿠키가 `WithUnsecure` 로 동작(콜백 정상화). 운영은 전 구간 TLS + 쿠키 `Secure`.
- 자세한 CA 운영(발급·갱신·폐기·CRL/OCSP)은 `docs/CMS-STEPCA-SPEC.md` §6b·§6c.
