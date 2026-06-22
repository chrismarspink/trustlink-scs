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

## 2. 이미지 확보 — 두 가지 방법

### (A) Docker Hub — compose-only 설치 [권장, 이미지 게시 후]
커스텀 이미지(zot·BFF)를 Docker Hub 에 게시(배포자 1회). 기본 게시본: **`jkkim7202/trustlink-zot`, `jkkim7202/trustlink-admin`** (2026-06-22):
```bash
docker login -u <계정>                  # push 권한 계정
NS=<계정> bash scripts/push-images.sh   # <계정>/trustlink-zot, .../trustlink-admin push
```
설치측은 빌드 없이 compose 로만:
```bash
docker compose -f docker-compose.yml -f docker-compose.deploy.yml pull
docker compose -f docker-compose.yml -f docker-compose.deploy.yml up -d
```
> 다른 네임스페이스면 `TRUSTLINK_ZOT_IMAGE`/`TRUSTLINK_ADMIN_IMAGE` env 로 지정. 미게시 상태면 (B) 사용.

### (B) 소스 빌드 [이미지 미게시 시]
```bash
# zot 이미지(trustlink:latest): zot 소스에서 빌드 (make binary-minimal / docker build)
# BFF 이미지(trustlink-admin:latest) + UI: 동봉 스크립트
bash admin-bff/build.sh        # UI 빌드 → go 빌드 → 이미지 빌드 → recreate
```
업스트림 이미지(keycloak·step-ca·postgres·dependency-track)는 compose 가 공개 레지스트리에서 자동 pull.

## 3. 기동 + 초기 설정

```bash
# 3-1) Keycloak 렐름/클라이언트/사용자 + htpasswd(ci) + OIDC 시크릿 자동 구성 + zot 기동
bash scripts/bootstrap.sh

# 3-2) step-ca 기동 (Root/Intermediate 자동 init, CRL 활성)
docker compose up -d step-ca
#   신뢰 앵커·발급 CA 를 호스트로 추출(BFF 가 마운트해 다운로드/검증에 사용)
docker compose exec -T step-ca cat /home/step/certs/root_ca.crt         > stepca/root_ca.crt
docker compose exec -T step-ca cat /home/step/certs/intermediate_ca.crt > stepca/issuer_ca.crt
#   (재현성 주의: ca.json 의 crl.enabled=true, provisioner claims.maxTLSCertDuration=8760h 패치 필요 — SPEC §11)

# 3-3) Dependency-Track 부트스트랩(팀/권한/API 키 → .env 의 DT_API_KEY)
bash scripts/dt-bootstrap.sh

# 3-4) 전체 스택 기동
docker compose up -d
```

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
