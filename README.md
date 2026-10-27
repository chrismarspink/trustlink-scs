# TrustLink SCS

소프트웨어 공급망 보안(SCS) 플랫폼. 제품 산출물(바이너리·문서·이미지)을 버전별로 보관하고,
SBOM·취약점·VEX 를 산출물에 OCI referrer 로 묶어 관리·배포한다.

- **사람**(브라우저) → Keycloak 단일 로그인 / **기계·CLI**(oras·docker) → ci 계정 또는 개인 API 키
- **그룹 기반 RBAC**(admins / developers / users), 지정되지 않은 경로는 모두 거부(fail-closed)
- **SBOM·취약점·VEX**: SBOM 첨부 → Dependency-Track 분석 → VEX 발행

> 설치·업데이트: [INSTALL.md](INSTALL.md) · 데모 계정: [docs/DEMO-ACCOUNTS.md](docs/DEMO-ACCOUNTS.md)
> ⚠️ 평문 HTTP 구성이다. 운영 전 TLS 적용·기본 비밀번호 교체 필수.

## 구성 — 오픈소스는 공식 이미지 무수정

| 서비스 | 이미지 | 역할 |
|---|---|---|
| `trustlink-admin` | **자체** (이 저장소 `admin-bff/` + `trustlink-ui/`) | 단일 프론트도어(:28080) — UI·관리 콘솔·BFF API, zot·Keycloak 프록시, DT 중개, 제품 권한·기계 계정을 zot 설정으로 렌더 |
| `zot` | `ghcr.io/project-zot/zot` | OCI 레지스트리(:28081 직접 pull/push), RBAC·API 키 |
| `keycloak` + `keycloak-db` | `quay.io/keycloak/keycloak` + `postgres` | OIDC 인증, 사용자·그룹 (전용 DB) |
| `dtrack-apiserver` + `dtrack-db` | `dependencytrack/apiserver` + `postgres` | SBOM 취약점 분석(헤드리스, 내부 전용) |

TrustLink 가 각 모듈에 대해 아는 것은 **이미지 주소(.env)** 와 `docker-compose.yaml` 에 내장한 표준 설정
(zot 설정 파일, Keycloak realm import JSON)뿐이다. 모듈 업데이트 = `.env` 태그 변경.

```
브라우저 ──▶ :28080 trustlink-admin ──┬─▶ /auth  → keycloak ── keycloak-db
                                      ├─▶ /v2 /zot → zot
                                      └─▶ DT API  → dtrack-apiserver ── dtrack-db
oras/docker ──▶ :28081 zot (BFF 가 내려가도 동작, 인증·RBAC 은 zot 이 직접)
```

## 빠른 시작

```bash
cp .env.example .env      # 비밀번호·시크릿 변경
docker compose up -d      # 설치 끝 (realm·관리자 계정·DT 키 자동)
```
접속: `http://<FRONT_HOST>:28080` → `.env` 의 `TL_ADMIN_USER` 로 로그인 → 관리 콘솔 › 사용자에서 계정 발급.

## 저장소 구조

```
docker-compose.yaml        ★ 설치 산출물 (전 모듈 + zot 설정 + Keycloak realm 내장)
.env.example               이미지 주소(버전 고정)·시크릿·관리자 계정
admin-bff/                 BFF (Go, 표준 라이브러리만) — build.sh 로 로컬 빌드
trustlink-ui/              UI (React + Vite)
scripts/
  push-images.sh           trustlink-admin 이미지 Docker Hub 게시
  deploy-remote.sh         상시 서버 반영(git pull → 빌드 → compose up)
  migrate-keycloak-h2.sh   (1회용) 구 구성 Keycloak H2 → Postgres 계정 이전
tools/                     개발·검증 도구(verify, dt-verify, dogfood-sbom, push-stack, zot-sbom)
samples/                   샘플 SBOM
docs/                      설계·가이드 문서
```

## 개발

```bash
# .env 에 TRUSTLINK_ADMIN_IMAGE=trustlink-admin:latest (로컬 빌드 이미지 사용)
bash admin-bff/build.sh   # UI 빌드 → go 빌드(golang:1.22 컨테이너) → 이미지 → BFF 재생성
docker run --rm -v "$PWD/admin-bff":/src -w /src golang:1.22 go test ./...
```
