# TrustLink SCS — 설치·업데이트

설치 산출물은 **`docker-compose.yaml` 1개 + `.env`** 다. 오픈소스 모듈(zot·Keycloak·Dependency-Track·PostgreSQL)은
공식 이미지를 무수정으로 내려받고, 자체 이미지는 `trustlink-admin` 하나다.

## 0. 사전 요구
- Docker 24+, Docker Compose v2.23+ (`configs.content` 사용)
- 메모리 8GB 이상 권장(Dependency-Track ≈ 4.5GB)
- 브라우저가 접속할 호스트명(`FRONT_HOST`)이 서버를 가리켜야 한다. 시험용이면 `/etc/hosts` 에 `127.0.0.1 trustlink`
- 개방 포트: **28080**(웹·관리·로그인), **28081**(레지스트리 pull/push)

## 1. 설치

```bash
cp .env.example .env
vi .env          # 모든 change-me-* 값을 강한 값으로. FRONT_HOST 는 실제 접속 주소.
docker compose up -d
docker compose ps   # zot-init 은 Exited (0) 이 정상
```

자동으로 처리되는 것:
| 항목 | 방법 |
|---|---|
| Keycloak realm·그룹(admins/developers/users)·OIDC 클라이언트 | 공식 `--import-realm` (realm 이 없을 때만) |
| TrustLink 관리자 1명(`TL_ADMIN_USER`, admins) | 위 realm import 에 포함 — **최초 1회만** |
| 레지스트리 계정 ci·svc-bff | `zot-init` 이 htpasswd 생성(기동 시마다 .env 값 반영) |
| Dependency-Track admin 비밀번호·API 키 | BFF 가 최초 기동 시 설정·발급, `tl-sor` 볼륨에 보관 |

설치 후: `http://<FRONT_HOST>:28080` → 관리자로 로그인 → **관리 콘솔 › 사용자**에서 계정 발급(임시 비밀번호 자동 생성).
데모 계정이 필요하면 `.env` 에 `COMPOSE_PROFILES=demo` 후 `docker compose up -d` ([docs/DEMO-ACCOUNTS.md](docs/DEMO-ACCOUNTS.md)).

## 2. 업데이트 (계정·데이터 유지)

```bash
vi .env                       # 예: KEYCLOAK_IMAGE=quay.io/keycloak/keycloak:26.8.0
docker compose pull
docker compose up -d          # 바뀐 서비스만 재생성
```
- 데이터는 모두 named volume 에 있어 컨테이너·이미지를 바꿔도 유지된다.

  | 볼륨 | 내용 |
  |---|---|
  | `kc-db` | Keycloak 계정·그룹·realm |
  | `tl-data` | 레지스트리 아티팩트·SBOM·VEX |
  | `dtrack-db`, `dtrack-data` | 취약점 분석 DB |
  | `tl-sor` | 웹 세션·감사 기록·DT API 키 |
- realm import 는 realm 이 이미 있으면 건너뛴다 → 운영 중 바꾼 비밀번호·추가 사용자 유지.
- 업데이트 전 백업 권장:
  ```bash
  docker compose exec -T keycloak-db pg_dump -U keycloak keycloak > kc-$(date +%F).sql
  docker compose exec -T dtrack-db  pg_dump -U dtrack  dtrack   > dt-$(date +%F).sql
  ```
- 메이저 버전 업그레이드(예: Keycloak 26→27, PostgreSQL 16→17)는 각 프로젝트의 업그레이드 노트를 먼저 확인.
  PostgreSQL 메이저 변경은 dump/restore 가 필요하다.

## 3. 구 구성에서 전환 (1회)

구 구성(Keycloak `start-dev` + 내장 H2, zot 자체 빌드 이미지)에서 넘어올 때:
1. `git pull` 후 `.env` 에 새 항목 추가(`.env.example` 참고: `KC_DB_PASSWORD`, `TL_ADMIN_*`, `*_IMAGE` 등).
   `ZOT_OIDC_CLIENT_SECRET`·`TRUSTLINK_ADMIN_SECRET` 은 **기존 값 유지**.
2. 구 compose 프로젝트 이름이 `trustlink` 가 아니면 `.env` 에 `COMPOSE_PROJECT_NAME=<기존 이름>` (기존 볼륨 재사용).
3. `bash scripts/migrate-keycloak-h2.sh` — H2 의 계정을 Postgres 로 이전(비밀번호 유지, 구 볼륨은 보존).
4. `docker compose up -d`

## 4. 설정 커스터마이즈
| 항목 | 위치 |
|---|---|
| 그룹↔레포 RBAC, 보존정책 | `docker-compose.yaml` › `configs.zot-config` (`accessControl`, `retention`) |
| 보존정책 실제 적용 | `.env` `ZOT_RETENTION_DRYRUN=false` |
| 사용자·그룹 | 관리 콘솔 › 사용자 (또는 Keycloak 관리 콘솔 `/auth/admin`, master realm 으로 로그인 → trustlink realm) |

## 5. 검증 도구
`tools/verify.sh`(인증·RBAC 점검, 데모 계정 필요), `tools/dt-verify.sh`(DT 연동).
