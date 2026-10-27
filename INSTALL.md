# TrustLink SCS — 설치·업데이트

설치 산출물은 **`docker-compose.yaml` 1개 + `.env`** 다. 오픈소스 모듈(zot·Keycloak·Dependency-Track·PostgreSQL)은
공식 이미지를 무수정으로 내려받고, 자체 이미지는 `trustlink-admin` 하나다.

## 0. 사전 요구
- Docker 24+, Docker Compose v2.23+ (`configs.content` 사용)
- 메모리 8GB 이상 권장(Dependency-Track ≈ 4.5GB)
- 브라우저가 접속할 호스트명(`FRONT_HOST`)이 서버를 가리켜야 한다. 시험용이면 `/etc/hosts` 에 `127.0.0.1 trustlink`
- 개방 포트: **28080**(웹·관리·로그인), **28081**(레지스트리 pull/push)
- **호스트 방화벽(ufw 등)이 켜진 서버**: zot 컨테이너가 OIDC issuer(`http://<FRONT_HOST>:28080`)에 접속할 수 있도록
  컨테이너 대역 → 28080 을 1회 허용한다(재부팅 후에도 유지, BFF IP 가 바뀌어도 무관). 28080 은 원래 공개 포트라 노출 범위는 늘지 않는다.
  ```bash
  sudo ufw allow from 172.16.0.0/12 to any port 28080 proto tcp comment "trustlink: containers -> BFF (OIDC issuer)"
  ```
  허용이 없으면 zot 이 `failed to initialize new relying party oidc` 로 재시작을 반복한다.
  (`FRONT_HOST` 가 도메인이면 compose 의 네트워크 별칭으로 내부에서 바로 BFF 로 가므로 이 규칙도 필요 없다.)

## 1. 설치

```bash
cp .env.example .env
vi .env          # 모든 change-me-* 값을 강한 값으로. FRONT_HOST 는 실제 접속 주소.
docker compose up -d
docker compose ps
```

자동으로 처리되는 것:
| 항목 | 방법 |
|---|---|
| Keycloak realm·그룹(admins/developers/users)·OIDC 클라이언트 | 공식 `--import-realm` (realm 이 없을 때만) |
| TrustLink 관리자 1명(`TL_ADMIN_USER`, admins) | 위 realm import 에 포함 — **최초 1회만** |
| 레지스트리 계정 ci·svc-bff | BFF 가 zot htpasswd 로 생성(기동 시마다 .env 값 반영) |
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

## 4. 계정·권한 운영 (관리 콘솔)

| 메뉴 | 하는 일 |
|---|---|
| 사용자 | 사람 계정 생성(임시 비밀번호 1회 표시)·역할(관리자/내부 개발자/외부 사용자)·고객사 지정·비활성·삭제·비밀번호 재설정 |
| 고객사 | 고객사 추가·삭제 (Keycloak 그룹 `org-<ID>`) |
| 제품 권한 | 제품마다 업로드(쓰기)·다운로드(읽기) 대상 지정. 개별 설정이 없는 제품은 내부(개발자·ci) 전용 |
| 기계 계정 | oras 자동화용 계정 발급 — `ci-…`(업로드), `robot-…`(다운로드), 만료일·재발급·폐기 |

- 판정은 zot 기본 기능(accessControl)이 한다. BFF 는 위 설정을 zot 설정 파일·htpasswd(`zot-managed` 볼륨)로 만들고,
  zot 이 재시작 없이 반영한다(보통 1~2초). 웹 조회·일괄 다운로드도 같은 규칙으로 판정한다.
- 역할·고객사 변경은 사용자가 다음에 로그인할 때 적용된다.
- 사람 계정의 oras 사용: 웹 로그인 비밀번호는 받지 않는다 → zot 화면(`/zot`)에서 본인 API 키를 발급해 사용.

## 5. 설정 커스터마이즈
| 항목 | 위치 |
|---|---|
| 기본 권한 규칙, 보존정책 | `docker-compose.yaml` › `configs.zot-config` (`accessControl` 기본값, `retention`) — 제품별 권한은 관리 콘솔 |
| 보존정책 실제 적용 | `.env` `ZOT_RETENTION_DRYRUN=false` |
| 사용자·그룹 | 관리 콘솔 › 사용자 (또는 Keycloak 관리 콘솔 `/auth/admin`, master realm 으로 로그인 → trustlink realm) |

## 6. 검증 도구
`tools/verify.sh`(인증·RBAC 점검, 데모 계정 필요), `tools/dt-verify.sh`(DT 연동).
