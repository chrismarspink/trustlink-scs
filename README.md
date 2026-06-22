# TrustLink SCS

zot(OCI 레지스트리) + Keycloak(OIDC) + step-ca(CA) + Dependency-Track(취약점) + TrustLink BFF 로 구성된
**공급망 보안(Software Supply-chain Security) 스택**.
- **사람**(브라우저) → Keycloak OIDC 로그인 / **기계·CLI**(oras·docker) → htpasswd 또는 API 키
- **그룹 기반 RBAC**(developers / partners / customers / admins) fail-closed
- **SBOM·취약점·VEX**(syft·Dependency-Track), **CMS 서명·암호화 배포**(step-ca + openssl, .p7s/.p7m)

> **설치(타 시스템)**: [INSTALL.md](INSTALL.md) — 소스 빌드 / Docker Hub compose-only 두 경로.
> 전체 제품 설계(BFF·CA·CMS·FIPS): [docs/CMS-STEPCA-SPEC.md](docs/CMS-STEPCA-SPEC.md). 데모 계정: [docs/DEMO-ACCOUNTS.md](docs/DEMO-ACCOUNTS.md).
> ⚠️ PoC 기본 비밀번호는 시연용 — 운영 전 전부 교체 + TLS 적용.

## 1. 역할 → 그룹 → 권한

| 역할 | Keycloak 그룹 | repo 경로 | 허용 동작 |
|---|---|---|---|
| 개발자 | `developers` | `products/**` | read, create, update |
| 파트너사 | `partners` | `products/**` | read |
| 고객사 | `customers` | `products/**` | read |
| 관리자 | `admins` | (adminPolicy) | read, create, update, delete |
| CI/CLI(기계) | htpasswd `ci` | `products/**` | read, create, update |

기본 정책은 `defaultPolicy: []`(전부 차단) → 필요한 경로만 여는 fail-closed.
샘플 사용자(역할별 1명): `dev1`, `partner1`, `acme1`, `admin1` / 공통 비밀번호 `Passw0rd!` (PoC 전용).

## 2. 기동 / 검증

```bash
# 1) 시크릿 채우기
cp .env.example .env
# .env 의 KC_ADMIN_PASSWORD, CI_PASSWORD 를 임의 값으로 변경

# 2) 부트스트랩(전 과정 자동): htpasswd 생성 → keycloak 기동 → realm/client/users 구성
#    → 클라이언트 시크릿을 .env 와 zot/config.json 에 자동 반영 → zot 기동
bash scripts/bootstrap.sh

# 3) 검증(모두 PASS 여야 함)
bash scripts/verify.sh
```

`verify.sh` 통과 항목:
1. `zot verify` 설정 스키마 유효
2. zot `/v2/`(401, 인증 필요) · Keycloak realm · OIDC discovery 헬스
3. 익명 push 거부(401, fail-closed)
4. htpasswd `ci` 계정으로 `products/**` 에 curl 기반 OCI push/pull 성공
5. `dev1` OIDC 토큰의 `groups` 클레임에 `developers` 포함(그룹 매퍼 동작)

### 브라우저 OIDC 로그인 확인(수동)
1. 호스트 `/etc/hosts` 에 다음을 추가(issuer/hostname 정렬, 아래 §4 참고):
   ```
   127.0.0.1 keycloak
   ```
2. 브라우저로 http://localhost:5002/ 접속 → zot UI 에서 Keycloak 로그인 → `dev1 / Passw0rd!`.
3. CLI/CI 용 자격증명이 필요하면 로그인 후 zot UI 에서 **API 키**를 발급해 사용합니다.

## 2-B. 개발된 TrustLink(호스트 바이너리, 최신 UI)에 적용

도커 이미지(`zot:latest`)의 임베드 UI 가 구버전이라, 최신 UI 를 쓰는 **호스트 TrustLink**(`bin/zot-darwin-arm64`, `http://localhost:28080`)에 동일한 Keycloak OIDC + RBAC 를 적용했습니다.

- 설정: [trustlink/config.json](trustlink/config.json) → `/tmp/zot-run.json` 으로 복사해 기동.
  - `issuer = http://localhost:8085/realms/trustlink`, `externalUrl = http://localhost:28080`
  - `htpasswd`/`credentialsfile` 은 이 레포의 절대경로(`zot/htpasswd`, `zot/oidc-credentials.json`)를 참조.
- Keycloak 은 `KC_HOSTNAME=http://localhost:8085` 로 전환 → **호스트 프로세스와 브라우저 모두 `/etc/hosts` 없이** localhost 로 issuer 에 도달(sudo 불필요).
- 도커 zot(5002, 구버전 UI)는 `docker compose stop zot` 으로 중지. (issuer 가 localhost 로 바뀌어 도커 내부 zot 와는 양립 불가)

기동(수동):
```bash
cd /Users/chris/ZOT
cp deploy/zot-keycloak/trustlink/config.json /tmp/zot-run.json
./bin/zot-darwin-arm64 serve /tmp/zot-run.json     # 기존 28080 프로세스는 먼저 종료
```
브라우저: http://localhost:28080/ → 우측 상단 사람 아이콘 → **Keycloak** → `dev1 / Passw0rd!`.

> accessControl 은 `products/**` 와 **`innotium/**`** 두 경로에 그룹 RBAC 를 적용합니다(developers RW · partners/customers R · admins 전체 · ci RW). 기존 Innotium 제품(8개)이 이 정책으로 그룹별 노출됩니다.
> `defaultPolicy: []`(fail-closed)이므로 그 외 경로와 **비로그인 사용자에게는 조회되지 않습니다**. 다른 네임스페이스를 열려면 동일 형식의 블록을 추가하세요.

## 3. 인증 설계 (중요)

- **사람**은 OIDC(브라우저)로 로그인합니다. 그룹 기반 `accessControl` 은 **UI 세션 로그인** 사용자와, **OIDC 로그인 후 발급한 API 키**(로그인 시 저장된 그룹을 승계)에 적용됩니다.
- **CLI/CI(oras, docker)는 OIDC 를 직접 쓸 수 없습니다.** → htpasswd `ci` 계정 또는 발급한 API 키를 사용합니다.

```bash
# 예: ci 계정으로 oras 사용(오라스 설치 시)
oras login localhost:5002 -u ci -p "$CI_PASSWORD" --insecure
oras push --insecure localhost:5002/products/app:1 ./artifact:application/octet-stream
```

## 4. 한계 / 이 환경에 맞춘 보정 (반드시 숙지)

이 PoC 는 **오프라인(폐쇄망) 환경**에서 로컬 캐시 이미지만으로 구성되었습니다. TASK 기준안 대비 다음을 보정했습니다.

| 항목 | 기준안 | 이 PoC 보정 | 이유 |
|---|---|---|---|
| Keycloak DB | postgres:16 (`kc-db`) | **서비스 제거, start-dev 내장 H2** | postgres:16 이미지 반입 불가. PoC 데이터 비영속. |
| Keycloak 이미지 | `:26.0` | `:latest` (= **26.5.5**, 로컬 캐시) | 해당 태그만 로컬에 존재. `KC_BOOTSTRAP_ADMIN_*` 동일. |
| zot 이미지 | `ghcr.io/project-zot/zot:latest` | 로컬 태그 **`zot:latest`** | ghcr 접근 불가. |
| htpasswd 생성 | `docker run httpd:2.4` | **호스트 `htpasswd`** 사용 | httpd:2.4 이미지 반입 불가. |
| Keycloak 포트 | 8080 | **8085**(내부=외부) | 호스트 8080 을 다른 프로젝트(`uecm-keycloak`)가 점유. |
| zot 포트 | 5000 | 호스트 **5002**→컨테이너 5000 | 호스트 5000 을 macOS AirPlay 가 점유. |
| 검증 도구 | `oras` | **curl 기반 OCI API** push/pull | oras 미설치·반입 불가. |
| `extensions.mgmt` | enable | **제거** | 설치 버전에서 redundant/무시(`zot verify` 경고). |
| OIDC 시크릿 | `config.json` 인라인 | **`credentialsfile` 분리** | 시크릿 git 유출 방지 + deprecated 경고 제거. |

### issuer / hostname 정렬 (가장 흔한 함정)
토큰의 `issuer`, zot `config.json` 의 `issuer`, 브라우저가 접근하는 Keycloak 주소가 **모두 동일 호스트·포트**여야 OIDC 가 성공합니다.
- 이 PoC 는 `KC_HOSTNAME=http://keycloak:8085` 로 issuer 를 고정하고, **컨테이너 내부 포트도 8085**(`KC_HTTP_PORT`)로 맞춰 내부=외부를 일치시켰습니다.
- zot 컨테이너는 docker DNS 로 `keycloak:8085` 에 도달하고, **브라우저는 `/etc/hosts` 의 `127.0.0.1 keycloak`** 로 동일 이름·포트에 도달합니다.

### zot `externalUrl` (브라우저 로그인 화면이 안 뜨는 원인)
zot 은 OIDC 로그인 시 `redirect_uri` 를 `http.externalUrl` 에서 만듭니다. **미설정 시 컨테이너 내부 주소 `http://0.0.0.0:5000/...` 로 생성**되어 Keycloak 가 `Invalid parameter: redirect_uri` 로 거부 → 로그인 화면이 뜨지 않습니다.
- 이 PoC 는 `config.json` 에 `"externalUrl": "http://localhost:5002"` 를 설정해 `redirect_uri = http://localhost:5002/zot/auth/callback/oidc` 로 만들고, 이는 Keycloak `zot` 클라이언트의 등록 redirectUris 와 일치합니다.
- `verify.sh` 가 이 redirect_uri origin 을 자동 점검합니다.
- (참고) `config.json` 의 마운트 파일만 바꾸면 실행 중 zot 가 즉시 반영하지 못할 수 있으니 `docker compose restart zot` 로 재기동하세요.

### OIDC 그룹 클레임의 적용 범위
- Keycloak group-membership 매퍼로 토큰 `groups` 클레임이 정상 발급됨을 `verify.sh` 가 확인합니다(`dev1 → developers`).
- 그룹 기반 `accessControl` 은 **UI 세션 사용자**와 **로그인 후 발급한 API 키**에 적용됩니다.
- **원시 Keycloak access token 을 `/v2` API 에 Bearer 로 직접 제시하면 거부(401)됩니다.** zot 의 OIDC Bearer(workload identity, `http.auth.bearer.oidc`)는 htpasswd/openid/apikey 핸들러와 **상호 배타적**이라(이 경로를 켜면 htpasswd `ci` 가 무력화됨) 이 PoC 에서는 사용하지 않습니다. 따라서 CLI/CI 의 그룹 권한이 필요하면 **OIDC 로그인 → API 키 발급** 경로를 사용하세요.

### 운영 전환 TODO
- **TLS**: PoC 는 평문(HTTP, `--insecure`). 운영은 zot `http.tls` 와 Keycloak HTTPS 활성화 필수. 평문에서는 모든 자격증명이 노출됩니다.
- **hostname**: Keycloak `start-dev`/`KC_HOSTNAME_STRICT=false` 대신, 운영은 고정 FQDN + `start` 모드 + 적절한 `KC_HOSTNAME`.
- **DB 영속화**: 운영은 외부 Postgres(또는 영속 볼륨)로 Keycloak DB 분리.
- **시크릿**: `.env`, `zot/htpasswd`, `zot/oidc-credentials.json` 는 커밋 금지(`.gitignore` 에 포함). 운영은 시크릿 매니저로 관리.
- **OpenID credentialsfile**: 이 PoC 는 클라이언트 시크릿을 `config.json` 인라인 대신 `credentialsfile`(`zot/oidc-credentials.json`)로 분리했습니다 → `config.json` 에 시크릿이 없어 커밋 안전하며 deprecated 경고도 사라집니다.

## 5. 정리

```bash
docker compose down -v   # 컨테이너 + 볼륨 삭제
```

## 6. 파일 구조

```
deploy/zot-keycloak/
├─ docker-compose.yml          # keycloak(8085) + zot(5002). postgres 제거(H2).
├─ .env / .env.example         # 시크릿(.env 는 커밋 금지)
├─ zot/
│  ├─ config.json              # OIDC + htpasswd + apikey + accessControl (시크릿 없음)
│  ├─ oidc-credentials.json    # bootstrap.sh 가 생성(클라이언트 시크릿, 커밋 금지)
│  └─ htpasswd                 # bootstrap.sh 가 생성(ci 계정, 커밋 금지)
├─ keycloak/
│  └─ configure-realm.sh       # kcadm 으로 realm/client/groups/users 구성(컨테이너 내 실행)
├─ scripts/
│  ├─ bootstrap.sh             # 전 과정 자동화 + 시크릿 반영
│  └─ verify.sh                # zot verify / 헬스 / curl push·pull / 그룹 클레임
└─ README.md
```
