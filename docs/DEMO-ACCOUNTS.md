# TrustLink 데모 계정 (PoC 전용)

> ⚠️ **데모/PoC 전용입니다.** 아래 계정·비밀번호는 시연 편의를 위해 의도적으로 공개합니다.
> **운영(production)에서는 절대 사용하지 말고**, 반드시 비밀번호 교체 + 계정 정리 + TLS를 적용하세요.

## 사람 사용자 (Keycloak OIDC) — 공통 비밀번호 `Passw0rd!`

| 사용자 | 그룹 | 역할 / 권한 (products·innotium 레포) |
|---|---|---|
| `dev1`, `dev2` | developers | 개발자 — pull/push, README 편집·VEX 첨부/수정·서명 검증 (read+create+update) |
| `partner1`, `partner2` | partners | 파트너사 — 조회(read)만 |
| `acme1`, `acme2` | customers | 고객 — 조회(read)만 |
| `admin1`, `admin2` | admins | 관리자 — 전체(+delete) + 관리 콘솔(`http://trustlink:28080/admin`) |
| `qa-tester` | developers | 관리 콘솔에서 생성한 샘플(그룹 변경 데모용) |

> ⚠️ **반드시 `http://trustlink:28080` 으로 접속하세요(localhost 아님).** OIDC issuer·redirect_uri·쿠키가 모두 `trustlink` 오리진 기준이라, `localhost`로 접속하면 로그인 콜백에서 `failed to get state: named cookie not present` 가 납니다. `trustlink` 호스트는 `/etc/hosts` 에 등록되어 있어야 합니다(예: `127.0.0.1 trustlink`).

- 로그인: TrustLink UI(http://trustlink:28080) 우측 상단 사람 아이콘 → Keycloak → 위 계정.
- 관리 콘솔(http://trustlink:28080/admin)은 단일 프론트도어의 React SPA로 서빙되며, `admins` 그룹(admin1/admin2)만 접근(그 외 403).

## 접속 엔드포인트 (두 진입점)

| 용도 | 주소 | 비고 |
|---|---|---|
| 웹 콘솔 · 관리 · 로그인 | `http://trustlink:28080` | TrustLink(BFF). OIDC 브라우저 로그인. |
| 레지스트리 pull/push (oras·docker) | `http://trustlink:28081` | zot 직접. htpasswd 계정/API 키 인증. |

> CLI 는 zot(:28081)에 **직접** 접속하므로 **웹 콘솔(:28080/BFF)이 내려가도 pull/push 는 계속 동작**합니다. 인증·RBAC 는 두 경로 동일(zot accessControl).

## 기계/CLI 계정 (htpasswd) — 비밀번호는 `.env`

| 계정 | 용도 | 권한 | 비밀번호 위치 |
|---|---|---|---|
| `ci` | CI/CLI(oras·docker) 업로드/다운로드 | products·innotium read+create+update | `.env` `CI_PASSWORD` (PoC 기본 `ci-poc-pw`) |
| `svc-bff` | 관리 BFF의 레지스트리 관리(태그 삭제 등) | adminPolicy(전체) | `.env` `SVC_BFF_PASS` (PoC 기본 `svc-bff-poc-pw`) |

CLI 예시 (레지스트리 직접 진입점 `:28081`):
```bash
# oras (아티팩트)
oras login trustlink:28081 -u ci -p '<CI_PASSWORD>' --plain-http
oras push --plain-http trustlink:28081/products/<name>:<ver> app.tar
oras pull --plain-http trustlink:28081/products/<name>:<ver>

# docker (컨테이너 이미지) — daemon.json 에 평문 HTTP 1회 등록 필요:
#   { "insecure-registries": ["trustlink:28081"] }  → docker 재시작
docker login trustlink:28081 -u ci -p '<CI_PASSWORD>'
docker push trustlink:28081/products/<name>:<ver>
```

## 관리자 (인프라)

| 대상 | 계정 | 비밀번호 위치 |
|---|---|---|
| Keycloak 관리 콘솔 | `admin` | `.env` `KC_ADMIN_PASSWORD` (PoC 기본 `admin-poc-pw`) |

> 참고: `.env`, `zot/htpasswd`, `zot/oidc-credentials.json` 은 `.gitignore` 로 커밋 제외됩니다.
> 이 문서에 적힌 값은 **데모 기본값**이며, 실제 `.env` 를 변경하면 그 값이 우선합니다.
