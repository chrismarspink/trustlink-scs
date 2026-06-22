# TrustLink SCS 개발 가이드 (ZOT → TrustLink 변환) — v2

> v2 변경점: (1) **전제 보강** — 사용자는 바이너리 + SBOM + VEX를 **모두 업로드**(이미 존재할 수 있음). 기본 동작 = **수용·검증·관리**, 생성은 **보조(fallback)**. (2) **GUI 결정** — React 유지 + **shadcn/ui + Tailwind**(zui의 MUI 대체). zui는 컴포넌트 재사용 대상이 아니라 **zot API 연동 패턴의 참조**로 사용.

---

## 0. 변환 원칙

zot 코어는 최대한 손대지 않는다. "변환"의 실체:
1. **재브랜딩 + 설정** — zot은 레지스트리 엔진으로 유지(OIDC·accessControl·search(CVE)·apikey).
2. **UI 신규 구축** — **React + shadcn/ui + Tailwind**로 TrustLink 고유 UI. (zui의 MUI 컴포넌트를 포크 재사용하지 않고, zui는 zot GraphQL/auth 연동 방식의 참조로만 활용.)
3. **BFF 추가** — 수용·검증·SBOM/VEX·관리 오케스트레이션.
4. **엔진 통합** — Syft·Dependency-Track·vexctl을 compose 백엔드로.

> zot 소스를 직접 고쳐야 하면 변경 최소화·문서화(upstream 병합 생존).

---

## 1. 아키텍처

```
[사용자] ─OIDC─► Keycloak
   ▼ (TrustLink 고유 UI: React + shadcn/ui + Tailwind)
 trustlink-ui ── trustlink-bff ─┬─► zot (/v2, search GraphQL[목록·CVE], mgmt, referrer)
                                 ├─► 검증 엔진(서명·SBOM↔바이너리·VEX↔SBOM·스키마)
                                 ├─► Syft (SBOM 없을 때만 생성)
                                 ├─► Dependency-Track API (위험분석+VEX, 헤드리스)
                                 ├─► vexctl (OpenVEX)
                                 └─► Keycloak Admin API (사용자 관리)
```

---

## 2. 저장소/모듈 구조

```
trustlink-scs/
├─ zot/config.json          # OIDC(Keycloak)·accessControl(4역할)·search.cve·apikey
├─ trustlink-ui/            # 신규 React + shadcn/ui + Tailwind (Vite 권장)
├─ trustlink-bff/           # 신규: 수용·검증·SBOM/VEX·관리 API
├─ engines/                 # syft / dependency-track(+db) / vexctl
├─ keycloak/                # realm import, Admin API 연동
├─ docker-compose.yml
└─ docs/                    # zot 문서 참조 + 본 가이드
```

---

## 3. 수용(Ingest)·검증 파이프라인 — v2 핵심

업로드를 **번들**로 받아 분류·검증·분기한다.

```
1) 분류    바이너리(+서명)/소스SBOM/바이너리SBOM/VEX 존재 여부 판별
2) 검증    서명(cosign/Authenticode) · SBOM↔바이너리(해시/메타) · VEX↔SBOM(PURL) · 스키마
3) 결합    바이너리=subject push, 나머지=referrer attach (oras-go)
4) 분기    SBOM 있음→보관/표시(덮어쓰기 금지) · 없음→Syft 생성 제안(보조)
           VEX 있음→편집기로 불러와 편집/갱신(원본 보존·doc_version++) · 없음→초안
5) 표기    출처(Sparrow/xSCAN/외부) + 신뢰등급 + 검증 리포트(통과/경고/실패)
6) 멱등    동일 digest 재업로드는 중복 판별, 변경분만 갱신
7) 감사    전 단계 append-only + 해시체인 기록
```

**불변 규칙**: 업로드된 SBOM/VEX는 **덮어쓰지 않는다.** 편집은 새 버전으로 생성하고 원본은 보존.

---

## 4. zot에서 재사용(만들지 말 것)

| 기능 | zot 제공 | 사용처 |
|---|---|---|
| 목록·태그·검색 | search GraphQL `/v2/_zot/ext/search` | UI 목록/상세 |
| CVE 1차 표시 | search 내장 Trivy 스캔 | 위험분석 간이 뷰 |
| SBOM/VEX/서명 결합 | OCI referrers | 부속물 조회·결합 |
| 인증 | OIDC(Keycloak) + API 키 | 로그인·CLI |
| 권한 | accessControl.repositories(그룹×동작) | 4역할 |
| 헬스 | /livez /readyz /startupz | 시스템 상태 |
| 설정검증 | `zot schema` / `zot verify` | config 필드 기준 |

---

## 5. trustlink-bff가 새로 담당

- **수용·검증**(§3) — 번들 분류·서명/정합/스키마 검증·검증 리포트.
- **SBOM 보기**: 업로드 SBOM을 파싱해 UI에 전달(컴포넌트·라이선스·CVE).
- **SBOM 생성(보조)**: 없을 때만 Syft 실행→referrer attach→DT 업로드.
- **소스 SBOM**: CI(Sparrow) 보관 기본, 소스 지정/업로드 시 Syft/cdxgen.
- **위험분석**: zot CVE(GraphQL) + DT findings 병합, VEX 적용 잔존위험.
- **VEX**: 업로드 VEX 로드→편집→승인→DT audit→CycloneDX 생성, vexctl(OpenVEX)·CSAF 내보내기.
- **관리**: Keycloak Admin API 래핑(사용자), accessControl 매핑(권한), 용량·로그·상태 집계.
- **감사로그**: 해시체인.

---

## 6. TrustLink 고유 UI — 화면 (React + shadcn/ui + Tailwind)

1. **로그인** — Keycloak OIDC.
2. **대시보드** — 용량/디스크/최근 업로드/시스템 상태. (shadcn: card, chart 영역, badge)
3. **아티팩트 목록** — search GraphQL, 검색·필터. (shadcn: data table)
4. **아티팩트 상세** — 바이너리 메타 + referrers(SBOM/VEX/서명) + **검증 상태 배지** + 다운로드.
5. **검증 리포트** — 서명·정합·스키마 결과(통과/경고/실패), 출처·신뢰등급. (v2 신규)
6. **SBOM 뷰어** — 컴포넌트·라이선스·CVE. **있으면 표시 / 없으면 "생성(Syft)" 버튼(보조)**.
7. **위험 분석** — CVE 목록·심각도, VEX 적용 잔존위험(DT 연동).
8. **VEX 편집기** — **업로드 VEX 불러오기** → status/justification/impact/action 편집 → 승인 → CycloneDX 생성·서명·attach(원본 보존·doc_version++·diff).
9. **관리** — 사용자(Keycloak Admin API)·권한(accessControl×그룹)·로그·레지스트리(리텐션/삭제)·시스템 상태·(향후 오브젝트 스토리지).

> 스택 메모: Vite + React + TypeScript + Tailwind + shadcn/ui(컴포넌트 복사 소유). 데이터 테이블·폼·다이얼로그·배지·차트 영역을 shadcn 컴포넌트로 구성. 관리 화면이 많으면 헤드리스 admin(Refine 등)을 BFF API에 얹는 것도 선택지지만, shadcn 직접 구성이 커스터마이즈·소유권에 유리.

---

## 7. 인증 — Keycloak (zot 기본 인증 제거)

- zot config 인증을 OIDC(Keycloak)로(htpasswd 제거, API 키 보조). 리다이렉트 `http://<host>/zot/auth/callback/oidc`.
- 4역할 = Keycloak 그룹 → zot accessControl(read/create/update/delete).
- 사용자 관리는 TrustLink UI가 Keycloak Admin API 호출(콘솔 비노출).
- API 키: config `apikey: true`, 로그인 후 `POST /zot/auth/apikey`(스코프·만료) → CI/ORAS.

---

## 8. docker-compose (서비스)

```
keycloak(+db) · zot(OIDC·search.cve·apikey) · trustlink-bff · trustlink-ui(React/shadcn)
dependency-track-apiserver(+db, 헤드리스) · syft · vexctl · (선택)grype/trivy · (향후)object storage
```
모두 self-host·폐쇄망 가능. DT Frontend 미배포. 이미지·취약점DB·모델 반입 미러링.

---

## 9. 개발 워크플로우

1. **trustlink-ui 생성**: `npm create vite@latest`(React+TS) → Tailwind 설정 → shadcn/ui 초기화(`npx shadcn@latest init`) → 필요한 컴포넌트 add. zui 소스는 **zot GraphQL 쿼리·OIDC 로그인 흐름 참조**로만 본다(MUI 컴포넌트는 가져오지 않음).
2. **zot 백엔드 기동**: `zot serve config.json`(search[cve]·ui·mgmt 활성, OIDC·accessControl·apikey).
3. **trustlink-bff 스캐폴딩**: zot search/mgmt 프록시 + 수용·검증 + Syft/DT/vexctl/Keycloak-Admin 엔드포인트.
4. UI에 화면(§6) 구현, BFF API 연결.
5. `zot schema > schema.json` / `zot verify config.json`로 설정 검증.
6. 빌드: UI production build, BFF 컨테이너화 → compose 통합.

### 9.1 자기 dogfooding — 스택을 TrustLink 로 공급망 관리

TrustLink 스택 자체(자체 컴포넌트 + 서브모듈 + 설정)를 버전별로 TrustLink(zot)에 올리고 SBOM·취약점·VEX·서명을 자동 생성한다. 한 줄 실행:

```sh
# 도구: syft(brew install syft), oras. 버전은 자동(빌드 타임스탬프 YYYYMMDD-HHMMSS).
bash scripts/dogfood-sbom.sh
# 특정 버전 지정: VER=20260621-162005 bash scripts/dogfood-sbom.sh
```

컴포넌트당 자동 수행: **syft → CycloneDX SBOM → `innotium/<comp>:<ver>` push + SBOM referrer 부착 → DT 업로드·분석 → VEX 발행 → CMS 서명**. 대상 = `trustlink-admin`·`zot`·`keycloak`·`step-ca`·`dependency-track`·`postgres` + `trustlink-config`(compose+설정 tar). 결과는 관리 콘솔 대시보드(버전별 컴포넌트 수·취약점·VEX 그래프)와 산출물 페이지에서 확인. 외부 기밀 반출은 CA·수신자 페이지의 **서명+암호화 패키지(.p7m)**.

**구현 함정(스크립트에 반영됨):**
- `oras push/pull` 은 **절대경로 파일을 거부**(path validation). 반드시 basename(상대경로)으로 push — 그래야 수신자가 pull 할 때 path-traversal 차단에 안 걸린다.
- 큰 SBOM 의 base64 를 셸 argv 로 넘기면 "Argument list too long" → python 이 파일에서 직접 인코딩.
- VEX 발행/서명은 BFF 세션(admin) + zot 쓰기 자격(ci basic)을 함께 전달해야 referrer 바인딩이 된다.
- `$(ls f && echo f:type)` 는 ls 출력까지 인자로 새어 oras 인자 오염 → `[ -f f ] && echo f:type` 사용.

### 9.2 전체 스택 배포 패키지 + 가이드 + 프로젝트 SBOM

- **전체 스택 push** [scripts/push-stack.sh](../scripts/push-stack.sh): 6개 이미지를 `docker save|gzip`→`oras push` 로 `innotium/<comp>-image:<ver>` 아티팩트화(air-gap·oras 일관·데몬 insecure 불필요). 경량 설치 패키지 `innotium/trustlink-install:<ver>`(compose+config+images.txt+INSTALL.md) push 후 **CMS 서명(.p7s)**. ci 자격 PoC 기본 내장(운영은 env). 설치: install 패키지 oras pull→검증→images.txt 각 이미지 pull+`docker load`→`docker compose up`.
- **zot 프로젝트 SBOM** [scripts/zot-sbom.sh](../scripts/zot-sbom.sh): zot Go 소스(`/Users/chris/ZOT`) syft 스캔→`innotium/zot-source:<ver>` SBOM(소스 의존성, 3052 comps)+DT 취약점+VEX+서명. 이미지 SBOM(`innotium/zot`)과 구분.
- **CMS 서명 포맷 (`GET /api/share/package`)**: 서명키는 항상 있으므로 **기본 `.p7s`(SignedData, 수신자 불필요·루트로 검증)**, 수신자 인증서 지정 시 **`.p7m`(EnvelopedData 암호화)**. GUI(수신자 페이지)에서 라디오로 선택.
- **매뉴얼/가이드**: 전용 업로드 기능은 없으나 **OCI referrer 로 첨부**하면(`oras attach --artifact-type application/vnd.trustlink.guide+markdown ... guide.md:text/markdown`) 아티팩트 "전체 다운로드(zip)"의 `docs/` 에 포함되어 함께 받아진다(`kindDir` 가 guide/manual/markdown/pdf→`docs`).
- **pull 명령 표시**: 아티팩트 페이지가 `oras pull` 을 항상 표시, 컨테이너 이미지(config.mediaType 가 image config)면 `docker pull` 도 자동 표시.

---

## 10. 참조 — zot 공식 문서/저장소

- 문서: `https://zotregistry.dev` (버전별)
- 소스: `https://github.com/project-zot/zot`
- UI(참조): `https://github.com/project-zot/zui` (React+MUI — **연동 패턴 참조용**)
- 확장(search GraphQL·mgmt·events) / API(`/v2/_zot/ext/...`) / 설정 스키마(`zot schema`)

> 설치 zot 버전으로 필드·API·확장을 맞춰 확인하고, 본 가이드 설정/엔드포인트는 `zot schema`·Swagger로 검증·보정.

---

## 11. 개발 체크리스트 (v2)
- [ ] zot config: OIDC·accessControl(4역할)·search.cve·apikey + `zot verify` 통과
- [ ] Keycloak realm/그룹/클라이언트 + OIDC 리다이렉트 동작
- [ ] **trustlink-ui 신규(Vite+React+TS+Tailwind+shadcn/ui)** — 로그인/목록/상세
- [ ] trustlink-bff: zot search/mgmt 프록시 + 헬스 집계
- [ ] **수용·검증 파이프라인**(번들 분류·서명/정합/스키마 검증·검증 리포트·출처표기·멱등)
- [ ] **검증 리포트 화면** + 아티팩트 상세의 검증 배지
- [ ] SBOM 뷰어(있으면 표시) + **없을 때만 생성(Syft)** 버튼
- [ ] 소스 SBOM(CI 보관 기본 / 소스 지정·업로드 시 생성)
- [ ] 위험분석(zot CVE + DT findings 병합, VEX 적용 잔존위험)
- [ ] VEX 편집기(**업로드 VEX 불러오기**→편집→승인→CycloneDX→서명→attach, 원본 보존)
- [ ] 관리: 사용자(Keycloak Admin)·권한·로그(해시체인)·레지스트리·시스템상태·(향후 오브젝트스토리지)
- [ ] Dependency-Track 헤드리스 연동(Frontend 미배포)
- [ ] docker-compose 통합 기동·폐쇄망 반입

> 변환 기조: zot 코어 최소 수정 + TrustLink 고유 UI(React/shadcn)/BFF 추가. **수용·검증(P1)**을 작게 통과시키고 분석→생성→제품화를 한 층씩.
