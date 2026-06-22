# TrustLink SCS — TODO

> 이 파일이 할 일(backlog)의 단일 소스다. "할 일 뭐 있지?" 물으면 여기를 참조한다.
> 상세 배경/분석은 [docs/PRODUCT-ANALYSIS.md](docs/PRODUCT-ANALYSIS.md) 참조.

## (b) 인증/세션 통합 — BFF 인증 게이트웨이 [우선]
**배경:** 현재 제품 페이지(zot 세션)와 관리 콘솔(BFF 세션 `tl_admin_sid`)이 **이중 세션**이다.
→ 이중 로그인, 로그인 콜백 버그("failed to get state"), 역할 기반 메뉴 노출이 제품 페이지에서 불완전(BFF 세션 없으면 그룹 판별 불가).
**목표:** BFF를 단일 인증 게이트웨이로 세워 **단일 세션 + OIDC 토큰 서명검증**.

- [x] BFF에서 OIDC 토큰 **서명검증**(JWKS, `exp`/`iss`/`azp`) — `admin-bff/oidc.go`(stdlib 전용 RS256, go.mod 무의존성 유지). discovery 로 issuer/jwks_uri 확보(KC_HOSTNAME_BACKCHANNEL_DYNAMIC 로 jwks_uri=백채널 도달가능 호스트). kid 미스 시 1회 JWKS 갱신(회전). 검증 실패 시 콜백 401(fail-closed). 구 `parseToken`(PoC) 제거. **주의:** Keycloak access token 은 `aud="account"` 라 aud==clientID 불가 → `azp==clientID` 로 판정. 검증: 실 토큰(admin1/admins) 통과 + 서명변조 거부(`oidc_integration_test.go`, OIDC_TEST_TOKEN opt-in).
- [ ] **단일 세션 쿠키**로 제품/관리 통일 (zot 세션 + BFF 세션 일원화)
- [ ] 레지스트리(`/v2`) 접근 인가를 게이트웨이/토큰 기반으로 — zot **레포별 RBAC 보존** 전제
- [~] **외부 세션 저장** — 재시작/재배포 로그아웃 해소: `SessionStore` 를 파일 영속화(`/var/lib/trustlink/sessions.json`, tl-sor 볼륨, atomic write+load-on-start+만료prune). put/get/del 인터페이스 동일 → 핸들러 무변경. **stdlib 전용**(go.mod 무의존성 유지 위해 Redis 클라이언트 대신 SoR·recipients 와 동일한 파일 패턴 채택). 검증: 실 로그인→BFF restart→같은 쿠키 /api/me 200(`session_test.go` 단위 + 라이브 e2e). **남은(S2):** 다중 인스턴스 HA 가 필요해지면 동일 인터페이스를 Redis 백엔드로 교체(파일은 단일 인스턴스 한정).
- [ ] (b 완료 후) AppHeader의 역할 판별을 단일 세션 기반으로 정리, 제품 페이지에서도 admins면 항상 "관리" 노출

**메모:** 분석 문서의 S0(보안 하드닝)와 동일 작업이므로 함께 진행 권장.
관련: [AppHeader.tsx](trustlink-ui/src/components/AppHeader.tsx)(현재 `/api/session` 기준 best-effort), `admin-bff/main.go`(`parseToken`, `SessionStore`).

---

## 기타 알려진 후속 (분석 문서 기준)
- [ ] BFF 미사용 VEX 엔드포인트 정리: `/api/vex/upload`·`/status`·`/export` (관리 VEX 탭 제거로 미사용. 제품 VexPanel이 쓰는 findings/analysis/publish/enabled는 유지)
- [ ] **수용·검증 게이트** 구현(제품 핵심 차별점): 서명검증 / SBOM↔바이너리 / VEX↔SBOM / 스키마 정합 → fail-closed (S1)
  - 설계 완료: [docs/SUPPLY-CHAIN-TOOLS.html](docs/SUPPLY-CHAIN-TOOLS.html)(도구 추천·전체 아키텍처), [docs/SCS-QUICKWIN-DESIGN.md](docs/SCS-QUICKWIN-DESIGN.md)(구현 설계). 선택 트랙=Quick-win 3종(Trivy·Cosign·게이트).
  - 순서: ① zot `cve`(Trivy) 활성화 → ② cosign 키+검증 → ③ verify.go 게이트+리포트 referrer → ④ promote fail-closed+UI 배지.
  - 미결정: (a) cosign 검증=사이드바 vs Go라이브러리, (b) Trivy DB=인터넷 vs 내부미러.
  - [x] ① zot `cve`(Trivy) 활성화: config.container.json `extensions.search.cve` 추가, 재시작 후 로그로 DB다운로드+스캔 동작 확인(Trivy 컴파일 포함 실증). 단 데모 제품은 oras 바이너리(octet-stream)라 Trivy(이미지 레이어 스캔) 미적용.
  - [x] ①' DT 취약점 연동: 바이너리/SBOM 아티팩트의 취약점 소스는 DT. `dtVulnCount`(dtLookupProject+dtProjectMetrics) 추가, stats.go 취약점 로직=DT 우선→zot Trivy→더미. 검증: npouch:2.0.0 실 9건(synthetic=False). DT 미분석 제품은 더미 유지(SBOM→DT 분석 시 자동 실데이터).
- [ ] **TLS** 전 구간 + 쿠키 `Secure`/`SameSite` 정상화 (S0)
- [ ] **HA/확장**: 무상태 BFF 다중화+LB, zot 객체스토리지(S3/SeaweedFS)+Redis 캐시, Keycloak/DB HA (S2)
- [ ] **백업/DR · 관측성(메트릭/로그/알림) · 헬스체크(zot·bff)** (S2)
- [~] **CI/CD**: 멀티스테이지 빌드, 이미지 서명·SBOM 생성(자기 dogfooding), 버전 핀 (S3)
  - [x] **자기 dogfooding 파이프라인** [scripts/dogfood-sbom.sh](scripts/dogfood-sbom.sh): 스택 구성요소(자체 trustlink-admin·zot + 서브모듈 keycloak·step-ca·dependency-track·postgres) + 설정 번들을 `innotium/<comp>:<버전>` 으로 zot 에 올리고, 컴포넌트별 **syft SBOM(CycloneDX) → DT 취약점 분석 → VEX 발행 → CMS 서명** 자동화. SBOM 도구=syft(brew). 버전=빌드 타임스탬프 `YYYYMMDD-HHMMSS`(OCI 태그 안전·정렬). 검증: 6개+config 전부 실데이터(예 postgres 7373 comps/60 vulns, synthetic=false), 대시보드 `/api/stats` 노출, 서명 verified=true. 외부 반출은 `share/package`(.p7m). **함정 메모:** oras 는 절대경로 파일 거부 → basename(상대경로)로 push(=pull 시 path-traversal 회피); base64 SBOM 은 argv 길이 한계로 python 이 파일에서 직접 인코딩.
  - [x] **전체 스택 배포 패키지** [scripts/push-stack.sh](scripts/push-stack.sh): 6개 이미지 `docker save→oras push`(`innotium/<comp>-image:<ver>`, air-gap·oras일관) + 경량 설치패키지 `innotium/trustlink-install:<ver>`(compose+config+images.txt) CMS 서명(.p7s). ci 자격 PoC 내장. 검증: 전 이미지 push + 설치패키지 verified=True.
  - [x] **zot 프로젝트 SBOM** [scripts/zot-sbom.sh](scripts/zot-sbom.sh): zot Go 소스 syft 스캔→`innotium/zot-source` (3052 comps, 취약점 157, VEX, 서명). 이미지 SBOM과 구분.
  - [x] **syft 자체 SBOM 생성** `admin-bff/sbom.go` `POST /api/sbom/generate`(BFF 내장 syft): source=self(컨테이너 rootfs 649 comps) 또는 아티팩트 blob 스캔→CycloneDX referrer 부착. self-scan 은 비표준이라 보조; 표준 경로=실제 이미지 스캔(push-stack 후).
  - [x] **CMS 서명 포맷 p7s/p7m** `share.go` `share/package`: 수신자 없음→`.p7s`(서명만, 루트 검증), 수신자 지정→`.p7m`(암호화). GUI 라디오 선택([Recipients.tsx](trustlink-ui/src/pages/admin/ca/Recipients.tsx)).
  - [x] **매뉴얼/가이드 첨부·다운로드**: OCI referrer(`vnd.trustlink.guide+markdown`)로 첨부→번들 zip `docs/` 에 포함. `kindDir` 에 docs 분류 추가. (전용 업로드 GUI 는 미구현)
  - [x] **pull 명령 oras 일관**: 아티팩트 페이지 `oras pull` 항상 + 이미지면 `docker pull` 자동표시([api.ts](trustlink-ui/src/lib/api.ts) `getPullInfo`).
  - **남은:** 멀티스테이지 빌드 최적화, 버전 핀(latest 태그 고정), CI 자동 트리거, 가이드 업로드 GUI, trustlink-scs 중복 SBOM(수동/self thin/self 649) 정리.
- [ ] `deploy/` git 추적(현재 미추적) + 환경 분리(dev/stg/prod)

---

## 완료 (참고)
- [x] 관리 콘솔을 신규 React(shadcn/Tailwind) UI로 교체, 구 vanilla 콘솔(page.go) 제거
- [x] 대시보드 그래프 추가(디스크 게이지·그룹/레포 막대), 제목 "TrustLink SCS 관리 콘솔"
- [x] 관리 콘솔에서 취약점·VEX 탭 제거(제품 VexPanel로 일원화)
- [x] 로그아웃 수정(zot POST + Keycloak end-session 복귀), 세션 만료→401 재로그인 처리
- [x] 대시보드 SBOM/VEX 통계: BFF `/api/stats`(OCI referrer 집계) → 버전별 SBOM 컴포넌트 수 막대 + VEX 상태(등급)별 막대 + 합계 카드
- [x] (a) 통합 셸: 공용 사이드바 하나에 **제품(아티팩트·문서) + 관리 콘솔(8항목) 동시 출력**, 공용 상단바, 관리 섹션 역할 기반 노출(확정 비-admin만 숨김), 관리 페이지 코드 스플릿
- [x] 대시보드 "제품 버전 추이" 라인차트에 **VEX 타입별 추이**(영향있음·영향없음·수정됨·조사중) 추가. `versionStat.Vex` 신설.
- [x] referrerStats 누적 버그 수정: VEX/SBOM referrer를 합산하지 않고 **종류별 최신(created 주석) 1건만** 집계 → 재발행이 누적이 아니라 교체로 반영.
- [x] 배포 함정 해소: compose `trustlink-admin` 에 build: 없음 → `docker compose build` 는 no-op(새 코드 미배포). `admin-bff/build.sh`(UI→go빌드→docker build→recreate)로 배포할 것.
- [x] zot 직접 진입점 분리: zot 서비스에 `ports: ["28081:5000"]` 공개 → BFF(28080) 죽어도 pull/push 동작. `/v2` 인증/RBAC 는 zot 자신이 강제(htpasswd/apikey/OIDC). 업로드 Location 이 상대경로라 직접 push 도 28081 에 머묾(externalUrl 28080 으로 안 튕김). 검증: BFF stop 상태에서 oras push/pull 성공. UI·관리콘솔·OIDC 브라우저 로그인은 계속 28080 경유.
- [x] 문서화: 인앱 도움말 `/docs`(Docs.tsx) 에 두 진입점(웹 28080 / 레지스트리 28081) + oras·docker pull/push 예시(insecure-registry 안내) 반영, 구성도에 zot 직접 진입점 추가. `docs/DEMO-ACCOUNTS.md` 에 엔드포인트 표·CLI 예시 갱신(28080→28081).
- [x] **CMS 신뢰 외부공유 + step-ca 통합** (명세: [docs/CMS-STEPCA-SPEC.md](docs/CMS-STEPCA-SPEC.md)) — §11 1~8 전부 구현·검증:
  - step-ca 독립 서비스(평면1, 포트 28443, Root+Intermediate 자동 init, CRL 활성). 신뢰앵커 `stepca/root_ca.crt`.
  - CA 어댑터 `admin-bff/ca.go`(StepCaAdapter, `step` CLI) — issue/list/status/crl/reachable. SoR `admin-bff/sor.go`(JSONL 감사).
  - CMS `admin-bff/cms.go`(openssl cms sign/verify, FIPS provider 탐지). 검증: `cms -verify -CAfile root -purpose any`.
  - 워크플로 `admin-bff/share.go` `POST /api/share/sign`: 묶음(subject+SBOM+VEX 다이제스트) 발급→CMS 서명→Zot referrer(`application/pkcs7-signature`) 바인딩→SoR.
  - GUI `pages/admin/CertAuthority.tsx`(읽기 우선: 신뢰앵커·발급목록·CRL·감사), 네비 "인증서·신뢰(CA)".
  - BFF 이미지: distroless→alpine+openssl+step CLI. 검증: 협력사 독립 검증(root만으로 CMS 성공), §9 장애격리(TrustLink/step-ca 상호 비전파) 통과.
  - **재현성 주의:** step-ca `ca.json`(stepca-data 볼륨) 수동 패치 2건 — `crl.enabled=true`, provisioner `claims.maxTLSCertDuration=8760h`(고객 인증서 1년). 볼륨 새로 만들면 재패치 필요(Phase2 자동화).
- [x] **CA 관리 GUI 전체화**(인증기관 운영) — `pages/admin/CertAuthority.tsx`:
  - 발급(리프, 서버 키 `POST /api/ca/issue`), **고객 CSR 서명**(`/api/ca/sign-csr`, 고객 키 미노출), **폐기**(`/api/ca/revoke`, OTT토큰+10진 시리얼), **재발급**(`/api/ca/reissue`, 동일 CN), CRL 다운로드, 감사.
  - **수신자 인증서 임포트**(EnvelopedData 대상) [recipients.go](admin-bff/recipients.go) `/api/ca/recipients` GET/POST/DELETE — 외부 공개 인증서만 저장.
  - 결정(사용자 확정): 키 생성=리프만(루트/중간 CLI·오프라인), 고객인증서=CSR서명+임포트 둘 다, 최대수명=1년. 쓰기는 confirm 이중확인.
  - 검증: 발급/CSR서명/폐기(→CRL 1건 반영)/재발급/수신자임포트 OIDC end-to-end 성공.
  - [x] **CMS EnvelopedData 암호화 + 서명+암호화 패키지 다운로드** — `cms.go` `cmsEncrypt`/`cmsDecrypt`(stdlib openssl 호출, FIPS-ready: AES-256-GCM+RSA-OAEP+SHA-256, `CMS_CONTENT_CIPHER`/`CMS_RSA_PADDING` env 교체). `share.go` `GET /api/share/package?repo=&tag=&recipientId=` — 산출물 번들 zip→CMS 서명→수신자 인증서 암호화→`.p7m` 다운로드(`X-TrustLink-Fips`/`-Serial` 헤더). GUI=수신자 페이지([Recipients.tsx](trustlink-ui/src/pages/admin/ca/Recipients.tsx)) 수신자·레포·태그 선택→다운로드. 검증: 라운드트립 단위테스트 + 라이브 e2e(임포트→다운로드→복호→루트검증→번들추출, npouch:latest 8파일). **사업모델 확정:** 벤더(우리)/운영자(US파트너) 분리, NIST CMVP 목표 → SPEC §6·§12·§12b 반영. 현 alpine PoC 는 fips=false(검증은 배포 OE 사안).
  - **남은:** CRL 즉시성(cacheDuration 단축), 발급 GUI 승인 워크플로 강화.
  - **남은(Phase2/확인필요):** Root/Issuing 분리운영, OCSP 정식화, RFC3161 TSA, **FIPS 검증모듈 OE 교체(alpine→RHEL UBI/Ubuntu Pro FIPS, §12)**, nPouch 운반체 연계지점(§12b), 게이트(track②③)와 share/sign 연결.
