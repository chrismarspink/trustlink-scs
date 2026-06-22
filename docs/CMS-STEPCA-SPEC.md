# TrustLink — CMS 기반 신뢰 외부공유 + step-ca 통합 구현 명세

> **For Claude Code.** 이 문서는 구현 지시서다. 모든 결정은 확정된 것이며, "확인 필요" 표시 항목만 외부 검증이 필요하다. 순서대로 구현한다.

---

## 0. 목적 (Purpose)

TrustLink는 이미 **VEX 편집·저장**까지 구현 완료된 상태다. 이 위에 다음 두 가지를 추가한다.

1. **CMS 기반 신뢰된 외부 공유** — 산출물 + SBOM + VEX 묶음을 CMS(RFC 5652)로 서명(필요 시 수신자 암호화)하여, 폐쇄망 경계를 넘어 협력사·고객사가 진본성·무결성을 검증할 수 있게 한다.
2. **step-ca 통합** — 위 서명에 쓸 인증서를 발급/관리하는 CA를 TrustLink에 통합한다. **step-ca 소스는 수정하지 않는다. 설정 + 인터페이스(어댑터)로만 연동한다.**

---

## 1. 핵심 결정 (확정 — 변경 금지)

| 항목 | 결정 | 근거 |
|---|---|---|
| 서명 형식 | **CMS (RFC 5652)** | 현행 표준, PKCS#7 하위호환 포함, OpenSSL 현행 명령(`openssl cms`)과 직결 |
| 암호 모듈 | **OpenSSL FIPS provider (FIPS 140-3 검증 모듈)** | CMMC SC.L2-3.13.11. 검증된 모듈을 **수정 없이 그대로** 사용 |
| CA 엔진 | **step-ca (smallstep)** — EJBCA 사용 안 함 | 경량 Go 단일 바이너리, air-gap 단순, OpenSSL과 일관 |
| step-ca 통합 방식 | **소스 무수정. 독립 서비스 + API 어댑터** | 신뢰 컴포넌트 비개조 원칙 |
| 서명 vs 암호화 | **서명은 항상. 암호화는 조건부(기본 nPouch 위임)** | 키 분배 문제 최소화 |
| 결정 로직 | **규칙 기반(결정적·감사 가능)** | 보안 게이트는 비결정적 AI 금지 |
| PQC | **별도 PoC 트랙. 본선 제외** | step-ca 공식 미지원 + FIPS 검증 PQC 모듈 미성숙 |
| 인증 | **Keycloak (OIDC, 공유 단일 평면)** | GitLab·Zot·TrustLink 공통 |
| 배포 환경 | **air-gap 폐쇄망 전제** | Rocky Linux 9.x / Windows Server |

---

## 2. 통합 아키텍처 — step-ca = "신뢰 영역의 Zot"

기존 Zot 패턴(**TrustLink의 백엔드이면서, 독립 포트로 TrustLink가 죽어도 push/pull 가능**)을 step-ca에 동일하게 적용한다.

### 2.1 3평면 분리 (필수)

```
평면 1 — 신뢰/검증 평면 (독립·상시, TrustLink 무관)
  step-ca 자체 포트: REST/ACME 발급 API, OCSP, CRL 배포
  검증자(협력사·CI)는 step-ca(또는 배포된 CRL)에 직접 접근
  → TrustLink가 죽어도 검증·CRL/OCSP·갱신 생존

평면 2 — 발급/제어 평면 (TrustLink 어댑터 경유)
  TrustLink CA 어댑터가 step-ca API 호출: 발급 요청·폐기·정책
  → TrustLink 죽으면 자동 발급 워크플로만 멈춤 (평면 1 무관)

평면 3 — 관리/표현 평면 (TrustLink GUI, 폴백 = step-ca CLI)
  CA 관리 GUI (읽기 우선): 목록·만료·CRL 대시보드·감사
  → TrustLink 죽으면 GUI만 비활성, 운영자는 CLI로 관리
```

**불변 규칙:** 평면 1은 절대 TrustLink에 종속시키지 않는다. 검증자는 step-ca에 직접 닿는다. TrustLink는 평면 2·3(편의·자동화·표현)만 담당한다.

### 2.2 배포 형태

- step-ca를 **별도 컨테이너로 동봉(co-deployed)** 하되 **독립 프로세스·독립 포트**로 구동한다. (배포 편의 = "내장"의 실질, 런타임은 격리.)
- TrustLink ↔ step-ca 통신은 **네트워크 API 호출**(같은 호스트라도 포트 경유). 프로세스 결합 금지.
- Zot과 대칭 구조로 배치한다.

| | Zot (기존) | step-ca (신규) |
|---|---|---|
| 역할 | 아티팩트 저장 백엔드 | 인증서·신뢰 백엔드 |
| 독립 포트 | 있음 | 있음 (REST/OCSP) |
| TrustLink 죽어도 | push/pull 가능 | 검증·CRL/OCSP·갱신 가능 |
| 직접 접근자 | ORAS 사용자 | 검증 협력사·CI·갱신 클라이언트 |

---

## 3. 서명·공유 데이터 흐름

게이트 직후 단계로 삽입한다. (AI·게이트와 독립.)

```
규칙 게이트 통과
   │
   ├─(1) TrustLink CA 어댑터 → step-ca: 서명 인증서 발급/조회 (평면 2)
   │
   ├─(2) OpenSSL FIPS provider: 산출물 + SBOM + VEX 묶음을 CMS SignedData 서명
   │       (필요 시 외부 협력사 대상 EnvelopedData 암호화 — 조건부)
   │
   ├─(3) RFC 3161 내부 TSA: 타임스탬프 부착 (인증서 만료 후 검증 가능)
   │
   ├─(4) Zot OCI Referrers: .p7s(+VEX/SBOM/서명)를 아티팩트 다이제스트에 바인딩
   │
   └─(5) SoR 기록 + 대시보드 갱신
              │
              └─ nPouch 반출 (게이트 통과분만)
```

검증 측:
```
openssl cms -verify ... -CAfile <step-ca 루트(신뢰 앵커)>
   + 인증서 유효성: 배포된 CRL (air-gap 주력) / step-ca OCSP (동일 세그먼트 보조)
```

---

## 4. CA 어댑터 인터페이스 (평면 2 — TrustLink 측)

step-ca를 추상 인터페이스 한 겹 뒤에 둔다. **평면 1(검증·OCSP)은 이 어댑터를 거치지 않는다.**

```
interface CAAdapter:
  issueCert(csr, profile)        -> Certificate      # 게이트 통과 시 발급
  revokeCert(serial, reason)     -> RevocationResult  # 폐기
  getCRL()                       -> CRL               # 조회/배포 트리거
  getCertStatus(serial)          -> CertStatus        # GUI용 상태
  listCerts(filter)              -> Certificate[]      # GUI용 목록
```

- 구현체: `StepCaAdapter` — step-ca REST/ACME API 호출.
- 어댑터는 **발급·관리(평면 2·3)만** 추상화한다.
- 개인키는 어댑터/GUI 경로에 노출하지 않는다.

---

## 5. 신뢰 모델 / 키 관리

### 5.1 PKI 계층

```
Root CA (오프라인 보관, 일상 서명에 사용 금지)
   └─ Issuing CA (step-ca가 운영, 온라인 내부)
        └─ TrustLink 릴리즈 서명 인증서 (CMS 서명용)
        └─ (조건부) 수신자 암호화 인증서
```

- **Root ≠ 서명 키.** 루트는 오프라인 매체에 분리 보관. 일상 서명은 하위 인증서로만.
- 서명 개인키는 FIPS 140-3 HSM/모듈에 보관(가능 시).

### 5.2 신뢰 앵커 배포 (air-gap)

- 수신자(협력사·고객) 온보딩 시 **step-ca 루트 인증서를 신뢰 앵커로 오프라인 사전 배포**한다.
- 수신자는 루트 하나만 신뢰하면 TrustLink 서명을 검증한다 (N×M 키 분배 문제 회피).

### 5.3 폐기 (air-gap 현실)

- **CRL 파일 배포를 주력**으로: step-ca가 CRL 생성 → 예약 오프라인 동기화로 수신자에 배포.
- **OCSP는 동일 폐쇄망 세그먼트 내 검증자에게만** 보조로 제공 (OCSP는 온라인 전제라 망 넘는 검증에 부적합).
- **짧은 수명 인증서**로 폐기 의존을 줄인다 (step-ca 강점).

### 5.4 타임스탬프

- RFC 3161 **내부 TSA**로 서명에 타임스탬프 부착 → 인증서 만료 후에도 서명 검증 가능 (수명 긴 방산 산출물 필수).

---

## 6. 암호화 (조건부 — 기본은 서명만) — ✅ 구현됨

- **기본값: CMS 암호화 안 함.** 기밀성은 nPouch가 담당(통제된 배포).
- **예외: nPouch를 쓰지 않는 외부 협력사 대상**일 때 CMS `EnvelopedData`로 서명+암호화.
  - 수신자 인증서 레지스트리(`/api/ca/recipients`, [recipients.go](../admin-bff/recipients.go))에서 수신자 공개키 확보. 공개 인증서만 보관(개인키는 수신자 보유).
  - CMS 다중 수신자(RecipientInfo) — `cmsEncrypt` 가 N개 수신자 인증서를 받도록 구현.
  - 수명 긴 암호 산출물은 복호 키 보관(escrow) 정책 필요(운영 정책).

**구현 (`admin-bff/cms.go`, `share.go`):**
- 흐름: 산출물 번들(zip: 바이너리·SBOM·VEX) → `cmsSign`(SignedData) → `cmsEncrypt`(EnvelopedData, 수신자 인증서) → `.p7m` 다운로드.
- 엔드포인트: `GET /api/share/package?repo=&tag=&recipientId=` (admins). 응답 헤더에 `X-TrustLink-Fips`, `X-TrustLink-Serial`.
- GUI: 관리 콘솔 → CA · 수신자 인증서 ([Recipients.tsx](../trustlink-ui/src/pages/admin/ca/Recipients.tsx)) 에서 수신자·레포·태그 선택 → 패키지 생성·다운로드.
- 수신측: `openssl cms -decrypt -inform DER -in pkg.signed.p7m -recip cert.pem -inkey key.pem | openssl cms -verify -inform DER -CAfile root_ca.crt -purpose any` (TrustLink·step-ca 없이 루트만으로 검증).

**FIPS-ready 알고리즘 (env 로 OE 별 교체 가능):**
| 용도 | 기본값 | env | FIPS |
|---|---|---|---|
| 콘텐츠 암호화(대칭) | `-aes-256-gcm` (AEAD) | `CMS_CONTENT_CIPHER` | 승인 (AES) |
| 키 전송(RSA 패딩) | `oaep` | `CMS_RSA_PADDING` | 권장 (PKCS1 v1.5 는 레거시) |
| 서명 다이제스트 | SHA-256 (openssl 기본) | — | 승인 |

> 검증: 자체 라운드트립 테스트([cms_roundtrip_test.go](../admin-bff/cms_roundtrip_test.go)) + 라이브 e2e(수신자 인증서 임포트 → 패키지 다운로드 → 복호 → 루트 검증 → 번들 추출) 통과. 현재 PoC 컨테이너(alpine)는 `X-TrustLink-Fips: false` — fips provider 미탑재(§12: 검증 모듈은 배포 OE 사안).

---

## 6b. 인증서 수명주기 (발급·갱신·재발급·폐기·다운로드)

2계층 CA: **Root**(신뢰 앵커) → **Issuing/Intermediate**(리프 서명) → **Leaf**(릴리스 서명·고객). 검증자는 Root 만 사전 신뢰하면 되고, Issuing·Leaf 체인은 CMS 서명에 임베드된다.

**다운로드 (구현됨):**
- `GET /api/ca/root` → Root PEM (`trustlink-root.crt`). **수신자 사전 배포 대상**.
- `GET /api/ca/issuer` → Issuing(Intermediate) PEM (`trustlink-issuer.crt`). 리프 체인은 서명에 이미 임베드되므로 검증엔 불필요, 운영 참고용.
- GUI: 관리 콘솔 → 인증서·신뢰(CA) → 개요. (지문·만료도 표시)

**리프(Leaf) — 단명, 빈번:**
| 동작 | 방법 | 시나리오 |
|---|---|---|
| 발급 | `POST /api/ca/issue` / 릴리스 서명 시 자동(24h) | 릴리스 서명·고객 서버 인증서 |
| CSR 서명 | `POST /api/ca/sign-csr` | 고객 키 미노출 발급 |
| 재발급 | `POST /api/ca/reissue` (동일 CN, 새 키) | 분실·키 교체 |
| 폐기 | `POST /api/ca/revoke` → CRL 반영 | 유출·오발급 |
- **릴리스 서명용 리프는 매 서명마다 새 24h 인증서**라 갱신 개념 불필요(만료 전 소임 종료). 고객 인증서(최대 1년)는 만료 전 재발급.

**Issuing(Intermediate) CA — 장수명(수년):**
- **갱신(rollover):** 만료 임박 시 동일 Root 로 새 Intermediate 재서명. 기존 리프는 유효 유지. 새 키로 교체하면 이후 서명의 임베드 체인이 갱신됨(수신자 영향 없음 — Root 불변).
- **키 유출 대응:** Root 로 Intermediate 폐기 → 새 Intermediate 발급 → 영향 리프 재발급. (중대 사건, 수동 운영)
- step-ca: `stepca-data` 볼륨의 `intermediate_ca.crt`. 교체 시 호스트 `stepca/issuer_ca.crt` 도 갱신(다운로드 동기화).

**Root CA — 초장수명(10년+), 오프라인 권장:**
- **롤오버:** 만료 임박 → 새 Root 생성 → **구·신 Root 병행 신뢰 기간**(cross-sign 또는 두 앵커 동시 배포) → 수신자에 새 Root 사전 배포(가장 비용 큰 작업) → 구 Root 폐지.
- 전략: Root 수명을 충분히 길게 잡아 롤오버 빈도 최소화. MVP 는 step-ca 가 Root 보유, 운영은 **Root 오프라인 보관 + Intermediate 만 온라인**(SPEC §10 Phase2 "Root/Issuing 분리운영").
- **재현성 주의:** `stepca-data` 볼륨 재생성 시 Root/Intermediate 재초기화 → 신뢰 앵커 지문 변경 → 수신자 재배포 필요.

---

## 6c. CRL / OCSP 운영

**CRL — 구현됨:**
- step-ca `crl.enabled=true`. 평면1 직접: `https://step-ca:9000/crl` (DER, `application/pkix-crl`). TrustLink 경유: `GET /api/ca/crl` 패스스루.
- 검증자: 서명 검증 시 CRL 을 받아 인증서 시리얼 대조 → 폐기분 거부(fail-closed). 평면1 독립이라 **TrustLink 가 죽어도 CRL 직접 접근 가능**.
- **즉시성:** CRL 캐시 주기(step-ca `crl.cacheDuration`) 가 폐기 반영 지연을 좌우. 짧게=즉시성↑·부하↑. 폐쇄망 배포 주기와 함께 정책값 결정(§12).
- 검증: 폐기 시 CRL 에 1건 반영 확인 완료(todo CA 항목).

**OCSP — 미제공 (step-ca 설계상):**
- step-ca 는 **OCSP responder 를 내장하지 않는다**(CRL + 단명 인증서 모델 권장). ca.json 에 ocsp 키 없음.
- **대안·권고:**
  1. **단명 인증서**(릴리스 서명 24h) → 폐기 창이 짧아 OCSP 불필요. ← 본선 채택.
  2. **CRL 주기 단축** → 준실시간 폐기 확인.
  3. 정식 OCSP 필요 시 **외부 OCSP responder**(예: `openssl ocsp` 또는 별도 제품)를 평면1 에 추가 — 본선 제외(Phase2 검토).
- 결론: **단명 인증서 + CRL** 조합으로 OCSP 없이 폐기를 충분히 통제. 고객 장수명 인증서(최대 1년)는 CRL 로 폐기 확인.

---

## 7. 인증·감사

- TrustLink·CA GUI·step-ca 관리는 **Keycloak(OIDC)** 로 인증.
- CA 관리 화면은 발급·폐기 권한을 쥔 **고가치 표적** → 강한 접근통제 + 감사 로그 필수.
- 발급·폐기 등 쓰기 작업: 강한 인증 + 감사 + (가능 시) 승인 절차. **GUI는 읽기 우선**으로 시작.
- 모든 발급·폐기·서명 행위는 SoR에 기록(누가·언제·무엇을).

---

## 8. 제약 및 비목표 (Non-goals)

- **step-ca 소스 수정 금지.** 설정 + 어댑터로만 연동. 보안 패치 추종·감사 신뢰 유지.
- **OpenSSL FIPS 모듈 수정/재컴파일 금지.** 검증된 모듈을 그대로, FIPS 모드·승인 알고리즘으로 호출. "FIPS 모드 켜짐 ≠ FIPS 검증" — 실행 모듈 버전이 활성 CMVP 인증과 일치해야 함.
- **결정은 규칙 기반.** AI는 보강·서술만. 서명·반출 차단 결정에 비결정적 AI 사용 금지.
- **PQC 본선 제외.** 본선은 전통 RSA/ECDSA + FIPS. PQC는 별도 PoC(OpenSSL oqs-provider/3.5 native), step-ca 밖에서.
- **평면 1을 TrustLink에 종속시키지 말 것.**

---

## 9. 장애 시나리오 (구현 검증 기준)

| 시나리오 | 기대 동작 |
|---|---|
| TrustLink 다운 | 기존 인증서 검증 ✅, CRL/OCSP ✅, step-ca CLI로 수동 발급·폐기 ✅. 멈추는 것: 자동 발급 워크플로·GUI |
| step-ca 다운 | 새 발급·갱신·OCSP 멈춤. 단 서명된 산출물 + 배포된 CRL로 검증 일정 기간 지속(짧은 수명·CRL 캐시 완충). → step-ca 재시작/이중화 필요 |
| 둘 다 분리 | 한쪽 장애가 다른 쪽으로 전파되지 않음 |

---

## 10. 4개월 MVP 범위 vs Phase 2

**MVP (본선, 검증 가능):**
- step-ca 독립 서비스 구동(단일 Issuing CA) + 루트 분리 보관
- CA 어댑터(`issueCert`/`getCertStatus`/`listCerts` 중심) + `StepCaAdapter`
- OpenSSL FIPS provider로 CMS SignedData 서명·검증
- Zot OCI Referrers 바인딩 + SoR 기록
- 신뢰 앵커(루트) 수신자 사전 배포 절차
- CA 관리 GUI(읽기 우선) + Keycloak 인증 + 감사

**Phase 2:**
- ✅ CMS EnvelopedData 암호화 + 수신자 인증서 레지스트리 (§6, `share/package`)
- 완전 역할 분리(Root/Issuing CA 분리 운영), CRL 자동화, OCSP 정식화
- RFC 3161 TSA 정식 운영
- PQC 하이브리드 PoC 통합 검토(공식 step-ca PQC 지원 시 어댑터 교체)

---

## 11. 구현 순서 (Claude Code 실행)

1. **step-ca 독립 서비스 기동** — Docker 컨테이너, 독립 포트, REST/ACME + CRL. 소스 무수정. Issuing CA 초기화, 루트는 분리 생성 후 오프라인 보관(MVP는 단일 CA로 시작 가능).
2. **CA 어댑터 구현** — `CAAdapter` 인터페이스 + `StepCaAdapter`(step-ca API 호출). 평면 2 한정.
3. **CMS 서명 모듈** — OpenSSL FIPS provider 호출. 입력: 산출물 + SBOM + VEX 묶음 → 출력: `.p7s`(DER). FIPS provider 활성 확인 로직 포함.
4. **검증 모듈** — `openssl cms -verify` + 신뢰 앵커(CAfile) + CRL 확인.
5. **Zot Referrers 바인딩** — `.p7s` + VEX/SBOM을 아티팩트 다이제스트에 referrers로 첨부. SoR 기록.
6. **게이트 직후 워크플로 연결** — 게이트 통과 → 발급(어댑터) → CMS 서명 → 바인딩 → SoR.
7. **CA 관리 GUI(읽기 우선)** — 목록·만료·CRL·감사. Keycloak 인증. 쓰기(발급/폐기)는 승인·이중확인.
8. **장애 격리 검증** — §9 시나리오 테스트.

---

## 12. 확인 필요 항목 (외부 검증)

- **목표 인증 = NIST CMVP** (확정). 모듈 = OpenSSL FIPS 140-3 검증 provider.
- **OE 회색지대 (중요):** CMVP 인증서는 OE(OS+프로세서)에 묶인다. OpenSSL FIPS provider 인증서는 **glibc 기반 OE만 등재** — **Alpine/musl 은 검증 OE 아님**(현 PoC 이미지로는 NIST 검증 주장 불가). Rocky 9 는 "FIPS 모드 동작"은 되나 Red Hat 인증서 OE 는 *RHEL 9* 라 엄격 CMVP 주장엔 회색지대 → **RHEL 9 UBI 또는 Ubuntu Pro FIPS** 권장. Windows Server OE 별도 확인.
- **모듈 무수정·승인 알고리즘:** AES-256-GCM / RSA-OAEP / SHA-256 (§6). env 로 OE 검증 모듈에 맞춤.
- **FIPS provider 활성 시:** 모듈 버전 + CMVP 인증번호 + OE 를 SoR/배포문서에 기록(감사 증거 체인). `fipsStatus()` 가 active 보고.
- **step-ca CRL/OCSP 설정 상세:** 폐쇄망 CRL 배포 주기·짧은 수명 인증서 정책 값.
- **nPouch 연계 지점:** released 산출물 + referrers를 nPouch가 소비하는 인터페이스 확인. → 아래 §12b 모델 참조.

---

## 12b. 사업·인증 모델 — 벤더/운영자 분리 (US 파트너)

**확정 모델:** Innotium 은 **소프트웨어 벤더(납품·지원)**, 키·데이터·인증서·운영은 **미국 현지 파트너(운영자)**. 미국 정부/국방 시장에 적합한 정석 구조 — 외산 키 통제 우려 해소(키·CA·암호 연산이 US-side), FIPS 검증·OE·ATO/CMMC 부담이 운영자에게 귀속.

| | Innotium (벤더) | 미국 파트너 (운영자) |
|---|---|---|
| SW(코드·UI·오케스트레이션) | ✅ 납품·지원 | — |
| 검증 OE(RHEL/Ubuntu Pro FIPS)·FIPS 모드 | (지원 문서) | ✅ 선택·구성 |
| 서명/암호 **키**·HSM, CA(step-ca)·인증서·CRL | — | ✅ 생성·운영 |
| 산출물(데이터) | — | ✅ 보관 |
| ATO / CMMC / FedRAMP | — | ✅ 취득 |

**벤더(우리) 책임 = 제품의 FIPS-ready 화:**
- 키·인증서·신뢰앵커·OE 를 **전부 외부 주입**(하드코딩 금지). 현 구조 부합: step-ca 별도 서비스 + 키 볼륨 + env.
- **승인 알고리즘만** 사용(§6), env 로 교체 가능.
- **자체 암호 엔진 비탑재** — 보안 연산은 OS 검증 openssl/HSM 위임(CMVP 부담 회피).
- 우리 납품 SW 자체의 **SBOM + 서명 릴리스**(dogfooding), 배포·운영 가이드 제공.

**암호 boundary 결정:** 서명을 CMS(TrustLink openssl)로 수행 → FIPS 범위 = **운영자의 검증 모듈+키**. nPouch 는 서명+암호화된 `.p7m`/산출물의 **운반체**(암호 불필요). nPouch 가 자체 서명을 갖출 경우 §6 의 CMS 는 "nPouch 미사용 협력사" 예외로 회귀 가능.

**법적(개발 외):** 수출통제(EAR ECCN 5D002) 분류, 계약상 키 유출·오설정 책임을 운영자 귀속으로 명문화.

---

## 13. 매핑 (CMMC / NIST SP 800-171)

- 서명(무결성·진본성), 암호화(기밀성) → **SC.L2-3.13.11** (FIPS 검증 암호), **SC.L2-3.13.8** (전송 기밀성, 암호화 시)
- 키 수립·관리 → **SC.L2-3.13.10**
- *주의: CMMC는 후속 목표. 본 구현은 "암호·키 통제 충족"으로 포지셔닝하며, CMMC 인증 달성과 동일시하지 않는다.*
