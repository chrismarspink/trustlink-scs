# Quick-win 구현 설계 — Trivy · Cosign · 검증 게이트

> 상위 설계/추천: [SUPPLY-CHAIN-TOOLS.html](SUPPLY-CHAIN-TOOLS.html). 이 문서는 그중 **Quick-win 3종**을 구현 수준으로 상세화한다.
> 정합 원칙(DESIGN-STRATEGY-v2): zot 코어 비수정 · CycloneDX 통일 · 단일 진입점 · referrer 불변 · 엔진은 통합.

## 사전 확인된 사실 (실측)
- zot CVE GraphQL(`Image{Vulnerabilities{Count}}`)은 **동작하나 Count=0** → `search` 확장은 있고 `cve`(Trivy) 블록만 미설정.
- 기존 서명 = **cosign sigstore 번들** `application/vnd.dev.sigstore.bundle.v0.3+json`(DSSE, predicate `cosign/sign/v1`). cosign verify 대상.
- repo에 cosign 키/스크립트 없음. 폐쇄망 = Fulcio/Rekor(keyless) 불가 → **키 기반(cosign.pub/.key)** 전제.
- BFF는 distroless + go.mod 의존성 0(순수 stdlib). 무거운 라이브러리 추가는 비용.

---

## A. Trivy — zot 내장 CVE 스캔 활성화  〔노력: 낮음〕

### 변경
`trustlink/config.container.json` 의 `extensions.search` 에 `cve` 추가:
```json
"search": {
  "enable": true,
  "cve": {
    "updateInterval": "24h",
    "trivy": { "dbRepository": "ghcr.io/aquasecurity/trivy-db" }
  }
}
```
- `docker compose restart zot` → 로그에 Trivy DB 로드 → GraphQL `Count` > 0 확인.

### 폐쇄망 처리
- `dbRepository` 를 **내부 OCI 미러**(예: zot 자신의 `mirror/trivy-db`)로 지정. 외부 trivy-db 를 한 번 받아 `oras cp` 로 내부에 적재.
- PoC(인터넷 가용)는 기본값 그대로.

### 영향 / 검증
- `stats.go`의 `svcVulnCount` 가 실데이터 반환 → 대시보드 취약점 추이의 `synthetic` 자동 해제(실 CVE 있는 버전). 스캔 결과 없으면 기존 더미 폴백 유지.
- 검증: 게이트의 "CVE 임계" 체크 입력으로 사용.
- 리스크: zot `binary-type` 가 비어 있어 Trivy 컴파일 포함 여부 불확실 → **활성화 후 Count 증가·로그로 실증**. 미포함이면 zot 이미지 재빌드(`-search` + trivy 태그) 또는 Grype 사이드카로 대체.

---

## B. Cosign — 서명 + 검증  〔노력: 중간〕

### 키 관리 (폐쇄망)
- `cosign generate-key-pair` → `cosign.key`(CI 서명용·secret), `cosign.pub`(BFF 검증용).
- `cosign.pub` 를 BFF 에 read-only 마운트(`/etc/trustlink/cosign.pub`), `.env`/secret 로 경로 주입. `cosign.key` 는 git 금지(.gitignore), CI secret.

### 서명 (CI 또는 발행 시)
```bash
cosign sign --key cosign.key --tlog-upload=false \
  trustlink:28081/products/<name>:<ver>
```
→ 기존과 동일한 sigstore 번들 referrer 부착.

### 검증 (BFF) — 구현 방식 **결정 필요**
| 방식 | 장점 | 단점 |
|---|---|---|
| **(권장) cosign 사이드바 컨테이너** | BFF 의존성 0 유지, distroless 보존, 공식 이미지 | 컨테이너 1개 추가, localhost 호출 |
| Go sigstore 라이브러리 직접 | 프로세스 1개 | sigstore/cosign 의존 트리 대량 유입(현재 0 → 수백) |

권장: `cosign` 사이드바(내부 전용) — BFF가 `cosign verify --key /keys/cosign.pub --offline ...` 를 내부 호출(exec API 또는 얇은 HTTP 래퍼). 결과(서명자 identity·유효성)를 게이트로 전달.

---

## C. 수용·검증 게이트 (BFF)  〔노력: 중간·자체〕

### 신규 모듈 `admin-bff/verify.go`
엔드포인트:
- `POST /api/verify {repo, tag}` → 검증 실행 → 리포트 반환 + **referrer 부착**. (guardGroups: developers/security/admins)
- `GET  /api/verify/report?repo=&tag=` → 최신 검증 리포트 조회.
- `POST /api/registry/promote {repo, fromTag, toTag}` → **PASS일 때만** 태그 승격(fail-closed). (guardGroups: admins)

### 검증 규칙 (각 check → pass | warn | fail + detail)
| # | 체크 | 도구/근거 | 기본 심각도 |
|---|---|---|---|
| 1 | 서명 유효 + 신뢰 키 | cosign verify(B) | fail |
| 2 | SBOM 존재 + CycloneDX 스키마 | referrer 파싱 | fail |
| 3 | SBOM ↔ 바이너리 정합 | SBOM subject/해시 = OCI manifest digest | warn |
| 4 | VEX ↔ SBOM PURL 매핑 | VEX 대상 PURL ⊆ SBOM 컴포넌트 PURL | warn |
| 5 | VEX 반영 후 잔존 Critical/High | zot CVE(A) − VEX(not_affected/fixed) ≤ 임계 | fail |

판정: 하나라도 fail → **FAIL**, fail 없고 warn 있으면 **WARN**, 전부 pass → **PASS**.
정책(어떤 체크가 hard/soft, 임계값)은 초기 하드코딩 → 이후 OPA/Rego 로 외부화(T2).

### 검증 리포트 referrer (신규)
- artifactType: `application/vnd.trustlink.verification-report.v1+json`
- subject: 이미지 manifest, 불변·누적(VEX와 동일하게 **최신 1건**을 `created` 주석으로 선별).
- 본문: `{verdict, checks:[{id,status,detail}], cveSummary, signer, generatedAt, policyVersion}`.

### 집행 지점
1. **push 직후(비동기)** — 리포트 생성·부착, 제품/대시보드에 등급 배지.
2. **승격 시** — `/api/registry/promote` 가 PASS 강제(fail-closed). dev→released.
3. (선택·엄격) pull 차단 — MVP 제외.

### UI (trustlink-ui)
- 제품 상세: 검증 등급 배지 + 리포트 카드(체크별 pass/warn/fail).
- 관리 대시보드: 제품별 검증 등급 분포(기존 차트 패턴 재사용).

### 감사
- 검증·승격 행위를 기존 로그에 append(전략 §5 해시체인). 누가·언제·판정.

---

## 데이터 모델 (referrers 확장)
```
products/<name>:<ver>
 ├─ *.cdx.json                  SBOM
 ├─ vex.cdx.json                VEX (최신 1건 반영)
 ├─ *.sigstore.bundle           서명 (cosign)              ← 체크①
 └─ verification-report.json    NEW: 게이트 판정(불변)     ← 산출
```

## compose / 배포 변경
- zot: `cve` 설정만(포트 변경 없음).
- `cosign` 사이드바 서비스 추가(내부 전용, `cosign.pub` 마운트).
- BFF: `verify.go` + 3 엔드포인트, `cosign.pub` 경로 env. `build.sh` 로 빌드·배포.
- 시크릿: `cosign.key`(CI), `cosign.pub`(BFF) — git 금지, `.gitignore` 등록.

## 결정 필요 (2건)
1. **cosign 검증 방식** — 사이드바(권장) vs Go 라이브러리.
2. **Trivy DB** — PoC 인터넷 기본 vs 폐쇄망 내부 미러(prod).

## 단계 순서 (저위험 → 고위험)
1. Trivy 활성화·실증 (config만, 즉시 가치) →
2. cosign 키 + 사이드바 + `verifySignature` →
3. 게이트 `verify.go`(체크 1·2·5 먼저, 3·4 추가) + 리포트 referrer →
4. promote fail-closed + UI 배지.
