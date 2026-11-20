# innoPouch 웹 스택 시연 — nginx · PHP · Node.js 취약점 검출 → 통보 → 판단 → 패치 안내

> 한 줄 메시지: **"지금 문제가 되는 nginx·PHP·Node.js 취약점이 제품에 들어오면 TrustLink 가 스스로 찾아 알리고, AI 가 판단 초안을 만들고, 사람이 승인한 결과와 패치 버전(11.1)이 고객에게 전달되며, 그 전 과정이 규제 증빙으로 남는다."**
>
> 소요: 본 시연 약 10분(사전 준비 별도). 대상 제품: `products/innopouch` 11.0(취약) → 11.1(패치).
> 시험 메일 수신자: **jkkim@innotium.com 만** (서버 `MAIL_ALLOWLIST`). 다른 주소는 발송되지 않고 통보 기록에 "허용 목록 밖"으로 남는다.

---

## 1. 시연 데이터 — 구성요소와 버전

`tools/demo_innopouch_gen.py --web` 이 만든다(1.0~10.0 데이터는 그대로). 11.x SBOM 에는 웹 관리 콘솔 번들 3종과 자체 모듈 11개만 넣어 초점을 흐리지 않았다.

| 구성요소 | 11.0 (취약) | 11.1 (패치) | SBOM 의 CPE (Dependency-Track 매칭 키) | purl |
|---|---|---|---|---|
| nginx | **1.28.0** | **1.30.7** (2026-11-18 stable) | `cpe:2.3:a:f5:nginx_open_source:<v>:*:*:*:*:*:*:*` | `pkg:generic/nginx@<v>` |
| PHP | **8.3.7** | **8.3.37** (2026-11-19) | `cpe:2.3:a:php:php:<v>:*:*:*:*:*:*:*` | `pkg:generic/php@<v>` |
| Node.js | **22.12.0** | **22.23.5** (2026-11-11 보안 릴리스) | `cpe:2.3:a:nodejs:node.js:<v>:*:*:*:*:*:*:*` | `pkg:generic/node@<v>` |

왜 이 CPE 인가:
- Dependency-Track(DT)은 **자체 인터넷 피드(NVD)** 의 CPE 로 매칭한다. TrustLink 취약점 DB 미러는 쓰지 않는다(미러가 비어 있어도 검출됨).
- **nginx 는 2025년 이후 CVE 가 NVD 에 `f5:nginx_open_source` 로 등록**된다. 예전 표기 `f5:nginx` 로 넣으면 최근 CVE 가 하나도 안 잡힌다(2026-11-20 NVD API 로 확인: `f5:nginx_open_source:1.28.0` → 30건, `f5:nginx:1.28.0` → 0건).
- `pkg:generic` purl 은 OSV·GitHub Advisory 대상이 아니므로 출처는 **NVD** 로 표시된다.

### 1.1 예상 검출 규모(2026-11-20 NVD 기준, DT 피드 시점에 따라 달라짐)

| 구성요소(11.0) | 예상 건수 | CVSS v3 심각도 분포 | CISA KEV |
|---|---|---|---|
| nginx 1.28.0 | 30 | CRITICAL 1 · HIGH 17 · MEDIUM 10 · LOW 2 | 없음 |
| PHP 8.3.7 | 약 49 | CRITICAL 9 · HIGH 17 · MEDIUM 20 · LOW 3 | **3건** |
| Node.js 22.12.0 | 18 | CRITICAL 2 · HIGH 7 · MEDIUM 7 · LOW 2 | **1건** |

11.1 은 세 구성요소 모두 NVD 기준 해당 없음(0건). 단, 아래 "예상 잔여"를 참고.

### 1.2 시연에서 짚을 CVE (1차 출처로 확인, 2026-11-20)

**PHP 8.3.7 → 8.3.37**

| CVE | 내용 | 심각도 | KEV | 영향 → 수정 | 출처 |
|---|---|---|---|---|---|
| CVE-2026-109618 | OOM 처리 중 메모리 손상 → 비인증 원격 코드 실행 | CRITICAL (NVD 9.8, PHP v4 9.2) | **예** (2026-10-26 등재, 기한 10-29) | 8.3.0~8.3.35 → **8.3.36** | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-109618) · [PHP 8.3.36](https://www.php.net/ChangeLog-8.php#8.3.36) · [KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| CVE-2026-109619 | 요청 상태 잔존(stale request-state) → 비인증 원격 코드 실행 | HIGH (NVD 8.1, PHP v4 9.2) | **예** (2026-10-26) | 8.3.0~8.3.35 → **8.3.36** | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-109619) · [CISA 경보](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching) |
| CVE-2024-4577 | Windows PHP-CGI 인자 주입(Best-Fit) → 원격 코드 실행 | CRITICAL 9.8 | **예** (2024-06-12, 랜섬웨어 사용 Known) | 8.3.0~8.3.7 → **8.3.8** | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-4577) |
| CVE-2026-6722 | (2026-05 PHP 보안 릴리스) | CRITICAL (NVD 9.8) | 아니오 | → 8.3.31 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-6722) |
| CVE-2026-17543 | PGSQL `E'...'` 백슬래시 SQL 주입 | CRITICAL (NVD 9.8) | 아니오 | → 8.3.33 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-17543) |

- 11.1 을 8.3.36 이 아니라 **8.3.37** 로 한 이유: 2026-11-19 릴리스(8.3.37)가 PHP-CGI·FPM·Session 등 신규 CVE 10여 건(CVE-2026-129538, -129496, -129289 …)을 고쳤다. NVD 반영 전이라 지금은 8.3.36 도 깨끗해 보이지만 며칠 안에 잡힌다.
- **CVE-2024-4577 은 Windows + CGI 전용**이다. innoPouch 는 linux-amd64 빌드 + PHP-FPM 이므로 "영향 없음" VEX 를 시연하기 좋은 항목이다(아래 5단계).

**nginx 1.28.0 → 1.30.7** — "지금 문제가 되는 nginx": 2026-11-18 에 10건을 한꺼번에 고친 1.30.7/1.31.9 가 나왔고, 5월 이후 거의 매달 보안 릴리스가 이어졌다.

| CVE | 내용 | 심각도(F5 CVSS v3.1 / v4) | KEV | 1.28.0 영향 → 수정 | 출처 |
|---|---|---|---|---|---|
| CVE-2026-123007 | HTTP/2 흐름 제어 메모리 손상(ASLR 꺼지면 코드 실행) | HIGH 8.1 / 9.2 | 아니오 | → 1.30.7 (2026-11-18) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-123007) |
| CVE-2026-123634 | resolver 응답 처리 use-after-free | HIGH 8.1 / 9.2 | 아니오 | → 1.30.7 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-123634) |
| CVE-2026-113425 | mail 프록시 모듈 use-after-free | HIGH 8.1 / 9.2 | 아니오 | → 1.30.7 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-113425) |
| CVE-2026-121810 · 123633 | HTTP/3 · HTTP/2 use-after-free | HIGH 8.1 / 9.2 | 아니오 | → 1.30.7 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-121810) |
| CVE-2026-118899 | TLS 1.3 요청 본문 무한 루프(DoS) | HIGH 7.5 / 8.7 | 아니오 | → 1.30.7 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-118899) |
| CVE-2026-97205 | AIO 사용 시 use-after-free | NVD 9.8 **CRITICAL** | 아니오 | → 1.30.6 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-97205) |
| CVE-2026-42945 | rewrite 모듈 버퍼 오버플로(비인증) — **EPSS 68%** | HIGH 8.1 / 9.2 | 아니오 | 0.6.27~1.30.0 → 1.30.1 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-42945) |
| CVE-2026-9256 | rewrite 모듈 힙 오버플로 — EPSS 11% | HIGH 8.1 / 9.2 | 아니오 | → 1.30.2 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-9256) |
| CVE-2026-1642 | 업스트림 TLS 평문 주입(MITM) | MEDIUM 5.9 / 8.2 | 아니오 | → 1.28.2 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-1642) |

전체 목록·영향 범위: [nginx 보안 권고](https://nginx.org/en/security_advisories.html), 1.30.7 이 현재 stable: [nginx 다운로드](https://nginx.org/en/download.html). nginx 는 KEV 등재 건이 없다(2026-11-18 KEV 카탈로그 기준).

**Node.js 22.12.0 → 22.23.5**

| CVE | 내용 | 심각도 | KEV | 수정 | 출처 |
|---|---|---|---|---|---|
| CVE-2026-111497 | 내장 Brotli 디코더 범위 밖 쓰기 → 원격 코드 실행 가능 — EPSS 82% | CRITICAL (NVD 9.8) | **예** (2026-10-27, Google Brotli 로 등재) | 22.23.4 (2026-10-21) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-111497) · [Node 10월 보안 릴리스](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) |
| CVE-2025-55130 | 권한 모델 우회(심볼릭 링크) | CRITICAL (NVD 9.1) | 아니오 | 22.22.0 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-55130) |
| CVE-2026-58043 | 권한 모델 경로 경계 과다 허용 | HIGH 8.4 | 아니오 | 22.23.2 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-58043) |

11.1 을 22.23.4 가 아니라 **22.23.5** 로 한 이유: 2026-11-11 보안 릴리스가 HTTP/2·TLS CVE 10여 건(CVE-2026-123863 …)을 더 고쳤다([릴리스 노트](https://nodejs.org/en/blog/release/v22.23.5)). 이 건들도 NVD 반영 후 11.0 에 추가로 잡힐 수 있다.

### 1.3 예상 잔여(11.1 에서도 보일 수 있는 것)
- **CVE-2007-3205**(PHP `parse_str`, 2007): NVD 구성이 `php:php:*`(버전 범위 없음)라 DT 가 모든 PHP 버전에 매칭할 수 있다. "오래된 CPE 데이터로 생긴 오탐 → VEX 로 '영향 없음' 처리" 사례로 쓰면 된다.

---

## 2. 사전 준비 (시연 전날 ~ 1시간 전)

| # | 확인 | 방법 |
|---|---|---|
| 1 | innoPouch 1.0~10.0·계정이 이미 있다 | 예전 `tools/demo-innopouch.sh` 실행 결과(`innopouch-demo/credentials.env`) — `ci-innopouch` 업로드 계정 |
| 2 | **KEV 사본** | 시스템 › 취약점 DB 미러 → "CISA KEV" 받기. 이게 없으면 KEV 배지·KEV 우선순위·자동 초안의 KEV 선별이 안 된다(DT 검출 자체는 됨). EPSS 는 DT 가 자체로 받는다 |
| 3 | DT 피드가 최신 | DT 관리 화면에서 NVD 미러링 최근 시각 확인. 11-18 nginx CVE 가 없으면 1.2 표의 앞쪽 몇 건만 빠진다 |
| 4 | AI 연결(VEX 용도) = 로컬 Gemma | 시스템 › AI 연결 → VEX 용도 "서버 내부" · 연결 시험 OK |
| 5 | 자동 초안 설정 | BFF 환경 `AI_AUTODRAFT`(기본 on), `AI_AUTODRAFT_MAX`(기본 10). 로컬 CPU 모델은 건당 1~2분이라 시연에는 **5** 를 권장(바꾸면 BFF 재생성 필요) |
| 6 | 메일 | `MAIL_ALLOWLIST=jkkim@innotium.com` — 내부 통보·고객 통보 모두 이 주소로만 나간다. 통보 받는 개발자/관리자 계정 중 하나의 이메일이 jkkim@innotium.com 이어야 내부 메일이 도착한다 |
| 7 | 고객 등록 | 관리 › 고객 통지(고객 레지스트리)에 innoPouch 고객(acme)과 연락처 jkkim@innotium.com |
| 8 | 시험 실행 | `bash tools/demo-innopouch-web.sh 11.0 --dry-run` — 서버에 접속하지 않고 할 일만 출력 |

**권장 운영: 11.0 은 시연 30~60분 전에 올린다.** DT 분석 + 통보 묶음(5분) + 자동 초안(건당 1~2분)이 끝나 있어야 10분 안에 전 과정을 보여 줄 수 있다. 시연 중에는 업로드 장면을 "다시" 보여 주고(멱등 — 이미 있으면 건너뜀), 11.1 은 시연 중에 실제로 올린다.

```bash
. innopouch-demo/credentials.env                  # TL_REG · TL_REPO · TL_PUSH_USER · TL_PUSH_PASS (파일은 공유 금지)
bash tools/demo-innopouch-web.sh 11.0 --dry-run   # 확인
BFF=http://<서버>:28080 ADMIN=admin1 ADMIN_PW='…' bash tools/demo-innopouch-web.sh 11.0 --sync
```
`--sync` 는 10분 주기 감시를 기다리지 않고 바로 DT 에 적재시킨다(관리 › 취약점 통보 › 지금 동기화 와 같음).

---

## 3. 시연 순서 (약 10분)

### ① 11.0 업로드 (0:00–1:00)
- **화면**: 터미널에서 `bash tools/demo-innopouch-web.sh 11.0` — 출력에 nginx 1.28.0 · PHP 8.3.7 · Node.js 22.12.0 과 CPE 가 보인다. 아티팩트 › products/innopouch › 11.0 에 바이너리 + SBOM + 설치 매뉴얼.
- **말할 것**: "개발사는 평소처럼 빌드 결과와 SBOM 만 올립니다. 보안팀이 따로 할 일은 없습니다."

### ② 10분 안에 감시·분석 (1:00–2:00)
- **화면**: 관리 › 취약점 통보 — "감시 중인 버전" 이 하나 늘고 마지막 동기화 결과 "적재 1건".
- **말할 것**: "TrustLink 가 10분마다 SBOM 이 붙은 모든 버전을 Dependency-Track 에 넣습니다. DT 는 NVD 를 매일 받아 오므로, **올린 뒤에 새 CVE 가 나와도** 같은 경로로 잡힙니다(11-18 nginx 10건이 그 예)."

### ③ 새 취약점 통보 메일(내부) (2:00–3:00)
- **화면**: jkkim@innotium.com 메일함 — 제목 `[TrustLink] innopouch 11.0 — 새 취약점 약 97건 (판단 필요)`, 본문은 CRITICAL 부터 30건 + 판단 화면 링크. 화면 우상단 종 아이콘에도 같은 통보.
- **말할 것**: "제품 업로드 권한자와 관리자에게만 갑니다. 고객에게는 아직 아무것도 안 갑니다 — 판단이 끝난 VEX 만 고객에게 나갑니다."

### ④ VEX 판단 대기열 — KEV(PHP) 최상단 (3:00–4:00)
- **화면**: 상단 메뉴 VEX 판단(/vex) — `products/innopouch:11.0` 행이 맨 위, KEV 열에 빨간 불꽃 배지 **KEV 4**, AI 열에 **자동 초안 n** 배지. 행의 "판단하기 →" 로 제품 화면 이동.
- 제품 화면 › 취약점 분석 · VEX 편집 › "취약점 분석 불러오기": P1 실제 악용(KEV) 4건이 맨 위 — PHP CVE-2026-109618 · -109619 · CVE-2024-4577, Node CVE-2026-111497. 각 줄에 `NVD` 출처 배지, `KEV 기한 …` 불꽃 배지, `EPSS 82%` 같은 배지.
- **말할 것**: "100건 가까운 취약점을 CVSS 순이 아니라 **실제로 악용되고 있는가(KEV)** → 악용 확률(EPSS)·치명 순으로 줄 세웁니다. 담당자는 위에서부터 보면 됩니다."

### ⑤ AI 일괄 판정 초안(로컬 Gemma) (4:00–6:00)
- **화면**: 제품 화면 위쪽 보라색 "AI 일괄 판정" 패널 — **자동 초안** 배지와 단계 표시(새 취약점 통보 ✓ → AI 자동 초안 → 사람 확인·저장 → VEX 발행). 통보가 나가자마자 KEV·치명 항목만 골라 자동으로 시작된 것.
- 항목의 "AI 판정·대응" 펼치기: 위쪽은 **내부 미러/규칙으로 계산한 사실**(KEV 조치 기한, 공개 익스플로잇), 아래는 **AI 작성** 문장. 근거 칩이 출처별 색으로 표시된다(V1 NVD, X2 KEV, X1 EPSS, R1 OSV, C1 SBOM). 마우스를 올리면 원문.
- 시연 포인트 — CVE-2024-4577: 사용 맥락에 "Linux 전용 빌드, PHP-FPM 사용(CGI·Windows 아님)" 을 적고 "AI 초안 다시 요청" → `영향 없음 / 실행 경로에 없음` 초안. KEV 항목이라 "2인 검토 권장" 경고가 함께 뜬다.
- **말할 것**: "AI 는 서버 안의 모델(Gemma)이라 데이터가 밖으로 나가지 않습니다. AI 는 **입력 사실을 인용한 초안만** 쓰고, 근거 없는 '영향 없음'은 규칙이 '조사 중'으로 내립니다. 버전 번호를 지어내면 경고합니다."
- 참고: `pkg:generic` 구성요소는 OSV 대조가 안 되어 "목표 버전"이 비어 있을 수 있다 → 수정 버전은 ⑦의 고객 통지(11.1 안내)에서 사람이 정한다.

### ⑥ 사람 승인 · VEX 발행 (6:00–7:00)
- **화면**: PHP CVE-2026-109618 → "초안 적용" → 내용 확인 → 저장(영향 있음 / 업데이트). CVE-2024-4577 → 영향 없음 저장. "VEX 발행 (새 referrer)".
- 발행되면 기존 기능으로 그 제품 고객에게 **VEX 갱신 통보**(개발자 코멘트 제외)가 jkkim@innotium.com 으로 간다.
- **말할 것**: "기록되는 것은 사람이 저장한 판단뿐입니다. AI 초안을 누가 언제 어떤 근거로 받아들였는지가 원장에 남습니다."

### ⑦ 고객 통지 — 패치 권고, 11.1 안내 (7:00–8:00)
- **화면**: 관리 › 고객 통지 → innoPouch 11.0 을 쓰는 고객(acme) 선택 → 패치 권고 통지(대상 CVE 요약 + "11.1 로 업데이트: nginx 1.30.7 · PHP 8.3.37 · Node.js 22.23.5") 발송 → jkkim@innotium.com 수신 확인.
- **말할 것**: "고객은 '무엇이 위험하고, 어느 버전으로 올리면 되는지'만 받습니다. 원청은 자기 계정으로 nPouch·SBOM·VEX 를 받아 자체 시스템에서 검증합니다."
- (이 화면은 고객 레지스트리·고객 통지 기능이다. 화면 문구는 배포 버전에 따라 다를 수 있다.)

### ⑧ 11.1 업로드 → 해당 CVE 사라짐 (8:00–9:00)
```bash
BFF=http://<서버>:28080 ADMIN=admin1 ADMIN_PW='…' bash tools/demo-innopouch-web.sh 11.1 --sync
```
- **화면**: 1~2분 뒤 products/innopouch › 11.1 › 취약점 분석 불러오기 → nginx·PHP·Node.js 항목 0건(잔여가 있으면 1.3 참고). 관리 › 대시보드의 버전별 추이에서 11.0 → 11.1 감소. 11.1 에 대해서는 새 취약점 통보가 오지 않는다.
- **말할 것**: "패치 버전이 실제로 위험을 없앴는지를 같은 기준(SBOM + DT)으로 확인합니다."

### ⑨ 규제 보고서 증빙 (9:00–10:00)
- **화면**: 규제·보고 › 보고서함 → 새 보고서(제품 innoPouch, 관리자 역할) → PDF. 관리 › 로그에서 원장 이벤트 순서:
  `notify-vuln-new`(내부 통보) → `ai-autodraft`(자동 초안 시작: KEV·치명 건수) → `ai-draft`(건별: 모델·입력 사실 해시·출력 해시) → `vex-publish` → `notify-vex-published`(고객 통보) → 고객 통지.
- **말할 것**: "CRA·공급망 보안 가이드가 요구하는 '취약점 인지 → 판단 → 고객 통지 → 조치 확인'의 시각과 근거가 자동으로 남습니다."

---

## 4. 대비책 (DT 피드가 느리거나 결과가 늦을 때)

| 증상 | 대처 |
|---|---|
| 업로드 후 2분이 지나도 통보가 없다 | 관리 › 취약점 통보 › **지금 동기화** — 적재 + 모아 둔 알림 즉시 발송(5분 묶음 대기 생략) |
| DT 분석이 아직이다(취약점 0건) | 제품 화면 "취약점 분석 불러오기"를 1분 뒤 다시. DT 는 SBOM 적재 후 분석까지 보통 1~2분 |
| 최근 nginx CVE(11-18)가 안 보인다 | DT 의 NVD 미러링이 아직 반영 전. 1.2 표의 5월~10월 nginx CVE(CVE-2026-42945 등)와 PHP·Node KEV 로 시연 진행 |
| KEV 배지가 안 보인다 | 취약점 DB 미러에 KEV 사본이 없음 → 시스템 › 취약점 DB 미러 › CISA KEV 받기(수 초). 화면 상단에 "KEV 사본 없음 — 미러 확인" 표시가 나온다 |
| 자동 초안이 안 돌았다 | AI 연결(VEX) 상태 확인. 대기열에서 "AI 일괄" 버튼으로 수동 시작(같은 결과, 자동 초안 배지만 없음) |
| AI 가 느리다 | 패널의 진행률·남은 시간을 보여 주고 다음 단계로. 이미 끝난 KEV 항목 1~2건으로 ⑤·⑥ 진행 |
| 시연 당일 업로드 자체가 불안하다 | **전날 11.0 을 올려 둔다**(권장 운영). 시연 중에는 업로드 스크립트를 다시 돌려 "이미 있음 — 건너뜀"(멱등)을 보여 주고 ③부터 진행 |

---

## 5. 참고
- 생성기: `tools/demo_innopouch_gen.py <폴더> --web [11.0|11.1]` (1.0~10.0: 기존 사용법 그대로)
- 업로드: `tools/demo-innopouch-web.sh <11.0|11.1> [--dry-run] [--sync]` — 자격 증명은 환경 변수로만, 태그·SBOM 이 있으면 건너뜀
- 자동 초안: `admin-bff/vex_autodraft.go` — 새 취약점 통보 직후, AI(VEX) 사용 가능 시 미분석 KEV·CRITICAL 만 최대 `AI_AUTODRAFT_MAX`(기본 10)건, 진행 중이면 건너뜀, 원장 `ai-autodraft`
- 1차 출처: [nginx 보안 권고](https://nginx.org/en/security_advisories.html) · [PHP 8 ChangeLog](https://www.php.net/ChangeLog-8.php) · [Node.js 2026-10 보안 릴리스](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) · [Node.js v22.23.5](https://nodejs.org/en/blog/release/v22.23.5) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) · [NVD](https://nvd.nist.gov/) (2026-11-20 조회)
