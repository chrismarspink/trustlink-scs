// 홈 화면의 공지와 버전별 새 소식. 새 버전을 낼 때 RELEASES 맨 앞에 한 항목을 더한다
// (version 은 package.json 과 같게). 공지는 NOTICES 에 더하고, 지난 공지는 지워도 된다.

export type Notice = { date: string; title: string; body: string; level?: 'info' | 'warn' };
export type Release = { version: string; date: string; title: string; items: { kind: '신규' | '개선' | '수정'; text: string }[] };

export const NOTICES: Notice[] = [
  {
    date: '2026-11-23',
    title: '첫 화면이 "홈"으로 바뀌었습니다',
    body: '로그인하면 소개·공지·새 소식이 먼저 보입니다. 아티팩트 목록은 왼쪽 메뉴 제품 › 아티팩트에 있습니다.',
  },
  {
    date: '2026-11-20',
    title: '취약점 DB 는 매일 새벽(02~06시)에 갱신됩니다',
    body: 'OSV·KEV·EPSS·EOL 데이터를 서버 안 미러로 받아 둡니다. 그 시간대에는 취약점 결과가 잠시 바뀔 수 있습니다.',
  },
  {
    date: '2026-11-20',
    title: '대시보드 숫자는 최대 5분 늦게 반영될 수 있습니다',
    body: '빠른 표시를 위해 직전 집계를 먼저 보여 줍니다. 대시보드의 새로 고침 버튼을 누르면 바로 최신으로 바뀝니다.',
    level: 'warn',
  },
];

export const RELEASES: Release[] = [
  {
    version: '2.14.2', date: '2026-11-23', title: '대시보드 불러오기 진행 표시',
    items: [{ kind: '개선', text: '대시보드를 여는 동안 기본 지표·버전 추이·보안 집계 중 무엇을 받았는지 막대와 경과 시간으로 표시, 새로 집계 중에도 표시' }],
  },
  {
    version: '2.14.1', date: '2026-11-23', title: '내 제품 접기·펼치기',
    items: [{ kind: '개선', text: '내 제품에서 제품·버전별로 접고 펼침 — 버전은 접힌 채로 KEV·치명·높음 건수를 먼저 보여 줌' }],
  },
  {
    version: '2.14.0', date: '2026-11-23', title: '홈 화면',
    items: [
      { kind: '신규', text: '첫 화면에 소개 자료·공지·버전별 새 소식·바로 가기를 모은 홈 화면' },
      { kind: '개선', text: '아티팩트 목록은 제품 › 아티팩트(/artifacts)로 이동' },
    ],
  },
  {
    version: '2.13.0', date: '2026-11-21', title: '제품 소개 자료',
    items: [{ kind: '신규', text: '저장 → 검증 → 판단 → 통보 → 규제 대응을 장면으로 보여 주는 소개 자료' }],
  },
  {
    version: '2.12.0', date: '2026-11-20', title: '빠른 대시보드와 진행 표시',
    items: [
      { kind: '개선', text: '대시보드·통계가 즉시 열림(직전 집계를 먼저 보여 주고 뒤에서 갱신)' },
      { kind: '신규', text: '오래 걸리는 작업(공개 저장소 분석, 규제 대응 검증, PDF 받기 등)에 단계·막대·경과 시간 표시' },
    ],
  },
  {
    version: '2.11.4', date: '2026-11-20', title: '취약점 통보 기록 쪽 나눔',
    items: [{ kind: '개선', text: '통보 기록을 기간(1·7·30·90일)과 쪽 단위로 조회' }],
  },
  {
    version: '2.11.0', date: '2026-11-20', title: '고객 등록부와 고객 통지',
    items: [
      { kind: '신규', text: '고객 등록부 — 고객별 납품 제품·담당자·언어 관리' },
      { kind: '신규', text: '고객 통지 — KEV·치명 취약점에 대한 패치 권고 메일 초안을 자동으로' },
      { kind: '개선', text: '고객 통지 후보 필터(구성요소·심각도·검색), AI 설명 진행 표시' },
    ],
  },
  {
    version: '2.10.0', date: '2026-11-20', title: 'VEX 판단 대기열',
    items: [
      { kind: '신규', text: '전 제품·버전의 미판단 취약점을 KEV·치명 순으로 한 화면에' },
      { kind: '신규', text: '제품별 AI 일괄 판정과 진행 패널' },
    ],
  },
  {
    version: '2.9.0', date: '2026-11-19', title: '규제 카탈로그와 보고서',
    items: [
      { kind: '신규', text: '미국·EU·일본·한국 등 공급망 보안 규제 카탈로그' },
      { kind: '신규', text: '보고서 발행(한/영·판 관리)과 보고서함, 현황 메일에 PDF 첨부' },
      { kind: '신규', text: '공개 저장소 분석 — 상류 오픈소스 건강도 점검' },
    ],
  },
  {
    version: '2.8.0', date: '2026-11-19', title: '취약점 DB 미러와 AI',
    items: [
      { kind: '신규', text: '인터넷이 막힌 곳에서도 쓰는 취약점 DB 미러(OSV·KEV·EPSS·EOL)' },
      { kind: '신규', text: 'AI VEX 판단 초안, 규제 대응 검증' },
    ],
  },
  {
    version: '2.7.0', date: '2026-11-05', title: '대시보드 확장',
    items: [{ kind: '신규', text: '할 일 패널, 보안 현황·공급망 품질·고객·배포·운영 탭' }],
  },
];

// 홈 "공급망 참고 링크". 아이콘은 각 사이트의 공식 아이콘을 public/logos 에 받아 둔 것
// (설치 환경이 인터넷에 막혀 있어도 깨지지 않게 외부에서 불러오지 않는다).
export type ExtLink = { label: string; desc: string; url: string; logo: string };
export const EXT_LINKS: { group: string; links: ExtLink[] }[] = [
  {
    group: '오픈소스 — TrustLink 구성 요소',
    links: [
      { label: 'Dependency-Track', desc: 'SBOM 기반 구성요소·취약점 분석', url: 'https://dependencytrack.org/', logo: 'dependency-track.png' },
      { label: 'Syft', desc: '바이너리·이미지에서 SBOM 생성 (Anchore)', url: 'https://github.com/anchore/syft', logo: 'syft.png' },
      { label: 'zot', desc: 'OCI 산출물 레지스트리', url: 'https://zotregistry.dev/', logo: 'zot.png' },
      { label: 'ORAS', desc: 'OCI 산출물 업로드·다운로드 도구', url: 'https://oras.land/', logo: 'oras.png' },
      { label: 'Keycloak', desc: '계정·SSO·권한', url: 'https://www.keycloak.org/', logo: 'keycloak.svg' },
      { label: 'Sigstore Cosign', desc: '산출물 서명·검증', url: 'https://docs.sigstore.dev/', logo: 'sigstore.png' },
      { label: 'Notation', desc: '산출물 서명·검증 (Notary Project)', url: 'https://notaryproject.dev/', logo: 'notation.png' },
      { label: 'Gotenberg', desc: '보고서 PDF 변환', url: 'https://gotenberg.dev/', logo: 'gotenberg.png' },
    ],
  },
  {
    group: '표준·형식',
    links: [
      { label: 'CycloneDX', desc: 'SBOM·VEX 표준 (OWASP)', url: 'https://cyclonedx.org/', logo: 'cyclonedx.png' },
      { label: 'SPDX', desc: 'SBOM 표준 (ISO/IEC 5962)', url: 'https://spdx.dev/', logo: 'spdx.png' },
      { label: 'OpenVEX', desc: '취약점 영향 진술(VEX) 형식', url: 'https://github.com/openvex/spec', logo: 'openssf.png' },
      { label: 'CSAF', desc: '보안 권고 문서 표준 (OASIS)', url: 'https://www.csaf.io/', logo: 'csaf.png' },
      { label: 'OpenSSF Scorecard', desc: '오픈소스 저장소 보안 점수', url: 'https://scorecard.dev/', logo: 'openssf.png' },
    ],
  },
  {
    group: '취약점 정보',
    links: [
      { label: 'OSV', desc: '오픈소스 취약점 DB (Google)', url: 'https://osv.dev/', logo: 'osv.png' },
      { label: 'CISA KEV', desc: '실제 악용된 취약점 목록', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', logo: 'cisa.png' },
      { label: 'EPSS', desc: '악용 가능성 점수 (FIRST)', url: 'https://www.first.org/epss/', logo: 'first.png' },
      { label: 'endoflife.date', desc: '제품·라이브러리 지원 종료일', url: 'https://endoflife.date/', logo: 'endoflife.svg' },
      { label: 'Exploit-DB', desc: '공개 익스플로잇 모음', url: 'https://www.exploit-db.com/', logo: 'exploit-db.png' },
    ],
  },
  {
    group: '규제·가이드',
    links: [
      { label: 'NIST SSDF', desc: 'SP 800-218 안전한 SW 개발 프레임워크', url: 'https://csrc.nist.gov/pubs/sp/800/218/final', logo: 'nist.png' },
      { label: 'NTIA SBOM 최소 요소', desc: 'SBOM 에 들어가야 할 최소 항목', url: 'https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom', logo: 'ntia.png' },
      { label: 'CISA SBOM', desc: '미국 SBOM 자료 모음', url: 'https://www.cisa.gov/sbom', logo: 'cisa.png' },
      { label: 'EU 사이버 복원력법(CRA)', desc: 'Regulation (EU) 2024/2847', url: 'https://eur-lex.europa.eu/eli/reg/2024/2847/oj', logo: 'eu.svg' },
      { label: 'SW 공급망 보안 가이드라인', desc: '과학기술정보통신부 외', url: 'https://www.msit.go.kr/', logo: 'msit.png' },
    ],
  },
];
