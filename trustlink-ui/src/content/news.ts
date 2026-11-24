// 홈 화면의 공지와 버전별 새 소식. 새 버전을 낼 때 RELEASES 맨 앞에 한 항목을 더한다
// (version 은 package.json 과 같게). 공지는 NOTICES 에 더하고, 지난 공지는 지워도 된다.

export type Notice = { date: string; title: string; body: string; level?: 'info' | 'warn' };
export type Release = { version: string; date: string; title: string; items: { kind: '신규' | '개선' | '수정'; text: string }[] };

export const NOTICES: Notice[] = [
  {
    date: '2026-11-24',
    title: '관리 메뉴가 "신뢰 장부" 구조로 바뀌었습니다',
    body: '승인·판단 · 릴리스 · 고객 · 취약점·규제 대응 · 전달·기록 · 설정 순서입니다. 사람이 할 일은 승인·판단 › 승인 대기함에 모이고, 나간 메일은 전달·기록 › 발송함에서 봅니다. 주소는 그대로라 즐겨찾기는 그대로 쓸 수 있습니다.',
  },
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
    version: '2.28.1',
    date: '2026-11-24',
    title: '일괄 판정 진행 표시를 두 단계로',
    items: [
      { kind: '개선', text: '일괄 판정 진행을 ① 판정 ② 권고문 요약 보강으로 나눠 건수·시간을 따로 표시' },
      { kind: '수정', text: '중지를 누르면 바로 멈춘 것으로 표시하고, 뒤에서 돌던 요약 작업도 함께 멈춤' },
      { kind: '개선', text: '사용 맥락 판정의 지시문·출력을 더 줄여 다른 AI 작업 직후에도 빠르게' },
      { kind: '개선', text: 'KEV 표시를 진한 빨강에서 옅은 색으로(다른 출처 표시와 같은 톤)' },
    ],
  },
  {
    version: '2.28.0',
    date: '2026-11-24',
    title: 'VEX 판정 초안을 30초 안에',
    items: [
      { kind: '개선', text: '사용 맥락을 적지 않은 건은 규칙으로 바로 판정(전에는 건당 약 2분) — 판정 기준은 그대로, AI 는 영어 권고문 요약만 맡고 취약점마다 한 번만 만들어 다시 씀' },
      { kind: '개선', text: '사용 맥락을 적은 건은 AI 가 판정과 이유 한 문장만 쓰고 대응 계획은 규칙이 채움 — 같은 입력은 저장된 판정을 다시 씀' },
      { kind: '개선', text: '일괄 판정은 판정을 먼저 모두 내고, 권고문 요약은 뒤에서 채움' },
      { kind: '신규', text: 'VEX 판단 화면에 "도움말" — 판정이 어떻게 만들어지는지 장면으로 설명' },
      { kind: '개선', text: '메뉴 이름: 결정 → 승인·판단, 결정함 → 승인 대기함, 신호 → 취약점·규제 대응' },
      { kind: '수정', text: 'VEX 판단 목록의 KEV 표시가 두 줄로 꺾이던 문제' },
    ],
  },
  {
    version: '2.27.0',
    date: '2026-11-24',
    title: '메일 다시 보내기',
    items: [
      { kind: '신규', text: '발송함에서 "다시 보내기" — 메일 서버 오류나 재시작으로 못 나간 메일, 받지 못했다는 메일을 같은 내용·같은 받는 사람으로 다시 보냄(최근 30건, 30초 대기 중 취소 가능)' },
      { kind: '개선', text: '재시작으로 못 보낸 메일도 내용이 남아 다시 보낼 수 있음' },
    ],
  },
  {
    version: '2.26.0',
    date: '2026-11-24',
    title: '자동 메일을 새 틀로',
    items: [
      { kind: '개선', text: '승인 요청·취약점 알림·VEX 안내·수정 요청·만료 안내 메일에 공통 틀 적용 — 회사 로고, 메일의 목적, 보낸 모듈, 대상 제품, 받는 이유를 구분해 표시' },
      { kind: '개선', text: 'AI 가 쓴 분석에는 "AI 생성" 표시와 모델 이름을 붙임' },
      { kind: '개선', text: '소개 자료 탭의 "N장면" 글자를 점으로 바꿈(지금 보는 장면은 색으로 표시)' },
    ],
  },
  {
    version: '2.25.1', date: '2026-11-24', title: '이어 가기 보완',
    items: [{ kind: '수정', text: '이어 가기 확인이 겹쳐 두 번 도는 것을 막고, 이어 간 대응이 오류(재시작 등)로 끝나면 다음 확인 때 다시 이어 감' }],
  },
  {
    version: '2.25.0', date: '2026-11-24', title: '수정 버전 이어 가기 · 한눈에 보는 흐름',
    items: [
      { kind: '신규', text: '자동 대응 이어 가기 — 개발자 수정 요청 뒤 수정 버전이 올라오면(10분마다 확인) 원래 건을 "패치 나옴"으로 닫고 영향 고객 통지(관리자 승인)로 자동으로 이어 감' },
      { kind: '개선', text: '"신호 → 영향 → 결정 → 전달 → 기록 × 취약점·규제·만료" 흐름도를 홈·시작하기 문서·소개 자료(TrustLink 란 › 하나의 흐름)에' },
    ],
  },
  {
    version: '2.24.2', date: '2026-11-24', title: '결정함 정리',
    items: [{ kind: '개선', text: '결정함의 자동 대응 묶음도 8건만 보이고 나머지는 "외 N건"으로' }],
  },
  {
    version: '2.24.1', date: '2026-11-24', title: '빌드 수정',
    items: [{ kind: '수정', text: '2.24.0 서버 빌드 실패(발송함 종류 타입) 수정 — 2.24.0 내용이 이 버전으로 배포됨' }],
  },
  {
    version: '2.24.0', date: '2026-11-24', title: '신뢰 장부 — 결정함·발송함·메뉴 재배치',
    items: [
      { kind: '신규', text: '결정함 — 자동 대응 승인·VEX 판단·규제 후보·만료 예정·발송 대기를 한 곳에(관리 › 결정 › 결정함)' },
      { kind: '신규', text: '발송함 — 고객 통지·개발자 요청·현황 메일·내부 통보·만료 안내까지 나간 모든 메일을 한 목록에, 대기 중이면 취소' },
      { kind: '개선', text: '관리 메뉴를 제품 개념(납품 소프트웨어의 신뢰 장부)대로 재배치: 결정 · 릴리스 · 고객 · 신호 · 전달·기록 · 설정 — 주소는 그대로' },
      { kind: '개선', text: '소개 자료 맨 앞에 "TrustLink 란" 이야기(한 권의 장부 · 하나의 흐름 · 사람은 세 가지만)' },
    ],
  },
  {
    version: '2.23.0', date: '2026-11-23', title: '자동 대응 — 주기 검색·개발자 요청 승인·대시보드',
    items: [
      { kind: '신규', text: '주기 검색 — 납품 제품의 고객 설치 버전·최신 버전에서 아직 대응하지 않은 KEV·치명을 정해진 간격(기본 6시간)으로 찾아 자동 대응(지금 검색 버튼)' },
      { kind: '개선', text: '개발자 수정 요청도 관리자가 받는 사람·본문을 확인하고 승인해야 발송, 관리자에게 "보낼지 선택" 메일' },
      { kind: '신규', text: '대시보드 맨 위에 자동 대응 승인 대기(고객 통지·개발자 요청) 표시' },
    ],
  },
  {
    version: '2.22.1', date: '2026-11-23', title: '자동 대응 보완',
    items: [{ kind: '개선', text: '개발자 수정 요청에 "같은 제품의 다른 버전은 구성요소를 올려 해결됨" 단서 추가, 알림이 나뉘어 와도 버전당 최대 건수 유지' }],
  },
  {
    version: '2.22.0', date: '2026-11-23', title: '자동 대응',
    items: [
      { kind: '신규', text: '자동 대응 — 새 취약점(KEV·치명) 탐지 → AI 영향 분석 → 패치 버전 확인 → 패치 있으면 영향 고객 통지 초안과 관리자 승인 요청, 없으면 개발자에게 수정 요청 메일' },
      { kind: '신규', text: '고객 통지는 관리자가 추천된 받는 사람·메일을 확인하고 승인해야 나감(승인 뒤에도 발송함에서 취소 가능), 반려 사유 기록' },
    ],
  },
  {
    version: '2.21.0', date: '2026-11-23', title: '메일 템플릿·보내기 취소',
    items: [
      { kind: '신규', text: '현황 메일 템플릿 — 주간 보고·경영진 요약·긴급 공유·규제 일정·영문 월간을 골라 제목·인사말·항목을 채움({날짜}·{보낸 사람}·{받는 분}), 우리 템플릿 저장·삭제' },
      { kind: '신규', text: '보내기 취소 — 현황 메일과 고객 통지는 발송함에서 정한 시간(바로·10초·30초·1분·2분) 기다렸다 나가며, 그 사이 취소 가능. 취소한 고객은 다시 보낼 수 있음' },
    ],
  },
  {
    version: '2.20.0', date: '2026-11-23', title: '소개 자료 — 이야기 탭과 새 장면',
    items: [
      { kind: '개선', text: '소개 자료를 이야기 탭 3개로 — 공급망 보안 흐름 · 출시된 구버전도 계속 검증 · 고객 관리' },
      { kind: '신규', text: '"출시된 구버전도 계속 검증": 출고 뒤 노후화 → 재빌드 없이 매일 재검증·AI 분석 → 영향 고객 통지·새 버전 안내' },
      { kind: '신규', text: '"고객 관리": 고객·계정·제품 정보 → AI 분석·통지 초안 → 보안 권고·만료 안내·내 제품' },
    ],
  },
  {
    version: '2.19.0', date: '2026-11-23', title: '업종 구분·담당자 명함',
    items: [
      { kind: '개선', text: '업종에 방산·제조·통신·에너지·의료 추가, 업종별 색 배지와 업종 거르기(고객 등록부·고객사)' },
      { kind: '개선', text: '고객 담당자를 명함 형태로 — 회사 로고·이름·직함·부서·연락처·받는 통지, 직함·부서·휴대전화 입력' },
    ],
  },
  {
    version: '2.18.0', date: '2026-11-23', title: '고객 휴지통·백업·복원',
    items: [
      { kind: '신규', text: '고객 삭제는 휴지통으로 — "삭제된 고객" 탭에서 되살리거나, 이름을 그대로 입력해 확인한 뒤에만 완전 삭제' },
      { kind: '신규', text: '고객 정보 백업(고객·버전 정책·설정·로고를 JSON 하나로)과 복원 — 복원 전 지금 상태를 서버에 따로 저장' },
    ],
  },
  {
    version: '2.17.0', date: '2026-11-23', title: '회사 사용/중지와 로고',
    items: [
      { kind: '신규', text: '고객 회사 사용/중지 — 폐업·관계 종료·계약 해지·기타 사유와 메모를 남기고 지우지 않고 중지, 중지된 회사는 고객 통지·만료 알림·내 제품에서 빠지고 목록에서 기본으로 숨김' },
      { kind: '신규', text: '회사 로고 — 고객 등록부에서 올리면 고객 등록부·고객사·사용자·내 제품 화면에 표시(서버에만 저장)' },
    ],
  },
  {
    version: '2.16.3', date: '2026-11-23', title: '왼쪽 메뉴 정리',
    items: [{ kind: '개선', text: '맨 위에 홈·문서, 그 아래 "제품" 구역에 아티팩트·내 제품·VEX 판단·내 API 키' }],
  },
  {
    version: '2.16.2', date: '2026-11-23', title: '로그 원문 보기·쿠키 가림',
    items: [
      { kind: '신규', text: '로그 "원문 보기(기존)" — 예전처럼 한 줄 그대로, 위에 날짜·이벤트·사용자·주요 내용 표시' },
      { kind: '개선', text: '정리 보기에 날짜·시각·이벤트·사용자·주요 내용 열, 업로드·다운로드는 "제품 : 버전"으로 요약' },
      { kind: '수정', text: 'zot 로그에 남은 세션 쿠키 값을 화면에 보이기 전에 가림' },
    ],
  },
  {
    version: '2.16.1', date: '2026-11-23', title: '로그 찾기 보강',
    items: [
      { kind: '개선', text: '드문 조건(업로드·오류 등)도 한 번에 찾도록 읽는 범위 확대, "인증 성공"·"정리(GC·보존 정책)" 이벤트 추가' },
    ],
  },
  {
    version: '2.16.0', date: '2026-11-23', title: '로그 화면 개편',
    items: [
      { kind: '개선', text: '로그를 날짜별로 묶고 한 줄에 시각·레벨·이벤트·사용자·요약, 누르면 원문 펼침' },
      { kind: '신규', text: '이벤트(업로드·다운로드·삭제·인증 실패·오류 등)·레벨·사용자·기간으로 찾는 모드와 건수 요약' },
      { kind: '개선', text: '로그 응답 속도 — 파일 전체 대신 끝에서부터 필요한 만큼만 읽고 날짜는 바로 찾아감, 내부 호출은 기본으로 숨김' },
    ],
  },
  {
    version: '2.15.1', date: '2026-11-23', title: 'AI 성능 판단 보정',
    items: [{ kind: '수정', text: '측정 기록이 없을 때 판단이 "혼합"으로 기울던 문제 — 자료 없음은 안내만 하고 판단에는 넣지 않음' }],
  },
  {
    version: '2.15.0', date: '2026-11-23', title: 'AI 성능 대시보드',
    items: [
      { kind: '신규', text: '대시보드 › AI 성능 — 로컬 AI 글 쓰는 속도, 기능별 소요 시간·실패, 메모리·CPU·디스크 영향, 외부 LLM 이 필요한지 판단과 기능별 권장 연결' },
      { kind: '신규', text: '고객 데이터 없는 고정 문장으로 로컬·외부 LLM 속도를 재는 성능 측정 버튼' },
    ],
  },
  {
    version: '2.14.3', date: '2026-11-23', title: '규제 탐색 정비',
    items: [
      { kind: '개선', text: '규제 탐색 화면에 기능 설명·진행 단계, 출처별 사용 가능 여부와 설정 방법, 탐색 진행 표시' },
      { kind: '수정', text: '보고서용 AI 가 꺼져 있으면 AI 제안이 늘 건너뛰어지던 문제 — 일반 AI 로 제안' },
    ],
  },
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
