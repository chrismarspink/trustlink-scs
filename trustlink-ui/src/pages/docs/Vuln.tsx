import { DocTitle, Section, Glossary } from './_shared';

export default function Vuln() {
  return (
    <>
      <DocTitle title="취약점 · VEX" lead="SBOM 을 Dependency-Track 이 분석한 취약점을, VEX 로 분류·발행해 잔존 위험을 관리합니다." />

      <Section title="취약점 분석 · VEX 편집">
        <p>제품 상세의 <b>취약점 분석 · VEX</b> 카드에서 (security/developers/admins 그룹):</p>
        <ul className="list-disc pl-5">
          <li><b>취약점 분석 불러오기</b> — Dependency-Track 이 SBOM 을 분석한 취약점(CVE) 목록</li>
          <li><b>인라인 분류</b> — 항목별 상태(영향있음/영향없음/수정됨/조사중)·근거·코멘트 저장(감사 이력)</li>
          <li><b>VEX 발행</b> — 분류 결과를 CycloneDX VEX 로 추출해 <b>새 referrer 로 부착</b>(원본 불변)</li>
        </ul>
      </Section>

      <Section title="대시보드 추이">
        <p>관리 대시보드의 "제품 버전 추이" 는 버전별 SBOM 컴포넌트 수 / 취약점 수 / VEX 타입별 분포를 보여줍니다.</p>
        <ul className="list-disc pl-5">
          <li>취약점 수는 <b>Dependency-Track</b>(SBOM 분석) 우선, 컨테이너 이미지는 <b>zot 내장 Trivy</b> 가 소스</li>
          <li>분석 데이터가 없는 제품은 추이 시연용 더미로 표시(배지로 구분)</li>
        </ul>
      </Section>

      <Glossary items={[
        ['CVE', '공개 취약점 식별자(Common Vulnerabilities and Exposures). 예: CVE-2024-6119.'],
        ['Dependency-Track', 'SBOM 을 받아 알려진 취약점과 대조·관리하는 OSS. VEX 분석/발행의 백엔드 엔진.'],
        ['Trivy', 'zot 에 내장된 컨테이너 이미지 CVE 스캐너. 이미지 레이어 기반(바이너리 아티팩트는 DT 가 담당).'],
        ['VEX 상태', 'not_affected(영향없음)·affected(영향있음)·fixed(수정됨)·under_investigation(조사중).'],
        ['CycloneDX', 'SBOM·VEX 를 표현하는 표준 포맷. TrustLink 의 기본 포맷.']
      ]} />
    </>
  );
}
