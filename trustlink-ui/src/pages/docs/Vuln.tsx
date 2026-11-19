import { DocTitle, Section, Glossary, DocTable, Note } from './_shared';

export default function Vuln() {
  return (
    <>
      <DocTitle title="취약점 · VEX" lead="SBOM 에서 찾은 취약점마다 우리 제품에 실제로 영향이 있는지 판단하고, 그 결과를 VEX 로 발행해 고객에게 전달합니다." />

      <Section title="왜 VEX 가 필요한가">
        <p>SBOM 만 받은 고객은 구성요소 목록을 취약점 DB 와 대조해 수백 건의 CVE 를 보게 됩니다. 대부분은 해당 함수를 쓰지 않거나 실행 경로에 없어 실제 위험이 아닙니다. VEX 는 공급자가 "이 CVE 는 영향 없음(근거: 취약 코드가 실행 경로에 없음)", "이 CVE 는 영향 있음 — 11.0 으로 업데이트" 처럼 판단과 대응을 적어 보내는 문서입니다. 고객은 VEX 덕분에 진짜 조치할 것만 보게 됩니다.</p>
      </Section>

      <Section title="흐름">
        <ol className="list-decimal space-y-1.5 pl-5">
          <li><b>자동 분석</b> — CycloneDX SBOM 이 붙은 버전은 10분 주기로 Dependency-Track 에 등록되고, NVD·OSV·GitHub 권고와 대조됩니다(관리자가 취약점 DB 미러를 켜 두면 외부 대신 내부 사본을 씁니다).</li>
          <li><b>새 취약점 통보</b> — 새로 나온 취약점은 모아서 그 제품의 쓰기 권한자와 관리자에게 메일·알림으로 보냅니다.</li>
          <li><b>판단</b> — 제품 버전 화면의 <b>취약점 분석 · VEX</b> 에서 항목마다 상태·근거·대응을 정합니다.</li>
          <li><b>발행</b> — <b>VEX 발행</b>을 누르면 판단 결과가 CycloneDX VEX 로 만들어져 그 버전에 새 첨부로 붙습니다(이전 VEX 는 그대로 남음).</li>
          <li><b>고객 통보</b> — 발행과 동시에 그 제품의 읽기 권한이 있는 고객과 고객사 보안 담당 주소로 "영향 있음 n건 · 영향 없음 n건" 요약이 갑니다.</li>
        </ol>
      </Section>

      <Section title="판단 화면 쓰는 법">
        <p>보안·개발·관리자 그룹 사용자에게 보입니다. 목록은 <b>우선순위</b> 순으로 정렬됩니다.</p>
        <DocTable head={['우선순위', '기준', '권장 처리 시간']} rows={[
          [<b>P1 실제 악용</b>, 'CISA KEV 목록에 등재(실제 공격에 쓰이는 중)', 'KEV 기한 안, 가능하면 즉시'],
          [<b>P2 긴급</b>, '공개 익스플로잇 있음 · EPSS 10% 이상 · CRITICAL', '수일 안'],
          [<b>P3 높음</b>, 'HIGH', '다음 릴리스 전'],
          [<b>P4</b>, '나머지', '정기 검토']
        ]} />
        <p className="pt-1">항목마다 정하는 값:</p>
        <DocTable head={['상태', '뜻', '함께 적을 것']} rows={[
          [<b>조사중</b>, '아직 판단 중', '—'],
          [<b>영향 없음</b>, '우리 제품에서는 악용될 수 없음', <>근거 필수: 구성요소 미포함 · 취약 코드 미포함 · <b>실행 경로에 없음</b> · 공격자가 제어 불가 · 완화책 이미 존재</>],
          [<b>영향 있음</b>, '악용 가능 — 조치 필요', '대응: 업데이트 · 임시 완화 · 롤백 · 수정 안 함 · 수정 불가, 그리고 고객이 할 일'],
          [<b>수정됨</b>, '이 버전에서 이미 고침', '고친 버전·커밋']
        ]} />
        <ul className="list-disc space-y-1 pl-5 pt-1">
          <li><b>AI 초안</b> — 켜져 있으면 항목별로 "상태·근거·대응·목표 버전" 초안을 만들어 줍니다. 근거로 쓴 사실(SBOM·권고·사용 맥락)이 함께 표시되고, 저장은 사람이 확인한 뒤에만 됩니다. 미분류 항목은 <b>일괄 초안</b>으로 한 번에 받을 수 있습니다.</li>
          <li><b>목표 버전</b> — 영향 있음이면 OSV 의 영향 범위로 "몇 버전으로 올리면 되는지"를 규칙으로 계산해 보여 줍니다(AI 아님).</li>
          <li><b>감사 이력</b> — 누가 언제 어떤 판단을 저장·발행했는지 원장에 남습니다.</li>
        </ul>
        <Note tone="warn">"영향 없음"은 고객이 그 CVE 를 무시해도 된다는 공급자 보증입니다. 근거를 고객이 이해할 수 있게 적고, 확실하지 않으면 "조사중"으로 두세요.</Note>
      </Section>

      <Section title="고객 쪽에서 VEX 읽기">
        <ul className="list-disc space-y-1 pl-5">
          <li>버전 화면의 <b>VEX</b> 배지에 판단 건수가 나옵니다. 첨부 파일에서 원본 JSON 을 받을 수 있고, 전체 다운로드 zip 의 <code>vex/</code> 폴더에도 들어 있습니다.</li>
          <li>여러 판이 있으면 가장 최근 VEX 가 현재 판단입니다. 이전 판은 판단이 어떻게 바뀌었는지 보여 주는 기록입니다.</li>
          <li>VEX 는 CycloneDX 표준이라 고객의 SBOM·취약점 관리 도구(Dependency-Track 등)에 그대로 넣어 쓸 수 있습니다.</li>
        </ul>
      </Section>

      <Glossary items={[
        ['Dependency-Track', 'SBOM 을 받아 알려진 취약점과 대조하는 오픈소스 분석 엔진. TrustLink 안에서 화면 없이 씁니다.'],
        ['NVD · OSV · GitHub 권고', '공개 취약점 DB. CVE 정보·영향 버전 범위를 제공합니다.'],
        ['KEV', 'CISA Known Exploited Vulnerabilities — 실제 악용이 확인된 취약점 목록과 조치 기한.'],
        ['EPSS', '앞으로 30일 안에 악용될 확률 추정치(0~100%).'],
        ['CycloneDX VEX', 'TrustLink 가 발행하는 VEX 형식. 항목마다 상태(영향 없음·영향 있음·수정됨·조사중)와 근거(justification)·대응(response)을 담습니다.']
      ]} />
    </>
  );
}
