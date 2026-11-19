import { DocTitle, Section, Glossary, DocTable, Note } from './_shared';

const A = ({ href, children }: { href: string; children: string }) => (
  <a className="text-primary underline" href={href} target="_blank" rel="noreferrer">{children}</a>
);

export default function Rbac() {
  return (
    <>
      <DocTitle title="권한 · 참고" lead="누가 어떤 제품을 보고 올릴 수 있는지는 계정의 그룹과 제품별 권한으로 정해집니다. 웹 화면과 레지스트리(oras·docker)에 같은 규칙이 적용됩니다." />

      <Section title="계정 종류">
        <DocTable head={['종류', '쓰는 곳', '만드는 사람']} rows={[
          [<b>사람 계정</b>, '웹 로그인(회사 계정). 처음 로그인할 때 임시 비밀번호를 바꿉니다.', '관리자'],
          [<b>내 API 키</b>, '사람이 명령줄(oras·docker)로 올리고 받을 때. 권한은 내 계정과 같고, 기간(30일~1년)이 지나거나 계정이 꺼지면 막힙니다.', '본인'],
          [<b>자동화 계정</b>, <>CI·서버용. <code>ci-*</code> 는 올리기, <code>robot-*</code> 는 받기. 정해진 제품에만 권한이 있습니다.</>, '관리자(재발급·폐기 가능)']
        ]} />
      </Section>

      <Section title="그룹과 할 수 있는 일">
        <DocTable head={['그룹', '할 수 있는 일']} rows={[
          [<b>admins</b>, '모든 제품 + 관리 화면 전체(계정·고객사·제품 권한·통보·규제 보고서·시스템)'],
          [<b>developers</b>, '쓰기 권한을 받은 제품에 올리기, SBOM 생성, 취약점 판단·VEX 발행'],
          [<b>security</b>, '취약점 판단·VEX 발행(제품 열람은 제품 권한에 따름)'],
          [<b>고객사 그룹</b>, '읽기 권한을 받은 제품만 열람·다운로드, VEX 발행 통보 수신'],
          [<b>users</b>, '로그인만. 제품은 제품 권한을 받아야 보입니다']
        ]} />
      </Section>

      <Section title="제품 권한">
        <ul className="list-disc space-y-1 pl-5">
          <li>제품(저장소)마다 <b>쓰기 대상</b>과 <b>읽기 대상</b>을 사람·그룹·고객사·자동화 계정 단위로 지정합니다(관리 › 계정 및 권한 › 제품 권한).</li>
          <li>쓰기 = 올리기·첨부·SBOM 생성, 읽기 = 목록·상세·다운로드. 둘 다 없으면 그 제품은 목록에도 나오지 않습니다.</li>
          <li>권한 변경은 레지스트리에 즉시 반영됩니다. 웹과 명령줄 결과가 다르면 관리자에게 알려 주세요.</li>
        </ul>
        <Note tone="warn">규칙에 맞는 권한이 없으면 무조건 거부합니다(fail-closed). 새 고객사 계정은 제품 권한을 주기 전까지 아무것도 보이지 않는 것이 정상입니다.</Note>
      </Section>

      <Section title="통보는 누구에게 가나">
        <DocTable head={['일', '받는 사람']} rows={[
          ['새 취약점 발견', '그 제품의 쓰기 권한자 + 관리자 (내부)'],
          ['VEX 발행', '그 제품의 읽기 권한이 있는 고객 + 고객사 보안 담당 주소'],
          ['현황 메일', '관리자가 고른 사람(시스템 › 시스템 상태 › 현황 메일 보내기)']
        ]} />
        <p className="text-xs text-muted-foreground">통보는 화면 오른쪽 위 알림과 메일로 같이 갑니다. 메일 주소가 없는 계정은 알림만 받습니다.</p>
      </Section>

      <Section title="보안 원칙">
        <ul className="list-disc space-y-1 pl-5">
          <li><b>원본 불변</b> — 올린 SBOM·VEX 는 고치거나 지우지 않고 새 첨부로 쌓습니다.</li>
          <li><b>감사 원장</b> — 로그인·권한 변경·업로드·판단·발행·메일·보고서 생성이 추가 전용 기록에 남습니다.</li>
          <li><b>비밀정보</b> — 임시 비밀번호·API 키는 발급할 때 한 번만 보여 주고 다시 보여 주지 않습니다(임시 비밀번호는 저장하지 않음). 외부 AI·GitHub 키는 서버 파일(권한 600)에만 저장하고 화면에는 끝 4자리만 보입니다.</li>
          <li><b>AI 는 초안만</b> — 판단·발행·발송은 사람이 확인한 뒤에만 됩니다. 외부 AI 에는 메일 주소·계정 이름을 보내지 않습니다.</li>
        </ul>
      </Section>

      <Section title="참고 자료">
        <ul className="list-disc space-y-1 pl-5">
          <li>OCI 레지스트리 zot — <A href="https://zotregistry.dev">zotregistry.dev</A></li>
          <li>ORAS — <A href="https://oras.land">oras.land</A></li>
          <li>CycloneDX (SBOM·VEX) — <A href="https://cyclonedx.org">cyclonedx.org</A></li>
          <li>Dependency-Track — <A href="https://dependencytrack.org">dependencytrack.org</A></li>
          <li>syft — <A href="https://github.com/anchore/syft">github.com/anchore/syft</A></li>
          <li>CISA KEV — <A href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">cisa.gov/known-exploited-vulnerabilities-catalog</A></li>
          <li>CISA VEX 최소 요건 — <A href="https://www.cisa.gov/resources-tools/resources/minimum-requirements-vulnerability-exploitability-exchange-vex">cisa.gov (Minimum Requirements for VEX)</A></li>
        </ul>
      </Section>

      <Glossary items={[
        ['Keycloak', '로그인과 그룹(역할)을 관리하는 인증 서버. 웹 로그인은 OIDC 표준으로 합니다.'],
        ['fail-closed', '권한 규칙이 없거나 확인할 수 없으면 허용하지 않고 거부하는 방식.'],
        ['고객사', '고객 회사를 나타내는 그룹. 소속 계정과 보안 담당 통보 주소를 함께 관리합니다.'],
        ['감사 원장', '고칠 수 없게 덧붙이기만 하는 작업 기록. 누가 언제 무엇을 했는지 증빙으로 씁니다.']
      ]} />
    </>
  );
}
