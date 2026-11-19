import { Link } from 'react-router-dom';
import { registry, plainHttp } from '@/lib/utils';
import { DocTitle, Section, Glossary, ArchDiagram, FlowDiagram, DocTable, Note } from './_shared';

export default function GettingStarted() {
  const web = window.location.origin;
  const reg = `${window.location.protocol}//${registry}`;
  return (
    <>
      <DocTitle title="시작하기" lead="TrustLink SCS 는 소프트웨어 산출물과 그 SBOM·VEX 를 한곳에 보관하고, 취약점 판단 결과를 고객에게 전달하는 공급망 보안 플랫폼입니다." />

      <Section title="TrustLink 가 하는 일">
        <p>제품을 고객에게 넘길 때 "무엇으로 만들었고(SBOM), 알려진 취약점에 영향이 있는지(VEX)"를 함께 보여 줘야 하는 경우가 늘고 있습니다(EU CRA, 미국 연방 조달, 국내 공공·금융 등). TrustLink 는 이 일을 다음 순서로 처리합니다.</p>
        <ul className="list-disc space-y-1 pl-5">
          <li><b>보관</b> — 바이너리·컨테이너 이미지와 SBOM·VEX·서명·매뉴얼을 한 버전에 묶어 보관합니다. 올린 파일은 고치지 않고 새 파일로 쌓여 이력이 남습니다.</li>
          <li><b>분석</b> — SBOM 을 Dependency-Track 이 분석해 알려진 취약점(CVE)을 찾습니다. SBOM 이 없으면 웹에서 바로 만들 수 있습니다(syft).</li>
          <li><b>판단</b> — 보안 담당자가 취약점마다 "영향 있음/없음"을 정합니다. 실제 악용(KEV) 여부로 우선순위를 매기고, AI 가 판단 초안을 써 줍니다(결정은 사람).</li>
          <li><b>전달</b> — 판단 결과를 VEX 로 발행하면 그 제품을 받는 고객에게 메일로 통보됩니다. 고객은 웹이나 명령줄로 산출물과 SBOM·VEX 를 함께 받습니다.</li>
          <li><b>관리</b> — 계정·고객사·제품 권한, 규제 보고서, 현황 메일, 공개 저장소 점검 등은 관리자 화면에서 합니다.</li>
        </ul>
      </Section>

      <Section title="누가 무엇을 하나">
        <DocTable head={['역할', '주로 하는 일', '시작 화면']} rows={[
          [<b>개발자·CI</b>, '제품 버전 올리기, SBOM·VEX 첨부, SBOM 자동 생성', <Link className="text-primary underline" to="/docs/share">업로드·다운로드</Link>],
          [<b>보안 담당</b>, '취약점 판단(VEX 분류), AI 초안 검토, VEX 발행', <Link className="text-primary underline" to="/docs/vuln">취약점·VEX</Link>],
          [<b>고객·협력사</b>, '권한 받은 제품의 산출물·SBOM·VEX 내려받기, 통보 메일 확인', <Link className="text-primary underline" to="/">아티팩트</Link>],
          [<b>관리자</b>, '계정·고객사·제품 권한, 통보, 규제 보고서, 시스템 운영', <Link className="text-primary underline" to="/docs/rbac">권한·참고</Link>]
        ]} />
      </Section>

      <Section title="구성">
        <ArchDiagram />
        <p className="text-xs text-muted-foreground">
          사용자와 CI 는 TrustLink 한 주소로 들어옵니다. TrustLink 가 로그인(Keycloak)과 레지스트리(zot) 요청을 중계하고, 분석·PDF 변환·AI 는 내부에서만 씁니다.
          레지스트리는 TrustLink 와 독립적으로 보관되므로 관리 화면을 고치는 동안에도 산출물은 그대로입니다.
        </p>
      </Section>

      <Section title="처리 흐름">
        <FlowDiagram />
      </Section>

      <Section title="접속 주소">
        <DocTable head={['용도', '주소', '인증']} rows={[
          ['웹 화면·관리·로그인', <code>{web}</code>, '회사 계정(Keycloak) 로그인'],
          ['레지스트리 (oras · docker)', <code>{reg}</code>, <>사용자 이름 + <Link className="text-primary underline" to="/apikeys">내 API 키</Link> 또는 자동화 계정</>]
        ]} />
        {!!plainHttp && <Note tone="warn">이 서버는 평문 HTTP 레지스트리입니다. oras 에는 <code>--plain-http</code>, docker 에는 insecure-registries 설정이 필요합니다.</Note>}
      </Section>

      <Section title="처음 5분">
        <ol className="list-decimal space-y-1.5 pl-5">
          <li><code>{web}</code> 에 회사 계정으로 로그인합니다. 처음이면 관리자가 보낸 임시 비밀번호로 들어가 새 비밀번호를 정합니다.</li>
          <li><b>아티팩트</b> 화면에서 권한이 있는 제품을 고릅니다. 아무것도 안 보이면 관리자에게 제품 권한을 요청하세요(권한 없는 제품은 목록에도 나오지 않습니다).</li>
          <li>버전을 열면 <b>서명·SBOM·VEX 첨부 상태</b>, 첨부 파일, 취약점 분석 결과를 볼 수 있습니다. <b>전체 다운로드</b>는 산출물과 첨부를 zip 하나로 받습니다.</li>
          <li>명령줄로 올리거나 받으려면 <Link className="text-primary underline" to="/apikeys">내 API 키</Link>를 발급한 뒤 <Link className="text-primary underline" to="/docs/share">업로드·다운로드</Link> 문서를 따라 하세요.</li>
          <li>오른쪽 위 종 모양 아이콘에는 내 제품의 새 취약점·VEX 발행 통보가 쌓입니다(같은 내용이 메일로도 갑니다).</li>
        </ol>
      </Section>

      <Glossary items={[
        ['SBOM', '소프트웨어 자재 명세서. 제품에 들어간 구성요소·버전·라이선스 목록. TrustLink 는 CycloneDX 와 SPDX 를 받습니다.'],
        ['VEX', '취약점 영향 판단서. "이 CVE 가 우리 제품에 실제로 영향이 있는가"와 그 근거·대응을 적은 문서(CycloneDX VEX · OpenVEX).'],
        ['CVE', '공개 취약점 식별 번호. 예: CVE-2024-6119.'],
        ['KEV', '미국 CISA 가 "실제로 악용되고 있다"고 확인한 취약점 목록. TrustLink 에서 가장 먼저 처리할 대상(P1)입니다.'],
        ['OCI 레지스트리', '컨테이너 이미지와 임의 파일을 버전(태그)별로 보관하는 표준 저장소. TrustLink 는 zot 을 씁니다.'],
        ['referrer(첨부)', '한 버전에 매달린 부속 파일. SBOM·VEX·서명·매뉴얼을 본체를 바꾸지 않고 연결합니다.']
      ]} />
    </>
  );
}
