import { DocTitle, Section, Glossary, ArchDiagram, FlowDiagram } from './_shared';

export default function GettingStarted() {
  const host = window.location.host;
  const reg = `${window.location.hostname}:28081`;
  const ca = `${window.location.hostname}:28443`;
  return (
    <>
      <DocTitle title="시작하기" lead="TrustLink SCS — 공급망 보안 아티팩트 레지스트리. 컨테이너/바이너리와 그 SBOM·VEX·서명을 한곳에서 관리·검증·배포합니다." />

      <Section title="개요">
        <p>
          TrustLink SCS 는 OCI 레지스트리 <b>zot</b> 위에 인증(Keycloak)·취약점 분석(Dependency-Track)·서명(step-ca + CMS)을 결합한
          공급망 보안 플랫폼입니다. 산출물과 그 <b>SBOM·VEX·서명·검증 리포트</b>를 OCI <i>referrers</i> 로 함께 보관합니다.
        </p>
        <ul className="list-disc pl-5">
          <li>업로드된 SBOM/VEX/서명은 <b>덮어쓰지 않고</b> 새 referrer 로 누적 — 출처·이력 보존</li>
          <li>표준 포맷: <b>CycloneDX</b>(SBOM·VEX), <b>CMS/RFC 5652</b>(서명)</li>
          <li>게이트 통과분만 서명·반출(신뢰된 외부 공유)</li>
        </ul>
      </Section>

      <Section title="구성도">
        <ArchDiagram />
        <p className="text-xs text-muted-foreground">
          웹/관리는 TrustLink(:28080), 레지스트리 pull/push 는 zot(:28081), 인증서 발급·검증·CRL 은 step-ca(:28443)로 접근합니다.
          각 백엔드는 독립 평면으로, TrustLink 가 멈춰도 레지스트리·검증은 동작합니다.
        </p>
      </Section>

      <Section title="접속 엔드포인트">
        <ul className="list-disc pl-5">
          <li><b>웹 콘솔·관리·로그인</b> — <code>http://{host}</code> (TrustLink/BFF)</li>
          <li><b>레지스트리 pull/push</b> — <code>http://{reg}</code> (zot 직접)</li>
          <li><b>인증서·검증·CRL</b> — <code>https://{ca}</code> (step-ca, TLS·자체서명 → 루트 신뢰 필요)</li>
        </ul>
      </Section>

      <Section title="빠른 시작">
        <p>1) 브라우저로 <code>http://{host}</code> 접속 → Keycloak 로그인 → 제품 목록.</p>
        <p>2) 제품 카드 → 버전 선택 → 개요·SBOM/VEX·다운로드·취약점 분석 확인.</p>
        <p>3) CLI 업로드/다운로드는 <b>업로드·다운로드</b> 문서, 서명 검증은 <b>신뢰·검증(CA)</b> 문서를 참고하세요.</p>
      </Section>

      <Section title="처리 흐름">
        <FlowDiagram />
      </Section>

      <Glossary items={[
        ['OCI', '컨테이너/아티팩트 레지스트리 표준(Open Container Initiative). zot 이 이를 구현합니다.'],
        ['referrer', '특정 아티팩트(다이제스트)에 "매달린" 부속 객체. SBOM·VEX·서명을 본체를 변경하지 않고 연결합니다.'],
        ['SBOM', '소프트웨어 자재 명세서(Software Bill of Materials) — 구성 컴포넌트·버전·라이선스 목록.'],
        ['VEX', '취약점 활용성 교환(Vulnerability Exploitability eXchange) — "이 CVE 가 실제로 영향이 있는가"의 판정.'],
        ['CMS', 'Cryptographic Message Syntax(RFC 5652) — 서명/암호화 표준 메시지 형식. 산출물 묶음 서명에 사용.']
      ]} />
    </>
  );
}
