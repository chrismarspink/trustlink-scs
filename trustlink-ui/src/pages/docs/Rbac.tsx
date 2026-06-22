import { DocTitle, Section, Glossary } from './_shared';

export default function Rbac() {
  return (
    <>
      <DocTitle title="권한 · 참고" lead="Keycloak 그룹으로 접근을 제어하고, zot accessControl 이 레포별 읽기/쓰기를 강제합니다." />

      <Section title="권한 · 그룹 (RBAC)">
        <ul className="list-disc pl-5">
          <li><b>developers</b> · <b>ci</b> — 읽기/쓰기(push), VEX 편집</li>
          <li><b>security</b> — VEX 분류·발행</li>
          <li><b>partners</b> · <b>customers</b> — 읽기(다운로드)</li>
          <li><b>admins</b> — 전체 + 관리 콘솔(사용자·용량·로그·레지스트리·CA)</li>
        </ul>
        <p className="text-xs text-muted-foreground">인증서 발급·폐기 같은 CA 쓰기 작업은 admins 전용이며 이중확인을 거칩니다.</p>
      </Section>

      <Section title="참고 자료">
        <ul className="list-disc pl-5">
          <li>zot 레지스트리 — <a className="text-primary underline" href="https://zotregistry.dev" target="_blank" rel="noreferrer">zotregistry.dev</a></li>
          <li>ORAS — <a className="text-primary underline" href="https://oras.land" target="_blank" rel="noreferrer">oras.land</a></li>
          <li>CycloneDX — <a className="text-primary underline" href="https://cyclonedx.org" target="_blank" rel="noreferrer">cyclonedx.org</a></li>
          <li>Dependency-Track — <a className="text-primary underline" href="https://dependencytrack.org" target="_blank" rel="noreferrer">dependencytrack.org</a></li>
          <li>step-ca (smallstep) — <a className="text-primary underline" href="https://smallstep.com/docs/step-ca" target="_blank" rel="noreferrer">smallstep.com/docs/step-ca</a></li>
        </ul>
      </Section>

      <Glossary items={[
        ['RBAC', '역할 기반 접근 제어(Role-Based Access Control). Keycloak 그룹 → zot 정책으로 매핑.'],
        ['Keycloak', 'OIDC 신원 공급자(IdP). 로그인·그룹(역할)을 관리.'],
        ['accessControl', 'zot 설정의 레포별 권한 정책(read/create/update/delete).'],
        ['OIDC', 'OpenID Connect — 표준 인증 프로토콜. 웹 로그인에 사용.']
      ]} />
    </>
  );
}
