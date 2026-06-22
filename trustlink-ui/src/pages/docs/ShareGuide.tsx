import { DocTitle, Section, Code, Glossary } from './_shared';

export default function ShareGuide() {
  const reg = `${window.location.hostname}:28081`;
  return (
    <>
      <DocTitle title="업로드 · 다운로드" lead="OCI 표준 도구(oras/docker)로 레지스트리에 직접 올리고 내려받습니다. 웹 콘솔(:28080)이 멈춰도 동작합니다." />

      <Section title="업로드 (Push)">
        <p>레지스트리(<code>{reg}</code>)에 직접 올리고, SBOM/VEX 를 referrer 로 첨부합니다. 평문 HTTP 이므로 oras 는 <code>--plain-http</code>, docker 는 insecure-registry 설정이 필요합니다.</p>
        <Code>{`# 로그인 (htpasswd 계정 또는 API 키)
oras login ${reg} -u <ID> -p <PW> --plain-http

# 아티팩트 push
oras push --plain-http ${reg}/products/<name>:<ver> app.tar

# SBOM 첨부 (CycloneDX)
oras attach --plain-http ${reg}/products/<name>:<ver> \\
  --artifact-type application/vnd.cyclonedx+json sbom.cdx.json

# VEX 첨부
oras attach --plain-http ${reg}/products/<name>:<ver> \\
  --artifact-type application/vnd.cyclonedx.vex+json vex.cdx.json`}</Code>
        <p>컨테이너 이미지는 docker/podman 으로:</p>
        <Code>{`# docker daemon.json 에 1회 등록 (평문 HTTP 허용)
#   { "insecure-registries": ["${reg}"] }   → docker 재시작
docker login ${reg} -u <ID> -p <PW>
docker tag myimage:1.0 ${reg}/products/<name>:<ver>
docker push ${reg}/products/<name>:<ver>`}</Code>
      </Section>

      <Section title="다운로드 (Pull)">
        <p>웹 제품 상세 페이지에서:</p>
        <ul className="list-disc pl-5">
          <li><b>전체 다운로드(zip)</b> — 바이너리 + SBOM/VEX/서명을 한 번에(플랫폼별 폴더)</li>
          <li><b>파일별 다운로드</b> — referrer 행마다 단일 파일</li>
        </ul>
        <p>또는 CLI 로 레지스트리에서 직접:</p>
        <Code>{`oras pull --plain-http ${reg}/<repo>:<tag>
docker pull ${reg}/<repo>:<tag>`}</Code>
      </Section>

      <Glossary items={[
        ['oras', 'OCI Registry As Storage — 임의 아티팩트(바이너리·SBOM 등)를 OCI 레지스트리에 push/pull 하는 CLI.'],
        ['artifact-type', 'referrer 의 종류를 나타내는 미디어 타입. SBOM=application/vnd.cyclonedx+json, VEX=…vex+json.'],
        ['insecure-registry', 'docker 가 평문 HTTP 레지스트리에 접속하도록 허용하는 설정(데모용). 운영은 TLS 사용.'],
        ['htpasswd 계정 / API 키', 'CLI 인증 수단. OIDC 브라우저 로그인 없이 zot 에 직접 인증합니다.']
      ]} />
    </>
  );
}
