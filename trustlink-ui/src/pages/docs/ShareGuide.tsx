import { Link } from 'react-router-dom';
import { registry, plainHttp } from '@/lib/utils';
import { DocTitle, Section, Code, Glossary, DocTable, Note } from './_shared';

export default function ShareGuide() {
  const reg = registry;
  const p = plainHttp;
  return (
    <>
      <DocTitle title="업로드 · 다운로드" lead="제품 버전은 표준 도구 oras(파일)·docker(컨테이너 이미지)로 레지스트리에 올리고, SBOM·VEX·매뉴얼을 그 버전에 첨부합니다. 받는 쪽은 웹이나 같은 도구로 내려받습니다." />

      <Section title="준비">
        <ul className="list-disc space-y-1 pl-5">
          <li><b>도구</b> — <a className="text-primary underline" href="https://oras.land/docs/installation" target="_blank" rel="noreferrer">oras</a> 1.2 이상(파일), 컨테이너 이미지는 docker 또는 podman.</li>
          <li><b>사람이 쓸 때</b> — <Link className="text-primary underline" to="/apikeys">내 API 키</Link>에서 키를 발급합니다. 웹 로그인 비밀번호로는 oras 에 로그인할 수 없습니다. 키 권한은 내 계정 권한과 같습니다.</li>
          <li><b>CI·서버가 쓸 때</b> — 관리자에게 자동화 계정을 요청하세요. 올리기용은 <code>ci-제품명</code>, 받기용은 <code>robot-고객사</code> 형태로 만들어지며 해당 제품에만 권한이 있습니다.</li>
          <li><b>권한</b> — 올리려면 그 제품의 쓰기 권한, 받으려면 읽기 권한이 있어야 합니다. 권한이 없으면 <code>401/403</code> 이 납니다.</li>
        </ul>
        <Code>{`# 로그인 (키는 화면에 남지 않게 표준입력으로)
printf '%s' '<API 키>' | oras login ${reg} -u <내 사용자 이름> --password-stdin${p}`}</Code>
      </Section>

      <Section title="이름 규칙">
        <DocTable head={['항목', '규칙', '예']} rows={[
          ['저장소(제품)', <code>products/&lt;제품명&gt;</code>, <code>products/innopouch</code>],
          ['태그(버전)', '릴리스 버전 그대로. 같은 태그로 다시 올리면 새 버전이 그 태그를 가져갑니다', <code>10.0</code>],
          ['첨부 대상', '태그 대신 다이제스트(@sha256:…)로 붙이면 정확히 그 빌드에 붙습니다', <code>products/innopouch@sha256:…</code>]
        ]} />
      </Section>

      <Section title="올리기 — 파일 산출물">
        <p>본체를 먼저 올리고, 출력된 다이제스트에 SBOM·VEX·매뉴얼을 첨부합니다. 첨부 종류는 <code>--artifact-type</code> 으로 구분하며 TrustLink 는 아래 값을 알아봅니다.</p>
        <Code>{`# 1) 본체 올리기 — 다이제스트를 받아 둔다
DG=$(oras push${p} ${reg}/products/<제품명>:<버전> app.tar.gz \\
      --artifact-type application/vnd.<회사>.<제품>.v1 --format go-template='{{.digest}}')

# 2) SBOM 첨부 (CycloneDX JSON; SPDX 는 application/spdx+json)
oras attach${p} ${reg}/products/<제품명>@$DG \\
  --artifact-type application/vnd.cyclonedx+json sbom.cdx.json:application/vnd.cyclonedx+json

# 3) VEX 첨부 (공급자가 이미 판단한 경우)
oras attach${p} ${reg}/products/<제품명>@$DG \\
  --artifact-type application/vnd.cyclonedx.vex+json vex.cdx.json

# 4) 매뉴얼·가이드 첨부 (전체 다운로드 zip 의 docs/ 폴더로 들어감)
oras attach${p} ${reg}/products/<제품명>@$DG \\
  --artifact-type application/vnd.trustlink.guide+markdown INSTALL.md:text/markdown

# 5) 확인
oras discover${p} ${reg}/products/<제품명>:<버전> --format tree`}</Code>
        <DocTable head={['첨부', 'artifact-type', '화면 표시']} rows={[
          ['SBOM', <code>application/vnd.cyclonedx+json</code>, 'SBOM 배지 · 구성요소 수 · 취약점 분석 대상'],
          ['SBOM (SPDX)', <code>application/spdx+json</code>, 'SBOM 배지 · 패키지 수'],
          ['VEX', <code>application/vnd.cyclonedx.vex+json</code>, 'VEX 배지 · 판단 건수'],
          ['서명', 'cosign 서명(sigstore)', '서명됨 배지'],
          ['문서', <><code>application/vnd.trustlink.guide+markdown</code> · PDF</>, '첨부 파일 목록 · zip 의 docs/']
        ]} />
        <Note>SBOM 을 만들 수 없는 경우에도 올릴 수 있습니다. 버전 화면에서 <b>SBOM 생성 (syft)</b> 을 누르면 TrustLink 가 산출물을 스캔해 SBOM 을 만들어 첨부합니다(쓰기 권한 필요). 공급자가 낸 SBOM 과 자동 생성 SBOM 은 배지로 구분됩니다.</Note>
      </Section>

      <Section title="올리기 — 컨테이너 이미지">
        <Code>{`${p ? `# docker 는 평문 HTTP 레지스트리를 1회 등록해야 함
#   /etc/docker/daemon.json → { "insecure-registries": ["${reg}"] } 후 docker 재시작
` : ''}printf '%s' '<API 키>' | docker login ${reg} -u <사용자 이름> --password-stdin
docker tag myapp:1.0 ${reg}/products/<제품명>:1.0
docker push ${reg}/products/<제품명>:1.0
# SBOM·VEX 첨부는 위 oras attach 와 같다(대상: ${reg}/products/<제품명>:1.0)`}</Code>
      </Section>

      <Section title="CI 에서 자동으로 올리기">
        <p>빌드가 끝날 때 아래 단계를 넣으면 버전마다 산출물과 SBOM 이 함께 올라갑니다. 자격 증명은 CI 의 비밀 변수(<code>TL_USER</code>, <code>TL_KEY</code>)에 넣습니다.</p>
        <Code>{`# GitLab CI 예 (.gitlab-ci.yml) — GitHub Actions 도 같은 명령
publish:
  stage: deploy
  script:
    - syft dir:./dist -o cyclonedx-json=sbom.cdx.json      # SBOM 생성
    - printf '%s' "$TL_KEY" | oras login ${reg} -u "$TL_USER" --password-stdin${p}
    - DG=$(oras push${p} ${reg}/products/myapp:$CI_COMMIT_TAG dist/myapp.tar.gz --format go-template='{{.digest}}')
    - oras attach${p} ${reg}/products/myapp@$DG --artifact-type application/vnd.cyclonedx+json sbom.cdx.json:application/vnd.cyclonedx+json
  rules:
    - if: $CI_COMMIT_TAG`}</Code>
        <p>올린 뒤 10분 안에 SBOM 이 취약점 분석 대상으로 등록되고, 새 취약점이 나오면 그 제품의 쓰기 권한자와 관리자에게 통보됩니다.</p>
      </Section>

      <Section title="내려받기">
        <p><b>웹</b> — 아티팩트 → 제품 → 버전 화면에서:</p>
        <ul className="list-disc space-y-1 pl-5">
          <li><b>전체 다운로드</b> — 본체와 SBOM·VEX·서명·문서를 zip 하나로(플랫폼별 폴더, 종류별 하위 폴더).</li>
          <li><b>첨부 파일</b> — 행마다 파일 하나씩. 같은 종류를 여러 번 올렸으면 이전 판도 모두 남아 있습니다.</li>
        </ul>
        <p><b>명령줄</b> — 본체와 첨부를 따로 받습니다.</p>
        <Code>{`# 최신 버전 확인
oras repo tags${p} ${reg}/products/<제품명>

# 본체
oras pull${p} ${reg}/products/<제품명>:<버전> -o out/

# 첨부 중 VEX 만 모두 받기 (SBOM 은 application/vnd.cyclonedx+json)
for d in $(oras discover${p} ${reg}/products/<제품명>:<버전> \\
            --artifact-type application/vnd.cyclonedx.vex+json \\
            --format go-template='{{range .referrers}}{{.digest}} {{end}}'); do
  oras pull${p} ${reg}/products/<제품명>@$d -o out/
done

# 컨테이너 이미지
docker pull ${reg}/products/<제품명>:<버전>`}</Code>
      </Section>

      <Section title="자주 겪는 문제">
        <DocTable head={['증상', '원인과 해결']} rows={[
          [<code>unauthorized</code>, 'API 키가 만료됐거나 사용자 이름이 다름. 키를 새로 발급하고 사용자 이름(이메일 아님)으로 로그인.'],
          [<code>denied / 403</code>, '그 제품의 쓰기(또는 읽기) 권한이 없음. 관리자에게 제품 권한 요청.'],
          ['웹 목록에 제품이 안 보임', '읽기 권한이 없는 제품은 목록에서도 숨겨집니다.'],
          [<code>http: server gave HTTP response to HTTPS client</code>, '평문 HTTP 레지스트리. oras 는 --plain-http, docker 는 insecure-registries 설정.'],
          ['SBOM 을 올렸는데 취약점이 안 나옴', '분석 등록은 최대 10분 걸립니다. artifact-type 이 application/vnd.cyclonedx+json 인지 확인하세요(SPDX 는 표시만 되고 분석은 CycloneDX 기준).']
        ]} />
      </Section>

      <Glossary items={[
        ['oras', 'OCI 레지스트리에 임의 파일(바이너리·SBOM 등)을 올리고 받는 명령줄 도구.'],
        ['다이제스트', '내용의 SHA-256 지문(sha256:…). 태그는 옮겨질 수 있지만 다이제스트는 그 내용 하나만 가리킵니다.'],
        ['artifact-type', '본체·첨부의 종류를 나타내는 문자열. TrustLink 는 이 값으로 SBOM·VEX·서명·문서를 구분합니다.'],
        ['syft', 'Anchore 의 SBOM 생성 도구. 파일·디렉터리·이미지를 스캔해 구성요소 목록을 만듭니다.'],
        ['자동화 계정', '사람이 아닌 CI·서버용 계정(ci-*, robot-*). 정해진 제품에만 권한이 있고 관리자가 재발급·폐기합니다.']
      ]} />
    </>
  );
}
