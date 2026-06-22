import { DocTitle, Section, Code, Glossary } from './_shared';

export default function Trust() {
  const ca = `${window.location.hostname}:28443`;
  const reg = `${window.location.hostname}:28081`;
  return (
    <>
      <DocTitle title="신뢰 · 검증 (CA)" lead="산출물 묶음(바이너리+SBOM+VEX)을 CMS 로 서명해 폐쇄망 경계를 넘어 진본성·무결성을 검증합니다. 인증서는 step-ca(내장 CA)가 발급합니다." />

      <Section title="신뢰 구조 — 3평면 분리">
        <p>step-ca 는 "신뢰 영역의 zot" 으로, TrustLink 와 분리된 독립 평면에서 동작합니다.</p>
        <ul className="list-disc pl-5">
          <li><b>평면 1 (검증/CRL):</b> step-ca 자체 포트(<code>https://{ca}</code>) — 검증자·CI 가 직접 접근. <b>TrustLink 가 죽어도 검증·CRL·갱신 생존.</b></li>
          <li><b>평면 2 (발급/제어):</b> TrustLink CA 어댑터가 step-ca API 호출(발급·폐기). TrustLink 죽으면 자동 발급만 멈춤.</li>
          <li><b>평면 3 (관리 GUI):</b> 관리 콘솔의 "인증서·신뢰(CA)" — 목록·발급·폐기·감사(읽기 우선).</li>
        </ul>
      </Section>

      <Section title="키 계층 (PKI)">
        <Code>{`Root CA (신뢰 앵커 — 수신자에 사전 배포, 일상 서명에 미사용)
  └─ Issuing(Intermediate) CA  (step-ca 운영, 실제 발급 서명)
       ├─ TrustLink 릴리즈 서명 인증서 (CMS 서명용, 짧은 수명)
       ├─ 고객 인증서 (CSR 서명 — 고객이 개인키 보유)
       └─ (조건부) 수신자 암호화 인증서`}</Code>
        <p><b>신뢰 앵커(Root)</b> 하나만 수신자가 신뢰하면, 그 아래 모든 TrustLink 서명을 검증할 수 있습니다(N×M 키 분배 문제 회피).</p>
      </Section>

      <Section title="신뢰 앵커 배포 (수신자 온보딩)">
        <p>협력사·고객은 최초 1회 <b>Root 인증서</b>를 신뢰 앵커로 받아 둡니다(오프라인 사전 배포 권장).</p>
        <Code>{`# 루트(신뢰 앵커) 받기 — step-ca 직접
curl -k https://${ca}/roots.pem -o trustlink-root.pem

# (관리 콘솔) 인증서·신뢰(CA) → 개요 에서 지문 확인 후 대조`}</Code>
      </Section>

      <Section title="서명 검증 (수신 측)">
        <p>수신자는 받은 <code>.p7s</code>(CMS 서명)를 루트만으로 검증합니다. TrustLink·step-ca 가 없어도 됩니다.</p>
        <Code>{`# 1) zot 에서 서명(.p7s)·산출물 받기 (또는 nPouch 반출본)
oras pull --plain-http ${reg}/products/<name>:<ver>

# 2) CMS 검증 — 루트(신뢰 앵커)로 체인 검증 + 묶음 매니페스트 추출
openssl cms -verify -inform DER -in <name>.cms.p7s \\
  -CAfile trustlink-root.pem -purpose any -out bundle.json

# 3) 폐기 확인 (선택) — CRL 대조
curl -k https://${ca}/crl -o trustlink.crl
openssl crl -inform DER -in trustlink.crl -noout -text`}</Code>
        <p className="text-xs text-muted-foreground">
          검증 성공 시 <code>bundle.json</code> 에 subject(산출물)·SBOM·VEX 다이제스트가 들어 있어, 받은 파일들과 대조해 무결성을 확인합니다.
          (<code>-purpose any</code> 는 서명 인증서 용도 확장 때문 — 운영에선 codeSigning 템플릿 사용 권장.)
        </p>
      </Section>

      <Section title="서명+암호화 패키지 (외부 협력사 기밀 배포)">
        <p>
          특정 수신자에게만 기밀 전달할 때, 산출물 번들(바이너리·SBOM·VEX)을 <b>CMS 서명 후 수신자 인증서로 암호화</b>(EnvelopedData)한
          <code>.p7m</code> 으로 내려받습니다. 수신자만 개인키로 복호할 수 있고, 루트로 서명 검증이 됩니다.
        </p>
        <p className="text-xs text-muted-foreground">
          관리 콘솔 → <b>인증서·신뢰(CA) · 수신자</b> 에서 수신자 공개 인증서를 임포트한 뒤, 레포·태그를 골라 <b>패키지 생성·다운로드</b>.
          암호 알고리즘은 AES-256-GCM + RSA-OAEP(FIPS 승인, 배포 OE 의 검증 모듈에 맞게 교체 가능).
        </p>
        <Code>{`# 수신자: 개인키로 복호 → 루트로 서명 검증 → 번들 추출
openssl cms -decrypt -inform DER -in <name>.signed.p7m \\
  -recip recipient.crt -inkey recipient.key -outform DER \\
| openssl cms -verify -inform DER -CAfile trustlink-root.pem \\
  -purpose any -out bundle.zip`}</Code>
      </Section>

      <Section title="발급 · 폐기 (관리자)">
        <p>관리 콘솔 <b>인증서·신뢰(CA)</b> 에서: 리프 발급, 고객 CSR 서명, 폐기, 재발급, 수신자 인증서 임포트, 서명+암호화 패키지. 쓰기는 이중확인.</p>
        <p>CLI 폴백(평면1, TrustLink 무관): <code>step ca certificate …</code> / <code>step ca revoke …</code>.</p>
      </Section>

      <Section title="키 관리 자세 (현재 PoC ↔ 운영 목표)">
        <ul className="list-disc pl-5">
          <li><b>현재(PoC):</b> Root·Issuing 키가 step-ca 볼륨에 상주(at-rest 보호 강화 진행 중). 짧은수명 서명 인증서는 1회용(서명 후 폐기).</li>
          <li><b>운영 목표:</b> Root 키 오프라인 보관, Issuing 키 HSM/FIPS 모듈, 키 at-rest 암호화 + 비밀번호 분리.</li>
        </ul>
      </Section>

      <Glossary items={[
        ['CA (인증기관)', '인증서를 발급·폐기·관리하는 신뢰 주체. 여기서는 step-ca.'],
        ['신뢰 앵커 (Root CA)', '검증의 최상위 기준 인증서. 수신자가 이것만 신뢰하면 하위 서명 전체 검증 가능.'],
        ['Issuing/Intermediate CA', 'Root 아래에서 실제 발급을 수행하는 중간 CA. Root 노출을 줄입니다.'],
        ['CSR', '인증서 서명 요청 — 고객이 자기 개인키로 만든 공개 요청. 서명해주면 개인키 노출 없이 인증서 발급.'],
        ['CMS / .p7s', 'RFC 5652 서명 메시지. .p7s 는 그 서명 파일(여기선 묶음 매니페스트를 서명).'],
        ['CRL', '인증서 폐기 목록(Certificate Revocation List). 검증 시 폐기 여부 확인.'],
        ['provisioner', 'step-ca 에서 발급 권한·정책을 부여하는 단위(여기선 JWK provisioner "trustlink").']
      ]} />
    </>
  );
}
