import { Link } from 'react-router-dom';
import { DocTitle, Section, Code, DocTable, Glossary, Note } from './_shared';

const REPO = 'https://github.com/chrismarspink/trustlink-scs';

// 진단 수집기 사용 안내 문서.
export default function Collector() {
  return (
    <>
      <DocTitle
        title="진단 수집기"
        lead="itShield 같은 보안SW가 제품·도구 실행을 가로채는 호환성 문제를, 현장에서 안전하게 수집·분석하기 위한 Windows 포터블 도구입니다. 설치 없이 실행합니다."
      />

      <Section title="언제 쓰나">
        <ul className="list-disc space-y-1 pl-5">
          <li>제품이 <b>갑자기 실행되지 않거나 중단</b>되는데 원인이 불분명할 때</li>
          <li>보안 에이전트(후킹·주입·EDR)와의 <b>충돌이 의심</b>될 때</li>
          <li>지원·개발에 <b>재현·분석 자료</b>를 정확히 전달해야 할 때</li>
        </ul>
        <p>수집기는 증상만으로는 알 수 없는 <b>메커니즘</b>(주입된 모듈·기동 시 차단·크래시 덤프)을 사실로 모읍니다.</p>
      </Section>

      <Section title="받기">
        <ul className="list-disc space-y-1 pl-5">
          <li>
            <Link className="text-primary underline" to="/tools">진단 도구</Link> 화면에서 받거나, 아래에서 직접:
          </li>
          <li>
            최신 버전 — <a className="text-primary underline" href={`${REPO}/releases/latest`} target="_blank" rel="noreferrer">Releases(최신)</a>
          </li>
          <li>
            모든 버전(구버전 포함) — <a className="text-primary underline" href={`${REPO}/releases`} target="_blank" rel="noreferrer">전체 릴리스</a>
          </li>
        </ul>
        <DocTable
          head={['버전', '파일', '비고']}
          rows={[
            [
              'v0.1.1',
              <a className="text-primary underline" href={`${REPO}/releases/tag/collector-v0.1.1`} target="_blank" rel="noreferrer">ismart-collector-v0.1.1-x64.exe</a>,
              '최신 · 프리릴리스 · 미서명',
            ],
            [
              'v0.1.0',
              <a className="text-primary underline" href={`${REPO}/releases/tag/collector-v0.1.0`} target="_blank" rel="noreferrer">ismart-collector-v0.1.0-x64.exe</a>,
              '이전',
            ],
          ]}
        />
      </Section>

      <Section title="지원 환경">
        <ul className="list-disc space-y-1 pl-5">
          <li>Windows 10(1809+) · 11 · Server 2016/2019/2022/2025, <b>x64</b></li>
          <li>관리자 권한 없이 실행(포터블). 시스템을 변경하지 않습니다(읽기 전용 수집).</li>
        </ul>
      </Section>

      <Section title="무결성 검증 (받은 뒤)">
        <p>함께 올라온 <code>.sha256</code>과 비교해 파일이 변조되지 않았는지 확인합니다.</p>
        <Code>{`# PowerShell
Get-FileHash .\\ismart-collector-v0.1.1-x64.exe -Algorithm SHA256
# 출력 해시가 .sha256 파일 내용과 같아야 합니다`}</Code>
      </Section>

      <Section title="실행">
        <ul className="list-disc space-y-1 pl-5">
          <li><b>더블클릭</b> = 1회 진단 수집 → 번들 생성</li>
          <li>관리자가 발급한 설정(이슈 번호·업로드 토큰)은 실행파일 옆 <code>ismart-collector.conf</code>로 전달됩니다(토큰은 파일에만, 바이너리에 넣지 않음).</li>
          <li>수집 범위는 기본 <b>제품 한정</b>(최소 수집), 필요 시 <code>--scope system</code>으로 전역.</li>
        </ul>
        <Code>{`# 범위 지정 실행
ismart-collector.exe --scope system

# 특정 앱과의 충돌 진단(예: VSCode) — 그 프로세스의 로드/주입 모듈을 정확히 수집
ismart-collector.exe --scope system --target Code.exe`}</Code>
      </Section>

      <Section title="무엇을 수집하나 (전부 읽기 전용·수집 즉시 마스킹)">
        <DocTable
          head={['항목', '내용']}
          rows={[
            ['OS 정보', 'Windows 에디션·빌드·패치'],
            ['보안 SW', '설치 보안SW + 후킹/주입 에이전트 탐지'],
            ['프로세스 모듈', '프로세스별 로드/주입 DLL(후킹 모듈 노출)'],
            ['제품 로그', '이노스마트플랫폼 로그·버전·설정 경로'],
            ['크래시 덤프', 'WER/CrashDumps 경로'],
          ]}
        />
        <Note>비밀번호·토큰·사용자 경로 등 민감정보는 <b>번들에 담기기 전에 가립니다</b>. 수집 전 항목을 고지하고 동의받습니다.</Note>
      </Section>

      <Note tone="warn">
        현재 v0.1.0은 <b>프리릴리스·미서명</b>입니다. 받을 때 Windows SmartScreen 경고가 뜰 수 있습니다(추가 정보 → 실행). 코드서명된 정식 배포본부터는 경고가 사라집니다.
      </Note>

      <Glossary
        items={[
          ['후킹(hooking)', <>다른 프로그램의 동작(함수 호출·기동)을 가로채는 기법. 보안SW가 쓰지만, 충돌 시 대상 프로그램을 중단시키기도 함.</>],
          ['번들', <>수집 결과를 모은 묶음(파일 모음). 공통 이슈 번호로 TrustLink에 전달되어 분석·리포트에 쓰임.</>],
          ['마스킹', <>비밀번호·토큰·개인정보를 <code>***</code> 등으로 가려 노출을 막는 처리.</>],
        ]}
      />
    </>
  );
}
