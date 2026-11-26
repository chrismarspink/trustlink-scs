import { Download, Monitor, BookOpen } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Card, CardContent, Badge } from '@/components/ui/primitives';

// 진단 도구 — 현장에서 실행해 자료를 수집하는 다운로드형 에이전트 목록.
// 향후 에이전트가 늘어나면 AGENTS 배열에만 추가하면 된다(화면은 그대로).

type Agent = {
  id: string;
  name: string;
  desc: string;
  os: string; // 지원 OS(상세)
  osShort: string; // 배지용 짧은 표기
  repo: string; // GitHub 저장소 URL(Releases 에서 다운로드)
  latestTag: string;
  signed: boolean;
  status: string; // 예: 프리릴리스
  guide: string; // 문서 경로
};

const REPO = 'https://github.com/chrismarspink/trustlink-scs';

const AGENTS: Agent[] = [
  {
    id: 'ismart-collector',
    name: '진단 수집기',
    desc: 'Windows에서 보안SW 충돌(후킹·주입 등) 호환성 문제를 현장에서 수집하는 포터블 도구. 설치 없이 실행하면 진단 번들이 만들어집니다.',
    os: 'Windows 10(1809+)·11·Server 2016/2019/2022/2025, x64',
    osShort: 'Windows x64',
    repo: REPO,
    latestTag: 'collector-v0.1.1',
    signed: false,
    status: '프리릴리스',
    guide: '/docs/collector',
  },
];

export default function Tools() {
  return (
    <div>
      <h1 className="mb-1 text-2xl font-semibold tracking-tight">진단 도구</h1>
      <p className="mb-5 text-sm text-muted-foreground">
        현장에서 실행해 진단 자료를 수집하는 도구입니다. 받은 뒤 실행하면 번들이 생성되어 공통 이슈 번호로 TrustLink에 전달됩니다.
      </p>
      <div className="space-y-4">
        {AGENTS.map((a) => (
          <Card key={a.id}>
            <CardContent className="space-y-3 p-5">
              <div className="flex flex-wrap items-center gap-2">
                <Monitor size={18} className="text-primary" />
                <span className="text-base font-semibold">{a.name}</span>
                <Badge variant="muted">{a.osShort}</Badge>
                {a.signed ? <Badge variant="success">서명됨</Badge> : <Badge variant="outline">미서명 · {a.status}</Badge>}
              </div>
              <p className="text-sm text-muted-foreground">{a.desc}</p>
              <div className="flex flex-wrap gap-2">
                <a
                  className="inline-flex items-center gap-1 rounded-md bg-primary px-3 py-1.5 text-xs font-semibold text-primary-foreground"
                  href={`${a.repo}/releases/latest`}
                  target="_blank"
                  rel="noreferrer"
                >
                  <Download size={13} /> 최신 받기
                </a>
                <a
                  className="inline-flex items-center gap-1 rounded-md border px-3 py-1.5 text-xs"
                  href={`${a.repo}/releases`}
                  target="_blank"
                  rel="noreferrer"
                >
                  전체 버전(구버전)
                </a>
                <Link className="inline-flex items-center gap-1 rounded-md border px-3 py-1.5 text-xs" to={a.guide}>
                  <BookOpen size={13} /> 사용 안내
                </Link>
              </div>
              <p className="text-xs text-muted-foreground">
                지원 OS: {a.os} · 최신 {a.latestTag}
              </p>
            </CardContent>
          </Card>
        ))}
      </div>
      <p className="mt-6 text-xs text-muted-foreground">
        미서명 프리릴리스는 Windows SmartScreen 경고가 뜰 수 있습니다. 받은 파일은 함께 제공되는 <code>.sha256</code>으로 무결성을 확인하세요.
      </p>
    </div>
  );
}
