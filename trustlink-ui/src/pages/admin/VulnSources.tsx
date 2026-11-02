import { useEffect, useState } from 'react';
import { adminVulnSources, adminVulnSourcesSave, adminVulnReanalyze, type VulnSources as VS } from '@/lib/api';
import { Button, Input } from '@/components/ui/primitives';
import { SectionTitle, Alert, Loading } from './_ui';
import { cn } from '@/lib/utils';

// 라이브러리 생태계(앱 SBOM 에 주로 나오는 것). OS 배포판은 컨테이너 이미지 SBOM 을 다룰 때 추가.
const RECOMMENDED = ['npm', 'Maven', 'Packagist', 'PyPI', 'Go', 'NuGet', 'RubyGems', 'crates.io'];
const fmt = (t: string) => new Date(t).toLocaleString('ko-KR');

// 관리 › 설정 › 취약점 DB: Dependency-Track 이 대조할 취약점 출처.
export default function VulnSources() {
  const [vs, setVs] = useState<VS | null>(null);
  const [osv, setOsv] = useState<string[]>([]);
  const [gh, setGh] = useState(false);
  const [token, setToken] = useState('');
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<{ tone: 'ok' | 'warn' | 'crit'; text: string } | null>(null);
  const [err, setErr] = useState('');

  const load = () => adminVulnSources().then((x) => { setVs(x); setOsv(x.osv); setGh(x.github); }).catch((e) => setErr(String(e)));
  useEffect(() => { load(); }, []);

  const toggle = (e: string) => setOsv((cur) => (cur.includes(e) ? cur.filter((x) => x !== e) : [...cur, e]));
  const dirty = vs && (gh !== vs.github || token !== '' || [...osv].sort().join(';') !== [...vs.osv].sort().join(';'));

  const save = async () => {
    setBusy(true); setRes(null);
    try {
      const r = await adminVulnSourcesSave({ osv, github: gh, githubToken: token || undefined });
      setToken('');
      setRes(r.quietUntil
        ? { tone: 'warn', text: `저장했습니다. 새 DB 를 내려받은 뒤 감시 중인 모든 버전을 자동으로 다시 분석합니다(20분·2시간 뒤). 기존 버전에서 새로 잡히는 취약점은 ${fmt(r.quietUntil)}까지 통보하지 않고 기준선으로만 기록합니다.` }
        : { tone: 'ok', text: '저장했습니다.' });
      load();
    } catch (e) {
      setRes({ tone: 'crit', text: `저장 실패: ${String(e).replace(/^Error: /, '')}` });
    }
    setBusy(false);
  };
  const reanalyze = async () => {
    setBusy(true); setRes(null);
    try {
      const r = await adminVulnReanalyze();
      setRes({ tone: 'ok', text: `재분석 요청 ${r.requested}건${r.failed ? `, 실패 ${r.failed}건` : ''}` });
    } catch (e) {
      setRes({ tone: 'crit', text: String(e) });
    }
    setBusy(false);
  };

  return (
    <div className="mb-8">
      <SectionTitle>취약점 DB</SectionTitle>
      <p className="mb-3 text-sm text-muted-foreground">
        Dependency-Track 이 SBOM 의 부품과 대조할 취약점 출처입니다. NVD 는 항상 사용합니다(부품의 CPE 로 대조).
        OSV·GitHub 는 패키지 주소(purl)로 대조해 npm·Composer 같은 라이브러리 취약점을 더 많이, 더 빨리 찾습니다.
      </p>
      {err && <Alert tone="crit">오류: {err}</Alert>}
      {!vs ? (!err && <Loading />) : (
        <div className="space-y-4 rounded-lg border bg-card p-4">
          <div>
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <span className="text-sm font-medium">OSV (Google, 키 불필요)</span>
              <span className="text-xs text-muted-foreground">{osv.length}개 선택</span>
              <Button size="sm" variant="outline" className="ml-auto" onClick={() => setOsv(Array.from(new Set([...osv, ...RECOMMENDED])))}>권장 생태계 선택</Button>
              <Button size="sm" variant="ghost" onClick={() => setOsv([])}>모두 해제</Button>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {[...RECOMMENDED.filter((e) => vs.ecosystems.includes(e)), ...vs.ecosystems.filter((e) => !RECOMMENDED.includes(e))].map((e) => (
                <button key={e} onClick={() => toggle(e)}
                  className={cn('rounded-md border px-2 py-0.5 text-xs', osv.includes(e) ? 'border-primary bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-secondary',
                    RECOMMENDED.includes(e) && !osv.includes(e) && 'border-zinc-400 text-foreground')}>
                  {e}
                </button>
              ))}
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-3 border-t pt-4">
            <label className="flex items-center gap-2 text-sm font-medium">
              <input type="checkbox" checked={gh} onChange={(e) => setGh(e.target.checked)} /> GitHub Advisories
            </label>
            <Input type="password" className="max-w-sm" placeholder={vs.githubTokenSet ? '토큰 등록됨 — 바꿀 때만 입력' : 'GitHub 토큰(공개 저장소 읽기 권한)'}
              value={token} onChange={(e) => setToken(e.target.value)} />
          </div>
          {vs.quietUntil && new Date(vs.quietUntil) > new Date() && (
            <p className="text-xs text-amber-700">통보 보류 중: {fmt(vs.quietUntil)}까지 기존 버전의 새 취약점은 기준선으로만 기록합니다.</p>
          )}
          <div className="flex gap-2 border-t pt-4">
            <Button onClick={save} disabled={busy || !dirty}>{busy ? '처리 중…' : '저장'}</Button>
            <Button variant="outline" onClick={reanalyze} disabled={busy} title="감시 중인 모든 버전을 지금 다시 대조">지금 재분석</Button>
          </div>
        </div>
      )}
      {res && <div className="mt-3"><Alert tone={res.tone}>{res.text}</Alert></div>}
    </div>
  );
}
