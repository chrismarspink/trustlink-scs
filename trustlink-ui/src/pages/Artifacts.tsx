import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Package, Search, ShieldCheck, ShieldAlert } from 'lucide-react';
import { searchRepos, type Repo } from '@/lib/api';
import { Card, CardContent, Input, Badge } from '@/components/ui/primitives';
import { fmtBytes } from '@/lib/utils';

export default function Artifacts() {
  const [repos, setRepos] = useState<Repo[]>([]);
  const [q, setQ] = useState('');
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState('');

  const load = (query: string) => {
    setLoading(true);
    searchRepos(query)
      .then(setRepos)
      .catch((e) => setErr(String(e)))
      .finally(() => setLoading(false));
  };
  useEffect(() => load(''), []);

  return (
    <div>
      <h1 className="mb-1 text-2xl font-bold">아티팩트</h1>
      <p className="mb-5 text-sm text-muted-foreground">공급망 산출물(바이너리 + SBOM/VEX/서명) 레지스트리</p>

      <div className="mb-5 flex items-center gap-2">
        <div className="relative flex-1 max-w-md">
          <Search size={16} className="absolute left-3 top-2.5 text-muted-foreground" />
          <Input
            className="pl-9"
            placeholder="제품 검색…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && load(q)}
          />
        </div>
      </div>

      {err && <div className="rounded-md bg-red-100 p-3 text-sm text-red-700">{err}</div>}
      {loading ? (
        <p className="text-muted-foreground">불러오는 중…</p>
      ) : repos.length === 0 ? (
        <p className="text-muted-foreground">레포지토리가 없습니다.</p>
      ) : (
        <div className="grid gap-3 md:grid-cols-2">
          {repos.map((r) => (
            <Link key={r.name} to={`/artifact/${encodeURIComponent(r.name)}/latest`}>
              <Card className="transition hover:border-accent hover:shadow-md">
                <CardContent className="flex items-start gap-3">
                  <Package className="mt-1 text-accent" />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="truncate font-semibold">{r.name}</span>
                      {r.isSigned ? (
                        <ShieldCheck size={16} className="text-emerald-600" />
                      ) : (
                        <ShieldAlert size={16} className="text-red-500" />
                      )}
                    </div>
                    <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                      <span>{fmtBytes(r.size || 0)}</span>
                      {r.vulnerabilities?.Count != null && (
                        <Badge variant={r.vulnerabilities.Count > 0 ? 'warn' : 'success'}>
                          CVE {r.vulnerabilities.Count}
                        </Badge>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
