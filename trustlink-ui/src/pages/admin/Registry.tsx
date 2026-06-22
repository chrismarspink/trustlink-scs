import { useEffect, useState } from 'react';
import { Trash2 } from 'lucide-react';
import { adminRepos, adminRetention, adminDeleteTag, type RepoEntry, type Retention } from '@/lib/api';
import { Button } from '@/components/ui/primitives';
import { PageTitle, SectionTitle, Loading, Alert, Table, Th, Td } from './_ui';

export default function Registry() {
  const [repos, setRepos] = useState<RepoEntry[] | null>(null);
  const [ret, setRet] = useState<Retention | null>(null);
  const [err, setErr] = useState('');

  async function load() {
    setErr('');
    try {
      const [rs, rt] = await Promise.all([adminRepos(), adminRetention()]);
      setRepos(rs);
      setRet(rt);
    } catch (e) {
      setErr(String(e));
    }
  }
  useEffect(() => { load(); }, []);

  async function del(repo: string, tag: string) {
    if (!confirm(`${repo}:${tag} 태그를 삭제할까요?`)) return;
    try {
      await adminDeleteTag(repo, tag);
      await load();
    } catch (e) {
      alert('삭제 실패: ' + e);
    }
  }

  if (err) return (<><PageTitle>레지스트리 관리</PageTitle><Alert tone="crit">오류: {err}</Alert></>);
  if (!repos || !ret) return (<><PageTitle>레지스트리 관리</PageTitle><Loading /></>);

  return (
    <>
      <PageTitle>레지스트리 관리</PageTitle>

      <Alert tone="warn">
        리텐션 dryRun 삭제 예정: <b>{ret.count}</b>건. {ret.note}
      </Alert>
      {ret.candidates.length > 0 && (
        <Table>
          <thead>
            <tr><Th>레포</Th><Th>태그/digest</Th><Th>사유</Th></tr>
          </thead>
          <tbody>
            {ret.candidates.map((c, i) => (
              <tr key={i}>
                <Td className="font-mono">{c.Repository}</Td>
                <Td className="font-mono">{c.Reference}</Td>
                <Td>{c.Reason}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}

      <SectionTitle>레포지토리 / 태그</SectionTitle>
      {repos.length === 0 ? (
        <p className="text-sm text-muted-foreground">레포지토리가 없습니다.</p>
      ) : (
        <Table>
          <thead>
            <tr><Th>레포</Th><Th>태그</Th></tr>
          </thead>
          <tbody>
            {repos.map((r) => (
              <tr key={r.repo}>
                <Td className="font-mono align-top">{r.repo}</Td>
                <Td>
                  <div className="flex flex-wrap gap-2">
                    {r.tags.map((t) => (
                      <Button key={t} size="sm" variant="destructive" onClick={() => del(r.repo, t)}>
                        <Trash2 size={13} /> {t}
                      </Button>
                    ))}
                  </div>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </>
  );
}
