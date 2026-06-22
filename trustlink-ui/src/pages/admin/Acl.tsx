import { useEffect, useState } from 'react';
import { adminACL, type ACL, type ACLPolicy } from '@/lib/api';
import { Badge } from '@/components/ui/primitives';
import { PageTitle, Loading, Alert, Table, Th, Td } from './_ui';

function who(p: ACLPolicy): string {
  return [...(p.groups || []).map((g) => '그룹:' + g), ...(p.users || []).map((u) => '유저:' + u)].join(', ');
}

function Actions({ actions }: { actions?: string[] }) {
  return (
    <div className="flex flex-wrap gap-1">
      {(actions || []).map((a) => <Badge key={a} variant="muted">{a}</Badge>)}
    </div>
  );
}

export default function Acl() {
  const [acl, setAcl] = useState<ACL | null>(null);
  const [err, setErr] = useState('');

  useEffect(() => {
    adminACL().then(setAcl).catch((e) => setErr(String(e)));
  }, []);

  if (err) return (<><PageTitle>권한 매트릭스</PageTitle><Alert tone="crit">오류: {err}</Alert></>);
  if (!acl) return (<><PageTitle>권한 매트릭스</PageTitle><Loading /></>);
  if (acl.error) return (<><PageTitle>권한 매트릭스</PageTitle><Alert tone="warn">{acl.error}</Alert></>);

  const repos = acl.accessControl?.repositories || {};
  const adminPolicy = acl.accessControl?.adminPolicy;

  return (
    <>
      <PageTitle>권한 매트릭스</PageTitle>
      <Table>
        <thead>
          <tr><Th>경로</Th><Th>대상</Th><Th>권한</Th></tr>
        </thead>
        <tbody>
          {Object.entries(repos).flatMap(([pat, def]) => {
            const policies = def.policies || [];
            if (policies.length === 0) {
              return [
                <tr key={pat}>
                  <Td className="font-mono">{pat}</Td>
                  <Td className="text-muted-foreground">기본 차단</Td>
                  <Td>-</Td>
                </tr>
              ];
            }
            return policies.map((p, i) => (
              <tr key={`${pat}-${i}`}>
                <Td className="font-mono">{pat}</Td>
                <Td>{who(p)}</Td>
                <Td><Actions actions={p.actions} /></Td>
              </tr>
            ));
          })}
          {adminPolicy && (
            <tr>
              <Td className="font-mono">(adminPolicy)</Td>
              <Td>{who(adminPolicy)}</Td>
              <Td><Actions actions={adminPolicy.actions} /></Td>
            </tr>
          )}
        </tbody>
      </Table>
    </>
  );
}
