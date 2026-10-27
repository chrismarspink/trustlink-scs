import { useState } from 'react';
import { Copy, Check, KeyRound, X } from 'lucide-react';
import { Button } from '@/components/ui/primitives';
import { Alert } from './_ui';

// 자격 전달 창: 관리자가 담당자에게 넘길 계정·비밀번호와 안내문을 1회 표시한다.
//   kind=user → 개인(Keycloak) 계정 임시 비밀번호 / kind=ci → 공용 업로드 계정
//   kind=robot → 기계 계정(push=업로드 ci-*, pull=다운로드 robot-*) oras 비밀값
export type CredentialInfo = {
  kind: 'user' | 'ci' | 'robot'; username: string; password: string; group?: string;
  robotKind?: 'push' | 'pull'; products?: string[]; expires?: string;
};

// navigator.clipboard 는 보안 컨텍스트(HTTPS/localhost) 전용 → 평문 HTTP 배포에선 execCommand 폴백.
async function copyText(text: string) {
  if (window.isSecureContext && navigator.clipboard) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  document.execCommand('copy');
  document.body.removeChild(ta);
}

function CopyBtn({ text, label = '복사' }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <Button size="sm" variant="outline" onClick={async () => {
      await copyText(text);
      setDone(true); setTimeout(() => setDone(false), 1500);
    }}>
      {done ? <Check size={14} /> : <Copy size={14} />} {done ? '복사됨' : label}
    </Button>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className="w-24 shrink-0 text-sm text-muted-foreground">{label}</span>
      <code className="flex-1 rounded-md border bg-secondary px-3 py-1.5 font-mono text-sm">{value}</code>
      <CopyBtn text={value} />
    </div>
  );
}

function notice(c: CredentialInfo): string {
  const web = window.location.origin;
  const reg = `${window.location.hostname}:28081`;
  if (c.kind === 'ci') {
    return [
      '[TrustLink 업로드(CI) 계정 안내]',
      `레지스트리: ${reg} (oras 명령에 --plain-http 필요)`,
      `계정: ${c.username}`,
      `비밀번호: ${c.password}`,
      '업로드 가능 레포: products/**, innotium/** (삭제 불가)',
      '',
      '사용 예:',
      `  printf '%s' "$TL_PASS" | oras login ${reg} -u ${c.username} --password-stdin --plain-http`,
      '',
      '※ 빌드 서버의 CI 시크릿 변수(TL_USER/TL_PASS)로만 보관하고, 스크립트·문서·메신저에 남기지 마세요.',
    ].join('\n');
  }
  if (c.kind === 'robot') {
    const push = c.robotKind === 'push';
    const ref = `${reg}/${c.products?.[0] || 'products/<제품>'}`;
    return [
      push ? '[TrustLink 업로드용 기계 계정 안내]' : '[TrustLink 자동 다운로드 계정 안내]',
      `레지스트리: ${reg} (oras 명령에 --plain-http 필요)`,
      `계정: ${c.username}`,
      `토큰: ${c.password}`,
      `권한: ${push ? '업로드(쓰기)' : '다운로드(읽기)'} — ${(c.products || []).join(', ') || '(관리자가 제품 권한에서 지정)'}`,
      `만료: ${c.expires ? c.expires.slice(0, 10) : '없음'}`,
      '',
      '사용 예:',
      `  printf '%s' "$TL_PASS" | oras login ${reg} -u ${c.username} --password-stdin --plain-http`,
      push
        ? `  oras push --plain-http ${ref}:<버전> <파일>`
        : `  oras pull --plain-http ${ref}:<버전> -o ./download`,
      '',
      '※ 시스템의 시크릿 변수(TL_USER/TL_PASS)로만 보관하고, 스크립트·문서·메신저에 남기지 마세요.',
    ].join('\n');
  }
  return [
    '[TrustLink 계정 발급 안내]',
    `웹 주소: ${web}`,
    `계정: ${c.username}`,
    `임시 비밀번호: ${c.password}`,
    '※ 첫 로그인 시 비밀번호를 반드시 변경해야 합니다.',
    // oras 는 웹 비밀번호를 받지 않음 → 모든 사람 계정에 API 키 안내(권한은 계정 권한 그대로)
    ...[
      '',
      'oras(명령줄) 업로드·다운로드용 API 키 발급:',
      `  1) ${web} 접속 → 위 계정으로 로그인(비밀번호 변경)`,
      '  2) 왼쪽 메뉴 "내 API 키" → 용도·만료 선택 → 발급(한 번만 표시)',
      `  3) printf '%s' "<API 키>" | oras login ${reg} -u ${c.username} --password-stdin --plain-http`,
    ],
    '',
    '※ 이 안내는 확인 후 삭제하세요.',
  ].join('\n');
}

export default function CredentialDialog({ cred, onClose }: { cred: CredentialInfo; onClose: () => void }) {
  const text = notice(cred);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div className="w-full max-w-xl rounded-lg border bg-card p-5 shadow-lg">
        <div className="mb-4 flex items-center gap-2">
          <KeyRound size={18} className="text-accent" />
          <h2 className="text-base font-semibold">
            {cred.kind === 'ci' ? '업로드(CI) 계정 전달' : cred.kind === 'robot' ? '기계 계정 전달' : '임시 비밀번호 전달'}
          </h2>
          <button className="ml-auto text-muted-foreground hover:text-foreground" onClick={onClose} aria-label="닫기"><X size={18} /></button>
        </div>

        <div className="space-y-2">
          <Field label="계정" value={cred.username} />
          <Field label={cred.kind === 'user' ? '임시 비밀번호' : cred.kind === 'robot' ? '토큰' : '비밀번호'} value={cred.password} />
        </div>

        <div className="mt-4 mb-1 flex items-center justify-between">
          <span className="text-sm font-medium">전달용 안내문</span>
          <CopyBtn text={text} label="안내문 복사" />
        </div>
        <textarea readOnly value={text} rows={cred.kind === 'user' ? 15 : 14}
          className="w-full resize-none rounded-md border bg-secondary p-3 font-mono text-xs" />

        <div className="mt-3">
          <Alert tone="warn">
            {cred.kind === 'ci'
              ? '공용 계정입니다. 메일·메신저 대신 CI 시크릿 변수에 직접 등록하도록 전달하세요. 조회 기록은 감사 로그에 남습니다.'
              : cred.kind === 'robot'
                ? '이 창을 닫으면 토큰을 다시 볼 수 없습니다(필요 시 토큰 재발급 — 기존 토큰은 즉시 무효). 담당 시스템 관리자에게만 전달하세요.'
                : '이 창을 닫으면 비밀번호를 다시 볼 수 없습니다(필요 시 재설정). 본인에게만 전달하세요.'}
          </Alert>
        </div>
        <div className="mt-4 flex justify-end">
          <Button size="sm" onClick={onClose}>확인했습니다</Button>
        </div>
      </div>
    </div>
  );
}
