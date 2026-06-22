import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ShieldCheck, LogOut } from 'lucide-react';
import { Button } from '@/components/ui/primitives';
import { getSession, logout, type Session } from '@/lib/api';

// 제품/관리 공용 상단바 — 브랜드 + 사용자 + 로그아웃. 내비게이션은 Sidebar 가 담당.
export function AppHeader() {
  const [sess, setSess] = useState<Session | null>(null);

  useEffect(() => {
    getSession().then(setSess).catch(() => setSess(null));
  }, []);

  return (
    <header className="bg-primary text-primary-foreground">
      <div className="flex h-14 items-center gap-2 px-6">
        <Link to="/" className="flex select-none items-center gap-2 text-lg font-extrabold">
          <ShieldCheck className="text-accent" /> TrustLink SCS
        </Link>
        <div className="flex-1" />
        {sess?.username && (
          <span className="hidden text-xs text-primary-foreground/70 sm:block">
            {sess.username}{sess.groups?.length ? ` (${sess.groups.join(', ')})` : ''}
          </span>
        )}
        <Button
          variant="ghost"
          size="sm"
          className="ml-1 text-primary-foreground hover:bg-white/10"
          onClick={() => logout()}
        >
          <LogOut size={16} /> 로그아웃
        </Button>
      </div>
    </header>
  );
}
