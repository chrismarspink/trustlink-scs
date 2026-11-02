import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Bell } from 'lucide-react';
import { getNotifications, markNotificationsRead, type NoticeItem } from '@/lib/api';
import { cn } from '@/lib/utils';

// 상단바 통보 종: 안 읽은 수 + 최근 목록. 항목을 누르면 읽음 처리 후 해당 제품 버전으로 이동.
export function NotificationBell() {
  const [data, setData] = useState<{ items: NoticeItem[]; unread: number } | null>(null);
  const [open, setOpen] = useState(false);
  const [sel, setSel] = useState<NoticeItem | null>(null);
  const nav = useNavigate();

  const load = () => getNotifications().then(setData).catch(() => setData(null));
  useEffect(() => {
    load();
    const t = setInterval(load, 60_000);
    return () => clearInterval(t);
  }, []);
  if (!data) return null;

  const openItem = async (n: NoticeItem) => {
    setSel(n);
    if (!n.read) { await markNotificationsRead(n.id); load(); }
  };

  return (
    <div className="relative ml-auto">
      <button onClick={() => { setOpen((o) => !o); setSel(null); }} title="통보"
        className="relative rounded-md p-2 text-muted-foreground hover:bg-secondary hover:text-foreground">
        <Bell size={17} />
        {data.unread > 0 && (
          <span className="absolute right-1 top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-red-500 px-1 text-[10px] font-semibold text-white">
            {data.unread > 99 ? '99+' : data.unread}
          </span>
        )}
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} />
          <div className="absolute right-0 z-20 mt-1 w-[26rem] rounded-lg border bg-card text-foreground shadow-lg">
            <div className="flex items-center border-b px-4 py-2.5 text-sm font-medium">
              통보
              {data.unread > 0 && (
                <button onClick={async () => { await markNotificationsRead(); load(); }} className="ml-auto text-xs font-normal text-muted-foreground hover:text-foreground">
                  모두 읽음
                </button>
              )}
            </div>
            {sel ? (
              <div className="p-4 text-sm">
                <button onClick={() => setSel(null)} className="mb-2 text-xs text-muted-foreground hover:text-foreground">← 목록</button>
                <div className="mb-2 font-medium">{sel.title.replace(/^\[TrustLink\] /, '')}</div>
                <pre className="max-h-72 overflow-auto whitespace-pre-wrap font-sans text-xs leading-relaxed text-muted-foreground">{sel.body}</pre>
                <button onClick={() => { setOpen(false); nav(`/artifact/${encodeURIComponent(sel.repo)}/${encodeURIComponent(sel.tag)}`); }}
                  className="mt-3 text-xs font-medium underline underline-offset-4">제품 버전 열기</button>
              </div>
            ) : data.items.length === 0 ? (
              <p className="p-6 text-center text-sm text-muted-foreground">받은 통보가 없습니다.</p>
            ) : (
              <div className="max-h-96 divide-y overflow-auto">
                {data.items.map((n) => (
                  <button key={n.id} onClick={() => openItem(n)} className="flex w-full gap-2.5 px-4 py-2.5 text-left hover:bg-secondary">
                    <span className={cn('mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full', n.read ? 'bg-transparent' : 'bg-red-500')} />
                    <span className="min-w-0">
                      <span className={cn('block truncate text-sm', !n.read && 'font-medium')}>{n.title.replace(/^\[TrustLink\] /, '')}</span>
                      <span className="text-xs text-muted-foreground">{new Date(n.time).toLocaleString('ko-KR')}</span>
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
