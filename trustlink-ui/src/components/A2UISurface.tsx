import { useNavigate } from 'react-router-dom';
import { cn } from '@/lib/utils';

// A2UI(v0.9.1) 렌더러 — 기본 카탈로그 중 TrustLink 가 쓰는 부품만 그린다.
// 서버(에이전트)는 "무슨 부품을 어떤 값으로"만 JSON 으로 말하고, 화면은 아래 목록에 있는 부품만 자기 모양으로 그린다.
// 목록에 없는 부품은 그리지 않고, 서버가 보낸 것이 코드로 실행되는 일도 없다(openUrl 은 같은 사이트 경로만 연다).
// 규격: https://a2ui.org/specification/v0.9.1-a2ui/ — createSurface / updateComponents / updateDataModel, 부품은 id 로 잇는 평평한 목록.

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
export type A2Surface = { id: string; comps: Record<string, Json>; data: Json };
export type A2Action = { name: string; surfaceId: string; sourceComponentId: string; timestamp: string; context: Json };

const seg = (p: string) => p.split('/').filter(Boolean);
const getAt = (data: Json, path: string) => seg(path).reduce<any>((o, k) => (o == null ? undefined : o[k]), data); // eslint-disable-line @typescript-eslint/no-explicit-any
function setAt(data: Json, path: string, value: unknown): Json {
  const ks = seg(path);
  if (!ks.length) return (value as Json) ?? {};
  const out: Json = { ...data };
  let cur = out;
  ks.forEach((k, i) => {
    if (i === ks.length - 1) cur[k] = value;
    else { cur[k] = { ...(cur[k] || {}) }; cur = cur[k]; }
  });
  return out;
}

// 서버가 보낸 메시지를 화면 상태에 반영한다. createSurface 가 오면 새로 시작한다.
export function applyA2UI(prev: A2Surface | undefined, msgs: Json[]): A2Surface | undefined {
  let s = prev;
  for (const m of msgs || []) {
    if (m.createSurface) s = { id: m.createSurface.surfaceId, comps: {}, data: {} };
    else if (m.updateComponents && s && m.updateComponents.surfaceId === s.id) {
      const comps: Record<string, Json> = {}; // 이 양식들은 화면 전체를 한 번에 보낸다 — 이전 부품은 버린다
      for (const c of m.updateComponents.components || []) comps[c.id] = c;
      s = { ...s, comps };
    } else if (m.updateDataModel && s && m.updateDataModel.surfaceId === s.id) {
      s = { ...s, data: setAt(s.data, m.updateDataModel.path || '/', m.updateDataModel.value) };
    } else if (m.deleteSurface && s && m.deleteSurface.surfaceId === s.id) s = undefined;
  }
  return s;
}

const TEXT: Record<string, string> = {
  h1: 'text-lg font-bold', h2: 'text-base font-bold', h3: 'text-base font-semibold', h4: 'text-sm font-semibold', h5: 'text-sm font-medium',
  caption: 'text-xs text-muted-foreground', body: 'text-sm leading-relaxed',
};

export function A2UISurface({ surface, onData, onAction, busy }: {
  surface: A2Surface; onData: (path: string, value: unknown) => void; onAction: (a: A2Action) => void; busy?: boolean;
}) {
  const nav = useNavigate();
  const val = (v: unknown) => (v && typeof v === 'object' && 'path' in (v as Json) ? getAt(surface.data, (v as Json).path) : v);
  const kids = (c: Json): string[] => (Array.isArray(c.children) ? c.children : []);

  const render = (id: string, depth = 0): React.ReactNode => {
    const c = surface.comps[id];
    if (!c || depth > 12) return null;
    switch (c.component) {
      case 'Column': return <div key={id} className="flex flex-col gap-2.5">{kids(c).map((k) => render(k, depth + 1))}</div>;
      case 'Row': return <div key={id} className="flex flex-wrap items-center gap-2">{kids(c).map((k) => render(k, depth + 1))}</div>;
      case 'Card': return <div key={id} className="rounded-lg border p-3">{render(c.child, depth + 1)}</div>;
      case 'Divider': return <hr key={id} className="border-border" />;
      case 'Text': return <div key={id} className={cn('whitespace-pre-wrap break-words', TEXT[c.variant || 'body'] || TEXT.body)}>{String(val(c.text) ?? '')}</div>;
      case 'TextField': {
        const v = String(val(c.value) ?? '');
        const set = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => c.value?.path && onData(c.value.path, e.target.value);
        return (
          <label key={id} className="block text-xs font-medium text-muted-foreground">{String(val(c.label) ?? '')}
            {c.variant === 'longText'
              ? <textarea value={v} onChange={set} disabled={busy} rows={4} className="mt-1 w-full rounded-md border bg-background px-2 py-1.5 text-sm font-normal text-foreground outline-none focus:border-primary" />
              : <input value={v} onChange={set} disabled={busy} type={c.variant === 'obscured' ? 'password' : c.variant === 'number' ? 'number' : 'text'} className="mt-1 h-8 w-full rounded-md border bg-background px-2 text-sm font-normal text-foreground outline-none focus:border-primary" />}
          </label>
        );
      }
      case 'CheckBox':
        return (
          <label key={id} className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={!!val(c.value)} disabled={busy} onChange={(e) => c.value?.path && onData(c.value.path, e.target.checked)} /> {String(val(c.label) ?? '')}
          </label>
        );
      case 'ChoicePicker': {
        const cur: string[] = Array.isArray(val(c.value)) ? (val(c.value) as string[]) : [];
        const multi = c.variant === 'multipleSelection';
        const pick = (v: string) => {
          if (!c.value?.path) return;
          onData(c.value.path, multi ? (cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v]) : [v]);
        };
        return (
          <fieldset key={id} className="space-y-1">
            {c.label && <legend className="mb-1 text-xs font-medium text-muted-foreground">{String(val(c.label))}</legend>}
            {(c.options || []).map((o: Json) => (
              <label key={o.value} className={cn('flex cursor-pointer items-start gap-2 rounded-md border px-2 py-1.5 text-[13px]', cur.includes(o.value) && 'border-primary/50 bg-primary/5')}>
                <input type={multi ? 'checkbox' : 'radio'} name={`${surface.id}-${id}`} className="mt-0.5" checked={cur.includes(o.value)} disabled={busy} onChange={() => pick(o.value)} />
                <span className="min-w-0 break-words">{String(val(o.label) ?? o.value)}</span>
              </label>
            ))}
          </fieldset>
        );
      }
      case 'Button': {
        const run = () => {
          const ev = c.action?.event, fn = c.action?.functionCall;
          if (ev) {
            const context: Json = {};
            for (const [k, v] of Object.entries(ev.context || {})) context[k] = val(v);
            onAction({ name: ev.name, surfaceId: surface.id, sourceComponentId: id, timestamp: new Date().toISOString(), context });
          } else if (fn?.call === 'openUrl') {
            const url = String(val(fn.args?.url) ?? '');
            if (!url.startsWith('/') || url.startsWith('//')) return; // 같은 사이트 경로만
            if (url.startsWith('/api/')) window.location.assign(url); // 내려받기
            else nav(url);
          }
        };
        const v = c.variant || 'default';
        return (
          <button key={id} type="button" onClick={run} disabled={busy && !!c.action?.event}
            className={cn('inline-flex items-center rounded-md px-3 py-1.5 text-[13px] font-semibold disabled:opacity-50',
              v === 'primary' ? 'bg-primary text-primary-foreground hover:opacity-90' : v === 'borderless' ? 'px-1.5 font-medium text-primary hover:underline' : 'border hover:bg-secondary')}>
            {render(c.child, depth + 1)}
          </button>
        );
      }
      default: return null; // 허용 목록에 없는 부품은 그리지 않는다
    }
  };
  return <div data-a2ui={surface.id}>{render('root')}</div>;
}
