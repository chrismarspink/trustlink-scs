import { useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Play, Pause, Share2, Table2 } from 'lucide-react';
import { impactMap, type Impact, type ImpactNode } from '@/lib/api';
import { cn } from '@/lib/utils';

// 영향 지도: 취약점 하나가 구성요소 → 출고한 버전 → 고객으로 번지는 모습을 네 줄로 그리고, 시간 순서로 되감아 본다.
// 그림만으로는 정확한 확인이 어려우므로 같은 내용을 표로도 볼 수 있다.

const COLS: ImpactNode['type'][][] = [['vuln'], ['component'], ['version', 'safe'], ['customer']];
const COL_X = [16, 236, 476, 736];
const COL_TITLE = ['취약점', '구성요소', '출고한 버전', '고객'];
const NW = 200, NH = 54, GAP = 14, TOP = 44;

type Tone = 'idle' | 'bad' | 'warn' | 'ok' | 'sent' | 'hidden';
const TONE: Record<Tone, string> = {
  idle: 'border-slate-300 bg-white text-slate-700',
  bad: 'border-red-600 bg-red-50 text-red-900',
  warn: 'border-amber-600 bg-amber-50 text-amber-900',
  ok: 'border-emerald-600 bg-emerald-50 text-emerald-900',
  sent: 'border-violet-600 bg-violet-50 text-violet-900',
  hidden: 'border-slate-200 bg-white text-slate-400 opacity-10',
};
const STROKE: Record<Tone, string> = { idle: '#a1a1aa', bad: '#dc2626', warn: '#d97706', ok: '#059669', sent: '#7c3aed', hidden: '#e4e4e7' };

// 그 단계에서 이 상자가 어떤 색인가
function toneOf(n: ImpactNode, step: string): Tone {
  const at = ['shipped', 'found', 'judged', 'notified'].indexOf(step);
  if (n.type === 'vuln') return at >= 1 ? 'bad' : 'hidden';
  if (n.type === 'safe') return at >= 2 ? 'ok' : 'hidden';
  if (n.type === 'component') return at >= 1 ? 'bad' : 'idle';
  if (n.type === 'version') {
    if (at < 1) return 'idle';
    if (at < 2) return 'bad';
    return n.state === 'affected' ? 'bad' : n.state === 'not_affected' ? 'ok' : 'warn';
  }
  if (at < 1) return 'idle';
  if (at >= 3 && n.state === 'notified') return 'sent';
  return 'bad';
}

export default function ImpactMapPage() {
  const [sp, setSp] = useSearchParams();
  const vuln = (sp.get('vuln') || '').toUpperCase();
  const [q, setQ] = useState(vuln);
  const [d, setD] = useState<Impact | null>(null);
  const [err, setErr] = useState('');
  const [step, setStep] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [table, setTable] = useState(false);

  useEffect(() => {
    setD(null); setErr(''); setStep(0); setQ(vuln);
    if (!vuln) return;
    let alive = true;
    impactMap(vuln).then((r) => { if (alive) { setD(r); setStep(Math.min(1, r.steps.length - 1)); } }).catch((e) => alive && setErr(String(e).replace(/^(Api)?Error:\s*(\d{3}\s*)?/, '')));
    return () => { alive = false; };
  }, [vuln]);
  const steps = d?.steps || [];
  useEffect(() => {
    if (!playing || !steps.length) return;
    const t = setTimeout(() => { if (step >= steps.length - 1) setPlaying(false); else setStep(step + 1); }, 2200);
    return () => clearTimeout(t);
  }, [playing, step, steps.length]);

  const layout = useMemo(() => {
    const pos: Record<string, { x: number; y: number }> = {};
    let rows = 1;
    COLS.forEach((types, c) => {
      const ns = (d?.nodes || []).filter((n) => types.includes(n.type));
      rows = Math.max(rows, ns.length);
      ns.forEach((n, i) => { pos[n.id] = { x: COL_X[c], y: TOP + i * (NH + GAP) }; });
    });
    // 줄 수가 적은 열은 가운데로
    const h = TOP + rows * (NH + GAP) + 10;
    COLS.forEach((types) => {
      const ns = (d?.nodes || []).filter((n) => types.includes(n.type));
      const off = ((rows - ns.length) * (NH + GAP)) / 2;
      ns.forEach((n) => { pos[n.id].y += off; });
    });
    return { pos, h };
  }, [d]);

  const key = steps[step]?.key || 'shipped';
  const tone = (id: string): Tone => { const n = d?.nodes.find((x) => x.id === id); return n ? toneOf(n, key) : 'hidden'; };
  const go = (e: React.FormEvent) => { e.preventDefault(); if (q.trim()) setSp({ vuln: q.trim().toUpperCase() }); };

  return (
    <div className="mx-auto max-w-6xl">
      <div className="mb-4 flex flex-wrap items-end gap-3">
        <div className="flex-1">
          <h1 className="flex items-center gap-2 text-2xl font-bold"><Share2 size={22} /> 영향 지도</h1>
          <p className="mt-1 text-sm text-muted-foreground">취약점 하나가 구성요소, 출고한 버전, 고객으로 번지는 모습을 시간 순서로 봅니다.</p>
        </div>
        <form onSubmit={go} className="flex items-center gap-2">
          <label htmlFor="impact-q" className="sr-only">취약점 번호</label>
          <input id="impact-q" value={q} onChange={(e) => setQ(e.target.value)} placeholder="CVE-2026-…" className="h-9 w-56 rounded-md border bg-background px-3 text-sm outline-none focus:border-primary" />
          <button type="submit" className="h-9 rounded-md bg-primary px-4 text-sm font-semibold text-primary-foreground">보기</button>
        </form>
      </div>

      {err && <div className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700">{err}</div>}
      {!vuln && <div className="rounded-lg border border-dashed p-10 text-center text-sm text-muted-foreground">취약점 번호를 넣으면 지도를 그립니다. 묻고 찾기에서 취약점을 물은 뒤 "영향 지도 보기"로도 올 수 있습니다.</div>}
      {vuln && !d && !err && <div className="p-10 text-center text-sm text-muted-foreground">지도를 그리는 중…</div>}
      {d?.empty && <div className="rounded-lg border border-dashed p-10 text-center text-sm text-muted-foreground">{d.empty}</div>}

      {d && !d.empty && (
        <>
          <div className="mb-3 flex flex-wrap items-center gap-2 rounded-lg border bg-card p-2.5">
            <button type="button" onClick={() => { if (step >= steps.length - 1) setStep(0); setPlaying(!playing); }} className="inline-flex h-9 items-center gap-1.5 rounded-md border px-3 text-sm font-semibold hover:bg-secondary">
              {playing ? <Pause size={14} /> : <Play size={14} />} {playing ? '멈춤' : '처음부터 재생'}
            </button>
            {steps.map((s, i) => (
              <button key={s.key} type="button" aria-pressed={i === step} onClick={() => { setPlaying(false); setStep(i); }}
                className={cn('h-9 flex-1 rounded-md border px-3 text-sm font-semibold', i === step ? 'border-primary bg-primary text-primary-foreground' : 'hover:bg-secondary')}>
                {i + 1}. {s.label}{s.at ? ` · ${s.at}` : ''}
              </button>
            ))}
            <button type="button" aria-pressed={table} onClick={() => setTable(!table)} className={cn('inline-flex h-9 items-center gap-1.5 rounded-md border px-3 text-sm hover:bg-secondary', table && 'bg-secondary')}><Table2 size={14} /> 표로 보기</button>
          </div>
          <p className="mb-3 rounded-md bg-secondary/60 px-3 py-2 text-sm" aria-live="polite">{steps[step]?.text}</p>

          {!table ? (
            <div className="overflow-x-auto rounded-lg border bg-card">
              <div className="relative" style={{ width: 952, height: layout.h }}>
                {COL_TITLE.map((t, c) => (d.canCustomers || c < 3) && <div key={t} className="absolute top-3 text-xs font-semibold text-muted-foreground" style={{ left: COL_X[c], width: NW, textAlign: 'center' }}>{t}</div>)}
                <svg width={952} height={layout.h} className="absolute left-0 top-0" aria-hidden="true">
                  {d.edges.map((e, i) => {
                    const a = layout.pos[e.from], b = layout.pos[e.to];
                    if (!a || !b) return null;
                    const ta = tone(e.from), tb = tone(e.to);
                    const hide = ta === 'hidden' || tb === 'hidden';
                    const x1 = a.x + NW, y1 = a.y + NH / 2, x2 = b.x, y2 = b.y + NH / 2, mx = (x1 + x2) / 2;
                    return <path key={i} d={`M${x1} ${y1} C${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`} fill="none" stroke={STROKE[hide ? 'hidden' : tb]} strokeWidth={tb === 'idle' || hide ? 1.5 : 2.5} strokeOpacity={hide ? 0.25 : 0.9} style={{ transition: 'stroke .5s, stroke-opacity .5s' }} />;
                  })}
                </svg>
                {d.nodes.map((n) => {
                  const p = layout.pos[n.id];
                  if (!p) return null;
                  const t = toneOf(n, key);
                  const body = (<><span className="block truncate text-[13px] font-semibold">{n.label}</span><span className="block truncate text-xs opacity-80">{n.sub}</span></>);
                  const cls = cn('absolute rounded-lg border-2 px-2.5 py-1.5 text-left transition-all duration-500', TONE[t], n.link && t !== 'hidden' && 'hover:shadow-md');
                  const style = { left: p.x, top: p.y, width: NW, height: NH };
                  return n.link && t !== 'hidden'
                    ? <Link key={n.id} to={n.link} className={cls} style={style} title={`${n.label} — ${n.sub || ''}`}>{body}</Link>
                    : <div key={n.id} className={cls} style={style} aria-hidden={t === 'hidden'}>{body}</div>;
                })}
              </div>
            </div>
          ) : (
            <div className="overflow-x-auto rounded-lg border bg-card">
              <table className="w-full min-w-[560px] text-sm">
                <thead><tr className="text-left text-xs text-muted-foreground"><th className="px-3 py-2">종류</th><th className="px-3 py-2">이름</th><th className="px-3 py-2">상태</th></tr></thead>
                <tbody>
                  {d.nodes.filter((n) => n.type !== 'vuln').map((n) => (
                    <tr key={n.id} className="border-t">
                      <td className="px-3 py-2 text-muted-foreground">{{ component: '구성요소', version: '영향 버전', safe: '이 취약점이 없는 버전', customer: '고객', vuln: '' }[n.type]}</td>
                      <td className="px-3 py-2 font-medium">{n.link ? <Link to={n.link} className="text-primary hover:underline">{n.label}</Link> : n.label}</td>
                      <td className="px-3 py-2">{n.sub}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
            {([['bad', '영향 있음·발견'], ['warn', '판단 대기'], ['ok', '안전(영향 없음·이 취약점 없는 버전)'], ['sent', '통지 보냄']] as const).map(([t, l]) => (
              <span key={t} className="inline-flex items-center gap-1.5"><span className={cn('h-3 w-3 rounded border-2', TONE[t])} />{l}</span>
            ))}
            {!!d.more && <span>버전이 많아 {d.more}개는 그리지 않았습니다.</span>}
            {!d.canCustomers && <span>고객은 관리자에게만 보입니다.</span>}
          </div>
        </>
      )}
    </div>
  );
}
