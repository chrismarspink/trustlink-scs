import { useEffect, useState } from 'react';
import { Busy } from '@/components/Progress';
import {
  adminMirror, adminMirrorPolicy, adminMirrorSync, adminMirrorDT,
  type MirrorInfo, type MirrorPolicy, type MirrorSource
} from '@/lib/api';
import { Button, Input, Badge, StatusDot } from '@/components/ui/primitives';
import { PageHeader, SectionTitle, StatCard, Alert, Loading, Table, Th, Td, selectCls } from './_ui';
import { cn } from '@/lib/utils';

// 시스템 › 취약점 DB 미러: 어떤 DB 를, 어느 주기로, 언제 외부에 접속해 받는지(정책)와 로컬 기준 시점을 보여 준다.

const KST = { timeZone: 'Asia/Seoul' } as const;
const fmt = (t?: string) => (t ? new Date(t).toLocaleString('ko-KR', { ...KST, month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—');
const size = (n: number) => {
  if (n < 0) return '?';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let f = n;
  while (f >= 1024 && i < u.length - 1) { f /= 1024; i++; }
  return `${f.toFixed(f >= 100 || i === 0 ? 0 : 1)}${u[i]}`;
};
const ago = (t?: string) => {
  if (!t) return '';
  const h = (Date.now() - new Date(t).getTime()) / 3600e3;
  if (h < 1) return `${Math.max(1, Math.round(h * 60))}분 전`;
  if (h < 48) return `${Math.round(h)}시간 전`;
  return `${Math.round(h / 24)}일 전`;
};
const PERIODS = [
  { h: 24, label: '매일' },
  { h: 168, label: '매주' },
  { h: 720, label: '매월' }
];
const periodLabel = (h: number) => PERIODS.find((p) => p.h === h)?.label ?? `${h}시간`;
const GROUP_NOTE: Record<string, string> = {
  '1차': '분석에 직접 쓰는 DB',
  '2차': '판정·보고 보강',
  '스캐너': '폐쇄망에서 Grype·Trivy 를 그대로 돌리기 위한 완성본'
};

function statusOf(s: MirrorSource, running?: string) {
  if (running === s.id) return <StatusDot tone="warn">받는 중</StatusDot>;
  if (!s.enabled) return <StatusDot tone="off">꺼짐</StatusDot>;
  if (s.status === 'error') return <span title={s.error}><StatusDot tone="crit">실패</StatusDot></span>;
  if (s.status === 'never') return <StatusDot tone="off">아직 없음</StatusDot>;
  if (s.stale) return <StatusDot tone="warn">오래됨</StatusDot>;
  return <StatusDot tone="ok">최신</StatusDot>;
}

// 하루(KST 0~24시) 막대: 접속 창 음영 + 지금 위치
function DayBar({ p, now }: { p: MirrorPolicy; now: string }) {
  const toMin = (s: string) => { const [h, m] = s.split(':').map(Number); return h * 60 + m; };
  const s = toMin(p.windowStart);
  const e = toMin(p.windowEnd);
  const k = new Date(new Date(now).toLocaleString('en-US', KST));
  const cur = k.getHours() * 60 + k.getMinutes();
  const pct = (m: number) => `${(m / 1440) * 100}%`;
  const spans = s === e ? [[0, 1440]] : s < e ? [[s, e]] : [[s, 1440], [0, e]];
  return (
    <div className="mt-3">
      <div className="relative h-6 rounded bg-secondary">
        {p.mode === 'scheduled' && spans.map(([a, b]) => (
          <div key={a} className="absolute inset-y-0 rounded bg-sky-200" style={{ left: pct(a), width: pct(b - a) }} />
        ))}
        <div className="absolute inset-y-[-3px] w-0.5 bg-foreground" style={{ left: pct(cur) }} title="지금" />
      </div>
      <div className="mt-1 flex justify-between text-[11px] text-muted-foreground tabular-nums">
        {[0, 6, 12, 18, 24].map((h) => <span key={h}>{h}시</span>)}
      </div>
      <div className="mt-1 flex gap-4 text-xs text-muted-foreground">
        <span className="inline-flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-sm bg-sky-200" />외부 접속 허용 시간</span>
        <span className="inline-flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-sm bg-secondary ring-1 ring-border" />로컬만 사용</span>
        <span className="inline-flex items-center gap-1.5"><span className="h-2.5 w-0.5 bg-foreground" />지금(KST)</span>
      </div>
    </div>
  );
}

export default function Mirror() {
  const [info, setInfo] = useState<MirrorInfo | null>(null);
  const [err, setErr] = useState('');
  const [draft, setDraft] = useState<MirrorPolicy | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ tone: 'ok' | 'warn' | 'crit'; text: string } | null>(null);

  const load = () => adminMirror().then((x) => { setInfo(x); setErr(''); }).catch((e) => setErr(String(e)));
  useEffect(() => { load(); }, []);
  const st = info?.status;
  useEffect(() => {
    const t = setInterval(load, st?.running ? 5000 : 30000);
    return () => clearInterval(t);
  }, [st?.running]);
  useEffect(() => { if (st && !draft) setDraft(structuredClone(st.policy)); }, [st, draft]);

  const act = async (f: () => Promise<unknown>, ok: string) => {
    setBusy(true); setMsg(null);
    try { await f(); setMsg({ tone: 'ok', text: ok }); await load(); } catch (e) { setMsg({ tone: 'crit', text: String(e).replace(/^Error: /, '') }); }
    setBusy(false);
  };

  const head = (
    <PageHeader
      title="취약점 DB 미러"
      description="공개 취약점·악용·위협·라이선스 DB 를 내부에 복제해 두고, 분석은 로컬 사본으로만 합니다. 외부 접속은 정해진 시간에 미러만 합니다."
      actions={st && (
        <Button onClick={() => act(() => adminMirrorSync('all'), '켜 둔 DB 전체 받기를 시작했습니다.')}
          disabled={busy || !!st.running || st.policy.mode === 'offline'}
          title={st.policy.mode === 'offline' ? '폐쇄망 모드에서는 외부 접속을 하지 않습니다' : '접속 창과 상관없이 지금 받기(원장에 기록)'}>
          지금 전체 받기
        </Button>
      )}
    />
  );
  if (err) return (<>{head}<Alert tone="crit">오류: {err}</Alert></>);
  if (!info) return (<>{head}<Loading /></>);
  if (!info.installed) return (<>{head}<Alert tone="warn">미러 서비스(vuln-mirror)가 설치되어 있지 않습니다. docker-compose 의 vuln-mirror 서비스와 BFF 의 MIRROR_URL 을 설정하세요.</Alert></>);
  if (!info.reachable || !st || !draft) return (<>{head}<Alert tone="crit">{info.error || '미러 응답 없음'}</Alert></>);

  const p = st.policy;
  const enabled = st.sources.filter((s) => s.enabled);
  const dirty = JSON.stringify(draft) !== JSON.stringify(p);
  const nextAny = enabled.map((s) => s.nextAccess).filter(Boolean).sort()[0];
  const oldest = enabled.map((s) => s.localAsOf).filter(Boolean).sort()[0];
  const setSrc = (id: string, v: Partial<{ enabled: boolean; intervalH: number }>) =>
    setDraft({ ...draft, sources: { ...draft.sources, [id]: { ...draft.sources[id], ...v } } });
  const groups = Array.from(new Set(st.sources.map((s) => s.group)));
  const run = st.running ? st.sources.find((s) => s.id === st.running) : undefined;
  const queued = st.sources.filter((s) => s.status === 'running' && s.id !== st.running).length;

  return (
    <>
      {head}
      {run && <Busy className="mb-4" active since={run.lastAttempt} label={`${run.name} 받는 중`}
        hint={`${queued ? `대기 ${queued}종 · ` : ''}바뀐 파일만 받습니다 — 큰 DB(OSV·NVD 등)는 수 분~수십 분`} />}

      {/* 지금 상태: 로컬/외부 접속 경계 */}
      <div className="mb-6 rounded-lg border bg-card p-4">
        <div className="flex flex-wrap items-center gap-2">
          {p.mode === 'offline'
            ? <Badge variant="muted">폐쇄망 모드</Badge>
            : <Badge variant={st.inWindow ? 'warn' : 'success'}>{st.inWindow ? '접속 창 열림' : '로컬만 사용 중'}</Badge>}
          <span className="text-sm">
            {p.mode === 'offline'
              ? '외부 접속을 하지 않습니다. 모든 분석은 아래 "로컬 기준 시점"의 사본으로만 합니다.'
              : <>매일 <b>{p.windowStart}–{p.windowEnd}</b>(KST)에만 {p.upstream ? <>상위 미러 <code className="text-xs">{p.upstream}</code></> : '원본 사이트'}에 접속하고, 그 밖의 시간에는 로컬 사본만 씁니다.
                {!st.inWindow && nextAny && <> 다음 외부 접속: <b>{fmt(nextAny)}</b>.</>}</>}
          </span>
        </div>
        <DayBar p={p} now={st.now} />
        <ul className="mt-3 list-disc space-y-0.5 pl-5 text-xs text-muted-foreground">
          <li>외부에 접속하는 것은 미러 컨테이너 하나뿐입니다. Dependency-Track·TrustLink 는 미러 사본만 읽습니다(아래 "분석 엔진 연결"로 전환).</li>
          <li>DB 마다 주기(매일·매주·매월)가 지나면 다음 접속 창에서 받습니다. 원본이 그대로면(ETag·Last-Modified) 다시 받지 않습니다.</li>
          <li>로컬 기준 시점 = 그 DB 가 원본과 마지막으로 일치한 시각입니다. 주기의 2배+1일이 지나도 갱신되지 않으면 "오래됨"으로 표시합니다.</li>
          <li>디스크 여유가 {p.minFreeGB}GB 아래로 내려가면 받지 않습니다(같은 디스크의 기존 서비스 보호).</li>
          <li>받은 파일마다 SHA-256 을 남기고, 전체를 하나의 스냅샷 ID 로 묶습니다. 판정 당시 어떤 DB 를 썼는지 증명하는 근거입니다.</li>
        </ul>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="미러 DB" value={<>{enabled.length}<span className="text-base text-muted-foreground"> / {st.sources.length}종</span></>} />
        <StatCard label="로컬 사본" value={<>{size(st.totalBytes)}<span className="text-base text-muted-foreground"> · {st.fileCount}파일</span></>} />
        <StatCard label="디스크 여유" value={<>{size(st.diskFree)}<span className="text-base text-muted-foreground"> / {size(st.diskTotal)}</span></>} />
        <StatCard label="스냅샷 ID" value={<span className="font-mono text-base" title={st.snapshot}>{st.snapshot.slice(0, 12)}</span>} />
      </div>
      {oldest && <p className="mt-2 text-xs text-muted-foreground">가장 오래된 로컬 기준 시점: {fmt(oldest)} ({ago(oldest)})</p>}

      <SectionTitle>접속 정책</SectionTitle>
      <div className="flex flex-wrap items-end gap-4 rounded-lg border bg-card p-4">
        <label className="text-sm">
          <div className="mb-1 text-xs text-muted-foreground">모드</div>
          <select className={selectCls} value={draft.mode} onChange={(e) => setDraft({ ...draft, mode: e.target.value as MirrorPolicy['mode'] })}>
            <option value="scheduled">정기 접속</option>
            <option value="offline">폐쇄망(외부 접속 없음)</option>
          </select>
        </label>
        <label className="text-sm">
          <div className="mb-1 text-xs text-muted-foreground">접속 창 시작(KST)</div>
          <Input type="time" className="w-32" value={draft.windowStart} onChange={(e) => setDraft({ ...draft, windowStart: e.target.value })} />
        </label>
        <label className="text-sm">
          <div className="mb-1 text-xs text-muted-foreground">접속 창 끝(KST)</div>
          <Input type="time" className="w-32" value={draft.windowEnd} onChange={(e) => setDraft({ ...draft, windowEnd: e.target.value })} />
        </label>
        <label className="text-sm">
          <div className="mb-1 text-xs text-muted-foreground">최소 디스크 여유(GB)</div>
          <Input type="number" min={5} className="w-24" value={draft.minFreeGB} onChange={(e) => setDraft({ ...draft, minFreeGB: Number(e.target.value) })} />
        </label>
        <label className="min-w-[16rem] flex-1 text-sm">
          <div className="mb-1 text-xs text-muted-foreground">상위 미러(비우면 원본 사이트) — 폐쇄망은 DMZ 미러를 지정</div>
          <Input placeholder="http://dmz-mirror:8090" value={draft.upstream} onChange={(e) => setDraft({ ...draft, upstream: e.target.value.trim() })} />
        </label>
        {draft.upstream && (
          <>
            <label className="min-w-[16rem] flex-1 text-sm">
              <div className="mb-1 text-xs text-muted-foreground">허브 공개키(넣으면 서명·해시가 맞는 파일만 받음)</div>
              <Input placeholder="허브에서 `mirror pubkey` 로 확인한 값" value={draft.upstreamPubKey || ''} onChange={(e) => setDraft({ ...draft, upstreamPubKey: e.target.value.trim() })} />
            </label>
            <label className="min-w-[14rem] flex-1 text-sm">
              <div className="mb-1 text-xs text-muted-foreground">구독 키{p.upstreamKeySet ? ' — 저장됨(바꿀 때만 입력)' : ''}</div>
              <Input type="password" autoComplete="off" placeholder={p.upstreamKeySet ? '••••••••' : '허브가 발급한 키(tlsub_…)'} value={draft.upstreamKey || ''} onChange={(e) => setDraft({ ...draft, upstreamKey: e.target.value.trim() })} />
            </label>
          </>
        )}
        <div className="flex gap-2">
          <Button onClick={() => act(() => adminMirrorPolicy(draft).then((x) => setDraft(structuredClone(x.policy))), '정책을 저장했습니다(원장 기록).')} disabled={busy || !dirty}>저장</Button>
          <Button variant="ghost" onClick={() => setDraft(structuredClone(p))} disabled={busy || !dirty}>되돌리기</Button>
        </div>
      </div>
      {msg && <div className="mt-3"><Alert tone={msg.tone}>{msg.text}</Alert></div>}
      {p.upstream && (
        <p className="mt-3 text-xs text-muted-foreground">
          {st.upstreamVerified
            ? <>마지막으로 서명을 확인해 받아들인 허브 스냅샷: <code>{st.upstreamVerified.snapshot.slice(0, 12)}</code> · {fmt(st.upstreamVerified.generated)} · 허브 키 <code>{st.upstreamVerified.keyId}</code>{st.upstreamVerified.via === 'import' ? ' · 번들로 들여옴' : ''}</>
            : p.upstreamPubKey ? '허브 공개키가 설정됐습니다. 다음 접속부터 서명을 확인합니다.' : '허브 공개키가 없어 상위 미러의 내용을 검증하지 않고 받습니다.'}
        </p>
      )}
      {st.hub && (
        <div className="mt-3 rounded-lg border bg-card p-3 text-sm">
          <b>이 미러는 피드 허브입니다.</b> 받는 쪽에 넣을 공개키: <code className="break-all text-xs">{st.hub.pubKey}</code> (키 ID <code className="text-xs">{st.hub.keyId}</code>)
          {st.hub.subscribers && <div className="mt-1 text-xs text-muted-foreground">구독자 {st.hub.subscribers.length}곳{st.hub.subscribers.length > 0 && <>: {st.hub.subscribers.map((x) => `${x.name}${x.lastSeen ? ` (마지막 접속 ${fmt(x.lastSeen)})` : ' (접속 기록 없음)'}`).join(', ')}</>}</div>}
        </div>
      )}

      <SectionTitle>미러 대상과 로컬 기준 시점</SectionTitle>
      {groups.map((g) => (
        <div key={g} className="mb-5">
          <div className="mb-2 text-sm font-medium">{g} <span className="font-normal text-muted-foreground">— {GROUP_NOTE[g] ?? ''}</span></div>
          <Table>
            <thead>
              <tr>
                <Th className="w-8" />
                <Th>DB</Th>
                <Th>쓰임</Th>
                <Th>주기</Th>
                <Th>로컬 기준 시점</Th>
                <Th>다음 외부 접속</Th>
                <Th className="text-right">크기</Th>
                <Th>상태</Th>
                <Th />
              </tr>
            </thead>
            <tbody>
              {st.sources.filter((s) => s.group === g).map((s) => {
                const d = draft.sources[s.id] ?? { enabled: s.enabled, intervalH: s.intervalH };
                return (
                  <tr key={s.id}>
                    <Td><input type="checkbox" checked={d.enabled} onChange={(e) => setSrc(s.id, { enabled: e.target.checked })} title="미러 대상 켜기/끄기(저장 필요)" /></Td>
                    <Td>
                      <div className="font-medium">{s.name}</div>
                      <div className="text-xs text-muted-foreground">{s.category} · {s.license} · {s.hosts.join(', ')}</div>
                    </Td>
                    <Td className="text-xs">{s.use}</Td>
                    <Td>
                      <select className={cn(selectCls, 'h-8')} value={d.intervalH} onChange={(e) => setSrc(s.id, { intervalH: Number(e.target.value) })}>
                        {PERIODS.map((x) => <option key={x.h} value={x.h}>{x.label}</option>)}
                        {!PERIODS.some((x) => x.h === d.intervalH) && <option value={d.intervalH}>{periodLabel(d.intervalH)}</option>}
                      </select>
                    </Td>
                    <Td className="whitespace-nowrap text-xs tabular-nums">
                      {s.localAsOf ? <>{fmt(s.localAsOf)}<div className="text-muted-foreground">{ago(s.localAsOf)}</div></> : <span className="text-muted-foreground">받은 적 없음</span>}
                    </Td>
                    <Td className="whitespace-nowrap text-xs tabular-nums">
                      {p.mode === 'offline' ? <span className="text-muted-foreground">접속 안 함</span> : s.enabled ? fmt(s.nextAccess) : '—'}
                    </Td>
                    <Td className="whitespace-nowrap text-right text-xs tabular-nums">{s.files ? <>{size(s.bytes)}<div className="text-muted-foreground">{s.files}파일</div></> : '—'}</Td>
                    <Td className="whitespace-nowrap text-xs">
                      {statusOf(s, st.running)}
                      {s.status === 'error' && s.error && <div className="max-w-[16rem] truncate text-red-600" title={s.error}>{s.error}</div>}
                    </Td>
                    <Td>
                      <Button size="sm" variant="outline" disabled={busy || !!st.running || p.mode === 'offline' || !s.enabled}
                        onClick={() => act(() => adminMirrorSync(s.id), `${s.name} 받기를 시작했습니다.`)}>지금 받기</Button>
                    </Td>
                  </tr>
                );
              })}
            </tbody>
          </Table>
        </div>
      ))}
      {dirty && <Alert tone="warn">대상·주기를 바꿨습니다. 위 "접속 정책"의 저장을 눌러야 적용됩니다.</Alert>}

      <SectionTitle>방화벽 허용 목록</SectionTitle>
      <p className="mb-2 text-sm text-muted-foreground">미러 컨테이너만 아래 주소로 HTTPS(443) 나가기를 허용하면 됩니다. 나머지 서비스는 외부 접속이 필요 없습니다.</p>
      <div className="flex flex-wrap gap-1.5 rounded-lg border bg-card p-3 font-mono text-xs">
        {st.allowedHosts.map((h) => <span key={h} className="rounded bg-secondary px-1.5 py-0.5">{h}</span>)}
      </div>

      <SectionTitle>분석 엔진 연결 (Dependency-Track)</SectionTitle>
      <p className="mb-2 text-sm text-muted-foreground">
        DT 가 원본 대신 미러 사본을 내려받도록 주소를 바꿉니다. 미러에 해당 DB 가 있는 항목만 바뀌며, 원래 주소는 보관해 두었다가 되돌립니다.
        전환 뒤에는 DT 의 다음 정기 작업에서 정상적으로 받는지 확인하세요.
      </p>
      {info.dtError ? <Alert tone="warn">DT 설정을 읽지 못했습니다: {info.dtError}</Alert> : (
        <>
          <Table>
            <thead><tr><Th>DT 설정</Th><Th>현재 주소</Th><Th>미러 주소</Th><Th>상태</Th></tr></thead>
            <tbody>
              {(info.dt ?? []).map((d) => (
                <tr key={d.name}>
                  <Td className="font-mono text-xs">{d.name}</Td>
                  <Td className="break-all font-mono text-xs">{d.value}</Td>
                  <Td className="break-all font-mono text-xs">{d.usingMirror ? (d.original ? `원래: ${d.original}` : '') : d.mirrorValue ?? <span className="text-muted-foreground">미러에 없음</span>}</Td>
                  <Td className="whitespace-nowrap text-xs">{d.usingMirror ? <StatusDot tone="ok">미러 사용</StatusDot> : <StatusDot tone="off">원본 사용</StatusDot>}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
          <div className="mt-3 flex gap-2">
            <Button variant="outline" disabled={busy || !(info.dt ?? []).some((d) => d.mirrorValue)}
              onClick={() => { if (confirm('DT 가 미러 사본을 받도록 주소를 바꿉니다. 계속할까요?')) act(() => adminMirrorDT(true), 'DT 가 미러를 보도록 바꿨습니다(원장 기록).'); }}>미러로 전환</Button>
            <Button variant="ghost" disabled={busy || !(info.dt ?? []).some((d) => d.usingMirror)}
              onClick={() => act(() => adminMirrorDT(false), 'DT 주소를 원래대로 되돌렸습니다(원장 기록).')}>원본으로 되돌리기</Button>
          </div>
        </>
      )}

      <SectionTitle>최근 받기 기록</SectionTitle>
      <Table>
        <thead><tr><Th>시작</Th><Th>DB</Th><Th>방식</Th><Th>결과</Th><Th className="text-right">바뀐 파일</Th><Th className="text-right">받은 양</Th><Th>스냅샷</Th></tr></thead>
        <tbody>
          {st.runs.length === 0 && <tr><Td colSpan={7} className="text-muted-foreground">아직 기록이 없습니다.</Td></tr>}
          {st.runs.map((r) => (
            <tr key={r.start + r.id}>
              <Td className="whitespace-nowrap text-xs tabular-nums">{fmt(r.start)}</Td>
              <Td className="text-xs">{st.sources.find((s) => s.id === r.id)?.name ?? r.id}</Td>
              <Td className="text-xs">{r.trigger === 'manual' ? '수동' : '정기'}</Td>
              <Td className="text-xs">{r.status === 'ok' ? <StatusDot tone="ok">성공</StatusDot> : <span title={r.error}><StatusDot tone="crit">실패</StatusDot></span>}</Td>
              <Td className="text-right text-xs tabular-nums">{r.changed}</Td>
              <Td className="text-right text-xs tabular-nums">{size(r.bytes)}</Td>
              <Td className="font-mono text-xs"><span title={r.snapshot}>{r.snapshot.slice(0, 12)}</span></Td>
            </tr>
          ))}
        </tbody>
      </Table>
    </>
  );
}
