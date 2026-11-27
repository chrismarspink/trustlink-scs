package main

// 피드 허브 — 취약점 DB 수집을 한 곳(허브)에서 하고, 여러 설치가 받아 쓰게 하는 부분.
//
//  허브(MIRROR_HUB=1)  : 읽기에 구독 키를 요구하고, 매니페스트에 서명해 /_api/snapshot 으로 내준다.
//  받는 쪽(상위 미러 지정): 구독 키로 접속하고, 허브 공개키를 넣어 두면 서명과 파일 해시가 맞는 것만 교체한다.
//                          이미 받아들인 것보다 오래된 스냅샷은 거부한다(되돌리기 방지).
//  폐쇄망              : `mirror export` 로 스냅샷을 tar 한 개로 내보내고, `mirror import` 가 서명·해시를 검증해 들여온다.
//
// 허브 모드가 아니고 공개키도 넣지 않은 미러는 예전과 똑같이 동작한다(내부 전용, 읽기 인증 없음).

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const subHeader = "X-Mirror-Sub"

// ---------- 서명된 스냅샷 ----------

type snapFile struct {
	Path   string `json:"path"`
	Source string `json:"source"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type snapPayload struct {
	V         int        `json:"v"`
	Snapshot  string     `json:"snapshot"`
	Generated string     `json:"generated"`
	Files     []snapFile `json:"files"`
}

// snapEnvelope: 서명 대상은 Payload 바이트 그대로다(JSON 재직렬화 차이를 피한다).
type snapEnvelope struct {
	Payload []byte `json:"payload"`
	Sig     []byte `json:"sig"`
	KeyID   string `json:"keyId"`
}

func keyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:8])
}

func parsePubKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("허브 공개키 형식 오류(base64 32바이트)")
	}
	return ed25519.PublicKey(b), nil
}

// loadSignKey: 허브 서명 키(_state/sign.key). create 면 없을 때 만든다.
func (m *mirror) loadSignKey(create bool) error {
	p := m.statePath("sign.key")
	b, err := os.ReadFile(p)
	if err == nil {
		seed, derr := hex.DecodeString(strings.TrimSpace(string(b)))
		if derr != nil || len(seed) != ed25519.SeedSize {
			return errors.New("서명 키 파일이 손상됨: " + p)
		}
		m.signKey = ed25519.NewKeyFromSeed(seed)
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	if !create {
		return errors.New("서명 키가 없습니다 — 허브(MIRROR_HUB=1)에서 실행하세요")
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	if err := os.WriteFile(p, []byte(hex.EncodeToString(seed)), 0o600); err != nil {
		return err
	}
	m.signKey = ed25519.NewKeyFromSeed(seed)
	return nil
}

func (m *mirror) pubKey() ed25519.PublicKey { return m.signKey.Public().(ed25519.PublicKey) }

// envelope: 지금 매니페스트를 서명해 내준다.
func (m *mirror) envelope() (*snapEnvelope, error) {
	if m.signKey == nil {
		return nil, errors.New("서명 키 없음(허브 모드가 아님)")
	}
	m.mu.Lock()
	files := make([]snapFile, 0, len(m.files))
	for _, f := range m.files {
		files = append(files, snapFile{Path: f.Path, Source: f.Source, Size: f.Size, SHA256: f.SHA256})
	}
	snap, _, _ := m.snapshotLocked()
	m.mu.Unlock()
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	b, err := json.Marshal(snapPayload{V: 1, Snapshot: snap, Generated: time.Now().UTC().Format(time.RFC3339), Files: files})
	if err != nil {
		return nil, err
	}
	return &snapEnvelope{Payload: b, Sig: ed25519.Sign(m.signKey, b), KeyID: keyID(m.pubKey())}, nil
}

// cleanRel: 서명된 목록의 경로라도 data/ 밖으로 나가지 못하게 한다.
func cleanRel(rel string) bool {
	return rel != "" && !strings.Contains(rel, "..") && !strings.Contains(rel, "\\") && path.Clean("/"+rel) == "/"+rel
}

// openEnvelope: 서명을 검증하고 경로→항목 표를 돌려준다.
func openEnvelope(env *snapEnvelope, pubB64 string) (*snapPayload, map[string]snapFile, error) {
	pub, err := parsePubKey(pubB64)
	if err != nil {
		return nil, nil, err
	}
	if !ed25519.Verify(pub, env.Payload, env.Sig) {
		return nil, nil, errors.New("스냅샷 서명이 맞지 않음 — 받지 않음")
	}
	var p snapPayload
	if err := json.Unmarshal(env.Payload, &p); err != nil || p.V != 1 {
		return nil, nil, errors.New("스냅샷 형식 오류")
	}
	if parseT(p.Generated).IsZero() {
		return nil, nil, errors.New("스냅샷 생성 시각 없음")
	}
	exp := make(map[string]snapFile, len(p.Files))
	for _, f := range p.Files {
		if !cleanRel(f.Path) || len(f.SHA256) != 64 {
			return nil, nil, fmt.Errorf("스냅샷에 허용하지 않는 항목: %q", f.Path)
		}
		exp[f.Path] = f
	}
	return &p, exp, nil
}

// upstreamState: 마지막으로 검증해 받아들인 스냅샷(되돌리기 방지·화면 표시).
type upstreamState struct {
	KeyID     string `json:"keyId"`
	Generated string `json:"generated"`
	Snapshot  string `json:"snapshot"`
	Verified  string `json:"verified"`
	Via       string `json:"via"` // sync | import
}

func (m *mirror) lastUpstream() *upstreamState {
	var s upstreamState
	if readJSONFile(m.statePath("upstream.json"), &s) != nil || s.KeyID == "" {
		return nil
	}
	return &s
}

// checkRollback: 같은 허브 키로 이미 받아들인 것보다 오래된 스냅샷이면 거부한다.
func (m *mirror) checkRollback(keyID string, p *snapPayload) error {
	if last := m.lastUpstream(); last != nil && last.KeyID == keyID && parseT(p.Generated).Before(parseT(last.Generated)) {
		return fmt.Errorf("이미 받은 스냅샷(%s)보다 오래된 스냅샷(%s) — 받지 않음", last.Generated, p.Generated)
	}
	return nil
}

func (m *mirror) acceptUpstream(keyID string, p *snapPayload, via string) {
	_ = writeJSONFile(m.statePath("upstream.json"), upstreamState{KeyID: keyID, Generated: p.Generated, Snapshot: p.Snapshot,
		Verified: time.Now().UTC().Format(time.RFC3339), Via: via})
}

func (m *mirror) upstreamKey() string {
	b, _ := os.ReadFile(m.statePath("upstream.key"))
	return strings.TrimSpace(string(b))
}

// fetchSnapshot: 허브에서 서명된 스냅샷을 받아 검증한다.
func (m *mirror) fetchSnapshot(ctx context.Context, pol mirrorPolicy, subKey string) (*snapEnvelope, *snapPayload, map[string]snapFile, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(pol.Upstream, "/")+"/_api/snapshot", nil)
	if err != nil {
		return nil, nil, nil, err
	}
	req.Header.Set("User-Agent", mirrorUA)
	if subKey != "" {
		req.Header.Set(subHeader, subKey)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("허브 스냅샷: %v", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 200:
	case 401, 403:
		return nil, nil, nil, errors.New("허브가 구독 키를 거부함")
	case 404:
		return nil, nil, nil, errors.New("상위 미러가 서명된 스냅샷을 내주지 않음(허브 모드가 아님)")
	default:
		return nil, nil, nil, fmt.Errorf("허브 스냅샷: HTTP %d", resp.StatusCode)
	}
	var env snapEnvelope
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<20)).Decode(&env); err != nil {
		return nil, nil, nil, fmt.Errorf("허브 스냅샷: %v", err)
	}
	p, exp, err := openEnvelope(&env, pol.UpstreamPubKey)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := m.checkRollback(env.KeyID, p); err != nil {
		return nil, nil, nil, err
	}
	return &env, p, exp, nil
}

// ---------- 구독 키(허브) ----------

type subscriber struct {
	Name    string `json:"name"`
	Hash    string `json:"hash"` // 키의 SHA-256. 키 자체는 발급할 때 한 번만 보여 준다
	Created string `json:"created"`
}

var subNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

func (m *mirror) readSubs() []subscriber {
	var s []subscriber
	_ = readJSONFile(m.statePath("subscribers.json"), &s)
	return s
}

func (m *mirror) readSeen() map[string]string {
	s := map[string]string{}
	_ = readJSONFile(m.statePath("subscribers-seen.json"), &s)
	return s
}

// subscriberOf: 요청의 구독 키가 맞으면 구독자 이름. 목록 파일이 바뀌면 다시 읽는다(CLI 로 추가·삭제).
func (m *mirror) subscriberOf(r *http.Request) string {
	key := r.Header.Get(subHeader)
	if key == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(key))
	got := []byte(hex.EncodeToString(sum[:]))
	m.subMu.Lock()
	defer m.subMu.Unlock()
	if fi, err := os.Stat(m.statePath("subscribers.json")); err != nil {
		m.subs = nil
	} else if !fi.ModTime().Equal(m.subMod) {
		m.subs, m.subMod = m.readSubs(), fi.ModTime()
	}
	name := ""
	for _, s := range m.subs {
		if subtle.ConstantTimeCompare(got, []byte(s.Hash)) == 1 {
			name = s.Name
		}
	}
	if name == "" {
		return ""
	}
	// 마지막 접속 시각 — 10분에 한 번만 기록한다
	now := time.Now()
	if m.seen == nil {
		m.seen = m.readSeen()
	}
	if now.Sub(parseT(m.seen[name])) > 10*time.Minute {
		m.seen[name] = now.UTC().Format(time.RFC3339)
		_ = writeJSONFile(m.statePath("subscribers-seen.json"), m.seen)
	}
	return name
}

// guard: 허브 모드에서는 구독 키(또는 관리 키)가 있어야 읽을 수 있다. 상태 확인(healthz)만 열어 둔다.
func (m *mirror) guard(next http.Handler) http.Handler {
	if !m.hub {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_api/healthz" || m.authorized(r) || m.subscriberOf(r) != "" {
			next.ServeHTTP(w, r)
			return
		}
		writeJSON(w, 401, map[string]string{"error": "구독 키가 필요합니다(" + subHeader + ")"})
	})
}

type hubView struct {
	KeyID       string    `json:"keyId"`
	PubKey      string    `json:"pubKey"`
	Subscribers []subView `json:"subscribers,omitempty"` // 관리 키로 물었을 때만
}

type subView struct {
	Name     string `json:"name"`
	Created  string `json:"created"`
	LastSeen string `json:"lastSeen,omitempty"`
}

func (m *mirror) subViews() []subView {
	seen := m.readSeen()
	out := []subView{}
	for _, s := range m.readSubs() {
		out = append(out, subView{Name: s.Name, Created: s.Created, LastSeen: seen[s.Name]})
	}
	return out
}

// ---------- 명령줄: trustlink-admin mirror <sub|pubkey|export|import> ----------

func mirrorCLI(m *mirror, args []string) error {
	usage := errors.New("사용법: mirror sub add <이름> | sub list | sub rm <이름> | pubkey | export <파일.tar> | import <파일.tar>")
	switch {
	case len(args) == 3 && args[0] == "sub" && args[1] == "add":
		name := args[2]
		if !subNameRe.MatchString(name) {
			return errors.New("이름은 영소문자·숫자·._- (63자 이내)")
		}
		subs := m.readSubs()
		for _, s := range subs {
			if s.Name == name {
				return errors.New("이미 있는 이름: " + name + " (다시 발급하려면 rm 뒤 add)")
			}
		}
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return err
		}
		key := "tlsub_" + hex.EncodeToString(buf)
		sum := sha256.Sum256([]byte(key))
		subs = append(subs, subscriber{Name: name, Hash: hex.EncodeToString(sum[:]), Created: time.Now().UTC().Format(time.RFC3339)})
		if err := writeJSONFile(m.statePath("subscribers.json"), subs); err != nil {
			return err
		}
		fmt.Printf("구독자 %s 의 키(지금 한 번만 표시됩니다):\n%s\n", name, key)
		return nil
	case len(args) == 2 && args[0] == "sub" && args[1] == "list":
		for _, s := range m.subViews() {
			fmt.Printf("%-24s 발급 %s  마지막 접속 %s\n", s.Name, s.Created, strings.TrimSpace(s.LastSeen+" "))
		}
		return nil
	case len(args) == 3 && args[0] == "sub" && args[1] == "rm":
		subs, out := m.readSubs(), []subscriber{}
		for _, s := range subs {
			if s.Name != args[2] {
				out = append(out, s)
			}
		}
		if len(out) == len(subs) {
			return errors.New("없는 이름: " + args[2])
		}
		return writeJSONFile(m.statePath("subscribers.json"), out)
	case len(args) == 1 && args[0] == "pubkey":
		if err := m.loadSignKey(true); err != nil {
			return err
		}
		fmt.Printf("공개키: %s\n키 ID : %s\n", base64.StdEncoding.EncodeToString(m.pubKey()), keyID(m.pubKey()))
		return nil
	case len(args) == 2 && args[0] == "export":
		if err := m.loadSignKey(false); err != nil {
			return err
		}
		return m.exportBundle(args[1])
	case len(args) == 2 && args[0] == "import":
		return m.importBundle(args[1], env("MIRROR_PUBKEY", m.policy.UpstreamPubKey))
	}
	return usage
}

// ---------- 오프라인 번들 ----------
// tar: snapshot.json(서명된 스냅샷) → data/<경로> … 순서. 들여올 때 서명과 파일별 해시를 모두 확인한다.

func (m *mirror) exportBundle(out string) (err error) {
	env, err := m.envelope()
	if err != nil {
		return err
	}
	var p snapPayload
	if err := json.Unmarshal(env.Payload, &p); err != nil {
		return err
	}
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(out)
		}
	}()
	tw := tar.NewWriter(f)
	eb, _ := json.Marshal(env)
	now := time.Now()
	if err := tw.WriteHeader(&tar.Header{Name: "snapshot.json", Mode: 0o644, Size: int64(len(eb)), ModTime: now}); err != nil {
		return err
	}
	if _, err := tw.Write(eb); err != nil {
		return err
	}
	var total int64
	for _, sf := range p.Files {
		src, err := os.Open(filepath.Join(m.dataDir(), filepath.FromSlash(sf.Path)))
		if err != nil {
			return err
		}
		err = tw.WriteHeader(&tar.Header{Name: "data/" + sf.Path, Mode: 0o644, Size: sf.Size, ModTime: now})
		if err == nil {
			_, err = io.CopyN(tw, src, sf.Size)
		}
		src.Close()
		if err != nil {
			return fmt.Errorf("%s: %v (받는 중인 DB 가 있으면 끝난 뒤 다시 내보내세요)", sf.Path, err)
		}
		total += sf.Size
	}
	if err := tw.Close(); err != nil {
		return err
	}
	fmt.Printf("내보냄: %s — 파일 %d개, %s, 스냅샷 %s\n", out, len(p.Files), human(total), p.Snapshot)
	return nil
}

// importBundle: 미러를 멈춘 상태에서 실행한다(실행 중인 미러는 메모리의 매니페스트로 덮어쓴다).
func (m *mirror) importBundle(in, pubB64 string) error {
	if pubB64 == "" {
		return errors.New("허브 공개키가 없습니다 — 정책의 '허브 공개키' 또는 MIRROR_PUBKEY 로 지정하세요")
	}
	f, err := os.Open(in)
	if err != nil {
		return err
	}
	defer f.Close()
	tr := tar.NewReader(f)
	hd, err := tr.Next()
	if err != nil || hd.Name != "snapshot.json" {
		return errors.New("번들 형식 오류: 첫 항목이 snapshot.json 이 아님")
	}
	var env snapEnvelope
	if err := json.NewDecoder(io.LimitReader(tr, 256<<20)).Decode(&env); err != nil {
		return fmt.Errorf("번들 스냅샷: %v", err)
	}
	p, exp, err := openEnvelope(&env, pubB64)
	if err != nil {
		return err
	}
	if err := m.checkRollback(env.KeyID, p); err != nil {
		return err
	}
	minFree := int64(m.policy.MinFreeGB) << 30
	now := time.Now().UTC().Format(time.RFC3339)
	done := map[string]bool{}
	changed := 0
	for {
		hd, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(hd.Name, "data/")
		e, ok := exp[rel]
		if !ok || rel == hd.Name {
			return fmt.Errorf("스냅샷에 없는 항목: %s", hd.Name)
		}
		dst := filepath.Join(m.dataDir(), filepath.FromSlash(rel))
		if prev := m.files[rel]; prev != nil && prev.SHA256 == e.SHA256 {
			if _, err := os.Stat(dst); err == nil { // 이미 같은 내용
				done[rel] = true
				continue
			}
		}
		if free, _ := diskFree(m.dataDir()); free >= 0 && free-e.Size < minFree {
			return fmt.Errorf("디스크 여유 부족: 남은 %s, 받을 크기 %s, 최소 여유 %s", human(free), human(e.Size), human(minFree))
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		tmp, err := os.CreateTemp(filepath.Dir(dst), ".part-*")
		if err != nil {
			return err
		}
		h := sha256.New()
		_, err = io.Copy(io.MultiWriter(tmp, h), tr)
		if cerr := tmp.Close(); err == nil {
			err = cerr
		}
		if err == nil && hex.EncodeToString(h.Sum(nil)) != e.SHA256 {
			err = fmt.Errorf("%s: 해시가 스냅샷과 다름", rel)
		}
		if err == nil {
			err = os.Chmod(tmp.Name(), 0o644)
		}
		if err == nil {
			err = os.Rename(tmp.Name(), dst)
		}
		if err != nil {
			os.Remove(tmp.Name())
			return err
		}
		done[rel] = true
		changed++
	}
	if len(done) != len(exp) {
		return fmt.Errorf("번들이 불완전함: 스냅샷 %d개 중 %d개만 있음 — 매니페스트는 바꾸지 않았습니다", len(exp), len(done))
	}
	// 전부 확인된 뒤에만 매니페스트를 바꾸고, 스냅샷에 없는 파일을 정리한다
	files := map[string]*fileEntry{}
	for rel, e := range exp {
		fe := &fileEntry{Path: rel, Source: e.Source, Size: e.Size, SHA256: e.SHA256, Fetched: now, Checked: now}
		if prev := m.files[rel]; prev != nil && prev.SHA256 == e.SHA256 {
			fe.Fetched = prev.Fetched
		}
		files[rel] = fe
		st := m.states[e.Source]
		if st == nil {
			st = &sourceState{}
			m.states[e.Source] = st
		}
		st.Status, st.Error, st.LastSuccess, st.LastAttempt = "ok", "", p.Generated, now
	}
	for rel := range m.files {
		if _, ok := files[rel]; !ok {
			_ = os.Remove(filepath.Join(m.dataDir(), filepath.FromSlash(rel)))
			changed++
		}
	}
	m.files = files
	m.saveStateLocked()
	m.acceptUpstream(env.KeyID, p, "import")
	snap, total, n := m.snapshotLocked()
	if snap != p.Snapshot {
		return fmt.Errorf("들여온 뒤 스냅샷 ID 가 다름: %s ≠ %s", snap, p.Snapshot)
	}
	rec := runRecord{ID: "bundle", Trigger: "import", Start: now, End: time.Now().UTC().Format(time.RFC3339), Status: "ok", Changed: changed, Bytes: total, Snapshot: snap}
	if lf, err := os.OpenFile(m.statePath("runs.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640); err == nil {
		b, _ := json.Marshal(rec)
		_, _ = lf.Write(append(b, '\n'))
		lf.Close()
	}
	fmt.Printf("들여옴: 파일 %d개(바뀐 것 %d개), %s, 스냅샷 %s, 허브 키 %s\n", n, changed, human(total), snap, env.KeyID)
	return nil
}

// snapshotHandler: GET /_api/snapshot — 허브만 내준다.
func (m *mirror) snapshotHandler(w http.ResponseWriter, r *http.Request) {
	env, err := m.envelope()
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(env)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(buf.Bytes())
}
