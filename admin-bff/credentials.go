package main

// 자격 전달(관리자 → 담당자): 임시 비밀번호 자동 생성·재설정, 공용 업로드(ci) 계정 조회.
//   - 비밀번호는 응답으로 1회만 내려주고 서버에 저장하지 않는다(Keycloak 에는 temporary=true → 첫 로그인 시 변경 강제).
//   - 조회/발급 행위는 SoR 감사에 남기되 비밀번호 값은 기록하지 않는다.

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
)

// 혼동 문자(0/O, 1/l/I) 제외 — 구두·메신저 전달 시 오독 방지.
const pwAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"

// genTempPassword: 4자×3 그룹("Xk7p-Qm3d-Rt9w"), 그룹마다 숫자 1개 이상.
func genTempPassword() (string, error) {
	groups := make([]string, 3)
	for g := range groups {
		for {
			b := make([]byte, 4)
			for i := range b {
				n, err := rand.Int(rand.Reader, big.NewInt(int64(len(pwAlphabet))))
				if err != nil {
					return "", err
				}
				b[i] = pwAlphabet[n.Int64()]
			}
			if strings.ContainsAny(string(b), "23456789") {
				groups[g] = string(b)
				break
			}
		}
	}
	return strings.Join(groups, "-"), nil
}

// setTempPassword: Keycloak 임시 비밀번호 설정(첫 로그인 시 변경 강제).
func (s *Server) setTempPassword(uid, pw string) error {
	body, _ := json.Marshal(map[string]any{"type": "password", "value": pw, "temporary": true})
	resp, err := s.kcAdmin("PUT", "/users/"+uid+"/reset-password", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("keycloak reset-password %d", resp.StatusCode)
	}
	return nil
}

// POST /api/users/{id}/reset-password — 임시 비밀번호 재발급(1회 표시).
func (s *Server) apiResetPassword(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("id")
	var in struct {
		Username string `json:"username"` // 감사 기록용
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	pw, err := genTempPassword()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if err := s.setTempPassword(uid, pw); err != nil {
		writeJSON(w, 502, map[string]string{"error": "비밀번호 재설정 실패: " + err.Error()})
		return
	}
	_ = s.sor.append(SoREvent{Actor: w.Header().Get("X-User"), Action: "password-reset", Subject: in.Username})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]string{"id": uid, "username": in.Username, "password": pw})
}

// GET /api/credentials/ci — 공용 업로드(ci) 계정. BFF 는 이미 메트릭 조회용으로 ci 자격(ZOT_METRICS_*)을 보유.
func (s *Server) apiCICredential(w http.ResponseWriter, r *http.Request) {
	if s.cfg.MetricsPass == "" {
		writeJSON(w, 404, map[string]string{"error": "ci 자격 미설정(ZOT_METRICS_PASS)"})
		return
	}
	_ = s.sor.append(SoREvent{Actor: w.Header().Get("X-User"), Action: "ci-credential-view", Subject: s.cfg.MetricsUser})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]string{"username": s.cfg.MetricsUser, "password": s.cfg.MetricsPass})
}
