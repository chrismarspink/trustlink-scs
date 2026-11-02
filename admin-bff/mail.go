package main

// mail.go: 통보 메일 발송(SMTP). stdlib 전용 — 465 는 암묵적 TLS, 그 외 포트는 STARTTLS.
// MAIL_ALLOWLIST 가 설정되면 그 주소로만 보낸다(시험 기간 오발송 방지). 나머지 수신자는 버리고 기록한다.

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

type Mailer struct {
	Host, Port, User, Pass, From string
	Allow                        map[string]bool // 비면 제한 없음
}

func newMailer() *Mailer {
	m := &Mailer{
		Host: env("SMTP_HOST", ""), Port: env("SMTP_PORT", "465"),
		User: env("SMTP_USER", ""), Pass: env("SMTP_PASS", ""),
	}
	m.From = env("SMTP_FROM", m.User)
	for _, a := range strings.Split(env("MAIL_ALLOWLIST", ""), ",") {
		if a = strings.ToLower(strings.TrimSpace(a)); a != "" {
			if m.Allow == nil {
				m.Allow = map[string]bool{}
			}
			m.Allow[a] = true
		}
	}
	return m
}

func (m *Mailer) Configured() bool { return m.Host != "" && m.From != "" }

// filter: 허용 목록 밖의 수신자를 걸러 (보낼 것, 버린 것) 을 돌려준다.
func (m *Mailer) filter(to []string) (ok, dropped []string) {
	for _, a := range to {
		if m.Allow == nil || m.Allow[strings.ToLower(strings.TrimSpace(a))] {
			ok = append(ok, a)
		} else {
			dropped = append(dropped, a)
		}
	}
	return
}

// buildMessage: UTF-8 평문 메일(제목은 RFC 2047, 본문은 base64).
func buildMessage(from string, to []string, subject, body string, now time.Time) []byte {
	var b bytes.Buffer
	h := func(k, v string) { fmt.Fprintf(&b, "%s: %s\r\n", k, v) }
	h("From", (&mail.Address{Name: "TrustLink", Address: from}).String())
	h("To", strings.Join(to, ", "))
	h("Subject", mime.BEncoding.Encode("UTF-8", subject))
	h("Date", now.Format(time.RFC1123Z))
	h("MIME-Version", "1.0")
	h("Content-Type", `text/plain; charset="UTF-8"`)
	h("Content-Transfer-Encoding", "base64")
	b.WriteString("\r\n")
	enc := base64.StdEncoding.EncodeToString([]byte(body))
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
	return b.Bytes()
}

// Send: 허용된 수신자에게 발송. 보낸 주소·버린 주소를 돌려준다.
func (m *Mailer) Send(to []string, subject, body string) (sent, dropped []string, err error) {
	if !m.Configured() {
		return nil, nil, fmt.Errorf("메일 서버 미설정(SMTP_HOST)")
	}
	sent, dropped = m.filter(to)
	if len(sent) == 0 {
		return nil, dropped, nil
	}
	addr := net.JoinHostPort(m.Host, m.Port)
	tcfg := &tls.Config{ServerName: m.Host}
	var c *smtp.Client
	if m.Port == "465" {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}, "tcp", addr, tcfg)
		if err != nil {
			return nil, dropped, err
		}
		if c, err = smtp.NewClient(conn, m.Host); err != nil {
			conn.Close()
			return nil, dropped, err
		}
	} else {
		conn, err := net.DialTimeout("tcp", addr, 15*time.Second)
		if err != nil {
			return nil, dropped, err
		}
		if c, err = smtp.NewClient(conn, m.Host); err != nil {
			conn.Close()
			return nil, dropped, err
		}
		if err := c.StartTLS(tcfg); err != nil {
			c.Close()
			return nil, dropped, err
		}
	}
	defer c.Close()
	if m.User != "" {
		if err := c.Auth(smtp.PlainAuth("", m.User, m.Pass, m.Host)); err != nil {
			return nil, dropped, fmt.Errorf("인증 실패: %w", err)
		}
	}
	if err := c.Mail(m.From); err != nil {
		return nil, dropped, fmt.Errorf("보내는 주소 거부: %w", err)
	}
	for _, a := range sent {
		if err := c.Rcpt(a); err != nil {
			return nil, dropped, fmt.Errorf("받는 주소 거부(%s): %w", a, err)
		}
	}
	wc, err := c.Data()
	if err != nil {
		return nil, dropped, err
	}
	if _, err := wc.Write(buildMessage(m.From, sent, subject, body, time.Now())); err != nil {
		return nil, dropped, err
	}
	if err := wc.Close(); err != nil {
		return nil, dropped, err
	}
	return sent, dropped, c.Quit()
}

// GET /api/mail — 메일 설정 상태(비밀번호 제외).
func (s *Server) apiMailStatus(w http.ResponseWriter, r *http.Request) {
	allow := []string{}
	for a := range s.mail.Allow {
		allow = append(allow, a)
	}
	writeJSON(w, 200, map[string]any{
		"configured": s.mail.Configured(), "host": s.mail.Host, "port": s.mail.Port,
		"from": s.mail.From, "allowlist": allow,
	})
}

// POST /api/mail/test {to} — 시험 메일 발송(관리자).
func (s *Server) apiMailTest(w http.ResponseWriter, r *http.Request) {
	var in struct{ To string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.To == "" {
		writeJSON(w, 400, map[string]string{"error": "to 필수"})
		return
	}
	actor := w.Header().Get("X-User")
	body := fmt.Sprintf("TrustLink 메일 발송 시험입니다.\n\n보낸 사람(관리자): %s\n보낸 시각: %s\n서버: %s\n\n이 메일을 받았다면 TrustLink 통보 메일 설정이 정상입니다.",
		actor, time.Now().Format("2006-01-02 15:04:05 MST"), r.Host)
	sent, dropped, err := s.mail.Send([]string{in.To}, "[TrustLink] 메일 발송 시험", body)
	status := "sent"
	if err != nil {
		status = "failed"
	} else if len(sent) == 0 {
		status = "blocked"
	}
	_ = s.sor.append(SoREvent{Actor: actor, Action: "mail-test", Status: status,
		Detail: map[string]any{"to": in.To, "dropped": dropped, "error": errString(err)}})
	switch {
	case err != nil:
		writeJSON(w, 502, map[string]string{"error": err.Error()})
	case len(sent) == 0:
		writeJSON(w, 403, map[string]string{"error": "허용 목록(MAIL_ALLOWLIST)에 없는 주소라 보내지 않았습니다"})
	default:
		writeJSON(w, 200, map[string]any{"status": "sent", "to": sent})
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
