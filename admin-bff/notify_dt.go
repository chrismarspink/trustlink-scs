package main

// notify_dt.go: Dependency-Track 에 "새 취약점 → TrustLink 웹훅" 알림 규칙을 자동 등록(멱등).
// 웹훅 주소는 compose 내부망의 BFF 내부 전용 포트(NOTIFY_DT_DESTINATION, 기본 http://trustlink-admin:8089/dt/webhook).

import (
	"encoding/json"
	"fmt"
	"log"
	"time"
)

const dtRuleName = "TrustLink 통보"

func (s *Server) ensureDTNotificationRule() {
	if s.cfg.DTAdminPassword == "" {
		log.Printf("DT 알림 규칙: DT_ADMIN_PASSWORD 없음 — 수동 등록 필요")
		return
	}
	dest := env("NOTIFY_DT_DESTINATION", "http://trustlink-admin:8089/dt/webhook")
	for wait := 30 * time.Second; ; {
		err := s.registerDTRule(dest)
		if err == nil {
			log.Printf("DT 알림 규칙 확인: %s → %s", dtRuleName, dest)
			return
		}
		log.Printf("DT 알림 규칙 등록 대기: %v (%s 후 재시도)", err, wait)
		time.Sleep(wait)
		if wait < 10*time.Minute {
			wait *= 2
		}
	}
}

func (s *Server) registerDTRule(dest string) error {
	call, err := s.dtAdminCaller()
	if err != nil {
		return err
	}
	_, b, err := call("GET", "/api/v1/notification/publisher", "")
	if err != nil {
		return err
	}
	var pubs []struct{ UUID, Name, PublisherClass string }
	_ = json.Unmarshal(b, &pubs)
	pubUUID := ""
	for _, p := range pubs {
		if p.PublisherClass == "org.dependencytrack.notification.publisher.WebhookPublisher" {
			pubUUID = p.UUID
		}
	}
	if pubUUID == "" {
		return fmt.Errorf("DT 웹훅 발행기(WebhookPublisher) 없음")
	}

	_, b, err = call("GET", "/api/v1/notification/rule", "")
	if err != nil {
		return err
	}
	var rules []map[string]any
	_ = json.Unmarshal(b, &rules)
	var rule map[string]any
	for _, r := range rules {
		if r["name"] == dtRuleName {
			rule = r
		}
	}
	if rule == nil {
		body, _ := json.Marshal(map[string]any{"name": dtRuleName, "scope": "PORTFOLIO", "notificationLevel": "INFORMATIONAL",
			"publisher": map[string]string{"uuid": pubUUID}})
		code, b, err := call("PUT", "/api/v1/notification/rule", string(body))
		if err != nil {
			return err
		}
		if code != 201 && code != 200 {
			return fmt.Errorf("규칙 생성 실패(%d): %s", code, b)
		}
		_ = json.Unmarshal(b, &rule)
	}
	cfg, _ := json.Marshal(map[string]string{"destination": dest})
	if rule["enabled"] == true && rule["publisherConfig"] == string(cfg) {
		return nil // 이미 같은 설정
	}
	rule["enabled"] = true
	rule["notifyOn"] = []string{"NEW_VULNERABILITY"}
	rule["publisherConfig"] = string(cfg)
	body, _ := json.Marshal(rule)
	code, b, err := call("POST", "/api/v1/notification/rule", string(body))
	if err != nil {
		return err
	}
	if code != 200 {
		return fmt.Errorf("규칙 갱신 실패(%d): %s", code, b)
	}
	return nil
}
