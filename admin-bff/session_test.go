package main

import (
	"path/filepath"
	"testing"
	"time"
)

// TestSessionPersistence: put → 새 스토어(재시작 시뮬레이션)에서 복원되는지,
// 만료 세션은 복원에서 제외되는지, del 이 영속 반영되는지 검증.
func TestSessionPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")

	// 1) put → 파일 영속
	s1 := newStore(path)
	id := s1.put(Session{Username: "admin1", Groups: []string{"admins"}, Expiry: time.Now().Add(time.Hour)})

	// 2) "재시작": 같은 경로로 새 스토어 → 세션 복원
	s2 := newStore(path)
	sess, ok := s2.get(id)
	if !ok {
		t.Fatal("재시작 후 세션이 복원되지 않음")
	}
	if sess.Username != "admin1" || len(sess.Groups) != 1 || sess.Groups[0] != "admins" {
		t.Fatalf("복원된 세션 내용 불일치: %+v", sess)
	}

	// 3) 만료 세션은 복원 제외
	s2.put(Session{Username: "expired", Expiry: time.Now().Add(-time.Minute)})
	s3 := newStore(path)
	for _, v := range s3.m {
		if v.Username == "expired" {
			t.Fatal("만료 세션이 복원됨 (제외돼야 함)")
		}
	}

	// 4) del → 재시작 후에도 사라져 있어야 함
	s3.del(id)
	s4 := newStore(path)
	if _, ok := s4.get(id); ok {
		t.Fatal("del 한 세션이 재시작 후 복원됨")
	}
}

// TestSessionNoPath: 경로 미설정이면 인메모리로 동작(영속화 비활성).
func TestSessionNoPath(t *testing.T) {
	s := newStore("")
	id := s.put(Session{Username: "x", Expiry: time.Now().Add(time.Hour)})
	if _, ok := s.get(id); !ok {
		t.Fatal("인메모리 모드 put/get 실패")
	}
}
