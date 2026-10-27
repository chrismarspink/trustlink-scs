package main

import (
	"regexp"
	"testing"
)

func TestGenTempPassword(t *testing.T) {
	format := regexp.MustCompile(`^[` + pwAlphabet + `]{4}-[` + pwAlphabet + `]{4}-[` + pwAlphabet + `]{4}$`)
	digit := regexp.MustCompile(`[2-9]`)
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		pw, err := genTempPassword()
		if err != nil {
			t.Fatal(err)
		}
		if !format.MatchString(pw) {
			t.Fatalf("형식 불일치: %q", pw)
		}
		for _, g := range []string{pw[0:4], pw[5:9], pw[10:14]} {
			if !digit.MatchString(g) {
				t.Fatalf("그룹에 숫자 없음: %q", pw)
			}
		}
		if seen[pw] {
			t.Fatalf("중복 생성: %q", pw)
		}
		seen[pw] = true
	}
}
