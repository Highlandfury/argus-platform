package security

import (
	"strings"
	"testing"
)

func TestHashAndVerifyRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("unexpected PHC format: %s", hash)
	}
	ok, err := VerifyPassword(hash, "correct horse battery staple")
	if err != nil || !ok {
		t.Fatalf("verify correct password: ok=%v err=%v", ok, err)
	}
	ok, err = VerifyPassword(hash, "wrong password")
	if err != nil || ok {
		t.Fatalf("verify wrong password: ok=%v err=%v", ok, err)
	}
}

func TestHashUsesFreshSalt(t *testing.T) {
	a, err := HashPassword("same")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	b, err := HashPassword("same")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if a == b {
		t.Fatal("two hashes of the same password must differ (unique salts)")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	cases := []string{
		"",
		"plaintext",
		"$argon2id$v=19$m=65536,t=3,p=4$onlyfour",
		"$argon2i$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",
		"$argon2id$v=99$m=65536,t=3,p=4$c2FsdA$aGFzaA",
	}
	for _, c := range cases {
		if _, err := VerifyPassword(c, "x"); err == nil {
			t.Fatalf("expected ErrInvalidHash for %q", c)
		}
	}
}
