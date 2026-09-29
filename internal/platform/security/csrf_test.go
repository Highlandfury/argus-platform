package security

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestNewTokenFormatAndUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 64; i++ {
		raw, hash, err := NewToken()
		if err != nil {
			t.Fatalf("NewToken: %v", err)
		}
		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil || len(decoded) != tokenBytes {
			t.Fatalf("raw token not %d bytes of raw-url base64: %q (len=%d err=%v)", tokenBytes, raw, len(decoded), err)
		}
		if seen[raw] {
			t.Fatal("token collision within 64 draws — entropy source suspect")
		}
		seen[raw] = true
		if !bytes.Equal(hash, HashToken(raw)) {
			t.Fatal("returned hash does not match HashToken(raw)")
		}
	}
}

func TestSecureEqual(t *testing.T) {
	if !SecureEqual([]byte("abc"), []byte("abc")) {
		t.Fatal("equal slices must compare equal")
	}
	if SecureEqual([]byte("abc"), []byte("abd")) {
		t.Fatal("different slices must not compare equal")
	}
	if SecureEqual([]byte("abc"), []byte("abcdef")) {
		t.Fatal("different lengths must not compare equal")
	}
}

func TestVerifyCSRFDoubleSubmit(t *testing.T) {
	raw, hash, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}

	if !VerifyCSRF(raw, raw, hash) {
		t.Fatal("matching cookie+header+session hash must verify")
	}
	if VerifyCSRF("", raw, hash) {
		t.Fatal("missing cookie must fail")
	}
	if VerifyCSRF(raw, "", hash) {
		t.Fatal("missing header must fail")
	}
	other, _, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if VerifyCSRF(other, other, hash) {
		t.Fatal("pair not anchored to the session hash must fail")
	}
	if VerifyCSRF(raw, other, hash) {
		t.Fatal("cookie/header mismatch must fail")
	}
	if VerifyCSRF(raw, raw, nil) {
		t.Fatal("missing session hash must fail")
	}
}
