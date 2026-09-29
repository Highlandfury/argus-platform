package security

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

// tokenBytes is the entropy per session/CSRF token (256-bit).
const tokenBytes = 32

// NewToken mints a URL-safe random token and returns its SHA-256 hash for
// storage. Raw tokens are never persisted (SPEC §24.3).
func NewToken() (raw string, hash []byte, err error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, fmt.Errorf("security: token entropy: %w", err)
	}
	raw = base64.RawURLEncoding.EncodeToString(buf)
	return raw, HashToken(raw), nil
}

// HashToken returns SHA-256(raw), the storage form for session/CSRF tokens.
func HashToken(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

// SecureEqual compares two byte slices in constant time.
func SecureEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
