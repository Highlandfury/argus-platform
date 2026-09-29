package collectors

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
)

// EnrollmentTokenPrefix identifies enrollment credentials in logs/scanners.
// (Not a credential itself — the 128-bit random suffix is the secret.)
const EnrollmentTokenPrefix = "arg_enr_" //nolint:gosec

// tokenEncoding is lower-case base32 without padding (the documented format:
// 16 random bytes -> 26 characters, 34 including the prefix).
var tokenEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// MintEnrollmentToken returns a one-time enrollment credential and the SHA-256
// hash that is stored (raw tokens are never persisted; SPEC §8.1).
func MintEnrollmentToken() (raw string, hash []byte, err error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, fmt.Errorf("collectors: token entropy: %w", err)
	}
	raw = EnrollmentTokenPrefix + tokenEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(raw))
	return raw, sum[:], nil
}

// HashEnrollmentToken returns SHA-256(raw) for storage/lookup.
func HashEnrollmentToken(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}
