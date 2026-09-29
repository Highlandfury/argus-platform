package httpx

import (
	"crypto/rand"
	"encoding/hex"
)

// Request-ID policy (SPEC §15): correlation IDs are safe for structured logs —
// bounded length, restricted charset — so they can never inject log fields,
// newlines/control sequences, or cause unbounded log amplification. Values
// outside the policy are replaced with a generated 128-bit ID.
const (
	maxRequestIDLen = 64
)

// ValidRequestID reports whether a caller-supplied ID is acceptable.
func ValidRequestID(id string) bool {
	if id == "" || len(id) > maxRequestIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '.', c == ':', c == '+':
		default:
			return false
		}
	}
	return true
}

// NewRequestID generates a 128-bit random correlation ID.
func NewRequestID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "unavailable"
	}
	return hex.EncodeToString(buf)
}

// SanitizeRequestID returns the caller ID when it satisfies the policy, or a
// freshly generated one otherwise (also used by the gRPC interceptor).
func SanitizeRequestID(id string) string {
	if ValidRequestID(id) {
		return id
	}
	return NewRequestID()
}
