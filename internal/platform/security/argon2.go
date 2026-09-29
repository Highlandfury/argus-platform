// Package security holds password hashing and token primitives.
package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters (OWASP-recommended class; M1 baseline).
const (
	argonMemoryKiB   = 64 * 1024
	argonTime        = 3
	argonParallelism = 4
	argonSaltLen     = 16
	argonKeyLen      = 32
)

// ErrInvalidHash is returned when a stored password hash cannot be parsed.
var ErrInvalidHash = errors.New("security: invalid password hash format")

// HashPassword returns a PHC-formatted Argon2id string:
//
//	$argon2id$v=19$m=65536,t=3,p=4$<b64 salt>$<b64 hash>
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("security: hash salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemoryKiB, argonParallelism, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemoryKiB, argonTime, argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword reports whether password matches the PHC-encoded hash.
// Comparison is constant-time.
func VerifyPassword(encoded, password string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return false, ErrInvalidHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, ErrInvalidHash
	}
	var memoryKib, timeCost uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memoryKib, &timeCost, &parallelism); err != nil {
		return false, ErrInvalidHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrInvalidHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false, ErrInvalidHash
	}
	// Bound the decoded length before the uint32 conversion below.
	if len(want) > 1024 {
		return false, ErrInvalidHash
	}
	got := argon2.IDKey([]byte(password), salt, timeCost, memoryKib, parallelism, uint32(len(want))) //nolint:gosec // length bounded above
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
