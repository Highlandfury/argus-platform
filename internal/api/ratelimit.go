package api

import (
	"time"

	"github.com/argus-platform/argus/internal/platform/ratelimit"
)

// loginLimiter wraps the shared limiter with the login-specific policy:
// burst 10, sustained ~10/min (S-09: the 11th rapid attempt is rejected).
type loginLimiter struct {
	inner *ratelimit.Limiter
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{inner: ratelimit.New(10, 6*time.Second)}
}

// allow consumes a token; when denied it returns a retry hint.
func (l *loginLimiter) allow(key string) (bool, time.Duration) {
	return l.inner.Allow(key)
}
