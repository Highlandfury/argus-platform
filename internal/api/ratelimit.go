package api

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// loginLimiter is a per-key token bucket for the login endpoint.
// Defaults: burst 10, sustained ~10/min (one token per 6 s) — matching the
// S-09 expectation that the 11th rapid attempt is rejected with 429.
type loginLimiter struct {
	mu        sync.Mutex
	limiters  map[string]*rate.Limiter
	lastUsed  map[string]time.Time
	lastSweep time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{
		limiters:  make(map[string]*rate.Limiter),
		lastUsed:  make(map[string]time.Time),
		lastSweep: time.Now(),
	}
}

func (l *loginLimiter) limiterFor(key string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.lastSweep) > time.Minute {
		for k, t := range l.lastUsed {
			if now.Sub(t) > 10*time.Minute {
				delete(l.lastUsed, k)
				delete(l.limiters, k)
			}
		}
		l.lastSweep = now
	}
	lim, ok := l.limiters[key]
	if !ok {
		lim = rate.NewLimiter(rate.Every(6*time.Second), 10)
		l.limiters[key] = lim
	}
	l.lastUsed[key] = now
	return lim
}

// allow consumes a token; when denied it returns a retry hint.
func (l *loginLimiter) allow(key string) (bool, time.Duration) {
	lim := l.limiterFor(key)
	if lim.Allow() {
		return true, 0
	}
	return false, 6 * time.Second
}
