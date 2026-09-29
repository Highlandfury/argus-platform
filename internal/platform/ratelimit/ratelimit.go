// Package ratelimit provides a small per-key token-bucket limiter shared by the
// API (login) and the collector enrollment endpoint.
package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter is a per-key token bucket with idle-key sweeping.
type Limiter struct {
	burst  int
	every  time.Duration
	mu     sync.Mutex
	bucket map[string]*rate.Limiter
	seen   map[string]time.Time
	swept  time.Time
}

// New creates a limiter: burst tokens immediately, then one token per `every`.
func New(burst int, every time.Duration) *Limiter {
	return &Limiter{
		burst:  burst,
		every:  every,
		bucket: make(map[string]*rate.Limiter),
		seen:   make(map[string]time.Time),
		swept:  time.Now(),
	}
}

// Allow consumes a token for key; when denied it returns a retry hint.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	lim := l.forKey(key)
	if lim.Allow() {
		return true, 0
	}
	return false, l.every
}

func (l *Limiter) forKey(key string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.swept) > time.Minute {
		for k, t := range l.seen {
			if now.Sub(t) > 10*time.Minute {
				delete(l.seen, k)
				delete(l.bucket, k)
			}
		}
		l.swept = now
	}
	lim, ok := l.bucket[key]
	if !ok {
		lim = rate.NewLimiter(rate.Every(l.every), l.burst)
		l.bucket[key] = lim
	}
	l.seen[key] = now
	return lim
}
