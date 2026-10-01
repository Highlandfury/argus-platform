package poll

import (
	"sync"
	"time"
)

// Rate and safety limits (P2-AC-18).
//
// Canonical references:
//   - docs/07 §12.3 "Sessions": pooled per device; concurrency by tier
//     (fast 1, standard 2, slow 2); global collector cap ~100 concurrent
//     sessions; "no more than one walk in flight per device".
//   - docs/07 §12.3 "Rate safety": per-device request budget
//     "≤ 300 requests/min standard" enforced by the probe gate.
//   - docs/15 §27: "SNMP sessions ~100 concurrent GETBULKs max, ICMP 20
//     flows, ... queue overflow = skip + count (accounted), never unbounded
//     memory".
//
// Canonical names the standard-profile budget (300/min) and the tier session
// caps (fast 1, standard 2, slow 2) but is silent on the other profiles; this
// build picks conservative, documented values: fast keeps the canonical
// standard ceiling (its cadence already bounds request volume), slow gets a
// lower ceiling for expensive table walks, and inventory — not listed by the
// canonical tier table — mirrors the slow profile.
const (
	// RequestsPerMinuteStandard is the canonical per-device request budget.
	RequestsPerMinuteStandard = 300
	// RequestsPerMinuteFast keeps the canonical standard ceiling: the 30 s
	// cadence already bounds requests far below it.
	RequestsPerMinuteFast = 300
	// RequestsPerMinuteSlow is a conservative documented choice (canonical
	// silent): expensive slow-tier table walks get half the standard budget.
	RequestsPerMinuteSlow = 120
	// RequestsPerMinuteInventory is a conservative documented choice.
	RequestsPerMinuteInventory = 60

	// RequestBudgetWindow is the sliding window the budget is measured over.
	RequestBudgetWindow = time.Minute

	// DefaultGlobalSessionCap is the canonical collector-wide concurrent SNMP
	// session ceiling (~100, docs/07 §12.3 / docs/15 §27).
	DefaultGlobalSessionCap = 100

	// Tier session caps (docs/07 §12.3): fast 1, standard 2, slow 2.
	SessionCapFast     = 1
	SessionCapStandard = 2
	SessionCapSlow     = 2
	// SessionCapInventory mirrors the slow profile (canonical tier table does
	// not list inventory sessions; conservative documented choice).
	SessionCapInventory = 1
)

// RequestsPerMinute returns the canonical per-device request budget for a tier
// (docs/07 §12.3; conservative documented choices for the profiles canonical
// leaves unstated).
func RequestsPerMinute(tier string) int {
	switch NormalizeTier(tier) {
	case TierFast:
		return RequestsPerMinuteFast
	case TierSlow:
		return RequestsPerMinuteSlow
	case TierInventory:
		return RequestsPerMinuteInventory
	default:
		return RequestsPerMinuteStandard
	}
}

// TierSessionCap returns the per-device session concurrency cap for a tier
// (docs/07 §12.3).
func TierSessionCap(tier string) int {
	switch NormalizeTier(tier) {
	case TierFast:
		return SessionCapFast
	case TierSlow:
		return SessionCapSlow
	case TierInventory:
		return SessionCapInventory
	default:
		return SessionCapStandard
	}
}

// RequestLimiter is a per-device sliding-window request budget. Allow records
// the request when it fits; denied requests are not recorded (a saturated
// device cannot grow the window). It is safe for concurrent use.
type RequestLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	now    func() time.Time
	stamps []time.Time
}

// NewRequestLimiter builds a limiter for maxPerWindow requests per window.
// now defaults to time.Now.
func NewRequestLimiter(maxPerWindow int, now func() time.Time) *RequestLimiter {
	if now == nil {
		now = time.Now
	}
	if maxPerWindow <= 0 {
		maxPerWindow = RequestsPerMinuteStandard
	}
	return &RequestLimiter{max: maxPerWindow, window: RequestBudgetWindow, now: now}
}

// Allow reports whether one more request fits the budget, recording it when
// it does.
func (l *RequestLimiter) Allow() bool {
	if l == nil {
		return true
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(now)
	if len(l.stamps) >= l.max {
		return false
	}
	l.stamps = append(l.stamps, now)
	return true
}

// Count returns the requests recorded in the current window (tests/metrics).
func (l *RequestLimiter) Count() int {
	if l == nil {
		return 0
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(now)
	return len(l.stamps)
}

// Max returns the configured budget.
func (l *RequestLimiter) Max() int {
	if l == nil {
		return 0
	}
	return l.max
}

func (l *RequestLimiter) pruneLocked(now time.Time) {
	cutoff := now.Add(-l.window)
	keep := l.stamps[:0]
	for _, t := range l.stamps {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	l.stamps = keep
}

// SessionLimiter enforces the per-device tier session caps and the global
// collector-wide SNMP session ceiling (docs/07 §12.3). Acquisition is
// non-blocking: at the cap the probe is skipped and accounted
// (`rate_limited`), never queued unboundedly (docs/15 §27).
type SessionLimiter struct {
	mu          sync.Mutex
	globalMax   int
	globalInUse int
	perDevice   map[string]int
}

// NewSessionLimiter builds a limiter with the given global cap (<=0 takes the
// canonical ~100).
func NewSessionLimiter(globalMax int) *SessionLimiter {
	if globalMax <= 0 {
		globalMax = DefaultGlobalSessionCap
	}
	return &SessionLimiter{globalMax: globalMax, perDevice: make(map[string]int)}
}

// Acquire reserves one session for (deviceID, tier). It returns a release
// function on success; ok is false when the device's tier cap or the global
// cap is reached. The release function is idempotent.
func (l *SessionLimiter) Acquire(deviceID, tier string) (release func(), ok bool) {
	if l == nil {
		return func() {}, true
	}
	limit := TierSessionCap(tier)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.globalInUse >= l.globalMax || l.perDevice[deviceID] >= limit {
		return nil, false
	}
	l.globalInUse++
	l.perDevice[deviceID]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.globalInUse--
			l.perDevice[deviceID]--
			if l.perDevice[deviceID] <= 0 {
				delete(l.perDevice, deviceID)
			}
		})
	}, true
}

// GlobalInUse returns the current global session count (tests/metrics).
func (l *SessionLimiter) GlobalInUse() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.globalInUse
}

// GlobalMax returns the configured global ceiling.
func (l *SessionLimiter) GlobalMax() int {
	if l == nil {
		return 0
	}
	return l.globalMax
}

// DeviceInUse returns the current session count for a device (tests).
func (l *SessionLimiter) DeviceInUse(deviceID string) int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.perDevice[deviceID]
}
