package poll

import (
	"math/rand/v2"
	"time"
)

// Adaptive scheduling constants (P2-AC-17).
//
// Canonical references:
//   - docs/07 §12.3: "device backoff on consecutive failures (doubling to
//     15 min ceiling; critical devices 5 min ceiling); recovery resets fast";
//   - docs/07 §12.4 adaptive rules: "on timeout/CPU-stress signals ... step
//     cadence down (double, capped) with an event; rapid re-check when the
//     device recovers";
//   - docs/06 §9.8: "all schedules jittered ±10%";
//   - docs/06 §10.4: engine-level "adaptive backoff (30s→60s→300s)";
//   - docs/15 §27: ceilings "e.g. 15 min" / critical "ceiling 5 min".
const (
	// BackoffCeiling caps the failure-doubled per-target cadence (15 min).
	BackoffCeiling = 15 * time.Minute
	// CriticalBackoffCeiling caps critical devices at 5 min.
	CriticalBackoffCeiling = 5 * time.Minute
	// EngineBackoffFloor / EngineBackoffMid / EngineBackoffCap are the
	// engine-level global failure ladder: 30s → 60s → 300s (docs/06 §10.4).
	EngineBackoffFloor = 30 * time.Second
	EngineBackoffMid   = 60 * time.Second
	EngineBackoffCap   = 300 * time.Second
	// JitterPercent is the canonical anti-thundering-herd jitter (±10%).
	JitterPercent = 10
	// RecoveryRecheckMax bounds the fast re-check after a recovery: the next
	// probe after a failure streak ends (or a CPU-pressure streak clears) is
	// brought forward to at most one fast-tier interval, then the tier cadence
	// resumes (canonical "rapid re-check when the device recovers").
	RecoveryRecheckMax = FastInterval
)

// RandSource returns a uniform value in [0,1). It is the injectable RNG seam
// for deterministic jitter tests; the production default uses math/rand/v2.
type RandSource interface {
	Float64() float64
}

// defaultRandSource is the production randomness source (concurrency-safe
// package-level functions). Jitter is an anti-thundering-herd spread, not a
// security primitive.
type defaultRandSource struct{}

func (defaultRandSource) Float64() float64 { return rand.Float64() } //nolint:gosec // jitter, not crypto

// Jitter applies ±pct% jitter to base using r. The result never falls below
// one millisecond and never exceeds base*(1+pct/100). A nil source uses the
// process randomness; pct <= 0 takes the canonical 10%.
func Jitter(base time.Duration, pct int, r RandSource) time.Duration {
	if base <= 0 {
		return 0
	}
	if r == nil {
		r = defaultRandSource{}
	}
	if pct <= 0 {
		pct = JitterPercent
	}
	factor := 1 + (r.Float64()*2-1)*float64(pct)/100
	out := time.Duration(float64(base) * factor)
	if out < time.Millisecond {
		out = time.Millisecond
	}
	return out
}

// BackoffContext carries the per-target facts an adaptive policy needs beyond
// the base cadence: the consecutive-failure count, whether the device is
// critical (lower ceiling), whether the last probe recovered the target, and
// the current CPU-pressure streak (agent-reported hrProcessorLoad).
type BackoffContext struct {
	Base                time.Duration
	ConsecutiveFailures int
	Critical            bool
	// Recovered is true for the first successful probe after a failure
	// streak: the policy schedules a rapid re-check before resuming the
	// tier cadence (docs/07 §12.4).
	Recovered bool
	// CPUPressureSteps counts consecutive polls where the device reported
	// high hrProcessorLoad (docs/07 §12.7 device-CPU guard). It steps the
	// cadence down (double, capped) independently of failures.
	CPUPressureSteps int
}

// AdaptiveBackoffPolicy is the richer M9-S4 extension of BackoffPolicy. The
// engine prefers it when the configured policy implements it and falls back to
// BackoffPolicy.NextInterval otherwise (M9-S1 FixedBackoff and custom hooks
// keep working unchanged).
type AdaptiveBackoffPolicy interface {
	NextIntervalFor(BackoffContext) time.Duration
}

// AdaptiveBackoff is the P2-AC-17 policy: failure doubling to the tier
// ceiling, the critical 5-minute ceiling, rapid recovery re-check, CPU-stress
// step-down and ±10% jitter from an injectable RNG.
type AdaptiveBackoff struct {
	// Rand is the jitter source; nil uses math/rand/v2.
	Rand RandSource
	// JitterPercent overrides the canonical ±10%; 0 keeps the default.
	JitterPercent int
}

// NextInterval implements BackoffPolicy (M9-S1 compatibility path).
func (b AdaptiveBackoff) NextInterval(base time.Duration, failures int) time.Duration {
	return b.NextIntervalFor(BackoffContext{Base: base, ConsecutiveFailures: failures})
}

// NextIntervalFor implements AdaptiveBackoffPolicy.
//
// Rule order (canonical):
//  1. failure streak: double the tier cadence once per consecutive failure,
//     capped at 15 min (critical devices 5 min);
//  2. CPU-pressure streak: double the cadence once per poll, same ceiling;
//  3. recovery: one rapid re-check at min(base, 30 s), then the tier cadence;
//  4. otherwise: the tier cadence.
//
// Every result is jittered ±JitterPercent (canonical anti-thundering-herd).
func (b AdaptiveBackoff) NextIntervalFor(bc BackoffContext) time.Duration {
	base := bc.Base
	if base <= 0 {
		base = StandardInterval
	}
	ceiling := BackoffCeiling
	if bc.Critical {
		ceiling = CriticalBackoffCeiling
	}

	var raw time.Duration
	switch {
	case bc.ConsecutiveFailures > 0:
		raw = doubleCapped(base, bc.ConsecutiveFailures, ceiling)
	case bc.CPUPressureSteps > 0:
		raw = doubleCapped(base, bc.CPUPressureSteps, ceiling)
	case bc.Recovered:
		raw = base
		if raw > RecoveryRecheckMax {
			raw = RecoveryRecheckMax
		}
	default:
		raw = base
	}
	return Jitter(raw, b.JitterPercent, b.Rand)
}

// doubleCapped returns base doubled steps times, clamped to ceiling (and never
// below base).
func doubleCapped(base time.Duration, steps int, ceiling time.Duration) time.Duration {
	out := base
	for i := 0; i < steps; i++ {
		if out >= ceiling {
			return ceiling
		}
		out *= 2
		if out > ceiling {
			return ceiling
		}
	}
	return out
}

// EngineBackoffLadder returns the engine-level global failure ladder:
// 30 s, 60 s, 300 s, 300 s, … (docs/06 §10.4). Zero failures means no floor.
func EngineBackoffLadder(consecutiveFailures int) time.Duration {
	switch {
	case consecutiveFailures <= 0:
		return 0
	case consecutiveFailures == 1:
		return EngineBackoffFloor
	case consecutiveFailures == 2:
		return EngineBackoffMid
	default:
		return EngineBackoffCap
	}
}

// JitterFactorBounds returns the closed bounds ±pct% used by tests and docs.
func JitterFactorBounds(pct int) (lo, hi float64) {
	if pct <= 0 {
		pct = JitterPercent
	}
	return 1 - float64(pct)/100, 1 + float64(pct)/100
}
