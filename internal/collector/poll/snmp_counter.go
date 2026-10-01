package poll

import (
	"math"
	"time"
)

// Counter widths (canonical docs/07 §12.3: HC 64-bit counters are mandatory
// for bandwidth; 32-bit counters are still handled for errors/discards).
const (
	CounterWidth32 = 32
	CounterWidth64 = 64
)

// CounterConfig describes one counter series.
type CounterConfig struct {
	// Width is 32 or 64 (anything else is treated as 64).
	Width int
	// MaxRate is the plausible upper bound in units/second used to reject a
	// modular delta that would be a false spike (e.g. a reset from a high
	// value misread as a wrap). Zero disables the guard.
	MaxRate float64
}

// Counter reseed/update reasons (stable strings for logs/tests).
const (
	CounterReasonSeed          = "seed"
	CounterReasonDelta         = "delta"
	CounterReasonWrap          = "wrap"
	CounterReasonReset         = "reset"
	CounterReasonDiscontinuity = "discontinuity"
	CounterReasonReboot        = "reboot"
	CounterReasonOutOfOrder    = "out_of_order"
	CounterReasonRateGuard     = "rate_guard"
)

// CounterUpdate is the outcome of one counter observation.
type CounterUpdate struct {
	Emitted  bool    // a rate sample should be produced
	Rate     float64 // delta/elapsed in units/second when Emitted
	Reseeded bool    // baseline was reset; no sample this cycle
	Reason   string
}

// counterState is the per-series counter state machine (P2-AC-16). Rules:
//
//  1. First observation seeds the baseline (no sample).
//  2. A change of ifCounterDiscontinuityTime reseeds (no false spike).
//  3. A device reboot (sysUpTime drop, detected by the prober) reseeds all
//     counters via Reseed; the next observation seeds again.
//  4. value >= previous: delta = value - previous.
//  5. value < previous: if the previous value sits in the upper half of the
//     counter space, the decrease is treated as a wrap and the modular delta
//     is used (32- and 64-bit); otherwise it is a reset and reseeds. This is
//     the canonical "width + boot-time heuristic" (docs/07 §12.3).
//  6. Any delta whose implied rate exceeds MaxRate is rejected as a false
//     spike (reseed), never emitted as a rate.
//  7. Non-positive elapsed time (out-of-order replay, duplicate ts) is
//     ignored without advancing state.
//
// A 32-bit counter that wraps more than once per interval cannot be inverted
// (information loss); the documented requirement is HC counters for bandwidth,
// and the rate guard guarantees no false spike in that case.
type counterState struct {
	cfg               CounterConfig
	seeded            bool
	last              uint64
	lastTs            time.Time
	lastDiscontinuity uint64
	discontinuitySeen bool
}

func newCounterState(cfg CounterConfig) *counterState {
	if cfg.Width != CounterWidth32 {
		cfg.Width = CounterWidth64
	}
	return &counterState{cfg: cfg}
}

// mask returns the counter modulus - 1.
func (s *counterState) mask() uint64 {
	if s.cfg.Width == CounterWidth32 {
		return math.MaxUint32
	}
	return math.MaxUint64
}

// Reseed clears the baseline (device reboot or a caller-detected reset). The
// next Update seeds and emits nothing.
func (s *counterState) Reseed() {
	s.seeded = false
}

// Update consumes one counter observation.
func (s *counterState) Update(value uint64, ts time.Time, discontinuity *uint64) CounterUpdate {
	if discontinuity != nil {
		if !s.discontinuitySeen {
			s.lastDiscontinuity = *discontinuity
			s.discontinuitySeen = true
		} else if *discontinuity != s.lastDiscontinuity {
			s.lastDiscontinuity = *discontinuity
			s.seed(value, ts)
			return CounterUpdate{Reseeded: true, Reason: CounterReasonDiscontinuity}
		}
	}
	if !s.seeded {
		s.seed(value, ts)
		return CounterUpdate{Reseeded: true, Reason: CounterReasonSeed}
	}
	elapsed := ts.Sub(s.lastTs)
	if elapsed <= 0 {
		return CounterUpdate{Reason: CounterReasonOutOfOrder}
	}

	var (
		delta   uint64
		wrapped bool
	)
	if value >= s.last {
		delta = value - s.last
	} else {
		mask := s.mask()
		if s.last > mask/2 {
			// Modular wrap: last is close enough to the ceiling that the
			// decrease is a wrap, not a reset.
			delta = mask - s.last + value + 1
			wrapped = true
		} else {
			s.seed(value, ts)
			return CounterUpdate{Reseeded: true, Reason: CounterReasonReset}
		}
	}

	rate := float64(delta) / elapsed.Seconds()
	if s.cfg.MaxRate > 0 && rate > s.cfg.MaxRate {
		// False-spike guard: the implied rate is physically implausible, so
		// the baseline is untrustworthy (reset misread as wrap). Reseed.
		s.seed(value, ts)
		return CounterUpdate{Reseeded: true, Reason: CounterReasonRateGuard}
	}
	s.last, s.lastTs = value, ts
	reason := CounterReasonDelta
	if wrapped {
		reason = CounterReasonWrap
	}
	return CounterUpdate{Emitted: true, Rate: rate, Reason: reason}
}

func (s *counterState) seed(value uint64, ts time.Time) {
	s.seeded = true
	s.last = value
	s.lastTs = ts
}
