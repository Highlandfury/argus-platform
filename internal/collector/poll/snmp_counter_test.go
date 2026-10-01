package poll

import (
	"math"
	"testing"
	"time"
)

func TestCounterSeedThenRate(t *testing.T) {
	c := newCounterState(CounterConfig{Width: CounterWidth64})
	t0 := time.Unix(1000, 0)
	if got := c.Update(1000, t0, nil); got.Emitted || !got.Reseeded || got.Reason != CounterReasonSeed {
		t.Fatalf("first update = %+v, want seed", got)
	}
	got := c.Update(1600, t0.Add(10*time.Second), nil)
	if !got.Emitted || got.Rate != 60 {
		t.Fatalf("second update = %+v, want 60 B/s", got)
	}
}

func TestCounter32BitWrap(t *testing.T) {
	c := newCounterState(CounterConfig{Width: CounterWidth32})
	t0 := time.Unix(1000, 0)
	c.Update(math.MaxUint32-100, t0, nil) // seed near the ceiling
	got := c.Update(200, t0.Add(time.Second), nil)
	if !got.Emitted || got.Rate != 301 {
		t.Fatalf("32-bit wrap = %+v, want 301/s", got)
	}
	if got.Reason != CounterReasonWrap {
		t.Fatalf("reason = %q, want wrap", got.Reason)
	}
}

func TestCounter64BitWrap(t *testing.T) {
	c := newCounterState(CounterConfig{Width: CounterWidth64})
	t0 := time.Unix(1000, 0)
	c.Update(math.MaxUint64-100, t0, nil)
	got := c.Update(50, t0.Add(time.Second), nil)
	if !got.Emitted || got.Rate != 151 {
		t.Fatalf("64-bit wrap = %+v, want 151/s", got)
	}
}

func TestCounterResetFromLowValueReseeds(t *testing.T) {
	c := newCounterState(CounterConfig{Width: CounterWidth32})
	t0 := time.Unix(1000, 0)
	c.Update(1000, t0, nil)
	got := c.Update(10, t0.Add(time.Second), nil)
	if got.Emitted || !got.Reseeded || got.Reason != CounterReasonReset {
		t.Fatalf("reset = %+v, want reseed", got)
	}
	// The next observation seeds and the one after emits from the new baseline.
	c.Update(20, t0.Add(2*time.Second), nil)
	got = c.Update(30, t0.Add(3*time.Second), nil)
	if !got.Emitted || got.Rate != 10 {
		t.Fatalf("post-reset rate = %+v, want 10/s", got)
	}
}

func TestCounterFalseSpikeGuard(t *testing.T) {
	// A garbage jump (here an impossible one-second delta) must be rejected
	// instead of emitted as a rate spike.
	c := newCounterState(CounterConfig{Width: CounterWidth64, MaxRate: 12500000000})
	t0 := time.Unix(1000, 0)
	c.Update(1000, t0, nil)
	got := c.Update(1<<50, t0.Add(time.Second), nil)
	if got.Emitted || !got.Reseeded || got.Reason != CounterReasonRateGuard {
		t.Fatalf("rate guard = %+v, want reseed", got)
	}
}

func TestCounterDiscontinuityChangeReseeds(t *testing.T) {
	c := newCounterState(CounterConfig{Width: CounterWidth64})
	t0 := time.Unix(1000, 0)
	d0, d1 := uint64(0), uint64(77)
	c.Update(1000, t0, &d0)
	if got := c.Update(1100, t0.Add(time.Second), &d0); !got.Emitted {
		t.Fatalf("same discontinuity = %+v, want emitted", got)
	}
	if got := c.Update(1200, t0.Add(2*time.Second), &d1); got.Emitted || got.Reason != CounterReasonDiscontinuity {
		t.Fatalf("discontinuity change = %+v, want reseed", got)
	}
	// Re-seeded: the next change computes from the new baseline.
	got := c.Update(1250, t0.Add(3*time.Second), &d1)
	if !got.Emitted || got.Rate != 50 {
		t.Fatalf("post-discontinuity rate = %+v, want 50/s", got)
	}
}

func TestCounterRebootReseed(t *testing.T) {
	c := newCounterState(CounterConfig{Width: CounterWidth64})
	t0 := time.Unix(1000, 0)
	c.Update(1<<40, t0, nil)
	c.Update((1<<40)+100, t0.Add(time.Second), nil)
	c.Reseed() // device reboot detected by sysUpTime
	if got := c.Update(5, t0.Add(2*time.Second), nil); got.Emitted || got.Reason != CounterReasonSeed {
		t.Fatalf("post-reboot = %+v, want seed (no spike)", got)
	}
	got := c.Update(105, t0.Add(3*time.Second), nil)
	if !got.Emitted || got.Rate != 100 {
		t.Fatalf("post-reboot rate = %+v, want 100/s", got)
	}
}

func TestCounterOutOfOrderIgnored(t *testing.T) {
	c := newCounterState(CounterConfig{Width: CounterWidth64})
	t0 := time.Unix(1000, 0)
	c.Update(1000, t0, nil)
	if got := c.Update(2000, t0, nil); got.Emitted || got.Reason != CounterReasonOutOfOrder {
		t.Fatalf("same-ts update = %+v, want out_of_order", got)
	}
	if got := c.Update(1500, t0.Add(-time.Second), nil); got.Emitted || got.Reason != CounterReasonOutOfOrder {
		t.Fatalf("backwards-ts update = %+v, want out_of_order", got)
	}
	// State did not advance: the next in-order observation is still relative
	// to the original baseline and timestamp.
	got := c.Update(3000, t0.Add(2*time.Second), nil)
	if !got.Emitted || got.Rate != 1000 {
		t.Fatalf("after out-of-order = %+v, want 1000/s", got)
	}
}
