package poll

import (
	"context"
	"testing"
	"time"
)

// fixedRand returns a constant uniform value (0.5 = no jitter offset).
type fixedRand struct{ v float64 }

func (f fixedRand) Float64() float64 { return f.v }

// seqRand cycles a scripted value list.
type seqRand struct {
	i    int
	vals []float64
}

func (s *seqRand) Float64() float64 {
	v := s.vals[s.i%len(s.vals)]
	s.i++
	return v
}

func TestJitterBoundsAndMidpoint(t *testing.T) {
	base := 100 * time.Second
	if got := Jitter(base, 0, fixedRand{0.5}); got != base {
		t.Fatalf("midpoint jitter = %s, want %s", got, base)
	}
	loF, hiF := JitterFactorBounds(0)
	lo, hi := time.Duration(float64(base)*loF), time.Duration(float64(base)*hiF)
	for _, v := range []float64{0, 0.25, 0.5, 0.75, 0.999999} {
		got := Jitter(base, JitterPercent, fixedRand{v})
		if got < lo || got > hi {
			t.Fatalf("jitter(%v) = %s, outside ±10%% [%s,%s]", v, got, lo, hi)
		}
	}
	if got := Jitter(0, JitterPercent, fixedRand{1}); got != 0 {
		t.Fatalf("jitter(0) = %s, want 0", got)
	}
}

func TestAdaptiveBackoffDoublingAndCeilings(t *testing.T) {
	b := AdaptiveBackoff{Rand: fixedRand{0.5}}
	base := 30 * time.Second
	cases := []struct {
		failures int
		want     time.Duration
	}{
		{0, 30 * time.Second},
		{1, 60 * time.Second},
		{2, 120 * time.Second},
		{3, 240 * time.Second},
		{4, 480 * time.Second},
		{5, 900 * time.Second},
		{6, 900 * time.Second},
	}
	for _, tc := range cases {
		if got := b.NextInterval(base, tc.failures); got != tc.want {
			t.Fatalf("failures=%d: %s, want %s", tc.failures, got, tc.want)
		}
	}
	// Critical devices stop at the canonical 5-minute ceiling.
	crit := BackoffContext{Base: base, Critical: true, ConsecutiveFailures: 4}
	if got := b.NextIntervalFor(crit); got != CriticalBackoffCeiling {
		t.Fatalf("critical ceiling = %s, want %s", got, CriticalBackoffCeiling)
	}
	// The richer hook also serves the S1 NextInterval surface.
	if got := b.NextInterval(60*time.Second, 1); got != 120*time.Second {
		t.Fatalf("standard failure = %s, want 2m", got)
	}
}

func TestAdaptiveBackoffRecoveryRecheckAndPressure(t *testing.T) {
	b := AdaptiveBackoff{Rand: fixedRand{0.5}}
	// Recovery after a failure streak: one rapid re-check at the fast interval.
	rec := BackoffContext{Base: 5 * time.Minute, Recovered: true}
	if got := b.NextIntervalFor(rec); got != RecoveryRecheckMax {
		t.Fatalf("recovery re-check = %s, want %s", got, RecoveryRecheckMax)
	}
	// A fast target recovers at its own base (30 s = RecoveryRecheckMax).
	if got := b.NextIntervalFor(BackoffContext{Base: FastInterval, Recovered: true}); got != FastInterval {
		t.Fatalf("fast recovery = %s, want %s", got, FastInterval)
	}
	// CPU pressure doubles per step, capped at the ceiling.
	press := []time.Duration{60 * time.Second, 120 * time.Second, 240 * time.Second, 480 * time.Second, 900 * time.Second, 900 * time.Second}
	for i, want := range press {
		got := b.NextIntervalFor(BackoffContext{Base: FastInterval, CPUPressureSteps: i + 1})
		if got != want {
			t.Fatalf("pressure step %d = %s, want %s", i+1, got, want)
		}
	}
	// Failures take precedence over pressure when both are set.
	both := BackoffContext{Base: FastInterval, ConsecutiveFailures: 1, CPUPressureSteps: 5}
	if got := b.NextIntervalFor(both); got != 60*time.Second {
		t.Fatalf("failure+pressure = %s, want 60s", got)
	}
}

func TestEngineBackoffLadder(t *testing.T) {
	cases := map[int]time.Duration{
		0: 0, 1: 30 * time.Second, 2: 60 * time.Second, 3: 300 * time.Second, 7: 300 * time.Second,
	}
	for failures, want := range cases {
		if got := EngineBackoffLadder(failures); got != want {
			t.Fatalf("ladder(%d) = %s, want %s", failures, got, want)
		}
	}
}

// TestSchedulerAdaptiveCadenceRecovery drives the engine with the adaptive
// policy and a deterministic jitter midpoint: failures double the cadence to
// the 15-minute ceiling and the first success schedules a rapid re-check.
func TestSchedulerAdaptiveCadenceRecovery(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	clock := newTestClock(t0)
	fail := Result{PollType: PollICMP, Sent: 3, LossPercent: 100, ErrorClass: ErrorTimeout}
	ok := Result{PollType: PollICMP, Sent: 3, Received: 3}
	prober := &fakeProber{script: []Result{fail, fail, fail, fail, fail, fail, ok, ok, ok}}
	eng, healths := newTestEngine(clock, prober, func(c *Config) {
		c.Backoff = AdaptiveBackoff{Rand: fixedRand{0.5}}
	})
	eng.ApplyTargets([]Target{target("dev", TierFast)})

	step := func() {
		t.Helper()
		if n := eng.Step(context.Background(), clock.Now()); n != 1 {
			t.Fatalf("step probed %d, want 1", n)
		}
	}
	advance := func(d time.Duration) {
		t.Helper()
		clock.Advance(d)
	}
	step() // failure 1 -> next +60s
	advance(60 * time.Second)
	step() // failure 2 -> +120s
	advance(120 * time.Second)
	step() // failure 3 -> +240s
	advance(240 * time.Second)
	step() // failure 4 -> +480s
	advance(480 * time.Second)
	step() // failure 5 -> capped +900s
	advance(900 * time.Second)
	step() // failure 6 -> capped +900s
	advance(900 * time.Second)
	step() // success -> rapid re-check at +30s
	advance(30 * time.Second)
	step() // success -> tier cadence +30s
	advance(30 * time.Second)
	step() // success -> +30s

	n := len(*healths)
	wantFailures := []int{1, 2, 3, 4, 5, 6, 0, 0, 0}
	if n != len(wantFailures) {
		t.Fatalf("health rows = %d, want %d", n, len(wantFailures))
	}
	for i, want := range wantFailures {
		if (*healths)[i].ConsecutiveFailures != want {
			t.Fatalf("health[%d].failures = %d, want %d", i, (*healths)[i].ConsecutiveFailures, want)
		}
	}
	// The last failure probes happened at the 900 s ceiling; the recovering
	// success is reached at the ceiling too, and the NEXT probe after recovery
	// is the rapid re-check 30 s later (first success after the streak).
	got := []time.Duration{
		(*healths)[5].CheckedAt.Sub((*healths)[4].CheckedAt),
		(*healths)[6].CheckedAt.Sub((*healths)[5].CheckedAt),
		(*healths)[7].CheckedAt.Sub((*healths)[6].CheckedAt),
	}
	if got[0] != 900*time.Second || got[1] != 900*time.Second || got[2] != 30*time.Second {
		t.Fatalf("cadence deltas = %v, want [15m 15m 30s]", got)
	}
}

// TestSchedulerCPUPressureGuard proves the hrProcessorLoad guard steps the
// cadence down without counting failures, and recovery re-checks quickly.
func TestSchedulerCPUPressureGuard(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	clock := newTestClock(t0)
	hot := Result{PollType: PollSNMP, SnmpDone: true, CPULoadHigh: true, SnmpSamples: []Sample{
		{MetricKey: MetricSysCPUUtil, Value: 95},
	}}
	cool := Result{PollType: PollSNMP, SnmpDone: true, SnmpSamples: []Sample{
		{MetricKey: MetricSysCPUUtil, Value: 10},
	}}
	prober := &fakeProber{script: []Result{hot, hot, hot, cool, cool, cool}}
	eng, healths := newTestEngine(clock, prober, func(c *Config) {
		c.Backoff = AdaptiveBackoff{Rand: fixedRand{0.5}}
	})
	eng.ApplyTargets([]Target{target("dev", TierFast)})

	step := func() {
		t.Helper()
		if n := eng.Step(context.Background(), clock.Now()); n != 1 {
			t.Fatalf("step probed %d, want 1", n)
		}
	}
	step() // pressure 1 -> +60s
	if h := (*healths)[0]; h.Outcome != OutcomeSuccess || h.ErrorClass != ErrorCPUPressure || h.ConsecutiveFailures != 0 {
		t.Fatalf("pressure health = %+v", h)
	}
	clock.Advance(60 * time.Second)
	step() // pressure 2 -> +120s
	clock.Advance(120 * time.Second)
	step() // pressure 3 -> +240s
	clock.Advance(240 * time.Second)
	step() // cool -> recovery re-check +30s
	if h := (*healths)[3]; h.ErrorClass != "" || h.Outcome != OutcomeSuccess {
		t.Fatalf("cool health = %+v", h)
	}
	clock.Advance(30 * time.Second)
	step() // back to base +30s
	clock.Advance(30 * time.Second)
	if n := eng.Step(context.Background(), clock.Now()); n != 1 {
		t.Fatalf("final step probed %d, want 1", n)
	}
}

// TestSchedulerEngineLevelFailureLadder proves the engine-level floor: when
// entire cycles fail, untilNext is floored by the canonical 30→60→300 ladder,
// and a single success resets it.
func TestSchedulerEngineLevelFailureLadder(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	clock := newTestClock(t0)
	fail := Result{PollType: PollICMP, Sent: 1, ErrorClass: ErrorTimeout}
	ok := Result{PollType: PollICMP, Sent: 1, Received: 1}
	prober := &fakeProber{script: []Result{fail, fail, fail, fail, ok, ok}}
	eng, _ := newTestEngine(clock, prober, func(c *Config) {
		c.Backoff = AdaptiveBackoff{Rand: fixedRand{0.5}}
	})
	eng.ApplyTargets([]Target{target("fast", TierFast), target("std", TierStandard)})

	// Cycle 1: both fail; ladder(1)=30s does not exceed the per-target 60s/120s.
	eng.Step(context.Background(), clock.Now())
	clock.Advance(60 * time.Second)
	// Cycle 2: fast fails again; ladder(2)=60s equals the standard target's due.
	eng.Step(context.Background(), clock.Now())
	clock.Advance(60 * time.Second)
	// Cycle 3: standard fails; per-target nexts are now 240s (fast overdue at
	// +180s would be next), but ladder(3)=300s floors the engine wait.
	eng.Step(context.Background(), clock.Now())
	if got := eng.untilNext(clock.Now()); got != EngineBackoffCap {
		t.Fatalf("untilNext after all-failed cycles = %s, want %s", got, EngineBackoffCap)
	}
	if eng.engineFailures != 3 {
		t.Fatalf("engineFailures = %d, want 3", eng.engineFailures)
	}
	// Any successful probe resets the ladder.
	clock.Advance(EngineBackoffCap)
	eng.Step(context.Background(), clock.Now())
	if eng.engineFailures != 0 {
		t.Fatalf("engineFailures after success = %d, want 0", eng.engineFailures)
	}
}

// TestSchedulerJitterObservable proves schedules vary within ±10% for a
// scripted RNG sequence and stay exact at the midpoint.
func TestSchedulerJitterObservable(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	clock := newTestClock(t0)
	prober := &fakeProber{}
	rng := &seqRand{vals: []float64{0.25, 0.75}}
	eng, healths := newTestEngine(clock, prober, func(c *Config) {
		c.Backoff = AdaptiveBackoff{Rand: rng}
	})
	eng.ApplyTargets([]Target{target("dev", TierStandard)})
	eng.Step(context.Background(), clock.Now()) // first interval jitter +? -> 0.25 => 0.95*60=57s
	clock.Advance(57 * time.Second)
	eng.Step(context.Background(), clock.Now()) // 0.75 => 1.05*60=63s
	clock.Advance(63 * time.Second)
	eng.Step(context.Background(), clock.Now())

	got := []time.Duration{
		(*healths)[1].CheckedAt.Sub((*healths)[0].CheckedAt),
		(*healths)[2].CheckedAt.Sub((*healths)[1].CheckedAt),
	}
	want := []time.Duration{57 * time.Second, 63 * time.Second}
	base := StandardInterval
	lo := time.Duration(float64(base) * 0.9)
	hi := time.Duration(float64(base) * 1.1)
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("jittered interval[%d] = %s, want %s", i, got[i], want[i])
		}
		if got[i] < lo || got[i] > hi {
			t.Fatalf("jittered interval %s outside [%s,%s]", got[i], lo, hi)
		}
	}
}

// TestSchedulerFixedBackoffUnchanged guards the S1 default behavior: without an
// adaptive policy the tier cadence is exact and the engine ladder never floors.
func TestSchedulerFixedBackoffUnchanged(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	clock := newTestClock(t0)
	fail := Result{PollType: PollICMP, Sent: 1, ErrorClass: ErrorTimeout}
	prober := &fakeProber{script: []Result{fail, fail}}
	eng, _ := newTestEngine(clock, prober)
	eng.ApplyTargets([]Target{target("dev", TierFast)})
	eng.Step(context.Background(), clock.Now())
	if eng.engineFailures != 1 {
		t.Fatalf("engineFailures = %d, want 1", eng.engineFailures)
	}
	// FixedBackoff keeps the exact tier cadence; the ladder only floors waits
	// (30s here) and never shortens one.
	if got := eng.untilNext(clock.Now()); got != FastInterval {
		t.Fatalf("untilNext = %s, want %s", got, FastInterval)
	}
}
