package poll

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// testClock is a deterministic clock: Now is frozen unless advanced, and
// After returns a channel that fires when the deadline is reached (tests that
// drive Step directly never need to wait).
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock(t time.Time) *testClock { return &testClock{now: t} }

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func (c *testClock) After(_ time.Duration) <-chan time.Time {
	// Only Run uses After; the deterministic tests call Step directly and
	// never park on this channel.
	ch := make(chan time.Time)
	close(ch)
	return ch
}

// fakeProber records probes and returns a scripted sequence of results.
type fakeProber struct {
	mu     sync.Mutex
	calls  []string
	script []Result
	idx    int
}

func (f *fakeProber) Probe(_ context.Context, target Target) Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, target.DeviceID)
	if len(f.script) == 0 {
		return Result{PollType: PollICMP, Sent: 3, Received: 3, LossPercent: 0}
	}
	r := f.script[f.idx%len(f.script)]
	f.idx++
	return r
}

func (f *fakeProber) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func target(id string, tier string) Target {
	return Target{DeviceID: id, MgmtIP: netip.MustParseAddr("192.0.2.10"), Name: id, Tier: tier}
}

func newTestEngine(clock Clock, prober Prober, opts ...func(*Config)) (*Engine, *[]Health) {
	var mu sync.Mutex
	healths := &[]Health{}
	cfg := Config{
		Prober: prober,
		Clock:  clock,
		OnHealth: func(h Health) {
			mu.Lock()
			defer mu.Unlock()
			*healths = append(*healths, h)
		},
	}
	for _, o := range opts {
		o(&cfg)
	}
	return NewEngine(cfg), healths
}

func TestTierIntervalsAndNormalization(t *testing.T) {
	cases := []struct {
		tier string
		want time.Duration
	}{
		{TierFast, 30 * time.Second},
		{TierStandard, 60 * time.Second},
		{TierSlow, 5 * time.Minute},
		{TierInventory, 6 * time.Hour},
		{"FAST", 30 * time.Second},
		{" fast ", 30 * time.Second},
		{"unknown", 60 * time.Second},
		{"", 60 * time.Second},
	}
	for _, tc := range cases {
		if got := TierInterval(tc.tier); got != tc.want {
			t.Errorf("TierInterval(%q) = %s, want %s", tc.tier, got, tc.want)
		}
	}
	if got := NormalizeTier("weird"); got != TierStandard {
		t.Errorf("NormalizeTier(weird) = %q, want standard", got)
	}
}

func TestTargetFromPolicyValidation(t *testing.T) {
	if _, err := TargetFromPolicy(TargetSpec{DeviceID: "dev-1", MgmtIP: "not-an-ip", Name: "d", Tier: TierFast}); err == nil {
		t.Fatal("invalid IP must be rejected")
	}
	if _, err := TargetFromPolicy(TargetSpec{DeviceID: "", MgmtIP: "192.0.2.1", Name: "d", Tier: TierFast}); err == nil {
		t.Fatal("empty device id must be rejected")
	}
	got, err := TargetFromPolicy(TargetSpec{DeviceID: "dev-1", MgmtIP: "192.0.2.1", Name: "d", Tier: "nonsense"})
	if err != nil {
		t.Fatalf("TargetFromPolicy: %v", err)
	}
	if got.Tier != TierStandard {
		t.Fatalf("unknown tier normalized to %q, want standard", got.Tier)
	}
	if got.PollType != PollICMP {
		t.Fatalf("unknown poll type normalized to %q, want icmp", got.PollType)
	}
	snmp, err := TargetFromPolicy(TargetSpec{DeviceID: "dev-1", MgmtIP: "192.0.2.1", Name: "d", Tier: TierFast, PollType: PollSNMP, Kind: "switch"})
	if err != nil {
		t.Fatalf("TargetFromPolicy snmp: %v", err)
	}
	if snmp.PollType != PollSNMP || snmp.Kind != "switch" {
		t.Fatalf("snmp target = %+v, want snmp/switch", snmp)
	}
	if snmp.Key() != "dev-1:snmp" {
		t.Fatalf("target key = %q, want dev-1:snmp", snmp.Key())
	}
}

// TestSchedulerDeterministicTiers drives the scheduler with a frozen clock and
// proves each tier's cadence exactly (P2-AC-17 defaults).
func TestSchedulerDeterministicTiers(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	clock := newTestClock(t0)
	prober := &fakeProber{}
	eng, _ := newTestEngine(clock, prober)
	eng.ApplyTargets([]Target{target("fast-dev", TierFast), target("std-dev", TierStandard)})

	if n := eng.Step(context.Background(), clock.Now()); n != 2 {
		t.Fatalf("initial step probed %d, want 2", n)
	}
	if prober.callCount() != 2 {
		t.Fatalf("calls = %d, want 2", prober.callCount())
	}

	// +29s: nothing due.
	clock.Advance(29 * time.Second)
	if n := eng.Step(context.Background(), clock.Now()); n != 0 {
		t.Fatalf("step at +29s probed %d, want 0", n)
	}
	// +30s: fast only.
	clock.Advance(time.Second)
	if n := eng.Step(context.Background(), clock.Now()); n != 1 {
		t.Fatalf("step at +30s probed %d, want 1 (fast)", n)
	}
	// +60s: standard due; fast is due again (its next run was +60s).
	clock.Advance(30 * time.Second)
	if n := eng.Step(context.Background(), clock.Now()); n != 2 {
		t.Fatalf("step at +60s probed %d, want 2", n)
	}
	if prober.callCount() != 5 {
		t.Fatalf("total calls = %d, want 5", prober.callCount())
	}
}

// TestSchedulerBackoffHook proves the M9-S4 hook is consulted on failure and
// honored for rescheduling (the S1 default is FixedBackoff).
func TestSchedulerBackoffHook(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	clock := newTestClock(t0)
	prober := &fakeProber{script: []Result{
		{PollType: PollICMP, Sent: 3, Received: 0, LossPercent: 100, ErrorClass: ErrorTimeout},
		{PollType: PollICMP, Sent: 3, Received: 3, LossPercent: 0},
	}}
	hookCalls := 0
	eng, healths := newTestEngine(clock, prober, func(c *Config) {
		c.Backoff = backoffFunc(func(base time.Duration, failures int) time.Duration {
			hookCalls++
			if failures > 0 {
				return base * 2
			}
			return base
		})
	})
	eng.ApplyTargets([]Target{target("dev", TierFast)})

	eng.Step(context.Background(), clock.Now())
	if hookCalls != 1 {
		t.Fatalf("backoff hook calls = %d, want 1", hookCalls)
	}
	if (*healths)[0].ConsecutiveFailures != 1 || (*healths)[0].Outcome != OutcomeFailure {
		t.Fatalf("failure health = %+v", (*healths)[0])
	}
	// Fixed cadence would make it due at +30s; the 2x hook pushes it to +60s.
	clock.Advance(30 * time.Second)
	if n := eng.Step(context.Background(), clock.Now()); n != 0 {
		t.Fatalf("step at +30s probed %d, want 0 (doubled cadence)", n)
	}
	clock.Advance(30 * time.Second)
	if n := eng.Step(context.Background(), clock.Now()); n != 1 {
		t.Fatalf("step at +60s probed %d, want 1", n)
	}
	if (*healths)[1].ConsecutiveFailures != 0 || (*healths)[1].Outcome != OutcomeSuccess {
		t.Fatalf("recovery health = %+v", (*healths)[1])
	}
}

type backoffFunc func(time.Duration, int) time.Duration

func (f backoffFunc) NextInterval(base time.Duration, failures int) time.Duration {
	return f(base, failures)
}

// TestSchedulerApplyTargetsKeepsState: an unchanged target keeps its schedule;
// a removed target is dropped; a new target is due immediately.
func TestSchedulerApplyTargetsKeepsState(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	clock := newTestClock(t0)
	prober := &fakeProber{}
	eng, _ := newTestEngine(clock, prober)
	eng.ApplyTargets([]Target{target("a", TierFast), target("b", TierFast)})
	eng.Step(context.Background(), clock.Now())

	eng.ApplyTargets([]Target{target("b", TierFast), target("c", TierFast)})
	clock.Advance(10 * time.Second)
	// c is new and due now; b is not due before +30s.
	if n := eng.Step(context.Background(), clock.Now()); n != 1 {
		t.Fatalf("step probed %d, want 1 (new target c)", n)
	}
	if got := eng.Targets(); len(got) != 2 || got[0].DeviceID != "b" || got[1].DeviceID != "c" {
		t.Fatalf("targets after apply = %+v", got)
	}
}

// TestSchedulerRemovedTargetDiscardsProbe: completing a probe for a target
// removed mid-flight must not panic or re-add it.
func TestSchedulerRemovedTargetDiscardsProbe(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	clock := newTestClock(t0)
	prober := &blockingProber{started: make(chan struct{}), release: make(chan struct{})}
	eng, _ := newTestEngine(clock, prober)
	eng.ApplyTargets([]Target{target("gone", TierFast)})

	done := make(chan int, 1)
	go func() { done <- eng.Step(context.Background(), clock.Now()) }()
	<-prober.started
	eng.ApplyTargets(nil)
	close(prober.release)
	if n := <-done; n != 1 {
		t.Fatalf("step probed %d, want 1", n)
	}
	if got := eng.Targets(); len(got) != 0 {
		t.Fatalf("targets after removal = %+v", got)
	}
}

type blockingProber struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingProber) Probe(_ context.Context, _ Target) Result {
	b.once.Do(func() { close(b.started) })
	<-b.release
	return Result{PollType: PollICMP, Sent: 1, Received: 1}
}

// TestSchedulerRunCancels: Run exits promptly on context cancellation.
func TestSchedulerRunCancels(t *testing.T) {
	eng := NewEngine(Config{Prober: &fakeProber{}, Clock: RealClock{}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { eng.Run(ctx); close(done) }()
	eng.ApplyTargets([]Target{target("a", TierFast)})
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not exit on cancellation")
	}
}

func TestProbeEmitsSamplesAndHealth(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	clock := newTestClock(t0)
	prober := &fakeProber{script: []Result{{
		PollType: PollICMP, Sent: 3, Received: 2, LossPercent: 100.0 / 3.0,
		RTTAvg: 12 * time.Millisecond, Latency: 250 * time.Millisecond, ErrorClass: ErrorLoss,
	}}}
	var samples []Sample
	eng, healths := newTestEngine(clock, prober, func(c *Config) {
		c.OnSample = func(s Sample) { samples = append(samples, s) }
	})
	eng.ApplyTargets([]Target{target("dev-1", TierFast)})
	eng.Step(context.Background(), clock.Now())

	if len(samples) != 3 {
		t.Fatalf("samples = %d, want 3 (reachable, loss, rtt)", len(samples))
	}
	for _, s := range samples {
		if s.DeviceID != "dev-1" {
			t.Fatalf("sample %s device = %q, want dev-1", s.MetricKey, s.DeviceID)
		}
	}
	h := (*healths)[0]
	if h.LatencyMS != 250 || h.ErrorClass != ErrorLoss || h.Outcome != OutcomeSuccess {
		t.Fatalf("health = %+v", h)
	}
}

var errFakePing = errors.New("fake ping failure")

func TestClassifyPingError(t *testing.T) {
	if got := classifyPingError(ErrUnsupportedPlatform); got != ErrorUnsupported {
		t.Fatalf("unsupported = %q", got)
	}
	if got := classifyPingError(context.DeadlineExceeded); got != ErrorTimeout {
		t.Fatalf("deadline = %q", got)
	}
	if got := classifyPingError(errFakePing); got != ErrorUnreachable {
		t.Fatalf("generic = %q", got)
	}
}
