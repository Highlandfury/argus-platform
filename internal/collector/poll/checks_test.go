package poll

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

// checkFakeProber records calls and returns a scripted result.
type checkFakeProber struct {
	calls  []Target
	result Result
}

func (p *checkFakeProber) Probe(_ context.Context, target Target) Result {
	p.calls = append(p.calls, target)
	return p.result
}

// TestCheckExecutorRunsImmediateProbeWithoutSamples proves the on-demand path:
// the probe runs against the applied target, no metric samples are emitted, and
// exactly one on_demand health row is produced.
func TestCheckExecutorRunsImmediateProbeWithoutSamples(t *testing.T) {
	target := Target{
		DeviceID: "0198d5a3-0000-7000-8000-000000000010",
		MgmtIP:   netip.MustParseAddr("192.0.2.10"),
		Name:     "cr7", Tier: TierStandard, PollType: PollICMP,
	}
	prober := &checkFakeProber{result: Result{
		PollType: PollICMP, Sent: 3, Received: 3,
		RTTAvg: 2 * time.Millisecond, Latency: 3 * time.Millisecond,
	}}
	var health []Health
	runner := NewCheckExecutor(prober, func() []Target { return []Target{target} }, func(h Health) {
		health = append(health, h)
	})

	res, ok := runner.RunCheck(context.Background(), target.DeviceID, "icmp")
	if !ok {
		t.Fatal("target not found in the applied policy")
	}
	if res.Outcome() != OutcomeSuccess {
		t.Fatalf("outcome = %s, want success", res.Outcome())
	}
	if len(prober.calls) != 1 || prober.calls[0].DeviceID != target.DeviceID {
		t.Fatalf("prober calls = %+v", prober.calls)
	}
	if samples := res.Samples(target, time.Now()); len(samples) == 0 {
		t.Fatal("fixture result should render samples; the executor must discard them (assertion only)")
	}
	if len(health) != 1 {
		t.Fatalf("health rows = %d, want 1", len(health))
	}
	if health[0].Origin != OriginOnDemand || health[0].PollType != PollICMP || health[0].ConsecutiveFailures != 0 {
		t.Fatalf("health = %+v, want on_demand icmp with 0 failures", health[0])
	}
}

// TestCheckExecutorTargetMissing proves an unknown device/poll-type yields
// found=false (the adapter maps it to target_missing) and never probes.
func TestCheckExecutorTargetMissing(t *testing.T) {
	prober := &checkFakeProber{}
	runner := NewCheckExecutor(prober, func() []Target {
		return []Target{{
			DeviceID: "0198d5a3-0000-7000-8000-000000000010",
			MgmtIP:   netip.MustParseAddr("192.0.2.10"),
			Tier:     TierStandard, PollType: PollICMP,
		}}
	}, nil)

	if _, ok := runner.RunCheck(context.Background(), "0198d5a3-0000-7000-8000-000000000010", "snmp"); ok {
		t.Fatal("snmp target not in policy must not run")
	}
	if _, ok := runner.RunCheck(context.Background(), "0198d5a3-0000-7000-8000-0000000000ff", "icmp"); ok {
		t.Fatal("unknown device must not run")
	}
	if len(prober.calls) != 0 {
		t.Fatalf("prober called %d times, want 0", len(prober.calls))
	}
}

// TestScheduledHealthCarriesScheduledOrigin pins the origin on the scheduled
// path so on_demand rows are unambiguous.
func TestScheduledHealthCarriesScheduledOrigin(t *testing.T) {
	prober := &checkFakeProber{result: Result{PollType: PollICMP, Sent: 1, Received: 1, Latency: time.Millisecond}}
	var health []Health
	engine := NewEngine(Config{
		Prober:   prober,
		Clock:    &checkStaticClock{now: time.Now()},
		OnHealth: func(h Health) { health = append(health, h) },
	})
	engine.ApplyTargets([]Target{{
		DeviceID: "0198d5a3-0000-7000-8000-000000000010",
		MgmtIP:   netip.MustParseAddr("192.0.2.10"),
		Tier:     TierStandard, PollType: PollICMP,
	}})
	if n := engine.Step(context.Background(), time.Now()); n != 1 {
		t.Fatalf("probed %d targets, want 1", n)
	}
	if len(health) != 1 || health[0].Origin != OriginScheduled {
		t.Fatalf("health = %+v, want scheduled origin", health)
	}
}

// checkStaticClock is a fixed Clock (the scheduler tests own richer clocks; this
// keeps the origin assertion self-contained).
type checkStaticClock struct{ now time.Time }

func (c *checkStaticClock) Now() time.Time { return c.now }
func (c *checkStaticClock) After(_ time.Duration) <-chan time.Time {
	ch := make(chan time.Time)
	return ch
}
