package integration

// M9-S4 (Phase 2): adaptive scheduling and safety-limit acceptance plus the
// canonical M9 failure-suite additions (P2-AC-17/18, M9 verification list):
// target disappearance mid-run, unreachable management IP, credential removal
// with backoff interplay, collector restart (no stale schedules/counters),
// per-device rate-limit isolation and observed jitter bounds. The DB-backed
// cases run against the containerized database, the pinned snmpsim fixture and
// the real spool -> gRPC -> ingest path; nothing is mocked at the wire
// boundary.

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/collector/poll"
	"github.com/argus-platform/argus/internal/collector/spool"
)

// s4Rand is a fixed [0,1) jitter source (0.5 = exact cadence).
type s4Rand struct{ v float64 }

func (r s4Rand) Float64() float64 { return r.v }

// s4SeqRand cycles scripted jitter values.
type s4SeqRand struct {
	mu   sync.Mutex
	i    int
	vals []float64
}

func (r *s4SeqRand) Float64() float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	v := r.vals[r.i%len(r.vals)]
	r.i++
	return v
}

// s4ScriptedProber returns scripted results in call order (cycling) and keeps
// the call list for assertions.
type s4ScriptedProber struct {
	mu     sync.Mutex
	script []poll.Result
	calls  []poll.Target
	idx    int
}

func (p *s4ScriptedProber) Probe(_ context.Context, target poll.Target) poll.Result {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, target)
	if len(p.script) == 0 {
		return poll.Result{PollType: poll.PollICMP, Sent: 1, Received: 1}
	}
	r := p.script[p.idx%len(p.script)]
	p.idx++
	return r
}

func (p *s4ScriptedProber) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.calls)
}

// s4Sink collects emitted samples and health records.
type s4Sink struct {
	mu      sync.Mutex
	samples []poll.Sample
	health  []poll.Health
}

func (s *s4Sink) sample(x poll.Sample) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.samples = append(s.samples, x)
}

func (s *s4Sink) healthRec(x poll.Health) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.health = append(s.health, x)
}

func (s *s4Sink) takeHealth() []poll.Health {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.health
	s.health = nil
	return out
}

func (s *s4Sink) takeSamples() []poll.Sample {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.samples
	s.samples = nil
	return out
}

// s4AdaptiveEngine wires an engine with the adaptive policy at an exact-jitter
// midpoint so cadence assertions are deterministic.
func s4AdaptiveEngine(clock *itClock, prober poll.Prober, sink *s4Sink) *poll.Engine {
	return poll.NewEngine(poll.Config{
		Prober:      prober,
		Clock:       clock,
		Backoff:     poll.AdaptiveBackoff{Rand: s4Rand{0.5}},
		OnSample:    sink.sample,
		OnHealth:    sink.healthRec,
		Concurrency: 4,
	})
}

func s4Target(deviceID, ip, tier string) poll.Target {
	return poll.Target{
		DeviceID: deviceID, MgmtIP: netip.MustParseAddr(ip), Name: deviceID,
		Tier: tier, PollType: poll.PollICMP,
	}
}

// s4Step probes due targets and flushes the captured samples/health through the
// real spool and collector stream so they land in the database. It returns the
// flushed samples/health for assertions.
func s4Step(t *testing.T, engine *poll.Engine, clock *itClock, sink *s4Sink, sp *spool.Spool, rs *rawBatchStream) (int, []poll.Sample, []poll.Health) {
	t.Helper()
	n := engine.Step(context.Background(), clock.Now())
	if n == 0 {
		return 0, nil, nil
	}
	samples, health := sink.takeSamples(), sink.takeHealth()
	if len(samples) == 0 && len(health) == 0 {
		t.Fatalf("step probed %d targets but emitted nothing", n)
	}
	_, err := sp.Append(&spool.Batch{At: time.Now().UTC(), Samples: toSpoolSamplesIT(samples), Health: toSpoolHealthIT(health)})
	must(t, err)
	drainSpoolToStream(t, sp, rs)
	return n, samples, health
}

// TestM9S4BackoffCadenceAndRecovery proves the P2-AC-17 cadence end to end:
// consecutive failures double the fast-tier interval, the prober is not woken
// early, recovery resets the counter and the first post-recovery interval is
// the rapid re-check observed through poll_health rows.
func TestM9S4BackoffCadenceAndRecovery(t *testing.T) {
	env, id, store, orgID := m4Env(t, "m9s4-backoff-"+newUUID()[:8])
	orgUUID := mustUUID(t, orgID)
	siteID := siteIDForOrg(t, orgUUID)
	deviceID := createM9S2Device(t, orgUUID, siteID, "m9s4-backoff", "192.0.2.50", "switch", "fast")

	clock := &itClock{now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	fail := poll.Result{PollType: poll.PollICMP, Sent: 3, LossPercent: 100, ErrorClass: poll.ErrorTimeout}
	ok := poll.Result{PollType: poll.PollICMP, Sent: 3, Received: 3}
	prober := &s4ScriptedProber{script: []poll.Result{fail, fail, fail, ok, ok, ok}}
	sink := &s4Sink{}
	engine := s4AdaptiveEngine(clock, prober, sink)
	engine.ApplyTargets([]poll.Target{s4Target(deviceID.String(), "192.0.2.50", poll.TierFast)})

	sp, err := spool.Open(spool.Options{Dir: t.TempDir(), MaxBytes: 8 << 20, FsyncInterval: 10 * time.Millisecond})
	must(t, err)
	t.Cleanup(func() { _ = sp.Close() })
	rs := dialBatchStream(t, env, id, store)

	s4Step(t, engine, clock, sink, sp, rs) // failure 1 -> next +60s
	clock.Advance(30 * time.Second)
	if n := engine.Step(context.Background(), clock.Now()); n != 0 {
		t.Fatalf("probe at half the doubled interval probed %d, want 0", n)
	}
	clock.Advance(30 * time.Second)
	s4Step(t, engine, clock, sink, sp, rs) // failure 2 -> +120s
	clock.Advance(120 * time.Second)
	s4Step(t, engine, clock, sink, sp, rs) // failure 3 -> +240s
	clock.Advance(240 * time.Second)
	s4Step(t, engine, clock, sink, sp, rs) // success -> recovery re-check +30s
	clock.Advance(30 * time.Second)
	s4Step(t, engine, clock, sink, sp, rs) // success -> base cadence
	if got := prober.count(); got != 5 {
		t.Fatalf("prober calls = %d, want 5", got)
	}

	rows, err := ownerPool.Query(context.Background(), `
		SELECT outcome, error_class, consecutive_failures, ts FROM poll_health
		WHERE org_id = $1 AND device_id = $2 AND poll_type = 'icmp'
		ORDER BY ts`, orgUUID, deviceID)
	must(t, err)
	defer rows.Close()
	type rec struct {
		outcome string
		class   string
		fails   int
		ts      time.Time
	}
	var got []rec
	for rows.Next() {
		var r rec
		must(t, rows.Scan(&r.outcome, &r.class, &r.fails, &r.ts))
		got = append(got, r)
	}
	must(t, rows.Err())
	wantFails := []int{1, 2, 3, 0, 0}
	if len(got) != len(wantFails) {
		t.Fatalf("poll_health rows = %d, want %d (%+v)", len(got), len(wantFails), got)
	}
	for i, want := range wantFails {
		if got[i].fails != want {
			t.Fatalf("row %d consecutive_failures = %d, want %d", i, got[i].fails, want)
		}
	}
	for i := 0; i < 3; i++ {
		if got[i].outcome != poll.OutcomeFailure || got[i].class != poll.ErrorTimeout {
			t.Fatalf("row %d = %+v, want failure/timeout", i, got[i])
		}
	}
	for i := 3; i < 5; i++ {
		if got[i].outcome != poll.OutcomeSuccess || got[i].class != "" {
			t.Fatalf("row %d = %+v, want success", i, got[i])
		}
	}
	// Observed cadence: 60s, 120s, 240s, then the 30s rapid re-check.
	wantDeltas := []time.Duration{60 * time.Second, 120 * time.Second, 240 * time.Second, 30 * time.Second}
	for i, want := range wantDeltas {
		if d := got[i+1].ts.Sub(got[i].ts); d != want {
			t.Fatalf("cadence delta %d = %s, want %s", i, d, want)
		}
	}
}

// TestM9S4TargetRemovedMidRunAndUnreachable proves two canonical failures: a
// target whose management IP is unreachable fails and backs off, and a target
// that disappears from the policy mid-run stops being probed with no stale
// schedule; counters reseed when it returns.
func TestM9S4TargetRemovedMidRunAndUnreachable(t *testing.T) {
	env, id, store, orgID := m4Env(t, "m9s4-removed-"+newUUID()[:8])
	orgUUID := mustUUID(t, orgID)
	siteID := siteIDForOrg(t, orgUUID)
	sw := createM9S2Device(t, orgUUID, siteID, "m9s4-switch", "127.0.0.1", "switch", "standard")
	gone := createM9S2Device(t, orgUUID, siteID, "m9s4-gone", "192.0.2.99", "switch", "standard")
	host, port := snmpsimFixture(t)

	creds := poll.NewStaticCredentialSource()
	creds.Set(sw.String(), v2cCreds("switch"))
	creds.Set(gone.String(), v2cCreds("switch"))
	clock := &itClock{now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	prober := poll.NewSNMPProber(poll.SNMPProberConfig{
		Credentials:   creds,
		ClientFactory: snmpsimFactory(port, 300*time.Millisecond, 0),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:           clock.Now,
	})
	sink := &s4Sink{}
	engine := s4AdaptiveEngine(clock, prober, sink)

	targetSW := poll.Target{
		DeviceID: sw.String(), MgmtIP: netip.MustParseAddr(host), Name: "m9s4-switch",
		Tier: poll.TierStandard, PollType: poll.PollSNMP, Kind: "switch",
	}
	targetGone := poll.Target{
		DeviceID: gone.String(), MgmtIP: netip.MustParseAddr("192.0.2.99"), Name: "m9s4-gone",
		Tier: poll.TierStandard, PollType: poll.PollSNMP, Kind: "switch",
	}
	engine.ApplyTargets([]poll.Target{targetSW, targetGone})

	sp, err := spool.Open(spool.Options{Dir: t.TempDir(), MaxBytes: 8 << 20, FsyncInterval: 10 * time.Millisecond})
	must(t, err)
	t.Cleanup(func() { _ = sp.Close() })
	rs := dialBatchStream(t, env, id, store)

	n, _, health := s4Step(t, engine, clock, sink, sp, rs)
	if n != 2 {
		t.Fatalf("initial step probed %d, want 2", n)
	}
	byDevice := map[string]poll.Health{}
	for _, h := range health {
		byDevice[h.DeviceID] = h
	}
	if h := byDevice[sw.String()]; h.Outcome != poll.OutcomeSuccess {
		t.Fatalf("switch health = %+v, want success", h)
	}
	if h := byDevice[gone.String()]; h.Outcome != poll.OutcomeFailure ||
		(h.ErrorClass != poll.ErrorTimeout && h.ErrorClass != poll.ErrorUnreachable) {
		t.Fatalf("unreachable health = %+v, want failure/timeout|unreachable", h)
	}

	// The unreachable device has backed off to 2× the standard interval, so
	// advance both targets' second poll (the switch is due at +60s).
	clock.Advance(2 * poll.TierInterval(poll.TierStandard))
	n, samples, _ := s4Step(t, engine, clock, sink, sp, rs)
	if n != 2 {
		t.Fatalf("second step probed %d, want 2", n)
	}
	if !s4HasCounterSamples(samples) {
		t.Fatal("second switch poll produced no counter samples after the seed poll")
	}

	// The device disappears from the policy (soft delete): the engine drops it.
	engine.ApplyTargets([]poll.Target{targetSW})
	clock.Advance(10 * time.Minute)
	if n, _, _ := s4Step(t, engine, clock, sink, sp, rs); n != 1 {
		t.Fatalf("step after removal probed %d, want 1 (no stale schedule)", n)
	}
	if got := s4HealthCount(t, orgUUID, gone); got != 2 {
		t.Fatalf("unreachable device health rows = %d, want 2 (no probes after removal)", got)
	}

	// Remove the switch too, then re-add it: the fresh schedule is due
	// immediately and the counter state reseeds (no stale counters).
	engine.ApplyTargets(nil)
	clock.Advance(10 * time.Minute)
	if n := engine.Step(context.Background(), clock.Now()); n != 0 {
		t.Fatalf("step with no targets probed %d, want 0", n)
	}
	engine.ApplyTargets([]poll.Target{targetSW})
	n, samples, _ = s4Step(t, engine, clock, sink, sp, rs)
	if n != 1 {
		t.Fatalf("re-add step probed %d, want 1 (fresh schedule due immediately)", n)
	}
	if s4HasCounterSamples(samples) {
		t.Fatal("first poll after re-add emitted counter samples; state must reseed")
	}
	clock.Advance(poll.TierInterval(poll.TierStandard))
	_, samples, _ = s4Step(t, engine, clock, sink, sp, rs)
	if !s4HasCounterSamples(samples) {
		t.Fatal("counter samples did not resume after the reseed poll")
	}
}

func s4HasCounterSamples(samples []poll.Sample) bool {
	for _, s := range samples {
		switch s.MetricKey {
		case "net.if.in_octets", "net.if.out_octets", "net.if.in_errors", "net.if.out_errors",
			"net.if.in_discards", "net.if.out_discards":
			return true
		}
	}
	return false
}

func s4HealthCount(t *testing.T, orgID, deviceID uuid.UUID) int {
	t.Helper()
	var n int
	must(t, ownerPool.QueryRow(context.Background(), `
		SELECT count(*) FROM poll_health WHERE org_id = $1 AND device_id = $2`,
		orgID, deviceID).Scan(&n))
	return n
}

// TestM9S4CredentialRemovedMidRunBackoff proves the S3 removal path interacts
// with adaptive scheduling: the device fails closed with credential_missing,
// the cadence doubles, and restoring material recovers with a rapid re-check.
func TestM9S4CredentialRemovedMidRunBackoff(t *testing.T) {
	e := startM9S3Env(t, "m9s4-cred-"+newUUID()[:8])
	orgUUID := mustUUID(t, e.orgID)
	siteUUID := mustUUID(t, e.siteID)
	deviceID := createM9S2Device(t, orgUUID, siteUUID, "m9s4-cred", "127.0.0.1", "switch", "standard")
	credID := e.createCredential(t, "m9s4-cred", "snmp_v2c", "switch")
	e.bindCredential(t, credID, "device", deviceID, 10)

	id, store := e.enrollCollector(t, "collector-m9s4-cred")
	ss := dialSessionStream(t, e.m3Env, id, store)
	session := materializedSession(t, e.m3Env, ss)
	src := bundleCredentials(t, ss.seed, session, slog.New(slog.NewTextHandler(io.Discard, nil)))
	host, port := snmpsimFixture(t)
	clock := &itClock{now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	prober := poll.NewSNMPProber(poll.SNMPProberConfig{
		Credentials:   src,
		ClientFactory: snmpsimFactory(port, 300*time.Millisecond, 0),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:           clock.Now,
	})
	sink := &s4Sink{}
	engine := s4AdaptiveEngine(clock, prober, sink)
	target := poll.Target{
		DeviceID: deviceID.String(), MgmtIP: netip.MustParseAddr(host), Name: "m9s4-cred",
		Tier: poll.TierStandard, PollType: poll.PollSNMP, Kind: "switch",
	}
	engine.ApplyTargets([]poll.Target{target})

	// Poll 1: materialized credential works.
	if n := engine.Step(context.Background(), clock.Now()); n != 1 {
		t.Fatalf("seed step probed %d, want 1", n)
	}
	if h := sink.takeHealth(); len(h) != 1 || h[0].Outcome != poll.OutcomeSuccess {
		t.Fatalf("seed poll health = %+v, want success", h)
	}

	// The binding is removed: the next bundle has no material and the RAM
	// source drops the credential (fail closed).
	src.ApplySession(nil)
	clock.Advance(poll.TierInterval(poll.TierStandard))
	engine.Step(context.Background(), clock.Now())
	hs := sink.takeHealth()
	if len(hs) != 1 || hs[0].Outcome != poll.OutcomeFailure || hs[0].ErrorClass != poll.ErrorCredentialMissing || hs[0].ConsecutiveFailures != 1 {
		t.Fatalf("removed credential health = %+v, want failure/credential_missing/1", hs)
	}

	// Backoff doubled: nothing due at +60s, the second failure lands at +180s.
	clock.Advance(poll.TierInterval(poll.TierStandard))
	if n := engine.Step(context.Background(), clock.Now()); n != 0 {
		t.Fatalf("probe at half the doubled interval = %d, want 0", n)
	}
	clock.Advance(poll.TierInterval(poll.TierStandard))
	engine.Step(context.Background(), clock.Now())
	if hs = sink.takeHealth(); len(hs) != 1 || hs[0].ConsecutiveFailures != 2 {
		t.Fatalf("second failure health = %+v, want consecutive_failures=2", hs)
	}

	// Material restored (next sync re-delivers the credential): recovery with
	// a rapid re-check 30s later.
	src.ApplySession(session)
	clock.Advance(4 * time.Minute)
	engine.Step(context.Background(), clock.Now())
	hs = sink.takeHealth()
	if len(hs) != 1 || hs[0].Outcome != poll.OutcomeSuccess || hs[0].ConsecutiveFailures != 0 {
		t.Fatalf("recovery health = %+v, want success/0", hs)
	}
	clock.Advance(30 * time.Second)
	engine.Step(context.Background(), clock.Now())
	if hs = sink.takeHealth(); len(hs) != 1 || hs[0].Outcome != poll.OutcomeSuccess {
		t.Fatalf("rapid re-check health = %+v, want success", hs)
	}
}

// TestM9S4RestartResetsPollAndCounterState proves a collector restart starts
// with fresh schedules (due immediately, no stale next-run) and fresh counter
// baselines (no false rates), then resumes normal rates.
func TestM9S4RestartResetsPollAndCounterState(t *testing.T) {
	env, id, store, orgID := m4Env(t, "m9s4-restart-"+newUUID()[:8])
	orgUUID := mustUUID(t, orgID)
	siteID := siteIDForOrg(t, orgUUID)
	deviceID := createM9S2Device(t, orgUUID, siteID, "m9s4-restart", "127.0.0.1", "switch", "standard")
	host, port := snmpsimFixture(t)

	creds := poll.NewStaticCredentialSource()
	creds.Set(deviceID.String(), v2cCreds("switch"))
	clock := &itClock{now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	target := poll.Target{
		DeviceID: deviceID.String(), MgmtIP: netip.MustParseAddr(host), Name: "m9s4-restart",
		Tier: poll.TierStandard, PollType: poll.PollSNMP, Kind: "switch",
	}
	newProber := func() *poll.SNMPProber {
		return poll.NewSNMPProber(poll.SNMPProberConfig{
			Credentials:   creds,
			ClientFactory: snmpsimFactory(port, time.Second, 0),
			Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
			Now:           clock.Now,
		})
	}

	sp, err := spool.Open(spool.Options{Dir: t.TempDir(), MaxBytes: 8 << 20, FsyncInterval: 10 * time.Millisecond})
	must(t, err)
	t.Cleanup(func() { _ = sp.Close() })
	rs := dialBatchStream(t, env, id, store)

	// Pre-restart run: seed then a real counter interval.
	sink1 := &s4Sink{}
	engine1 := s4AdaptiveEngine(clock, newProber(), sink1)
	engine1.ApplyTargets([]poll.Target{target})
	s4Step(t, engine1, clock, sink1, sp, rs)
	sink1.takeSamples()
	clock.Advance(poll.TierInterval(poll.TierStandard))
	_, samples, _ := s4Step(t, engine1, clock, sink1, sp, rs)
	if !s4HasCounterSamples(samples) {
		t.Fatal("pre-restart counter poll produced no rates")
	}

	// Restart at the same instant: new engine + new prober, no stale state.
	sink2 := &s4Sink{}
	engine2 := s4AdaptiveEngine(clock, newProber(), sink2)
	engine2.ApplyTargets([]poll.Target{target})
	if n := engine2.Step(context.Background(), clock.Now()); n != 1 {
		t.Fatalf("post-restart first step probed %d, want 1 (fresh schedule due immediately)", n)
	}
	if s4HasCounterSamples(sink2.takeSamples()) {
		t.Fatal("post-restart first poll emitted counter samples; the baseline must reseed")
	}
	clock.Advance(poll.TierInterval(poll.TierStandard))
	_, samples, _ = s4Step(t, engine2, clock, sink2, sp, rs)
	if !s4HasCounterSamples(samples) {
		t.Fatal("counter rates did not resume after the post-restart seed poll")
	}

	// All four polls succeeded; no failure was recorded across the restart.
	var failures int
	must(t, ownerPool.QueryRow(context.Background(), `
		SELECT count(*) FROM poll_health
		WHERE org_id = $1 AND device_id = $2 AND poll_type = 'snmp' AND outcome = 'failure'`,
		orgUUID, deviceID).Scan(&failures))
	if failures != 0 {
		t.Fatalf("failure health rows across restart = %d, want 0", failures)
	}
}

// TestM9S4RateLimitDoesNotStarveTargets proves the per-device request budget
// sheds load for the saturated device while a different target on the same
// prober keeps polling successfully (P2-AC-18).
func TestM9S4RateLimitDoesNotStarveTargets(t *testing.T) {
	env, id, store, orgID := m4Env(t, "m9s4-ratelimit-"+newUUID()[:8])
	orgUUID := mustUUID(t, orgID)
	siteID := siteIDForOrg(t, orgUUID)
	heavy := createM9S2Device(t, orgUUID, siteID, "m9s4-heavy", "127.0.0.1", "switch", "standard")
	light := createM9S2Device(t, orgUUID, siteID, "m9s4-light", "127.0.0.2", "printer", "standard")
	host, port := snmpsimFixture(t)

	creds := poll.NewStaticCredentialSource()
	creds.SetDefault(v2cCreds("switch"))
	clock := &itClock{now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	prober := poll.NewSNMPProber(poll.SNMPProberConfig{
		Credentials:   creds,
		ClientFactory: snmpsimFactory(port, time.Second, 0),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:           clock.Now,
		// The documented standard budget is 300/min; the test uses 2 so the
		// table walk exceeds it immediately.
		RequestBudget: func(string) int { return 2 },
	})
	sink := &s4Sink{}
	engine := s4AdaptiveEngine(clock, prober, sink)
	engine.ApplyTargets([]poll.Target{
		{DeviceID: heavy.String(), MgmtIP: netip.MustParseAddr(host), Name: "heavy", Tier: poll.TierStandard, PollType: poll.PollSNMP, Kind: "switch"},
		{DeviceID: light.String(), MgmtIP: netip.MustParseAddr(host), Name: "light", Tier: poll.TierStandard, PollType: poll.PollSNMP, Kind: "printer"},
	})

	sp, err := spool.Open(spool.Options{Dir: t.TempDir(), MaxBytes: 8 << 20, FsyncInterval: 10 * time.Millisecond})
	must(t, err)
	t.Cleanup(func() { _ = sp.Close() })
	rs := dialBatchStream(t, env, id, store)

	for round := 0; round < 2; round++ {
		if n, _, _ := s4Step(t, engine, clock, sink, sp, rs); n != 2 {
			t.Fatalf("round %d probed %d targets, want 2", round, n)
		}
		// The rate-limited device backs off to 2× the standard interval, so
		// the next round must wait for both (the healthy one is overdue).
		clock.Advance(2 * poll.TierInterval(poll.TierStandard))
	}
	if got := s4ClassCount(t, orgUUID, heavy, poll.ErrorRateLimited); got != 2 {
		t.Fatalf("heavy rate_limited rows = %d, want 2", got)
	}
	if got := s4ClassCount(t, orgUUID, light, ""); got != 2 {
		t.Fatalf("light success rows = %d, want 2 (saturated device must not starve others)", got)
	}
}

func s4ClassCount(t *testing.T, orgID, deviceID uuid.UUID, class string) int {
	t.Helper()
	var n int
	must(t, ownerPool.QueryRow(context.Background(), `
		SELECT count(*) FROM poll_health
		WHERE org_id = $1 AND device_id = $2 AND error_class = $3`,
		orgID, deviceID, class).Scan(&n))
	return n
}

// TestM9S4JitterBoundsObserved proves every adaptive interval lands inside the
// canonical ±10% band and the scheduler wakes exactly at the jittered time.
func TestM9S4JitterBoundsObserved(t *testing.T) {
	clock := &itClock{now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	prober := &s4ScriptedProber{}
	rng := &s4SeqRand{vals: []float64{0, 0.9999}}
	sink := &s4Sink{}
	engine := poll.NewEngine(poll.Config{
		Prober:   prober,
		Clock:    clock,
		Backoff:  poll.AdaptiveBackoff{Rand: rng},
		OnHealth: sink.healthRec,
	})
	engine.ApplyTargets([]poll.Target{s4Target("dev-jitter", "192.0.2.60", poll.TierStandard)})

	// First interval: 0.9 × 60s = 54s exactly.
	if n := engine.Step(context.Background(), clock.Now()); n != 1 {
		t.Fatalf("initial step probed %d, want 1", n)
	}
	clock.Advance(53 * time.Second)
	if n := engine.Step(context.Background(), clock.Now()); n != 0 {
		t.Fatalf("probe before the jittered interval = %d, want 0", n)
	}
	clock.Advance(time.Second)
	if n := engine.Step(context.Background(), clock.Now()); n != 1 {
		t.Fatalf("probe at the jittered interval = %d, want 1", n)
	}
	// Second interval: ~1.09998 × 60s = 65.9988s (truncated), inside +10%.
	clock.Advance(65 * time.Second)
	if n := engine.Step(context.Background(), clock.Now()); n != 0 {
		t.Fatalf("probe before the upper-jitter interval = %d, want 0", n)
	}
	clock.Advance(time.Second)
	if n := engine.Step(context.Background(), clock.Now()); n != 1 {
		t.Fatalf("probe at the upper-jitter interval = %d, want 1", n)
	}
	if got := prober.count(); got != 3 {
		t.Fatalf("prober calls = %d, want 3", got)
	}
}
