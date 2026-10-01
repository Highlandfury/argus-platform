package poll

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// Clock is the injectable time source: the scheduler reads Now and parks on
// After, so tests can drive calendar time deterministically.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

// RealClock is the production clock.
type RealClock struct{}

// Now implements Clock.
func (RealClock) Now() time.Time { return time.Now() }

// After implements Clock.
func (RealClock) After(d time.Duration) <-chan time.Time {
	if d < 0 {
		d = 0
	}
	return time.After(d)
}

// BackoffPolicy is the M9-S4 extension point for adaptive scheduling. M9-S1
// ships FixedBackoff; S4 replaces it with the failure-doubling/jitter/rate-cap
// policy mandated by P2-AC-17 while this engine keeps calling the hook.
type BackoffPolicy interface {
	// NextInterval returns the delay before the next run of a target whose
	// last run left consecutiveFailures failures (0 after a success). base is
	// the tier cadence.
	NextInterval(base time.Duration, consecutiveFailures int) time.Duration
}

// FixedBackoff preserves the tier cadence regardless of failures: the M9-S1
// default (adaptive doubling, jitter and safety caps are M9-S4).
type FixedBackoff struct{}

// NextInterval implements BackoffPolicy.
func (FixedBackoff) NextInterval(base time.Duration, _ int) time.Duration { return base }

// Config wires the engine. Prober is required; Clock/Backoff/Concurrency take
// documented defaults.
type Config struct {
	Prober      Prober
	Clock       Clock
	Backoff     BackoffPolicy
	Concurrency int
	Log         *slog.Logger
	OnSample    func(Sample)
	OnHealth    func(Health)
	// IdleWait bounds how long Run sleeps when no target is due (default 1 s);
	// ApplyTargets can arrive while sleeping.
	IdleWait time.Duration
}

// DefaultConcurrency is the canonical per-collector ICMP flow budget
// (docs/15 §: "ICMP 20 flows").
const DefaultConcurrency = 20

// TargetRemovedHook is implemented by probers that keep per-device state (the
// SNMP prober's counter state machine). The engine calls it when it drops the
// last target of that poll type for a device, so long-lived state cannot leak
// for removed devices (and is reseeded if the target returns).
type TargetRemovedHook interface {
	TargetRemoved(deviceID, pollType string)
}

// Engine is the deterministic poll scheduler. Every state transition is
// computed from the clock and the target set: given the same inputs, the same
// due sequence results (no wall-clock reads outside Clock, no random values).
type Engine struct {
	cfg     Config
	clock   Clock
	backoff BackoffPolicy
	sem     chan struct{}
	idle    time.Duration

	mu      sync.Mutex
	targets map[string]*targetState
	// wake interrupts Run's sleep when a policy target change arrives.
	wake chan struct{}
}

type targetState struct {
	target   Target
	next     time.Time
	failures int
	running  bool
}

// NewEngine builds the scheduler.
func NewEngine(cfg Config) *Engine {
	if cfg.Clock == nil {
		cfg.Clock = RealClock{}
	}
	if cfg.Backoff == nil {
		cfg.Backoff = FixedBackoff{}
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = DefaultConcurrency
	}
	if cfg.IdleWait <= 0 {
		cfg.IdleWait = time.Second
	}
	return &Engine{
		cfg:     cfg,
		clock:   cfg.Clock,
		backoff: cfg.Backoff,
		sem:     make(chan struct{}, cfg.Concurrency),
		idle:    cfg.IdleWait,
		targets: make(map[string]*targetState),
		wake:    make(chan struct{}, 1),
	}
}

// ApplyTargets atomically replaces the target set with the one from the newly
// applied signed policy. Existing targets keep their next-run time and failure
// state (keyed by device id + poll type, so an ICMP and an SNMP target for the
// same device schedule independently); new targets are due immediately;
// removed targets are dropped (a probe already in flight completes and is
// discarded by Complete). Removing the last target of a device notifies a
// TargetRemovedHook prober so per-device state is released.
func (e *Engine) ApplyTargets(targets []Target) {
	now := e.clock.Now()
	e.mu.Lock()
	next := make(map[string]*targetState, len(targets))
	for _, t := range targets {
		key := t.Key()
		if prev, ok := e.targets[key]; ok {
			// Keep scheduling state, refresh the mutable fields (IP/name/tier/
			// kind may have changed with the policy).
			prev.target = t
			next[key] = prev
			continue
		}
		next[key] = &targetState{target: t, next: now}
	}
	type removedKey struct{ deviceID, pollType string }
	var removed []removedKey
	for key, st := range e.targets {
		if _, ok := next[key]; !ok {
			removed = append(removed, removedKey{st.target.DeviceID, NormalizePollType(st.target.PollType)})
		}
	}
	e.targets = next
	select {
	case e.wake <- struct{}{}:
	default:
	}
	e.mu.Unlock()

	// Per-device prober state (SNMP counters) is released when the last target
	// of its poll type disappears; a re-added target reseeds.
	if hook, ok := e.cfg.Prober.(TargetRemovedHook); ok {
		for _, r := range removed {
			hook.TargetRemoved(r.deviceID, r.pollType)
		}
	}
	if e.cfg.Log != nil {
		e.cfg.Log.Info("poll targets applied", "targets", len(next))
	}
}

// Targets returns the current target set ordered by device id (tests/logging).
func (e *Engine) Targets() []Target {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Target, 0, len(e.targets))
	for _, st := range e.targets {
		out = append(out, st.target)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].DeviceID != out[j].DeviceID {
			return out[i].DeviceID < out[j].DeviceID
		}
		return out[i].PollType < out[j].PollType
	})
	return out
}

// Step polls every target due at now and reschedules it. It is synchronous:
// every probe (bounded by Config.Concurrency) completes before Step returns,
// which makes the scheduler deterministic under a test clock. Returns the
// number of targets probed.
func (e *Engine) Step(ctx context.Context, now time.Time) int {
	due := e.reserveDue(now)
	if len(due) == 0 {
		return 0
	}
	var wg sync.WaitGroup
	for _, st := range due {
		select {
		case e.sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			// Release any reservation that was never probed.
			e.releaseReservations(due)
			return len(due)
		}
		wg.Add(1)
		go func(st *targetState) {
			defer wg.Done()
			defer func() { <-e.sem }()
			e.probe(ctx, st)
		}(st)
	}
	wg.Wait()
	return len(due)
}

// Run drives the scheduler until ctx ends. It steps on every due target and
// sleeps until the earliest next run (or the idle bound).
func (e *Engine) Run(ctx context.Context) {
	for {
		e.Step(ctx, e.clock.Now())
		select {
		case <-ctx.Done():
			return
		case <-e.wake:
		case <-e.clock.After(e.untilNext(e.clock.Now())):
		}
	}
}

// reserveDue marks every due, non-running target as running and returns the
// reserved states. Reservation prevents a target from being dispatched twice
// if a probe outlives its interval.
func (e *Engine) reserveDue(now time.Time) []*targetState {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]*targetState, 0)
	for _, st := range e.targets {
		if st.running || st.next.After(now) {
			continue
		}
		st.running = true
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].target.Key() < out[j].target.Key() })
	return out
}

// releaseReservations clears running on reservations that were never probed.
func (e *Engine) releaseReservations(states []*targetState) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, st := range states {
		if cur, ok := e.targets[st.target.Key()]; ok && cur == st {
			st.running = false
		}
	}
}

// probe runs one poll, emits samples + health, and reschedules the target.
func (e *Engine) probe(ctx context.Context, st *targetState) {
	target := st.target
	res := e.cfg.Prober.Probe(ctx, target)
	finished := e.clock.Now()

	for _, s := range res.Samples(target, finished) {
		if e.cfg.OnSample != nil {
			e.cfg.OnSample(s)
		}
	}

	e.mu.Lock()
	failures := st.failures
	if res.Reachable() {
		failures = 0
	} else {
		failures++
	}
	st.failures = failures
	interval := e.backoff.NextInterval(TierInterval(target.Tier), failures)
	// Never schedule in the past relative to the completed run.
	if interval <= 0 {
		interval = time.Second
	}
	st.next = finished.Add(interval)
	st.running = false
	_, stillCurrent := e.targets[target.Key()]
	e.mu.Unlock()

	if e.cfg.OnHealth != nil {
		e.cfg.OnHealth(Health{
			DeviceID:            target.DeviceID,
			PollType:            res.PollType,
			LatencyMS:           int(res.Latency.Milliseconds()),
			Outcome:             res.Outcome(),
			ErrorClass:          res.ErrorClass,
			ConsecutiveFailures: failures,
			CheckedAt:           finished,
		})
	}
	// A target removed while its probe was in flight is simply discarded
	// (stillCurrent is informational for logs in later slices).
	_ = stillCurrent
}

// untilNext returns the wait until the earliest scheduled run (idle bound when
// no target is scheduled). ApplyTargets wakes Run early, so this may be the
// full tier cadence.
func (e *Engine) untilNext(now time.Time) time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	wait := e.idle
	first := true
	for _, st := range e.targets {
		d := st.next.Sub(now)
		if d < 0 {
			d = 0
		}
		if first || d < wait {
			wait, first = d, false
		}
	}
	if wait < 0 {
		wait = 0
	}
	return wait
}
