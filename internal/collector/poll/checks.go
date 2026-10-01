package poll

import (
	"context"
	"time"
)

// DefaultCheckRunTimeout bounds one on-demand probe end to end. It is higher
// than a single scheduled probe budget because an SNMP walk may span several
// RPCs and the operator asked for this run explicitly; the bound still keeps
// a stuck probe from pinning a check worker forever.
const DefaultCheckRunTimeout = 30 * time.Second

// CheckExecutor runs on-demand checks (M10-S0) against the engine's currently
// applied target set. It bypasses the schedule entirely: it does not reserve
// the target, does not touch the failure/backoff state and does not reschedule
// anything. Probes still obey the SNMP prober's own safety limits (one walk in
// flight, request budget, session ceilings), so an on-demand check can never
// exceed the canonical rate/budget guards.
//
// Metric samples are deliberately NOT emitted: an on-demand check is not a
// scheduled poll, and writing an off-cadence point into a scheduled series
// would corrupt counter-rate math (the SNMP counter state machine is keyed on
// cadence). The probe is visible through poll_health with Origin=on_demand and
// through the CheckResult delivered to the server.
type CheckExecutor struct {
	prober   Prober
	targets  func() []Target
	onHealth func(Health)
	timeout  time.Duration
	now      func() time.Time
}

// NewCheckExecutor builds the executor. prober and targets are required;
// onHealth may be nil (health is then not emitted).
func NewCheckExecutor(prober Prober, targets func() []Target, onHealth func(Health)) *CheckExecutor {
	return &CheckExecutor{
		prober:   prober,
		targets:  targets,
		onHealth: onHealth,
		timeout:  DefaultCheckRunTimeout,
		now:      time.Now,
	}
}

// RunCheck executes one immediate probe for deviceID/pollType. It returns
// (result, true) when the device/type is present in the applied policy and
// (Result{}, false) when it is not (the adapter reports target_missing).
// An on-demand probe never emits metric samples; it emits one poll_health row
// with Origin=on_demand and consecutive_failures=0 (it does not participate in
// the adaptive-backoff streak).
func (e *CheckExecutor) RunCheck(ctx context.Context, deviceID, pollType string) (Result, bool) {
	want := NormalizePollType(pollType)
	target, found := e.TargetFor(deviceID, pollType)
	if !found {
		return Result{}, false
	}

	probeCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	res := e.prober.Probe(probeCtx, target)
	if res.PollType == "" {
		res.PollType = want
	}
	if e.onHealth != nil {
		e.onHealth(Health{
			DeviceID:            target.DeviceID,
			PollType:            res.PollType,
			LatencyMS:           int(res.Latency.Milliseconds()),
			Outcome:             res.Outcome(),
			ErrorClass:          res.ErrorClass,
			ConsecutiveFailures: 0,
			CheckedAt:           e.now().UTC(),
			Origin:              OriginOnDemand,
		})
	}
	return res, true
}

// TargetFor exposes the resolved target for an on-demand check (tests and
// adapters that need the target shape without probing).
func (e *CheckExecutor) TargetFor(deviceID, pollType string) (Target, bool) {
	want := NormalizePollType(pollType)
	for _, t := range e.targets() {
		if t.DeviceID == deviceID && NormalizePollType(t.PollType) == want {
			return t, true
		}
	}
	return Target{}, false
}
