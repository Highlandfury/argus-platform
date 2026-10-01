package poll

import (
	"context"
	"log/slog"
)

// MultiProber dispatches a poll to the prober registered for the target's poll
// type (M9-S2 wires ICMP + SNMP here without changing the scheduler). Unknown
// poll types fall back to the ICMP prober when one is registered; otherwise
// the probe reports `unsupported` and produces no samples.
type MultiProber struct {
	probers map[string]Prober
	log     *slog.Logger
}

// NewMultiProber builds the dispatcher. Keys are canonical poll types
// (PollICMP / PollSNMP).
func NewMultiProber(probers map[string]Prober) *MultiProber {
	return &MultiProber{probers: probers}
}

// WithLogger attaches a logger for dispatch diagnostics.
func (m *MultiProber) WithLogger(log *slog.Logger) *MultiProber {
	m.log = log
	return m
}

// Probe implements Prober.
func (m *MultiProber) Probe(ctx context.Context, target Target) Result {
	p := m.probers[target.PollType]
	if p == nil {
		p = m.probers[PollICMP]
	}
	if p == nil {
		if m.log != nil {
			m.log.Warn("no prober for poll type", "poll_type", target.PollType, "device_id", target.DeviceID)
		}
		return Result{PollType: target.PollType, ErrorClass: ErrorUnsupported}
	}
	return p.Probe(ctx, target)
}

// TargetRemoved implements TargetRemovedHook: state-holding probers are
// notified when the last target of their poll type disappears.
func (m *MultiProber) TargetRemoved(deviceID, pollType string) {
	for typ, p := range m.probers {
		if pollType != "" && typ != pollType {
			continue
		}
		if hook, ok := p.(TargetRemovedHook); ok {
			hook.TargetRemoved(deviceID, pollType)
		}
	}
}
