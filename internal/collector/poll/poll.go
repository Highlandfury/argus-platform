// Package poll implements the collector-side polling foundation (M9-S1):
// deterministic tier scheduling, ICMP probing, per-target metric samples and
// poll-health records.
//
// Scope boundary (PHASE_2_SPEC M9, slices S1-S4):
//   - S1: tiers, deterministic scheduling with an injectable clock, ICMP
//     prober, samples + poll health through the existing spool.
//   - S2 (this package): SNMP v2c/v3 client (GETBULK/GETNEXT, no SET),
//     declarative core templates, counter state machine (wrap/reset/reboot/
//     discontinuity), snmpsim-backed tests.
//   - S3: credential materialization behind CredentialSource.
//   - S4: adaptive backoff profiles, ±10% jitter, recovery re-check, CPU
//     guard, per-device request budgets and session ceilings through the
//     BackoffPolicy hook (present here) and Config limits.
package poll

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Canonical polling tiers (docs/07 §12.4; PHASE_2_SPEC P2-AC-17). The slow and
// inventory canonical entries are ranges (5-15 min / 6-24 h); this build uses
// the documented lower bound as the default, with per-target overrides owned by
// M9-S4.
const (
	TierFast      = "fast"
	TierStandard  = "standard"
	TierSlow      = "slow"
	TierInventory = "inventory"

	// FastInterval is the canonical fast tier (uplinks, liveness): 30 s.
	FastInterval = 30 * time.Second
	// StandardInterval is the canonical standard tier: 60 s.
	StandardInterval = 60 * time.Second
	// SlowInterval is the canonical slow tier lower bound (range 5-15 min).
	SlowInterval = 5 * time.Minute
	// InventoryInterval is the canonical inventory tier lower bound (6-24 h).
	InventoryInterval = 6 * time.Hour
)

// NormalizeTier maps a policy tier string onto a canonical tier. Unknown or
// empty values normalize to standard (a bad operator value must never disable
// a device from polling).
func NormalizeTier(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case TierFast:
		return TierFast
	case TierSlow:
		return TierSlow
	case TierInventory:
		return TierInventory
	default:
		return TierStandard
	}
}

// TierInterval returns the canonical cadence for a tier.
func TierInterval(tier string) time.Duration {
	switch NormalizeTier(tier) {
	case TierFast:
		return FastInterval
	case TierSlow:
		return SlowInterval
	case TierInventory:
		return InventoryInterval
	default:
		return StandardInterval
	}
}

// Target is one resolved poll target from the signed policy bundle.
type Target struct {
	DeviceID string
	MgmtIP   netip.Addr
	Name     string
	Tier     string // canonical tier
	// PollType selects the prober: PollICMP (default) or PollSNMP (M9-S2).
	PollType string
	// Kind is the device kind from inventory; it selects SNMP templates
	// (M9-S2). Empty is treated as unknown (system template only).
	Kind string
	// Critical lowerers the adaptive backoff ceiling to 5 min (canonical
	// docs/07 §12.3: "critical devices 5 min ceiling"). The collector honors
	// the flag; Phase 2 has no operator-facing criticality source in the
	// signed bundle yet, so production targets are non-critical until that
	// source lands (documented in M9_EVIDENCE §S4).
	Critical bool
}

// Key is the engine's scheduling identity. One device may carry both an ICMP
// and an SNMP target (liveness and metrics), each with its own cadence state.
func (t Target) Key() string { return t.DeviceID + ":" + NormalizePollType(t.PollType) }

// TargetSpec is the raw, unvalidated target shape from the signed policy.
type TargetSpec struct {
	DeviceID string
	MgmtIP   string
	Name     string
	Tier     string
	PollType string
	Kind     string
}

// NormalizePollType maps a policy poll-type string onto a canonical type.
// Unknown/empty values normalize to ICMP: liveness is always safe to attempt
// and a bad operator value must never disable a device from polling (same
// posture as NormalizeTier). SNMP-only targets are expressed explicitly.
func NormalizePollType(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case PollSNMP:
		return PollSNMP
	default:
		return PollICMP
	}
}

// TargetFromPolicy validates and normalizes one policy target. The server
// already validated the shape; re-validation here fails closed on a malformed
// signed document (defense in depth, SPEC §11).
func TargetFromPolicy(spec TargetSpec) (Target, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(spec.MgmtIP))
	if err != nil {
		return Target{}, fmt.Errorf("poll: target %s: invalid mgmt_ip %q", spec.DeviceID, spec.MgmtIP)
	}
	if strings.TrimSpace(spec.DeviceID) == "" {
		return Target{}, fmt.Errorf("poll: target with empty device_id")
	}
	return Target{
		DeviceID: spec.DeviceID,
		MgmtIP:   addr.Unmap(),
		Name:     spec.Name,
		Tier:     NormalizeTier(spec.Tier),
		PollType: NormalizePollType(spec.PollType),
		Kind:     strings.TrimSpace(spec.Kind),
	}, nil
}

// Sample is one produced metric observation, shaped for the existing
// collector spool/stream/ingest path (spool.Sample conversion in cmd).
type Sample struct {
	MetricKey  string
	Unit       string
	Value      float64
	Ts         time.Time
	DeviceID   string // wire device scope (M9)
	Dimensions map[string]string
}

// Health is one poll-health record (P2-AC-20).
type Health struct {
	DeviceID            string
	PollType            string
	LatencyMS           int
	Outcome             string
	ErrorClass          string
	ConsecutiveFailures int
	CheckedAt           time.Time
}

// Outcome values (proto/DB contract).
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
)

// Error classes (stable strings; fed to poll_health). SNMP adds M9-S2 classes:
// auth_failure (v3 authentication/decryption/usm errors), walk_truncation (a
// table walk terminated early or the agent stopped making progress) and
// template_drift (the device answered but an expected table/metric produced no
// data). credential_missing/credential_invalid cover the seam M9-S3 fills with
// materialized credentials. M9-S4 adds rate_limited (the per-device request
// budget or a session ceiling was hit; skip + count, docs/07 §12.3) and
// cpu_pressure (success outcome: the agent-reported hrProcessorLoad crossed
// the guard threshold, docs/07 §12.7).
const (
	ErrorNone              = ""
	ErrorTimeout           = "timeout"
	ErrorLoss              = "loss"
	ErrorUnreachable       = "unreachable"
	ErrorUnsupported       = "unsupported"
	ErrorAuthFailure       = "auth_failure"
	ErrorWalkTruncation    = "walk_truncation"
	ErrorTemplateDrift     = "template_drift"
	ErrorCredentialMissing = "credential_missing" //nolint:gosec // poll-health class string, not a secret
	ErrorCredentialInvalid = "credential_invalid" //nolint:gosec // poll-health class string, not a secret
	ErrorRateLimited       = "rate_limited"
	ErrorCPUPressure       = "cpu_pressure"
)

// Poll types.
const (
	PollICMP = "icmp"
	PollSNMP = "snmp"
)

// ICMP metric keys (M9-S1). Naming follows the canonical dotted namespace
// (docs/08 §5: `net.if.in_octets`, `wan.latency.p95_ms`):
//
//	net.icmp.reachable   1/0 liveness for this poll window (unit: state)
//	net.icmp.rtt_ms      average echo RTT in milliseconds (unit: ms)
//	net.icmp.loss_pct    echo loss over the window, 0-100 (unit: percent)
const (
	MetricReachable = "net.icmp.reachable"
	MetricRTT       = "net.icmp.rtt_ms"
	MetricLossPct   = "net.icmp.loss_pct"

	UnitState   = "state"
	UnitMS      = "ms"
	UnitPercent = "percent"
)

// MetricSysCPUUtil is the core SNMP pack's HOST-RESOURCES hrProcessorLoad
// series key (M9-S2). M9-S4's device-CPU impact guard (docs/07 §12.7) checks
// its values against a threshold before stepping the cadence down.
const MetricSysCPUUtil = "sys.cpu.util"
