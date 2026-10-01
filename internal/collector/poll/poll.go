// Package poll implements the collector-side polling foundation (M9-S1):
// deterministic tier scheduling, ICMP probing, per-target metric samples and
// poll-health records.
//
// Scope boundary (PHASE_2_SPEC M9, slices S1-S4):
//   - S1 (this package): tiers, deterministic scheduling with an injectable
//     clock, ICMP prober, samples + poll health through the existing spool.
//   - S4 adds adaptive backoff profiles, jitter and rate/safety caps through
//     the BackoffPolicy hook (present here) and Config limits.
//   - S2 adds SNMP; no SNMP code exists in this package yet.
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
}

// TargetFromPolicy validates and normalizes one policy target. The server
// already validated the shape; re-validation here fails closed on a malformed
// signed document (defense in depth, SPEC §11).
func TargetFromPolicy(deviceID, mgmtIP, name, tier string) (Target, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(mgmtIP))
	if err != nil {
		return Target{}, fmt.Errorf("poll: target %s: invalid mgmt_ip %q", deviceID, mgmtIP)
	}
	if strings.TrimSpace(deviceID) == "" {
		return Target{}, fmt.Errorf("poll: target with empty device_id")
	}
	return Target{
		DeviceID: deviceID,
		MgmtIP:   addr.Unmap(),
		Name:     name,
		Tier:     NormalizeTier(tier),
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

// Error classes (stable strings; SNMP classes arrive with M9-S2).
const (
	ErrorNone        = ""
	ErrorTimeout     = "timeout"
	ErrorLoss        = "loss"
	ErrorUnreachable = "unreachable"
	ErrorUnsupported = "unsupported"
)

// Poll types.
const (
	PollICMP = "icmp"
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
