package inventory

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Derived device statuses (M10-S1; P2-AC-22 partial: maintenance is M11).
const (
	// StatusUp: the newest scheduled poll succeeded, or its failure streak is
	// still below the down threshold (transient failures do not flap).
	StatusUp = "up"
	// StatusDown: the newest scheduled poll failed and consecutively failed at
	// least DownThreshold times.
	StatusDown = "down"
	// StatusUnknown: no scheduled poll health within the freshness window (or
	// no scheduled health at all), so the current state cannot be asserted.
	StatusUnknown = "unknown"
)

// DeviceStatus is the poll-health-derived rollup for one device. All probe
// fields describe the newest scheduled poll outcome; nil means no scheduled
// health exists. The payload key in list responses is `poll_status` because
// the device object's existing `status` field is the M7 inventory lifecycle
// state and must stay backward compatible.
type DeviceStatus struct {
	DeviceID            uuid.UUID
	Status              string
	Since               *time.Time
	LastOutcome         *string
	LastErrorClass      *string
	LastLatencyMS       *int
	ConsecutiveFailures *int
	LastCheckedAt       *time.Time
	// DownThreshold and FreshnessSeconds expose the derivation policy so
	// clients can render truthful explanations (canonical docs are silent).
	DownThreshold    int
	FreshnessSeconds int
}

// Payload renders the status object shared by GET /v1/devices/{id}/status and
// the `?include=status` list decoration.
func (s DeviceStatus) Payload() map[string]any {
	return map[string]any{
		"device_id":            s.DeviceID.String(),
		"status":               s.Status,
		"since":                statusTime(s.Since),
		"last_outcome":         s.LastOutcome,
		"last_error_class":     s.LastErrorClass,
		"last_latency_ms":      s.LastLatencyMS,
		"consecutive_failures": s.ConsecutiveFailures,
		"last_checked_at":      statusTime(s.LastCheckedAt),
		"down_threshold":       s.DownThreshold,
		"freshness_seconds":    s.FreshnessSeconds,
	}
}

func statusTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

// DeviceStatusProvider resolves poll-health rollups for a bounded set of
// device ids. The poll-health service implements it; the inventory list
// decorates payloads with the result when `?include=status` is requested.
type DeviceStatusProvider interface {
	DeviceStatuses(ctx context.Context, orgID uuid.UUID, deviceIDs []uuid.UUID) (map[uuid.UUID]DeviceStatus, error)
}

// InterfaceFreshnessSeconds is the M10-S2 interface rollup freshness window.
// It mirrors the device rollup choice (M10-S1 §7.3): the adaptive scheduler
// probes at least once per 15-minute backoff ceiling (+ jitter, batching and
// transport latency), so 20 minutes proves the interface row is still being
// observed. Canonical documents are silent; the value is exposed in every
// interface payload so clients can explain the rollup.
const InterfaceFreshnessSeconds = 20 * 60

// InterfaceStatusAt derives the live interface status from the newest SNMP
// observation, mirroring the device status vocabulary (up/down/unknown):
//
//	up       newest observation reports oper_status=up and is fresh
//	down     newest observation reports any other known IF-MIB state and is
//	         fresh (down, testing, dormant, not_present, lower_layer_down)
//	unknown  no SNMP observation yet (last_seen_at nil), no oper_status, or
//	         the last observation is older than the freshness window
//
// A stale row is unknown even if the last state was down: an observation that
// stopped cannot assert current state (same rule as the device rollup).
func InterfaceStatusAt(i Interface, now time.Time) string {
	if i.LastSeenAt == nil || i.OperStatus == nil {
		return StatusUnknown
	}
	if now.Sub(*i.LastSeenAt) > InterfaceFreshnessSeconds*time.Second {
		return StatusUnknown
	}
	if *i.OperStatus == "up" {
		return StatusUp
	}
	return StatusDown
}
