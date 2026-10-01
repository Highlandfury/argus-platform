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
