package pollhealth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/argus-platform/argus/internal/modules/inventory"
	"github.com/argus-platform/argus/internal/platform/database"
)

// Device status rollup policy (M10-S1; canonical docs are silent, the values
// are documented choices):
//
//   - Only scheduled poll health counts: on-demand checks (M10-S0) are
//     deliberately excluded because they are operator-triggered and carry
//     consecutive_failures=0.
//   - Down requires DownThreshold consecutive scheduled failures. One or two
//     failures are common transients at the 30–60 s cadences; three
//     consecutive failures means the target has missed its full retry ladder
//     and is the smallest streak that is not a single blip.
//   - Freshness is the window after which a missing scheduled row means
//     "unknown". The adaptive scheduler probes a target at least once per
//     backoff ceiling (15 min; 5 min for critical devices, M9-S4/docs/07
//     §12.3) plus ±10% jitter and transport/batch latency; 20 min covers the
//     worst case with margin. Outside it the collector/schedule is not
//     reporting, so the state cannot be asserted.
//   - `since` is the start of the current contiguous status run as observed
//     within the newest statusHistoryRows scheduled rows per device; for a run
//     longer than that window it reports the oldest row in the window (a
//     documented lower bound).
const (
	// StatusUp, StatusDown and StatusUnknown are re-exported aliases of the
	// inventory constants so poll-health callers do not duplicate strings.
	StatusUp      = inventory.StatusUp
	StatusDown    = inventory.StatusDown
	StatusUnknown = inventory.StatusUnknown

	// DownThreshold is the canonical-down consecutive scheduled failure streak.
	DownThreshold = 3
	// StatusFreshness is the documented freshness window (see above).
	StatusFreshness = 20 * time.Minute
	// statusHistoryRows bounds the per-device history walk used for `since`.
	statusHistoryRows = 1000
)

// scheduledRow is one scheduled poll-health row (newest first per device).
type scheduledRow struct {
	DeviceID            uuid.UUID
	Ts                  time.Time
	Outcome             string
	ErrorClass          string
	LatencyMS           int
	ConsecutiveFailures int
}

// classifyDeviceStatus derives one device's rollup from its scheduled rows
// (newest first). Pure function so transitions and freshness are unit-tested
// without a database.
func classifyDeviceStatus(deviceID uuid.UUID, rows []scheduledRow, now time.Time) inventory.DeviceStatus {
	st := inventory.DeviceStatus{
		DeviceID:         deviceID,
		Status:           StatusUnknown,
		DownThreshold:    DownThreshold,
		FreshnessSeconds: int(StatusFreshness.Seconds()),
	}
	if len(rows) == 0 {
		return st
	}
	last := rows[0]
	outcome := last.Outcome
	st.LastOutcome = &outcome
	if last.ErrorClass != "" {
		class := last.ErrorClass
		st.LastErrorClass = &class
	}
	latency := last.LatencyMS
	st.LastLatencyMS = &latency
	failures := last.ConsecutiveFailures
	st.ConsecutiveFailures = &failures
	checked := last.Ts
	st.LastCheckedAt = &checked

	if now.Sub(last.Ts) > StatusFreshness {
		// The schedule stopped reporting: the state cannot be asserted. The
		// unknown period starts when the newest row became stale.
		since := last.Ts.Add(StatusFreshness)
		st.Since = &since
		return st
	}

	if last.Outcome == "success" || last.ConsecutiveFailures < DownThreshold {
		st.Status = StatusUp
	} else {
		st.Status = StatusDown
	}
	st.Since = runStart(rows, st.Status)
	return st
}

// runStart resolves the start of the current status period:
//
//   - down: the first failure of the trailing failure streak, so "down since"
//     is when the outage began, not when the threshold was reached;
//   - up after success: the first success of the trailing success run
//     (recovery time);
//   - up with below-threshold failures: the start of the most recent success
//     run, i.e. the last time the device was provably reachable.
//
// The walk is bounded by the fetched window (statusHistoryRows); when the run
// extends past it, the oldest fetched row is the documented lower bound.
func runStart(rows []scheduledRow, status string) *time.Time {
	since := rows[0].Ts
	if status == StatusDown {
		for _, row := range rows {
			if row.Outcome != "failure" {
				break
			}
			since = row.Ts
		}
		return &since
	}
	i := 0
	for i < len(rows) && rows[i].Outcome != "success" {
		i++
	}
	if i == len(rows) {
		// Only below-threshold failures in the window; fall back to the
		// oldest row (the up period is longer than the fetched history).
		since = rows[len(rows)-1].Ts
		return &since
	}
	since = rows[i].Ts
	for ; i < len(rows) && rows[i].Outcome == "success"; i++ {
		since = rows[i].Ts
	}
	return &since
}

// DeviceStatuses returns rollups for the given devices (unknown when a device
// has no scheduled health). Runs in one tenant transaction; RLS + the explicit
// org predicate prevent cross-tenant reads.
func (s *Service) DeviceStatuses(ctx context.Context, orgID uuid.UUID, deviceIDs []uuid.UUID) (map[uuid.UUID]inventory.DeviceStatus, error) {
	out := make(map[uuid.UUID]inventory.DeviceStatus, len(deviceIDs))
	if len(deviceIDs) == 0 {
		return out, nil
	}
	ids := dedupeUUIDs(deviceIDs)
	for _, id := range ids {
		out[id] = inventory.DeviceStatus{
			DeviceID:         id,
			Status:           StatusUnknown,
			DownThreshold:    DownThreshold,
			FreshnessSeconds: int(StatusFreshness.Seconds()),
		}
	}
	now := time.Now().UTC()
	byDevice := make(map[uuid.UUID][]scheduledRow, len(ids))
	err := database.WithTenant(ctx, s.pool, orgID, func(ctx context.Context, tx pgx.Tx) error {
		// The lateral top-N uses the (org_id, device_id, ts DESC) index, so
		// the per-device history walk is bounded regardless of retention.
		rows, err := tx.Query(ctx, `
			SELECT h.device_id, h.ts, h.outcome, h.error_class, h.latency_ms, h.consecutive_failures
			FROM unnest($2::uuid[]) AS d(id)
			CROSS JOIN LATERAL (
				SELECT device_id, ts, id, outcome, error_class, latency_ms, consecutive_failures
				FROM poll_health
				WHERE org_id = $1 AND device_id = d.id AND origin = 'scheduled'
				ORDER BY ts DESC, id DESC
				LIMIT $3
			) h
			ORDER BY h.device_id, h.ts DESC, h.id DESC`,
			orgID, ids, statusHistoryRows)
		if err != nil {
			return fmt.Errorf("pollhealth: device statuses: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var r scheduledRow
			if err := rows.Scan(&r.DeviceID, &r.Ts, &r.Outcome, &r.ErrorClass, &r.LatencyMS, &r.ConsecutiveFailures); err != nil {
				return fmt.Errorf("pollhealth: scan status row: %w", err)
			}
			r.Ts = r.Ts.UTC()
			byDevice[r.DeviceID] = append(byDevice[r.DeviceID], r)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("pollhealth: iterate status rows: %w", err)
		}
		for id, deviceRows := range byDevice {
			out[id] = classifyDeviceStatus(id, deviceRows, now)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func dedupeUUIDs(ids []uuid.UUID) []uuid.UUID {
	seen := make(map[uuid.UUID]bool, len(ids))
	out := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}
