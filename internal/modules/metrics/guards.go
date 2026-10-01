package metrics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Cardinality guards (PHASE_2_SPEC P2-AC-11; canonical docs/08 §13.3 and
// docs/11 §20.4).
//
//   - default 250 series per device (template-derived cap; the canonical
//     "200 typical" wording in docs/11 was reconciled to the docs/08 §13.3
//     default of 250 by PHASE_2_SPEC consistency item 2);
//   - hard 10,000 series per site (plan default);
//   - runaway creation rate guard — the canonical docs say "series creation
//     rate per minute above threshold" without a number; this build uses 60
//     new series/min/device as the conservative documented threshold;
//   - over-cap or runaway creation quarantines that series only (ingest stops
//     for it; the device keeps ingesting its other series);
//   - retired series: no samples for 30 days -> tombstoned (retired_at kept
//     for history; CAGGs keep their materialized history until retention).
//
// The `metric.cardinality.exceeded` event is a structured slog event plus a
// Prometheus counter: Phase 2 has no platform events table yet (M11 adds the
// alert wiring; M10 surfaces quarantine state in the UI). Both the event sink
// and the counter follow the existing audit/telemetry patterns
// (internal/modules/inventory/audit.go, internal/modules/metrics/
// series_metrics.go).
const (
	// DefaultMaxSeriesPerDevice is the canonical per-device cap (docs/08 §13.3).
	DefaultMaxSeriesPerDevice = 250
	// DefaultMaxSeriesPerSite is the canonical per-site hard cap
	// (docs/11 §20.4).
	DefaultMaxSeriesPerSite = 10000
	// DefaultMaxSeriesPerMinutePerDevice is the runaway-creation threshold
	// (canonical docs are silent on the number; documented choice).
	DefaultMaxSeriesPerMinutePerDevice = 60
	// SeriesRetirementAge tombstones series inactive for 30 days (docs/08 §13.3).
	SeriesRetirementAge = 30 * 24 * time.Hour
)

// Quarantine reasons (stable strings; surfaced by the M10 UI later).
const (
	QuarantineReasonDeviceCap      = "device_series_cap"
	QuarantineReasonSiteCap        = "site_series_cap"
	QuarantineReasonCreationRate   = "creation_rate"
	QuarantineReasonOperatorAction = "operator_action"
)

// ErrDeviceNotFound is returned when a device-series guard cannot resolve the
// device inside the tenant.
var ErrDeviceNotFound = errors.New("metrics: device not found")

// CardinalityEvent is one `metric.cardinality.exceeded` occurrence.
type CardinalityEvent struct {
	Event     string    `json:"event"`
	Ts        time.Time `json:"ts"`
	OrgID     uuid.UUID `json:"org_id"`
	DeviceID  uuid.UUID `json:"device_id,omitempty"`
	SiteID    uuid.UUID `json:"site_id,omitempty"`
	SeriesID  int64     `json:"series_id,omitempty"`
	MetricKey string    `json:"metric_key,omitempty"`
	Scope     string    `json:"scope"`  // device | site | rate | operator
	Reason    string    `json:"reason"` // quarantine reason constant
	Cap       int       `json:"cap"`
	Current   int       `json:"current"`
}

// EventName is the canonical event type (docs/08 §13.3).
const EventName = "metric.cardinality.exceeded"

// CardinalitySink records cardinality events. Implementations must not fail
// ingest: the guard decision is already taken; recording is best-effort
// (mirrors the audit-sink contract).
type CardinalitySink interface {
	Record(ev CardinalityEvent)
}

// SlogCardinality is the production sink: one structured line per event.
type SlogCardinality struct {
	Logger *slog.Logger
}

// Record implements CardinalitySink.
func (s SlogCardinality) Record(ev CardinalityEvent) {
	if s.Logger == nil {
		return
	}
	s.Logger.Warn("metric cardinality exceeded",
		"event", ev.Event, "scope", ev.Scope, "reason", ev.Reason,
		"org_id", ev.OrgID, "device_id", ev.DeviceID, "site_id", ev.SiteID,
		"series_id", ev.SeriesID, "metric_key", ev.MetricKey,
		"cap", ev.Cap, "current", ev.Current)
}

// GuardOptions configures the device/site caps. Zero values take the
// canonical defaults; tests set small caps for determinism.
type GuardOptions struct {
	MaxPerDevice int
	MaxPerSite   int
	MaxPerMinute int
	Sink         CardinalitySink
	Now          func() time.Time
}

func (o GuardOptions) withDefaults() GuardOptions {
	if o.MaxPerDevice <= 0 {
		o.MaxPerDevice = DefaultMaxSeriesPerDevice
	}
	if o.MaxPerSite <= 0 {
		o.MaxPerSite = DefaultMaxSeriesPerSite
	}
	if o.MaxPerMinute <= 0 {
		o.MaxPerMinute = DefaultMaxSeriesPerMinutePerDevice
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

// classifyQuarantine decides whether one new series crosses a budget.
// Precedence: device cap, site cap, creation rate.
func classifyQuarantine(deviceCount, siteCount, createdLastMinute int, o GuardOptions) (reason string, scope string, capacity, current int, quarantine bool) {
	if deviceCount >= o.MaxPerDevice {
		return QuarantineReasonDeviceCap, "device", o.MaxPerDevice, deviceCount, true
	}
	if siteCount >= o.MaxPerSite {
		return QuarantineReasonSiteCap, "site", o.MaxPerSite, siteCount, true
	}
	if createdLastMinute >= o.MaxPerMinute {
		return QuarantineReasonCreationRate, "rate", o.MaxPerMinute, createdLastMinute, true
	}
	return "", "", 0, 0, false
}

// DeviceSeriesSpec is one device-scoped series to resolve or create. Device
// series arrive with the polling engine (M9); the guard is complete and tested
// now so the write path can adopt it without redesign.
type DeviceSeriesSpec struct {
	OrgID     uuid.UUID
	DeviceID  uuid.UUID
	MetricKey string
	Unit      string
	Canonical []byte
	DimHash   int64
}

// DeviceSeriesResult is the resolution outcome.
type DeviceSeriesResult struct {
	ID          int64
	Quarantined bool
	Reason      string
}

// EnsureDeviceSeries resolves or creates one device series, enforcing the
// per-device, per-site and creation-rate budgets. Over-budget series are
// created in the quarantined state (so the identity is reserved and the
// registry can show it) and a metric.cardinality.exceeded event is emitted.
// The cap check is advisory under concurrency: a race can overshoot by the
// number of concurrent creators, which the unique identity index bounds and
// the next guard call re-tightens. Must run inside a tenant transaction.
func EnsureDeviceSeries(ctx context.Context, tx pgx.Tx, spec DeviceSeriesSpec, opts GuardOptions) (DeviceSeriesResult, error) {
	o := opts.withDefaults()
	if len(spec.Canonical) == 0 {
		spec.Canonical = []byte("{}")
	}

	existing, found, err := resolveDeviceSeries(ctx, tx, spec)
	if err != nil {
		return DeviceSeriesResult{}, err
	}
	if found {
		return existing, nil
	}

	var siteID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT site_id FROM devices WHERE org_id = $1 AND id = $2`,
		spec.OrgID, spec.DeviceID).Scan(&siteID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return DeviceSeriesResult{}, fmt.Errorf("%w: %s", ErrDeviceNotFound, spec.DeviceID)
		}
		return DeviceSeriesResult{}, fmt.Errorf("metrics: resolve device site: %w", err)
	}

	var deviceCount, siteCount, createdLastMinute int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM metric_series
		WHERE org_id = $1 AND device_id = $2 AND retired_at IS NULL`,
		spec.OrgID, spec.DeviceID).Scan(&deviceCount); err != nil {
		return DeviceSeriesResult{}, fmt.Errorf("metrics: count device series: %w", err)
	}
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM metric_series ms
		JOIN devices d ON d.id = ms.device_id AND d.org_id = ms.org_id
		WHERE ms.org_id = $1 AND d.site_id = $2 AND ms.retired_at IS NULL`,
		spec.OrgID, siteID).Scan(&siteCount); err != nil {
		return DeviceSeriesResult{}, fmt.Errorf("metrics: count site series: %w", err)
	}
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM metric_series
		WHERE org_id = $1 AND device_id = $2 AND created_at > now() - interval '1 minute'`,
		spec.OrgID, spec.DeviceID).Scan(&createdLastMinute); err != nil {
		return DeviceSeriesResult{}, fmt.Errorf("metrics: count recent series: %w", err)
	}

	reason, scope, capacity, current, quarantine := classifyQuarantine(deviceCount, siteCount, createdLastMinute, o)

	var (
		id               int64
		quarantinedAt    *time.Time
		quarantineReason *string
	)
	if quarantine {
		now := o.Now().UTC()
		quarantinedAt = &now
		quarantineReason = &reason
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO metric_series (org_id, device_id, metric_key, dimensions, dim_hash, unit, quarantined_at, quarantine_reason)
		VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8)
		ON CONFLICT (org_id, device_id, metric_key, dim_hash) WHERE device_id IS NOT NULL
		DO NOTHING
		RETURNING id`,
		spec.OrgID, spec.DeviceID, spec.MetricKey, string(spec.Canonical), spec.DimHash, spec.Unit,
		quarantinedAt, quarantineReason).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		// Concurrent creator won the race: return its resolution.
		existing, found, err := resolveDeviceSeries(ctx, tx, spec)
		if err != nil {
			return DeviceSeriesResult{}, err
		}
		if !found {
			return DeviceSeriesResult{}, errors.New("metrics: device series unresolved after insert race")
		}
		return existing, nil
	}
	if err != nil {
		return DeviceSeriesResult{}, fmt.Errorf("metrics: insert device series: %w", err)
	}
	seriesCreated.Add(1)

	result := DeviceSeriesResult{ID: id}
	if quarantine {
		result.Quarantined = true
		result.Reason = reason
		emitCardinalityEvent(o.Sink, CardinalityEvent{
			Event: EventName, Ts: o.Now().UTC(), OrgID: spec.OrgID,
			DeviceID: spec.DeviceID, SiteID: siteID, SeriesID: id,
			MetricKey: spec.MetricKey, Scope: scope, Reason: reason,
			Cap: capacity, Current: current,
		})
	}
	return result, nil
}

// resolveDeviceSeries looks up one device series by identity.
func resolveDeviceSeries(ctx context.Context, tx pgx.Tx, spec DeviceSeriesSpec) (DeviceSeriesResult, bool, error) {
	var (
		id          int64
		quarantined bool
		reason      *string
	)
	err := tx.QueryRow(ctx, `
		SELECT id, quarantined_at IS NOT NULL, quarantine_reason FROM metric_series
		WHERE org_id = $1 AND device_id = $2 AND metric_key = $3 AND dim_hash = $4`,
		spec.OrgID, spec.DeviceID, spec.MetricKey, spec.DimHash).Scan(&id, &quarantined, &reason)
	if errors.Is(err, pgx.ErrNoRows) {
		return DeviceSeriesResult{}, false, nil
	}
	if err != nil {
		return DeviceSeriesResult{}, false, fmt.Errorf("metrics: resolve device series: %w", err)
	}
	res := DeviceSeriesResult{ID: id, Quarantined: quarantined}
	if reason != nil {
		res.Reason = *reason
	}
	return res, true, nil
}

// QuarantineSeries quarantines an existing series (runaway detection or
// operator action). Returns true when the series transitioned; already
// quarantined or retired series are a no-op.
func QuarantineSeries(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, seriesID int64, reason string, sink CardinalitySink) (bool, error) {
	if reason == "" {
		reason = QuarantineReasonOperatorAction
	}
	var (
		metricKey string
		deviceID  *uuid.UUID
	)
	err := tx.QueryRow(ctx, `
		UPDATE metric_series
		SET quarantined_at = now(), quarantine_reason = $3
		WHERE org_id = $1 AND id = $2 AND quarantined_at IS NULL AND retired_at IS NULL
		RETURNING metric_key, device_id`,
		orgID, seriesID, reason).Scan(&metricKey, &deviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("metrics: quarantine series: %w", err)
	}
	ev := CardinalityEvent{
		Event: EventName, Ts: time.Now().UTC(), OrgID: orgID, SeriesID: seriesID,
		MetricKey: metricKey, Scope: "operator", Reason: reason,
	}
	if deviceID != nil {
		ev.DeviceID = *deviceID
	}
	emitCardinalityEvent(sink, ev)
	return true, nil
}

func emitCardinalityEvent(sink CardinalitySink, ev CardinalityEvent) {
	cardinalityExceeded.WithLabelValues(ev.Scope).Inc()
	if sink != nil {
		sink.Record(ev)
	}
}

// RetireInactiveSeries tombstones series whose last activity is older than
// age (canonical: 30 days, docs/08 §13.3). Registry rows are kept for history
// (docs/11 §20.4). Called by the maintenance command under the owner role:
// FORCE RLS requires that role to be BYPASSRLS/superuser.
func RetireInactiveSeries(ctx context.Context, owner *pgxpool.Pool, age time.Duration) (int64, error) {
	if age <= 0 {
		age = SeriesRetirementAge
	}
	tag, err := owner.Exec(ctx, `
		UPDATE metric_series
		SET retired_at = now()
		WHERE retired_at IS NULL AND last_seen_at IS NOT NULL
		  AND last_seen_at < now() - make_interval(secs => $1)`, age.Seconds())
	if err != nil {
		return 0, fmt.Errorf("metrics: retire series: %w", err)
	}
	if n := tag.RowsAffected(); n > 0 {
		seriesRetired.Add(float64(n))
		return n, nil
	}
	return 0, nil
}
