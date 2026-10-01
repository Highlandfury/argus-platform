// Package ingest implements the server-side ingestion pipeline:
// receive → authenticate/authorize (transport) → validate → normalize
// (series) → deduplicate (batch claim) → persist → acknowledge after COMMIT
// (SPEC §12.1). It never acknowledges before durability.
package ingest

import (
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
	"github.com/argus-platform/argus/internal/modules/metrics"
)

// Validation bounds (SPEC §12.1).
const (
	// MaxBatchSamples mirrors ServerHello.max_batch_samples.
	MaxBatchSamples = 5000
	// MaxBatchHealth bounds poll-health records per batch (M9-S1; the
	// collector batches at 500, the server ceiling is deliberately higher).
	MaxBatchHealth = 1000
	// TimestampTolerance is the ±7 day acceptance window for sample ts.
	TimestampTolerance = 7 * 24 * time.Hour
	// maxAbsValue is the sanity bound for non-percent units. Percent metrics
	// are additionally range-checked to [0, 100].
	maxAbsValue = 1e15
	// maxLatencyMS bounds poll-health latency (1 day).
	maxLatencyMS = 24 * 60 * 60 * 1000
	// maxConsecutiveFailures bounds poll-health failure counters.
	maxConsecutiveFailures = 1_000_000
	// maxHealthClassLen bounds error_class storage (matches the DB check).
	maxHealthClassLen = 100
	// maxPollTypeLen bounds poll_type (icmp|snmp today, extensible).
	maxPollTypeLen = 20
)

// RejectError is a permanent, machine-readable rejection. The Reason string is
// served verbatim in BatchResult.reason and dead-lettered by the collector.
type RejectError struct {
	Reason string
	Detail string
}

func (e *RejectError) Error() string { return e.Reason + ": " + e.Detail }

// ValidatedSample is one wire sample that passed validation, with dimensions
// already canonicalized for series resolution. DeviceID is uuid.Nil for the
// Phase-1 collector-scoped series and set for M9 device-scoped samples.
type ValidatedSample struct {
	MetricKey string
	Unit      string
	Value     float64
	Ts        time.Time
	DeviceID  uuid.UUID
	Canonical []byte
	DimHash   int64
}

// ValidatedHealth is one poll-health record that passed validation (M9-S1).
type ValidatedHealth struct {
	DeviceID            uuid.UUID
	PollType            string
	LatencyMS           int
	Outcome             string
	ErrorClass          string
	ConsecutiveFailures int
	CheckedAt           time.Time
	// Origin is the normalized probe trigger: "scheduled" | "on_demand"
	// (M10-S0; empty from old collectors normalizes to scheduled).
	Origin string
}

// ValidateBatch checks and normalizes the sample section of a batch against
// the collector's current policy allowlist. It returns either all validated
// samples or one permanent rejection (the first failing sample). Kept for the
// Phase-1 callers/tests; the ingest path uses ValidateBatchPayload.
func ValidateBatch(batch *collectorv1.MetricBatch, allowlist map[string]MetricDef, now time.Time) ([]ValidatedSample, *RejectError) {
	if batch == nil {
		return nil, &RejectError{"validation.batch_missing", "empty batch payload"}
	}
	if batch.GetBatchSeq() <= 0 {
		return nil, &RejectError{"validation.batch_seq_invalid", "batch_seq must be > 0"}
	}
	if len(batch.GetSamples()) == 0 {
		return nil, &RejectError{"validation.batch_empty", "batch has no samples"}
	}
	return validateSamples(batch.GetSamples(), allowlist, now)
}

// ValidateBatchPayload checks a whole MetricBatch (M9-S1): samples against the
// policy allowlist, poll-health records against the poll-health bounds. A
// batch may carry samples, health, or both; it must carry at least one.
func ValidateBatchPayload(batch *collectorv1.MetricBatch, allowlist map[string]MetricDef, now time.Time) ([]ValidatedSample, []ValidatedHealth, *RejectError) {
	if batch == nil {
		return nil, nil, &RejectError{"validation.batch_missing", "empty batch payload"}
	}
	if batch.GetBatchSeq() <= 0 {
		return nil, nil, &RejectError{"validation.batch_seq_invalid", "batch_seq must be > 0"}
	}
	if len(batch.GetSamples()) == 0 && len(batch.GetHealth()) == 0 {
		return nil, nil, &RejectError{"validation.batch_empty", "batch has no samples and no health records"}
	}
	samples, rej := validateSamples(batch.GetSamples(), allowlist, now)
	if rej != nil {
		return nil, nil, rej
	}
	health, rej := validateHealth(batch.GetHealth(), now)
	if rej != nil {
		return nil, nil, rej
	}
	return samples, health, nil
}

// validateSamples normalizes the sample list (empty allowed for health-only
// batches at the payload level).
func validateSamples(samples []*collectorv1.MetricSample, allowlist map[string]MetricDef, now time.Time) ([]ValidatedSample, *RejectError) {
	if len(samples) > MaxBatchSamples {
		return nil, &RejectError{"validation.batch_too_large",
			fmt.Sprintf("batch has %d samples, limit is %d", len(samples), MaxBatchSamples)}
	}

	out := make([]ValidatedSample, 0, len(samples))
	oldest := now.Add(-TimestampTolerance)
	newest := now.Add(TimestampTolerance)
	for i, s := range samples {
		def, allowed := allowlist[s.GetMetricKey()]
		if !allowed {
			return nil, &RejectError{"validation.metric_not_allowed",
				fmt.Sprintf("sample %d: metric_key %q is not permitted by the current policy", i, s.GetMetricKey())}
		}
		value := s.GetValue()
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return nil, &RejectError{"validation.value_not_finite", fmt.Sprintf("sample %d: value is NaN/Inf", i)}
		}
		if math.Abs(value) > maxAbsValue {
			return nil, &RejectError{"validation.value_out_of_bounds", fmt.Sprintf("sample %d: |value| exceeds %g", i, maxAbsValue)}
		}
		if def.Unit == "percent" && (value < 0 || value > 100) {
			return nil, &RejectError{"validation.value_out_of_range",
				fmt.Sprintf("sample %d: percent value %g outside [0,100]", i, value)}
		}
		ts := s.GetTs()
		if ts == nil {
			return nil, &RejectError{"validation.sample_ts_missing", fmt.Sprintf("sample %d: ts is required", i)}
		}
		sampleTime := ts.AsTime()
		if sampleTime.Before(oldest) || sampleTime.After(newest) {
			return nil, &RejectError{"validation.sample_ts_out_of_range",
				fmt.Sprintf("sample %d: ts %s outside ±%s of now", i, sampleTime.UTC().Format(time.RFC3339), TimestampTolerance)}
		}
		unit := def.Unit
		if wire := s.GetUnit(); wire != "" {
			if wire != def.Unit {
				return nil, &RejectError{"validation.unit_mismatch",
					fmt.Sprintf("sample %d: unit %q does not match policy unit %q", i, wire, def.Unit)}
			}
			unit = wire
		}
		canonical, dimHash, err := metrics.CanonicalizeDimensions(s.GetDimensions())
		if err != nil {
			switch {
			case errors.Is(err, metrics.ErrTooManyDimensions):
				return nil, &RejectError{"validation.dimensions_too_many", fmt.Sprintf("sample %d: %v", i, err)}
			case errors.Is(err, metrics.ErrDimensionTooLong):
				return nil, &RejectError{"validation.dimension_too_long", fmt.Sprintf("sample %d: %v", i, err)}
			default:
				return nil, &RejectError{"validation.dimensions_invalid", fmt.Sprintf("sample %d: %v", i, err)}
			}
		}
		var deviceID uuid.UUID
		if raw := s.GetDeviceId(); raw != "" {
			id, err := uuid.Parse(raw)
			if err != nil {
				return nil, &RejectError{"validation.device_id_invalid",
					fmt.Sprintf("sample %d: device_id %q is not a UUID", i, raw)}
			}
			deviceID = id
		}
		out = append(out, ValidatedSample{
			MetricKey: s.GetMetricKey(),
			Unit:      unit,
			Value:     value,
			Ts:        sampleTime.UTC(),
			DeviceID:  deviceID,
			Canonical: canonical,
			DimHash:   dimHash,
		})
	}
	return out, nil
}

// validateHealth normalizes the poll-health section (M9-S1).
func validateHealth(records []*collectorv1.PollHealth, now time.Time) ([]ValidatedHealth, *RejectError) {
	if len(records) > MaxBatchHealth {
		return nil, &RejectError{"validation.health_too_many",
			fmt.Sprintf("batch has %d health records, limit is %d", len(records), MaxBatchHealth)}
	}
	out := make([]ValidatedHealth, 0, len(records))
	oldest := now.Add(-TimestampTolerance)
	newest := now.Add(TimestampTolerance)
	for i, h := range records {
		id, err := uuid.Parse(h.GetDeviceId())
		if err != nil {
			return nil, &RejectError{"validation.health_device_invalid",
				fmt.Sprintf("health %d: device_id %q is not a UUID", i, h.GetDeviceId())}
		}
		pollType := h.GetPollType()
		if pollType == "" || len(pollType) > maxPollTypeLen {
			return nil, &RejectError{"validation.health_poll_type_invalid",
				fmt.Sprintf("health %d: poll_type %q is empty or too long", i, pollType)}
		}
		outcome := h.GetOutcome()
		if outcome != "success" && outcome != "failure" {
			return nil, &RejectError{"validation.health_outcome_invalid",
				fmt.Sprintf("health %d: outcome %q must be success|failure", i, outcome)}
		}
		latency := int(h.GetLatencyMs())
		if latency < 0 || latency > maxLatencyMS {
			return nil, &RejectError{"validation.health_latency_invalid",
				fmt.Sprintf("health %d: latency_ms %d outside [0,%d]", i, latency, maxLatencyMS)}
		}
		failures := int(h.GetConsecutiveFailures())
		if failures < 0 || failures > maxConsecutiveFailures {
			return nil, &RejectError{"validation.health_failures_invalid",
				fmt.Sprintf("health %d: consecutive_failures %d outside [0,%d]", i, failures, maxConsecutiveFailures)}
		}
		if class := h.GetErrorClass(); len(class) > maxHealthClassLen {
			return nil, &RejectError{"validation.health_error_class_invalid",
				fmt.Sprintf("health %d: error_class exceeds %d chars", i, maxHealthClassLen)}
		}
		checked := h.GetCheckedAt()
		if checked == nil {
			return nil, &RejectError{"validation.health_ts_missing", fmt.Sprintf("health %d: checked_at is required", i)}
		}
		checkedAt := checked.AsTime()
		if checkedAt.Before(oldest) || checkedAt.After(newest) {
			return nil, &RejectError{"validation.health_ts_out_of_range",
				fmt.Sprintf("health %d: checked_at %s outside ±%s of now", i, checkedAt.UTC().Format(time.RFC3339), TimestampTolerance)}
		}
		// Probe origin (M10-S0): empty normalizes to scheduled so old
		// collectors and spool records replay unchanged.
		origin := h.GetOrigin()
		if origin == "" {
			origin = "scheduled"
		}
		if origin != "scheduled" && origin != "on_demand" {
			return nil, &RejectError{"validation.health_origin_invalid",
				fmt.Sprintf("health %d: origin %q must be scheduled|on_demand", i, origin)}
		}
		out = append(out, ValidatedHealth{
			DeviceID:            id,
			PollType:            pollType,
			LatencyMS:           latency,
			Outcome:             outcome,
			ErrorClass:          h.GetErrorClass(),
			ConsecutiveFailures: failures,
			CheckedAt:           checkedAt.UTC(),
			Origin:              origin,
		})
	}
	return out, nil
}
