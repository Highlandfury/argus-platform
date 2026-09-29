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

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
	"github.com/argus-platform/argus/internal/modules/metrics"
)

// Validation bounds (SPEC §12.1).
const (
	// MaxBatchSamples mirrors ServerHello.max_batch_samples.
	MaxBatchSamples = 5000
	// TimestampTolerance is the ±7 day acceptance window for sample ts.
	TimestampTolerance = 7 * 24 * time.Hour
	// maxAbsValue is the sanity bound for non-percent units. Percent metrics
	// are additionally range-checked to [0, 100].
	maxAbsValue = 1e15
)

// RejectError is a permanent, machine-readable rejection. The Reason string is
// served verbatim in BatchResult.reason and dead-lettered by the collector.
type RejectError struct {
	Reason string
	Detail string
}

func (e *RejectError) Error() string { return e.Reason + ": " + e.Detail }

// ValidatedSample is one wire sample that passed validation, with dimensions
// already canonicalized for series resolution.
type ValidatedSample struct {
	MetricKey string
	Unit      string
	Value     float64
	Ts        time.Time
	Canonical []byte
	DimHash   int64
}

// ValidateBatch checks and normalizes a batch against the collector's current
// policy allowlist. It returns either all validated samples or one permanent
// rejection (the first failing sample).
func ValidateBatch(batch *collectorv1.MetricBatch, allowlist map[string]MetricDef, now time.Time) ([]ValidatedSample, *RejectError) {
	if batch == nil {
		return nil, &RejectError{"validation.batch_missing", "empty batch payload"}
	}
	if batch.GetBatchSeq() <= 0 {
		return nil, &RejectError{"validation.batch_seq_invalid", "batch_seq must be > 0"}
	}
	samples := batch.GetSamples()
	if len(samples) == 0 {
		return nil, &RejectError{"validation.batch_empty", "batch has no samples"}
	}
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
		out = append(out, ValidatedSample{
			MetricKey: s.GetMetricKey(),
			Unit:      unit,
			Value:     value,
			Ts:        sampleTime.UTC(),
			Canonical: canonical,
			DimHash:   dimHash,
		})
	}
	return out, nil
}
