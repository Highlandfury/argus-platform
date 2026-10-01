package metrics

import (
	"fmt"
	"time"
)

// Resolution picker and rollup policy metadata (docs/08 §13.5, docs/11 §21.2;
// PHASE_2_SPEC P2-AC-07/08/09/10).
//
// Canonical picker (docs/08 §13.5, adopted by PHASE_2_SPEC consistency item 1
// over the docs/11 §20.4 wording):
//
//	≤ 6 h   → raw or 1m   (this service materializes 1m; raw fallback covers
//	                       spans the CAGG has not reached yet)
//	≤ 7 d   → 5m
//	≤ 90 d  → 1h
//	beyond  → 1d
//
// Explicit steps remain valid overrides; the API reports a warning when the
// override is finer than the picker's recommendation for the requested range.

const (
	// pickerRawWindow is the widest span still served at 1m resolution.
	pickerRawWindow = 6 * time.Hour
	// picker5mWindow is the widest span served by 5m rollups.
	picker5mWindow = 7 * 24 * time.Hour
	// picker1hWindow is the widest span served by 1h rollups.
	picker1hWindow = 90 * 24 * time.Hour
)

// Step is a supported downsampling resolution.
type Step string

// Supported steps.
const (
	// StepAuto asks the server to pick by time range (docs/08 §13.5).
	StepAuto Step = "auto"
	StepRaw  Step = "raw"
	Step10s  Step = "10s"
	Step1m   Step = "1m"
	Step5m   Step = "5m"
	Step1h   Step = "1h"
	Step1d   Step = "1d"
)

// Interval returns the bucket width (0 for raw/auto).
func (s Step) Interval() time.Duration {
	switch s {
	case Step10s:
		return 10 * time.Second
	case Step1m:
		return time.Minute
	case Step5m:
		return 5 * time.Minute
	case Step1h:
		return time.Hour
	case Step1d:
		return 24 * time.Hour
	default:
		return 0
	}
}

// sqlInterval renders the interval for PostgreSQL time_bucket.
func (s Step) sqlInterval() string {
	switch s {
	case Step10s:
		return "10 seconds"
	case Step1m:
		return "1 minute"
	case Step5m:
		return "5 minutes"
	case Step1h:
		return "1 hour"
	case Step1d:
		return "1 day"
	default:
		return ""
	}
}

// ParseStep validates a step parameter. The empty value is the canonical
// `auto` (picker) per docs/12 §22.8; explicit Phase-1 steps stay valid.
func ParseStep(raw string) (Step, error) {
	switch Step(raw) {
	case "", StepAuto:
		return StepAuto, nil
	case StepRaw, Step10s, Step1m, Step5m, Step1h, Step1d:
		return Step(raw), nil
	default:
		return "", fmt.Errorf("unknown step %q (allowed: auto, raw, 10s, 1m, 5m, 1h, 1d)", raw)
	}
}

// PickStep implements the canonical resolution picker (docs/08 §13.5).
func PickStep(from, to time.Time) Step {
	span := to.Sub(from)
	switch {
	case span <= pickerRawWindow:
		return Step1m
	case span <= picker5mWindow:
		return Step5m
	case span <= picker1hWindow:
		return Step1h
	default:
		return Step1d
	}
}

// ResolutionName maps a step to the canonical meta.resolution vocabulary
// (docs/12 §22.8 example: "rollup_1m", "raw"). 10s buckets are computed from
// raw samples, so they report as raw.
func ResolutionName(s Step) string {
	switch s {
	case Step1m:
		return "rollup_1m"
	case Step5m:
		return "rollup_5m"
	case Step1h:
		return "rollup_1h"
	case Step1d:
		return "rollup_1d"
	default:
		return "raw"
	}
}

// IsRollupStep reports whether the step reads a continuous aggregate.
func IsRollupStep(s Step) bool {
	_, ok := rollupPolicies[s]
	return ok
}

// RollupPolicy is the deterministic description of one continuous aggregate
// used both by the query engine (materialization boundary / raw fallback) and
// by the maintenance verification (`argus-server metrics-maintenance`).
//
// StartOffset/EndOffset/Schedule mirror the refresh policy created by
// migration 000012. The 1m values are canonical (docs/11 §21.2); the coarser
// values are documented choices (2 × bucket end offset, bucket-width
// schedule) because the canonical docs only specify the 1m policy.
type RollupPolicy struct {
	Step        Step
	CAGG        string // continuous aggregate name (metric_1m, ...)
	TenantView  string // org-filtered view the runtime role reads
	StartOffset time.Duration
	EndOffset   time.Duration
	Schedule    time.Duration
}

// PostgreSQL interval-to-epoch conventions (verified against the pinned
// image): a month is 30 days and a year is 365.25 days. The policy
// expectations below use '13 months' / '3 years' in SQL, so the Go side must
// use the same arithmetic (M8_EVIDENCE.md §3).
const (
	pgMonth = 30 * 24 * time.Hour
	pgYear  = 8766 * time.Hour // 365.25 days
)

// RollupPolicies returns the four CAGG policies in resolution order.
func RollupPolicies() []RollupPolicy {
	return []RollupPolicy{
		{Step: Step1m, CAGG: "metric_1m", TenantView: "metric_1m_tenant",
			StartOffset: 7 * 24 * time.Hour, EndOffset: 2 * time.Minute, Schedule: time.Minute},
		{Step: Step5m, CAGG: "metric_5m", TenantView: "metric_5m_tenant",
			StartOffset: 30 * 24 * time.Hour, EndOffset: 10 * time.Minute, Schedule: 5 * time.Minute},
		{Step: Step1h, CAGG: "metric_1h", TenantView: "metric_1h_tenant",
			StartOffset: 90 * 24 * time.Hour, EndOffset: 2 * time.Hour, Schedule: time.Hour},
		{Step: Step1d, CAGG: "metric_1d", TenantView: "metric_1d_tenant",
			StartOffset: pgYear + pgMonth, EndOffset: 48 * time.Hour, Schedule: time.Hour},
	}
}

// rollupPolicies indexes RollupPolicies by step for the query path.
var rollupPolicies = func() map[Step]RollupPolicy {
	m := make(map[Step]RollupPolicy, 4)
	for _, p := range RollupPolicies() {
		m[p.Step] = p
	}
	return m
}()

// RetentionPolicy is the canonical on-prem retention expectation
// (PHASE_2_SPEC P2-AC-09; docs/17 §35.1).
type RetentionPolicy struct {
	Relation string
	After    time.Duration
	// Configurable marks the raw policy, whose drop_after is operator-set
	// within [30 d, 90 d] via ARGUS_METRICS_RAW_RETENTION_DAYS.
	Configurable bool
}

// RetentionPolicies returns the five canonical retention policies. rawAfter is
// the configured raw window (30-90 days).
func RetentionPolicies(rawAfter time.Duration) []RetentionPolicy {
	return []RetentionPolicy{
		{Relation: "metric_samples", After: rawAfter, Configurable: true},
		{Relation: "metric_1m", After: 30 * 24 * time.Hour},
		{Relation: "metric_5m", After: 90 * 24 * time.Hour},
		{Relation: "metric_1h", After: pgYear + pgMonth}, // '13 months'
		{Relation: "metric_1d", After: 3 * pgYear},       // '3 years'
	}
}

// CompressionPolicy describes where compression is expected.
//
// On the pinned TimescaleDB 2.30.1, compression and row-level security cannot
// coexist on one hypertable (upstream issue timescale/timescaledb#6827), and
// Phase-1 G5 pins RLS on metric_samples. Raw compression is therefore blocked
// and documented (M8_EVIDENCE.md §5); the four CAGG materializations carry the
// compression policies this build can activate.
type CompressionPolicy struct {
	Relation  string
	After     time.Duration
	SegmentBy string
	OrderBy   string
}

// CompressionPolicies returns the compression expectations.
func CompressionPolicies() []CompressionPolicy {
	return []CompressionPolicy{
		{Relation: "metric_1m", After: 7 * 24 * time.Hour, SegmentBy: "series_id", OrderBy: "bucket DESC"},
		{Relation: "metric_5m", After: 7 * 24 * time.Hour, SegmentBy: "series_id", OrderBy: "bucket DESC"},
		{Relation: "metric_1h", After: 7 * 24 * time.Hour, SegmentBy: "series_id", OrderBy: "bucket DESC"},
		{Relation: "metric_1d", After: 7 * 24 * time.Hour, SegmentBy: "series_id", OrderBy: "bucket DESC"},
	}
}
