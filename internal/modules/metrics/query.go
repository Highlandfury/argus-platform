package metrics

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/argus-platform/argus/internal/platform/database"
)

// Query limits (SPEC §13: max 2,000 points; step ∈ {raw, 10s, 1m, 5m}).
const (
	// MaxPoints is the hard result cap per query.
	MaxPoints = 2000
	// MaxRange is the widest supported window (24 h per the Phase-1 UI).
	MaxRange = 24 * time.Hour
	// MaxFutureSkew tolerates minor clock skew on the `to` parameter.
	MaxFutureSkew = 5 * time.Minute
)

// Freshness semantics (documented Phase-1 rule): a latest sample is "fresh"
// when it is at most max(3 × the metric's policy interval, 30 s) old. The
// Phase-1 metric interval is the collector_cpu_percent policy interval (5 s),
// so the window is 30 s; policy-derived intervals are a later refinement.
const (
	freshnessMultiplier  = 3
	freshnessFloor       = 30 * time.Second
	phase1MetricInterval = 5 * time.Second
)

// Step is a supported downsampling resolution.
type Step string

// Supported steps.
const (
	StepRaw Step = "raw"
	Step10s Step = "10s"
	Step1m  Step = "1m"
	Step5m  Step = "5m"
)

// Interval returns the bucket width (0 for raw).
func (s Step) Interval() time.Duration {
	switch s {
	case Step10s:
		return 10 * time.Second
	case Step1m:
		return time.Minute
	case Step5m:
		return 5 * time.Minute
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
	default:
		return ""
	}
}

// ParseStep validates a step parameter ("" defaults to 10s per the contract).
func ParseStep(raw string) (Step, error) {
	switch Step(raw) {
	case "":
		return Step10s, nil
	case StepRaw, Step10s, Step1m, Step5m:
		return Step(raw), nil
	default:
		return "", fmt.Errorf("unknown step %q (allowed: raw, 10s, 1m, 5m)", raw)
	}
}

// Errors surfaced to the HTTP layer.
var (
	ErrUnknownCollector = errors.New("metrics: collector not found")
	ErrPointsExceeded   = errors.New("metrics: query exceeds the point limit")
	ErrRangeInvalid     = errors.New("metrics: invalid time range")
)

// KnownMetricKeys is the Phase-1 metric catalog (policy allowlist). Queries for
// anything else are rejected: no arbitrary metric access.
var KnownMetricKeys = map[string]bool{
	"collector_cpu_percent": true,
}

// CollectorAuthorizer resolves collector existence within the caller's org
// (implemented by the collectors module; keeps this package free of an import
// cycle).
type CollectorAuthorizer interface {
	CollectorExists(ctx context.Context, orgID, collectorID uuid.UUID) (bool, error)
}

// QueryService serves metric range/latest queries over TimescaleDB.
type QueryService struct {
	app   *pgxpool.Pool
	authz CollectorAuthorizer
}

// NewQueryService wires the query service.
func NewQueryService(app *pgxpool.Pool, authz CollectorAuthorizer) *QueryService {
	return &QueryService{app: app, authz: authz}
}

// RangeQuery is one validated metric query.
type RangeQuery struct {
	OrgID       uuid.UUID
	CollectorID uuid.UUID
	MetricKey   string
	From        time.Time
	To          time.Time
	Step        Step
}

// Latest is the current-value projection with freshness semantics.
type Latest struct {
	Ts         time.Time
	Value      float64
	AgeSeconds int64
	Status     string // fresh | stale
}

// RangeResult is the API projection of one query.
type RangeResult struct {
	Metric      string
	Unit        string
	Resolution  string
	From        time.Time
	To          time.Time
	Points      []Point
	Expected    int
	Returned    int
	Gaps        int
	SampleCount int64
	Latest      *Latest
	Status      string // no_data | fresh | stale
}

// Point is one returned sample/bucket.
type Point struct {
	Ts    time.Time
	Value float64
}

// QueryRange validates bounds, enforces the point cap, and executes the
// tenant-scoped query. It never builds SQL from user input: the metric key is
// a validated catalog value and everything else is bound parameters.
func (s *QueryService) QueryRange(ctx context.Context, q RangeQuery) (RangeResult, error) {
	if !KnownMetricKeys[q.MetricKey] {
		return RangeResult{}, fmt.Errorf("%w: metric %q", ErrUnknownCollector, q.MetricKey)
	}
	if !q.From.Before(q.To) {
		return RangeResult{}, fmt.Errorf("%w: from must be before to", ErrRangeInvalid)
	}
	if q.To.Sub(q.From) > MaxRange {
		return RangeResult{}, fmt.Errorf("%w: range exceeds %s", ErrRangeInvalid, MaxRange)
	}
	if q.To.After(time.Now().Add(MaxFutureSkew)) {
		return RangeResult{}, fmt.Errorf("%w: to is in the future", ErrRangeInvalid)
	}
	if s.authz != nil {
		exists, err := s.authz.CollectorExists(ctx, q.OrgID, q.CollectorID)
		if err != nil {
			return RangeResult{}, err
		}
		if !exists {
			return RangeResult{}, ErrUnknownCollector
		}
	}

	interval := q.Step.Interval()
	if interval > 0 {
		if points := expectedBuckets(q.From, q.To, interval); points > MaxPoints {
			return RangeResult{}, fmt.Errorf("%w: %d points for %s step (max %d)", ErrPointsExceeded, points, q.Step, MaxPoints)
		}
	}

	var result RangeResult
	err := database.WithTenant(ctx, s.app, q.OrgID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		if interval > 0 {
			result, err = queryBucketed(ctx, tx, q, interval)
		} else {
			result, err = queryRaw(ctx, tx, q)
		}
		if err != nil {
			return err
		}
		return attachLatest(ctx, tx, q, &result)
	})
	if err != nil {
		return RangeResult{}, err
	}
	return result, nil
}

// expectedBuckets counts bucket-aligned intervals intersecting [from, to].
// 10s/1m/5m divide a day, so Go's absolute-time Truncate and PostgreSQL's
// Unix-epoch time_bucket produce identical alignments.
func expectedBuckets(from, to time.Time, interval time.Duration) int {
	alignedStart := from.UTC().Truncate(interval)
	return int(to.Sub(alignedStart)/interval) + 1
}

func queryBucketed(ctx context.Context, tx pgx.Tx, q RangeQuery, interval time.Duration) (RangeResult, error) {
	rows, err := tx.Query(ctx, `
		SELECT time_bucket($3::interval, ms.ts) AS bucket,
		       avg(ms.value)::float8,
		       count(*)::bigint,
		       s.unit
		FROM metric_samples ms
		JOIN metric_series s ON s.id = ms.series_id
		WHERE ms.org_id = $1
		  AND s.collector_id = $2
		  AND s.metric_key = $4
		  AND ms.ts >= $5 AND ms.ts <= $6
		GROUP BY bucket, s.unit
		ORDER BY bucket`,
		q.OrgID, q.CollectorID, q.Step.sqlInterval(), q.MetricKey, q.From, q.To)
	if err != nil {
		return RangeResult{}, fmt.Errorf("metrics: query buckets: %w", err)
	}
	defer rows.Close()

	result := RangeResult{
		Metric:     q.MetricKey,
		Resolution: string(q.Step),
		From:       q.From.UTC(),
		To:         q.To.UTC(),
	}
	for rows.Next() {
		var (
			ts    time.Time
			value float64
			count int64
			unit  string
		)
		if err := rows.Scan(&ts, &value, &count, &unit); err != nil {
			return RangeResult{}, fmt.Errorf("metrics: scan bucket: %w", err)
		}
		result.Points = append(result.Points, Point{Ts: ts.UTC(), Value: value})
		result.SampleCount += count
		result.Unit = unit
	}
	if err := rows.Err(); err != nil {
		return RangeResult{}, fmt.Errorf("metrics: iterate buckets: %w", err)
	}
	result.Expected = expectedBuckets(q.From, q.To, interval)
	result.Returned = len(result.Points)
	if result.Expected > result.Returned {
		result.Gaps = result.Expected - result.Returned
	}
	return result, nil
}

func queryRaw(ctx context.Context, tx pgx.Tx, q RangeQuery) (RangeResult, error) {
	rows, err := tx.Query(ctx, `
		SELECT ms.ts, ms.value, s.unit
		FROM metric_samples ms
		JOIN metric_series s ON s.id = ms.series_id
		WHERE ms.org_id = $1
		  AND s.collector_id = $2
		  AND s.metric_key = $3
		  AND ms.ts >= $4 AND ms.ts <= $5
		ORDER BY ms.ts
		LIMIT $6`,
		q.OrgID, q.CollectorID, q.MetricKey, q.From, q.To, MaxPoints+1)
	if err != nil {
		return RangeResult{}, fmt.Errorf("metrics: query raw: %w", err)
	}
	defer rows.Close()

	result := RangeResult{
		Metric:     q.MetricKey,
		Resolution: string(StepRaw),
		From:       q.From.UTC(),
		To:         q.To.UTC(),
	}
	for rows.Next() {
		var (
			ts    time.Time
			value float64
			unit  string
		)
		if err := rows.Scan(&ts, &value, &unit); err != nil {
			return RangeResult{}, fmt.Errorf("metrics: scan raw: %w", err)
		}
		result.Points = append(result.Points, Point{Ts: ts.UTC(), Value: value})
		result.Unit = unit
	}
	if err := rows.Err(); err != nil {
		return RangeResult{}, fmt.Errorf("metrics: iterate raw: %w", err)
	}
	// The cap is enforced on the actual row count for raw queries.
	if len(result.Points) > MaxPoints {
		return RangeResult{}, ErrPointsExceeded
	}
	result.SampleCount = int64(len(result.Points))
	result.Returned = len(result.Points)
	result.Expected = result.Returned // raw does not synthesize gap expectations
	return result, nil
}

// attachLatest loads the most recent sample (native DISTINCT ON over the
// (series_id, ts DESC) index) and computes freshness. An old "latest" sample is
// never reported as fresh.
func attachLatest(ctx context.Context, tx pgx.Tx, q RangeQuery, result *RangeResult) error {
	var (
		ts    time.Time
		value float64
	)
	err := tx.QueryRow(ctx, `
		SELECT ms.ts, ms.value
		FROM metric_samples ms
		JOIN metric_series s ON s.id = ms.series_id
		WHERE ms.org_id = $1 AND s.collector_id = $2 AND s.metric_key = $3
		ORDER BY ms.ts DESC
		LIMIT 1`,
		q.OrgID, q.CollectorID, q.MetricKey).Scan(&ts, &value)
	if errors.Is(err, pgx.ErrNoRows) {
		result.Status = "no_data"
		return nil
	}
	if err != nil {
		return fmt.Errorf("metrics: query latest: %w", err)
	}
	window := time.Duration(freshnessMultiplier) * phase1MetricInterval
	if window < freshnessFloor {
		window = freshnessFloor
	}
	age := time.Since(ts)
	status := "fresh"
	if age > window || age < -MaxFutureSkew {
		status = "stale"
	}
	result.Latest = &Latest{Ts: ts.UTC(), Value: value, AgeSeconds: int64(math.Round(age.Seconds())), Status: status}
	result.Status = status
	return nil
}
