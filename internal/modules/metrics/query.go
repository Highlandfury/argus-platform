package metrics

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/argus-platform/argus/internal/platform/database"
	"github.com/argus-platform/argus/internal/platform/telemetry"
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
//
// Query shape (normative): the series for (collector, metric_key) are resolved
// FIRST (small metric_series lookup), then metric_samples is queried directly
// with series_id = ANY(...). The join-shaped alternative is plan-fragile: after
// the first multi-million-row load, the planner picked a nested loop that
// full-scanned metric_samples with the join as a post-scan filter (observed
// 16.7 s for a latest-value query). Resolving series first keeps every query
// index-driven on metric_samples_series_ts and independent of join estimates.
// Operational hygiene: ANALYZE metric_samples after bulk loads (chunk stats).
type QueryService struct {
	app   *pgxpool.Pool
	authz CollectorAuthorizer
	argus *telemetry.Argus
}

// NewQueryService wires the query service; argus may be nil in unit contexts.
func NewQueryService(app *pgxpool.Pool, authz CollectorAuthorizer, argus *telemetry.Argus) *QueryService {
	return &QueryService{app: app, authz: authz, argus: argus}
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
	queryStart := time.Now()
	err := database.WithTenant(ctx, s.app, q.OrgID, func(ctx context.Context, tx pgx.Tx) error {
		seriesIDs, unit, err := resolveSeries(ctx, tx, q)
		if err != nil {
			return err
		}
		result = RangeResult{
			Metric:     q.MetricKey,
			Unit:       unit,
			Resolution: string(q.Step),
			From:       q.From.UTC(),
			To:         q.To.UTC(),
		}
		if interval > 0 {
			result.Resolution = string(q.Step)
			if err := queryBucketed(ctx, tx, q, seriesIDs, interval, &result); err != nil {
				return err
			}
		} else {
			result.Resolution = string(StepRaw)
			if err := queryRaw(ctx, tx, q, seriesIDs, &result); err != nil {
				return err
			}
		}
		return attachLatest(ctx, tx, q, seriesIDs, &result)
	})
	if s.argus != nil {
		s.argus.DBQueryDuration.WithLabelValues("query").Observe(time.Since(queryStart).Seconds())
	}
	if err != nil {
		return RangeResult{}, err
	}
	return result, nil
}

// resolveSeries resolves the (org, collector, metric) series IDs and unit.
func resolveSeries(ctx context.Context, tx pgx.Tx, q RangeQuery) ([]int64, string, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, unit FROM metric_series
		WHERE org_id = $1 AND collector_id = $2 AND metric_key = $3`,
		q.OrgID, q.CollectorID, q.MetricKey)
	if err != nil {
		return nil, "", fmt.Errorf("metrics: resolve series: %w", err)
	}
	defer rows.Close()
	var (
		ids  []int64
		unit string
	)
	for rows.Next() {
		var id int64
		var u string
		if err := rows.Scan(&id, &u); err != nil {
			return nil, "", fmt.Errorf("metrics: scan series: %w", err)
		}
		ids = append(ids, id)
		if unit == "" {
			unit = u
		}
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("metrics: iterate series: %w", err)
	}
	return ids, unit, nil
}

// expectedBuckets counts bucket-aligned intervals intersecting [from, to].
// 10s/1m/5m divide a day, so Go's absolute-time Truncate and PostgreSQL's
// Unix-epoch time_bucket produce identical alignments.
func expectedBuckets(from, to time.Time, interval time.Duration) int {
	alignedStart := from.UTC().Truncate(interval)
	return int(to.Sub(alignedStart)/interval) + 1
}

func queryBucketed(ctx context.Context, tx pgx.Tx, q RangeQuery, seriesIDs []int64, interval time.Duration, result *RangeResult) error {
	result.Expected = expectedBuckets(q.From, q.To, interval)
	if len(seriesIDs) == 0 {
		result.Gaps = result.Expected
		return nil
	}
	// Per-series bucketed scan (scalar series_id => the (series_id, ts) index
	// is used as an index condition; the ANY(array) form let the planner pick
	// the (org_id, ts DESC) index and walk unrelated rows). Buckets are merged
	// as weighted averages across series (one series per metric in Phase 1).
	type bucket struct {
		sum   float64
		count int64
	}
	buckets := make(map[time.Time]*bucket)
	for _, seriesID := range seriesIDs {
		rows, err := tx.Query(ctx, `
			SELECT time_bucket($1::interval, ts) AS bucket,
			       sum(value)::float8,
			       count(*)::bigint
			FROM metric_samples
			WHERE org_id = $2 AND series_id = $3 AND ts >= $4 AND ts <= $5
			GROUP BY bucket`,
			q.Step.sqlInterval(), q.OrgID, seriesID, q.From, q.To)
		if err != nil {
			return fmt.Errorf("metrics: query buckets: %w", err)
		}
		for rows.Next() {
			var (
				ts    time.Time
				sum   float64
				count int64
			)
			if err := rows.Scan(&ts, &sum, &count); err != nil {
				rows.Close()
				return fmt.Errorf("metrics: scan bucket: %w", err)
			}
			b := buckets[ts.UTC()]
			if b == nil {
				b = &bucket{}
				buckets[ts.UTC()] = b
			}
			b.sum += sum
			b.count += count
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return fmt.Errorf("metrics: iterate buckets: %w", err)
		}
	}
	for ts, b := range buckets {
		result.Points = append(result.Points, Point{Ts: ts, Value: b.sum / float64(b.count)})
		result.SampleCount += b.count
	}
	sort.Slice(result.Points, func(i, j int) bool { return result.Points[i].Ts.Before(result.Points[j].Ts) })
	result.Returned = len(result.Points)
	if result.Expected > result.Returned {
		result.Gaps = result.Expected - result.Returned
	}
	return nil
}

func queryRaw(ctx context.Context, tx pgx.Tx, q RangeQuery, seriesIDs []int64, result *RangeResult) error {
	for _, seriesID := range seriesIDs {
		rows, err := tx.Query(ctx, `
			SELECT ts, value
			FROM metric_samples
			WHERE org_id = $1 AND series_id = $2 AND ts >= $3 AND ts <= $4
			ORDER BY ts
			LIMIT $5`,
			q.OrgID, seriesID, q.From, q.To, MaxPoints+1)
		if err != nil {
			return fmt.Errorf("metrics: query raw: %w", err)
		}
		for rows.Next() {
			var (
				ts    time.Time
				value float64
			)
			if err := rows.Scan(&ts, &value); err != nil {
				rows.Close()
				return fmt.Errorf("metrics: scan raw: %w", err)
			}
			result.Points = append(result.Points, Point{Ts: ts.UTC(), Value: value})
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return fmt.Errorf("metrics: iterate raw: %w", err)
		}
	}
	sort.Slice(result.Points, func(i, j int) bool { return result.Points[i].Ts.Before(result.Points[j].Ts) })
	// The cap is enforced on the actual row count for raw queries.
	if len(result.Points) > MaxPoints {
		return ErrPointsExceeded
	}
	result.SampleCount = int64(len(result.Points))
	result.Returned = len(result.Points)
	result.Expected = result.Returned // raw does not synthesize gap expectations
	return nil
}

// attachLatest loads the most recent sample using planner-deterministic index
// paths: max(ts) per series (backward index seek on (series_id, ts)) followed
// by a primary-key equality lookup for the value. The ORDER BY + ANY(array)
// form is not used here: it let the planner walk the (org_id, ts DESC) index
// across millions of newer rows of other series before reaching an older one
// (observed multi-second latest queries under load). A latest sample that is
// old is never reported as fresh.
func attachLatest(ctx context.Context, tx pgx.Tx, q RangeQuery, seriesIDs []int64, result *RangeResult) error {
	if len(seriesIDs) == 0 {
		result.Status = "no_data"
		return nil
	}
	var (
		bestTs    time.Time
		bestValue float64
	)
	for _, seriesID := range seriesIDs {
		var ts time.Time
		err := tx.QueryRow(ctx, `
			SELECT max(ts) FROM metric_samples
			WHERE org_id = $1 AND series_id = $2`,
			q.OrgID, seriesID).Scan(&ts)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			return fmt.Errorf("metrics: query latest ts: %w", err)
		}
		if !ts.After(bestTs) {
			continue
		}
		var value float64
		// Primary key (series_id, ts) equality: direct index lookup.
		err = tx.QueryRow(ctx, `
			SELECT value FROM metric_samples
			WHERE org_id = $1 AND series_id = $2 AND ts = $3`,
			q.OrgID, seriesID, ts).Scan(&value)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			return fmt.Errorf("metrics: query latest value: %w", err)
		}
		bestTs, bestValue = ts, value
	}
	if bestTs.IsZero() {
		result.Status = "no_data"
		return nil
	}
	window := time.Duration(freshnessMultiplier) * phase1MetricInterval
	if window < freshnessFloor {
		window = freshnessFloor
	}
	age := time.Since(bestTs)
	status := "fresh"
	if age > window || age < -MaxFutureSkew {
		status = "stale"
	}
	result.Latest = &Latest{Ts: bestTs.UTC(), Value: bestValue, AgeSeconds: int64(math.Round(age.Seconds())), Status: status}
	result.Status = status
	return nil
}
