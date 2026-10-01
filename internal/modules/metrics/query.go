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

// Query limits (PHASE_2_SPEC P2-AC-13; docs/08 §13.5; docs/12 §22.8):
// max 10,000 points per response, max 100 series, 15 s timeout, partial
// results flagged. The Phase-1 contract (2,000 points, 24 h max range, 5 s)
// was reconciled to these canonical values in M8 (M8_EVIDENCE.md §2).
const (
	// MaxPoints is the response point cap. Larger result sets are returned
	// truncated to the newest MaxPoints buckets with partial=true.
	MaxPoints = 10000
	// MaxSeries is the series cap per query. Additional series are dropped
	// deterministically (lowest ids first) with partial=true.
	MaxSeries = 100
	// MaxRange is the widest supported window, aligned with the 1d retention
	// horizon (3 years, docs/08 §13.4).
	MaxRange = 3 * 365 * 24 * time.Hour
	// MaxFutureSkew tolerates minor clock skew on the `to` parameter.
	MaxFutureSkew = 5 * time.Minute
	// QueryTimeout bounds every metric query server-side (canonical 15 s).
	QueryTimeout = 15 * time.Second
	// maxHardBuckets is the loud rejection bound: requests whose bucket count
	// exceeds MaxPoints × 100 are refused (422 query.points_exceeded) instead
	// of scanning pathological ranges for points that will be truncated away.
	maxHardBuckets = MaxPoints * 100
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

// Errors surfaced to the HTTP layer.
var (
	ErrUnknownCollector = errors.New("metrics: collector not found")
	ErrPointsExceeded   = errors.New("metrics: query exceeds the point budget")
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
// FIRST (small metric_series lookup), then the rollup or raw table is queried
// with series_id = ANY(...)-equivalent scalar lookups. The join-shaped
// alternative is plan-fragile (observed 16.7 s latest-value queries under
// load); resolving series first keeps every query index-driven.
//
// Rollup queries read the org-filtered tenant views (metric_1m_tenant, ...)
// and fall back to raw-bucket computation for the span newer than the CAGG
// materialization boundary; the boundary is conservative (end_offset +
// schedule) so no bucket is read from both sources (M8_EVIDENCE.md §2).
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
	Metric     string
	Unit       string
	Resolution string // effective step (auto resolved by the picker)
	From       time.Time
	To         time.Time
	Points     []Point
	Expected   int
	Returned   int
	Gaps       int

	SampleCount int64
	Latest      *Latest
	Status      string // no_data | fresh | stale

	// Canonical cap/fallback metadata (docs/12 §22.8; P2-AC-13).
	SeriesTotal       int
	SeriesReturned    int
	Partial           bool // series or points were truncated
	PointsTruncated   bool
	RawFallback       bool // recent span served from raw samples
	RollupMissing     bool // CAGG had no materialization for the older span
	ResolutionWarning string
}

// Point is one returned sample/bucket.
type Point struct {
	Ts    time.Time
	Value float64
}

// QueryRange validates bounds, applies the resolution picker and caps, and
// executes the tenant-scoped query. It never builds SQL from user input: the
// metric key is a validated catalog value, the step selects from a fixed
// policy table, and everything else is bound parameters.
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
	recommended := PickStep(q.From, q.To)
	step := q.Step
	if step == StepAuto {
		step = recommended
	}
	interval := step.Interval()
	if interval > 0 {
		if points := expectedBuckets(q.From, q.To, interval); points > maxHardBuckets {
			return RangeResult{}, fmt.Errorf("%w: %d buckets for %s step (hard budget %d; responses cap at %d)",
				ErrPointsExceeded, points, step, maxHardBuckets, MaxPoints)
		}
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

	warning := resolutionWarning(q.Step, recommended)
	var result RangeResult
	queryStart := time.Now()
	err := database.WithTenant(ctx, s.app, q.OrgID, func(ctx context.Context, tx pgx.Tx) error {
		seriesIDs, unit, total, err := resolveSeries(ctx, tx, q)
		if err != nil {
			return err
		}
		result = RangeResult{
			Metric:            q.MetricKey,
			Unit:              unit,
			Resolution:        string(step),
			ResolutionWarning: warning,
			From:              q.From.UTC(),
			To:                q.To.UTC(),
			SeriesTotal:       total,
		}
		if len(seriesIDs) > MaxSeries {
			seriesIDs = seriesIDs[:MaxSeries]
			result.Partial = true
		}
		result.SeriesReturned = len(seriesIDs)

		if step == StepRaw {
			if err := queryRaw(ctx, tx, q, seriesIDs, &result); err != nil {
				return err
			}
		} else if err := queryBucketed(ctx, tx, q, step, seriesIDs, &result); err != nil {
			return err
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

// resolutionWarning flags explicit overrides finer than the picker
// recommendation for the same range ("user override with warning", docs/08
// §13.5).
func resolutionWarning(requested, effective Step) string {
	if requested == StepAuto || requested == StepRaw {
		return ""
	}
	if ri, ei := requested.Interval(), effective.Interval(); ri > 0 && ei > 0 && ri < ei {
		return fmt.Sprintf("explicit step %s is finer than the recommended %s for this range", requested, effective)
	}
	return ""
}

// resolveSeries resolves the (org, collector, metric) series IDs and unit.
// At most MaxSeries ids are returned (lowest ids, deterministic); total is the
// exact series count for meta.series_total.
func resolveSeries(ctx context.Context, tx pgx.Tx, q RangeQuery) (ids []int64, unit string, total int, err error) {
	rows, err := tx.Query(ctx, `
		SELECT id, unit FROM metric_series
		WHERE org_id = $1 AND collector_id = $2 AND metric_key = $3
		ORDER BY id
		LIMIT $4`,
		q.OrgID, q.CollectorID, q.MetricKey, MaxSeries+1)
	if err != nil {
		return nil, "", 0, fmt.Errorf("metrics: resolve series: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var u string
		if err := rows.Scan(&id, &u); err != nil {
			return nil, "", 0, fmt.Errorf("metrics: scan series: %w", err)
		}
		ids = append(ids, id)
		if unit == "" {
			unit = u
		}
	}
	if err := rows.Err(); err != nil {
		return nil, "", 0, fmt.Errorf("metrics: iterate series: %w", err)
	}
	total = len(ids)
	if total > MaxSeries {
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM metric_series WHERE org_id = $1 AND collector_id = $2 AND metric_key = $3`,
			q.OrgID, q.CollectorID, q.MetricKey).Scan(&total); err != nil {
			return nil, "", 0, fmt.Errorf("metrics: count series: %w", err)
		}
	}
	return ids, unit, total, nil
}

// expectedBuckets counts bucket-aligned intervals intersecting [from, to].
// 10s/1m/5m/1h/1d divide a day, so Go's absolute-time Truncate and
// PostgreSQL's Unix-epoch time_bucket produce identical alignments.
func expectedBuckets(from, to time.Time, interval time.Duration) int {
	alignedStart := from.UTC().Truncate(interval)
	return int(to.Sub(alignedStart)/interval) + 1
}

// bucketAgg accumulates one output bucket from one or more sources (CAGG
// materialization and/or raw samples).
type bucketAgg struct {
	sum float64
	n   int64
}

func mergeBucket(buckets map[time.Time]*bucketAgg, ts time.Time, sum float64, n int64) {
	b := buckets[ts]
	if b == nil {
		b = &bucketAgg{}
		buckets[ts] = b
	}
	b.sum += sum
	b.n += n
}

// caggSelectSQL maps each rollup CAGG to its tenant-view read. Keys come from
// the fixed RollupPolicies table; no user input reaches this SQL.
var caggSelectSQL = map[string]string{
	"metric_1m": `SELECT bucket, "sum"::float8, n FROM metric_1m_tenant
	             WHERE org_id = $1 AND series_id = $2 AND bucket >= $3 AND bucket < $4`,
	"metric_5m": `SELECT bucket, "sum"::float8, n FROM metric_5m_tenant
	             WHERE org_id = $1 AND series_id = $2 AND bucket >= $3 AND bucket < $4`,
	"metric_1h": `SELECT bucket, "sum"::float8, n FROM metric_1h_tenant
	             WHERE org_id = $1 AND series_id = $2 AND bucket >= $3 AND bucket < $4`,
	"metric_1d": `SELECT bucket, "sum"::float8, n FROM metric_1d_tenant
	             WHERE org_id = $1 AND series_id = $2 AND bucket >= $3 AND bucket < $4`,
}

// queryBucketed serves bucketed steps. Rollup steps read the materialized
// CAGG for the span older than the conservative materialization boundary and
// compute the recent span from raw samples (raw fallback, P2-AC-07/08); the
// boundary never overlaps, so a bucket is never counted twice. 10s buckets
// are always computed from raw samples.
func queryBucketed(ctx context.Context, tx pgx.Tx, q RangeQuery, step Step, seriesIDs []int64, result *RangeResult) error {
	interval := step.Interval()
	result.Expected = expectedBuckets(q.From, q.To, interval)
	if len(seriesIDs) == 0 {
		result.Gaps = result.Expected
		return nil
	}
	buckets := make(map[time.Time]*bucketAgg)

	if pol, ok := rollupPolicies[step]; ok {
		// Conservative boundary: one full refresh schedule behind the CAGG
		// watermark, so a bucket is either fully materialized or fully
		// computed from raw (never split inconsistently).
		boundary := time.Now().UTC().Add(-(pol.EndOffset + pol.Schedule))
		cut := boundary.Truncate(interval)
		caggEnd := cut
		if caggEnd.After(q.To) {
			caggEnd = q.To
		}
		rollupBuckets := 0
		if q.From.Before(caggEnd) {
			n, err := queryCAGGBuckets(ctx, tx, pol, q, seriesIDs, q.From, caggEnd, buckets)
			if err != nil {
				return err
			}
			rollupBuckets = n
		}
		rawStart := q.From
		if cut.After(rawStart) {
			rawStart = cut
		}
		if rollupBuckets == 0 && rawStart.After(q.From) {
			// Nothing materialized for the older span (e.g. immediately after
			// migration): recompute it from raw so a truthful answer is
			// returned, bounded by the caps and the query timeout.
			result.RollupMissing = true
			rawStart = q.From
		}
		if !rawStart.After(q.To) {
			if err := queryRawBuckets(ctx, tx, q, seriesIDs, rawStart, q.To, step, buckets); err != nil {
				return err
			}
			result.RawFallback = true
		}
	} else {
		if err := queryRawBuckets(ctx, tx, q, seriesIDs, q.From, q.To, step, buckets); err != nil {
			return err
		}
	}

	points := make([]Point, 0, len(buckets))
	var samples int64
	for ts, b := range buckets {
		if b.n == 0 {
			continue
		}
		points = append(points, Point{Ts: ts, Value: b.sum / float64(b.n)})
		samples += b.n
	}
	sort.Slice(points, func(i, j int) bool { return points[i].Ts.Before(points[j].Ts) })
	result.SampleCount = samples
	if len(points) > MaxPoints {
		// Keep the newest buckets: charts care about the leading edge and the
		// response must stay within the canonical 10k budget.
		points = points[len(points)-MaxPoints:]
		result.PointsTruncated = true
		result.Partial = true
	}
	result.Points = points
	result.Returned = len(points)
	if result.Expected > result.Returned {
		result.Gaps = result.Expected - result.Returned
	}
	return nil
}

// queryCAGGBuckets reads the materialized buckets for the given (already
// bounded) span. Returns the number of bucket rows read so the caller can
// detect an empty materialization.
func queryCAGGBuckets(ctx context.Context, tx pgx.Tx, pol RollupPolicy, q RangeQuery, seriesIDs []int64, from, to time.Time, buckets map[time.Time]*bucketAgg) (int, error) {
	sql, ok := caggSelectSQL[pol.CAGG]
	if !ok {
		return 0, fmt.Errorf("metrics: no tenant view for %s", pol.CAGG)
	}
	total := 0
	for _, seriesID := range seriesIDs {
		rows, err := tx.Query(ctx, sql, q.OrgID, seriesID, from, to)
		if err != nil {
			return 0, fmt.Errorf("metrics: query %s: %w", pol.CAGG, err)
		}
		for rows.Next() {
			var (
				ts  time.Time
				sum float64
				n   int64
			)
			if err := rows.Scan(&ts, &sum, &n); err != nil {
				rows.Close()
				return 0, fmt.Errorf("metrics: scan %s bucket: %w", pol.CAGG, err)
			}
			mergeBucket(buckets, ts.UTC(), sum, n)
			total++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return 0, fmt.Errorf("metrics: iterate %s buckets: %w", pol.CAGG, err)
		}
	}
	return total, nil
}

// queryRawBuckets computes sum/count buckets from raw samples for the span
// [from, to]. The result is merged into the shared bucket map so a boundary
// bucket split across sources still aggregates exactly.
func queryRawBuckets(ctx context.Context, tx pgx.Tx, q RangeQuery, seriesIDs []int64, from, to time.Time, step Step, buckets map[time.Time]*bucketAgg) error {
	for _, seriesID := range seriesIDs {
		rows, err := tx.Query(ctx, `
			SELECT time_bucket($1::interval, ts) AS bucket,
			       sum(value)::float8,
			       count(*)::bigint
			FROM metric_samples
			WHERE org_id = $2 AND series_id = $3 AND ts >= $4 AND ts <= $5
			GROUP BY bucket`,
			step.sqlInterval(), q.OrgID, seriesID, from, to)
		if err != nil {
			return fmt.Errorf("metrics: query buckets: %w", err)
		}
		for rows.Next() {
			var (
				ts  time.Time
				sum float64
				n   int64
			)
			if err := rows.Scan(&ts, &sum, &n); err != nil {
				rows.Close()
				return fmt.Errorf("metrics: scan bucket: %w", err)
			}
			mergeBucket(buckets, ts.UTC(), sum, n)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return fmt.Errorf("metrics: iterate buckets: %w", err)
		}
	}
	return nil
}

// queryRaw returns exact samples, newest-first bounded by MaxPoints+1 per
// series, then keeps the newest MaxPoints overall with partial=true. Raw
// results are dense; the cap is enforced on the actual row count.
func queryRaw(ctx context.Context, tx pgx.Tx, q RangeQuery, seriesIDs []int64, result *RangeResult) error {
	truncated := false
	for _, seriesID := range seriesIDs {
		rows, err := tx.Query(ctx, `
			SELECT ts, value
			FROM metric_samples
			WHERE org_id = $1 AND series_id = $2 AND ts >= $3 AND ts <= $4
			ORDER BY ts DESC
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
		if len(result.Points) > MaxPoints {
			truncated = true
			break
		}
	}
	sort.Slice(result.Points, func(i, j int) bool { return result.Points[i].Ts.After(result.Points[j].Ts) })
	if len(result.Points) > MaxPoints {
		result.Points = result.Points[:MaxPoints]
		truncated = true
	}
	if truncated {
		result.PointsTruncated = true
		result.Partial = true
	}
	sort.Slice(result.Points, func(i, j int) bool { return result.Points[i].Ts.Before(result.Points[j].Ts) })
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
		var ts *time.Time
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
		if ts == nil || !ts.After(bestTs) {
			continue
		}
		var value float64
		// Primary key (series_id, ts) equality: direct index lookup.
		err = tx.QueryRow(ctx, `
			SELECT value FROM metric_samples
			WHERE org_id = $1 AND series_id = $2 AND ts = $3`,
			q.OrgID, seriesID, *ts).Scan(&value)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			return fmt.Errorf("metrics: query latest value: %w", err)
		}
		bestTs, bestValue = *ts, value
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
