package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/argus-platform/argus/internal/platform/authz"
	"github.com/argus-platform/argus/internal/platform/database"
)

// Multi-series query contract (M10-S1; docs/12 §22.8, P2-AC-21).
//
// POST /v1/metrics/query accepts explicit series ids (opaque `s_…` strings)
// and/or selectors `{device_id, metric_key, dimensions?}`. Selectors match all
// series of a device whose stored dimensions are a superset of the requested
// dimensions (canonical JSON subset match), which is the established selector
// semantics from docs/08 §13.5. Explicit ids and selectors are resolved
// inside the tenant transaction; every read is RLS-scoped, and the caller's
// scope bindings filter what is visible:
//
//   - selectors are filtered by scope exactly like list results (a device
//     outside the caller's scope simply contributes no series);
//   - explicit series ids follow item semantics (M7): missing, foreign and
//     out-of-scope ids are an identical 404, so the endpoint is not an
//     existence oracle.
//
// The canonical contract has no explicit scope filter parameter, so metrics
// queries never return 403 on scope grounds; the M7 "conflicting collection
// filter -> 403" rule remains on the device-list filter that the bulk status
// convention reuses (M10-S1 §B).
//
// Aggregations: avg/max/sum/rate are served from the materialized CAGG columns
// (sum/max/sum+n) for rollup spans and computed from raw samples for recent or
// explicit-raw spans. `rate` is the sample-weighted mean of stored values:
// counters are already normalized to per-second rates at ingest (docs/08
// §13.2), so no per-window counter differencing happens here. `p95` is not
// materialized in the CAGGs (docs/08 §13.2 precomputes percentile series at
// the collector), so p95 queries are computed from raw samples for the whole
// window and are only as complete as raw retention (documented limitation,
// M10_EVIDENCE.md).
//
// Caps (docs/12 §22.8, docs/08 §13.5): at most 100 series are returned, at
// most 10,000 points per response, and a pathological scan (>1,000,000
// buckets) is rejected with 422 query.points_exceeded instead of timing out.
// Multi-series responses allocate the 10k point budget evenly across the
// returned series and keep the newest buckets; each truncated series carries
// `truncated: true` and the response carries partial/points_truncated.

// Aggregation is one canonical query aggregation function.
type Aggregation string

// Canonical aggregation functions (docs/12 §22.8).
const (
	AggAvg  Aggregation = "avg"
	AggMax  Aggregation = "max"
	AggP95  Aggregation = "p95"
	AggRate Aggregation = "rate"
	AggSum  Aggregation = "sum"
)

// FillMode is the gap-filling policy for bucketed steps.
type FillMode string

// Canonical fill modes (docs/12 §22.8).
const (
	// FillNull leaves gaps as explicit nulls (default; never interpolated).
	FillNull FillMode = "null"
	// FillZero renders gaps as 0.
	FillZero FillMode = "zero"
	// FillPrevious carries the last observed value forward; leading gaps stay
	// null because there is nothing to carry.
	FillPrevious FillMode = "previous"
)

// Query errors surfaced to HTTP.
var (
	ErrSeriesNotFound  = errors.New("metrics: series not found")
	ErrAggUnsupported  = errors.New("metrics: unsupported aggregation")
	ErrQueryInvalid    = errors.New("metrics: invalid query")
	maxQueryEntries    = 500 // explicit ids + selectors accepted per request
	maxQuerySelectors  = 50  // selectors accepted per request
	maxQueryExplicitID = 500 // explicit ids accepted; responses still cap at 100
)

// ParseAggregation validates the agg parameter; empty defaults to avg.
func ParseAggregation(raw string) (Aggregation, error) {
	switch Aggregation(raw) {
	case "", AggAvg:
		return AggAvg, nil
	case AggMax, AggP95, AggRate, AggSum:
		return Aggregation(raw), nil
	default:
		return "", fmt.Errorf("%w: %q (allowed: avg, max, p95, rate, sum)", ErrAggUnsupported, raw)
	}
}

// ParseFill validates the fill parameter; empty defaults to null.
func ParseFill(raw string) (FillMode, error) {
	switch FillMode(raw) {
	case "", FillNull:
		return FillNull, nil
	case FillZero, FillPrevious:
		return FillMode(raw), nil
	default:
		return "", fmt.Errorf("%w: unknown fill %q (allowed: null, zero, previous)", ErrQueryInvalid, raw)
	}
}

// Selector resolves to every series of one device/metric/dimension subset.
type Selector struct {
	DeviceID   uuid.UUID
	MetricKey  string
	Dimensions map[string]string
}

// MatrixQuery is one validated multi-series query.
type MatrixQuery struct {
	OrgID     uuid.UUID
	Scope     authz.Scope
	SeriesIDs []int64
	Selectors []Selector
	From      time.Time
	To        time.Time
	Step      Step
	Agg       Aggregation
	Fill      FillMode
}

// MatrixPoint is one output bucket. A nil Value is an explicit gap (fill=null)
// or a leading gap under fill=previous; it is never interpolated.
type MatrixPoint struct {
	Ts    time.Time
	Value *float64
}

// MatrixSeries is one series' identity plus its (possibly dense) point list.
type MatrixSeries struct {
	ID          int64
	DeviceID    *uuid.UUID
	CollectorID *uuid.UUID
	MetricKey   string
	Unit        string
	DeviceName  *string
	Dimensions  map[string]string
	Points      []MatrixPoint
	Truncated   bool
	Gaps        int
}

// MatrixResult is the API projection of one multi-series query.
type MatrixResult struct {
	From              time.Time
	To                time.Time
	Step              Step
	Agg               Aggregation
	Fill              FillMode
	Series            []MatrixSeries
	SeriesTotal       int
	SeriesReturned    int
	Partial           bool
	PointsTruncated   bool
	RawFallback       bool
	RollupMissing     bool
	ResolutionWarning string
	Gaps              int64
	ExpectedPoints    int64
	ReturnedPoints    int64
}

// matrixSeriesRow is one resolved series identity.
type matrixSeriesRow struct {
	ID          int64
	DeviceID    *uuid.UUID
	CollectorID *uuid.UUID
	MetricKey   string
	Unit        string
	DeviceName  *string
	Dimensions  map[string]string
	siteID      *uuid.UUID
	deviceFound bool
	deviceGone  bool
}

// visible reports whether the row is inside the caller's scope and still
// addressable (a soft-deleted or physically missing device is not).
func (r matrixSeriesRow) visible(sc authz.Scope) bool {
	if r.DeviceID != nil && (!r.deviceFound || r.deviceGone) {
		return false
	}
	if sc.Unrestricted {
		return true
	}
	if r.siteID == nil {
		return false
	}
	return sc.AllowsSite(*r.siteID)
}

// QueryMatrix validates, resolves and executes one multi-series query.
func (s *QueryService) QueryMatrix(ctx context.Context, q MatrixQuery) (MatrixResult, error) {
	if len(q.SeriesIDs) == 0 && len(q.Selectors) == 0 {
		return MatrixResult{}, fmt.Errorf("%w: at least one series id or selector is required", ErrQueryInvalid)
	}
	if !q.From.Before(q.To) {
		return MatrixResult{}, fmt.Errorf("%w: from must be before to", ErrRangeInvalid)
	}
	if q.To.Sub(q.From) > MaxRange {
		return MatrixResult{}, fmt.Errorf("%w: range exceeds %s", ErrRangeInvalid, MaxRange)
	}
	if q.To.After(time.Now().Add(MaxFutureSkew)) {
		return MatrixResult{}, fmt.Errorf("%w: to is in the future", ErrRangeInvalid)
	}
	if _, err := ParseAggregation(string(q.Agg)); err != nil {
		return MatrixResult{}, err
	}
	if _, err := ParseFill(string(q.Fill)); err != nil {
		return MatrixResult{}, err
	}
	recommended := PickStep(q.From, q.To)
	step := q.Step
	if step == "" || step == StepAuto {
		step = recommended
	}
	agg := q.Agg
	if agg == "" {
		agg = AggAvg
	}
	fill := q.Fill
	if fill == "" {
		fill = FillNull
	}
	if step == StepRaw && agg != AggAvg {
		return MatrixResult{}, fmt.Errorf("%w: agg %s does not apply to step=raw (samples are exact and never aggregated)", ErrQueryInvalid, agg)
	}
	q.Step, q.Agg, q.Fill = step, agg, fill

	var buckets int
	if step != StepRaw {
		buckets = expectedBuckets(q.From, q.To, step.Interval())
		if buckets > maxHardBuckets {
			return MatrixResult{}, fmt.Errorf("%w: %d buckets for %s step (hard budget %d)",
				ErrPointsExceeded, buckets, step, maxHardBuckets)
		}
	}

	result := MatrixResult{
		From:              q.From.UTC(),
		To:                q.To.UTC(),
		Step:              step,
		Agg:               agg,
		Fill:              fill,
		ResolutionWarning: resolutionWarning(q.Step, recommended),
	}
	queryStart := time.Now()
	err := database.WithTenant(ctx, s.app, q.OrgID, func(ctx context.Context, tx pgx.Tx) error {
		rows, total, selectorCapped, err := resolveMatrixSeries(ctx, tx, q)
		if err != nil {
			return err
		}
		result.SeriesTotal = total
		if selectorCapped {
			result.Partial = true
		}
		if len(rows) > MaxSeries {
			rows = rows[:MaxSeries]
			result.Partial = true
		}
		result.SeriesReturned = len(rows)
		if buckets > 0 && len(rows) > 0 && int64(buckets)*int64(len(rows)) > int64(maxHardBuckets) {
			return fmt.Errorf("%w: %d series × %d buckets exceeds the scan budget",
				ErrPointsExceeded, len(rows), buckets)
		}

		// Even point allocation across the returned series; the newest buckets
		// win when a series does not fit its share.
		keep := MaxPoints
		if len(rows) > 1 {
			keep = MaxPoints / len(rows)
		}
		if keep < 1 {
			keep = 1
		}
		result.ExpectedPoints = int64(buckets) * int64(len(rows))

		for _, row := range rows {
			ms := MatrixSeries{
				ID:          row.ID,
				DeviceID:    row.DeviceID,
				CollectorID: row.CollectorID,
				MetricKey:   row.MetricKey,
				Unit:        row.Unit,
				DeviceName:  row.DeviceName,
				Dimensions:  row.Dimensions,
			}
			if step == StepRaw {
				if err := queryMatrixRawSeries(ctx, tx, q, row.ID, keep, &ms); err != nil {
					return err
				}
			} else if err := queryMatrixBucketedSeries(ctx, tx, q, row.ID, keep, &ms, &result); err != nil {
				return err
			}
			result.Gaps += int64(ms.Gaps)
			result.ReturnedPoints += int64(len(ms.Points))
			if ms.Truncated {
				result.Partial = true
				result.PointsTruncated = true
			}
			result.Series = append(result.Series, ms)
		}
		return nil
	})
	if s.argus != nil {
		s.argus.DBQueryDuration.WithLabelValues("query_matrix").Observe(time.Since(queryStart).Seconds())
	}
	if err != nil {
		return MatrixResult{}, err
	}
	return result, nil
}

// resolveMatrixSeries resolves explicit ids (all-or-nothing, uniform 404) and
// selectors (scope-filtered), returning the deduplicated series ordered by id.
// The returned total is exact when the resolution bounds are not hit; when a
// selector is capped it is a lower bound and the caller flags partial=true.
func resolveMatrixSeries(ctx context.Context, tx pgx.Tx, q MatrixQuery) ([]matrixSeriesRow, int, bool, error) {
	if len(q.SeriesIDs) > maxQueryExplicitID {
		return nil, 0, false, fmt.Errorf("%w: at most %d explicit series ids", ErrQueryInvalid, maxQueryExplicitID)
	}
	if len(q.Selectors) > maxQuerySelectors {
		return nil, 0, false, fmt.Errorf("%w: at most %d selectors", ErrQueryInvalid, maxQuerySelectors)
	}
	if len(q.SeriesIDs)+len(q.Selectors) > maxQueryEntries {
		return nil, 0, false, fmt.Errorf("%w: at most %d series entries per request", ErrQueryInvalid, maxQueryEntries)
	}

	found := make(map[int64]matrixSeriesRow)
	wanted := make(map[int64]bool, len(q.SeriesIDs))
	for _, id := range q.SeriesIDs {
		wanted[id] = true
	}
	if len(wanted) > 0 {
		ids := make([]int64, 0, len(wanted))
		for id := range wanted {
			ids = append(ids, id)
		}
		rows, err := tx.Query(ctx, `
			SELECT s.id, s.device_id, s.collector_id, s.metric_key, s.dimensions::text, s.unit,
			       COALESCE(d.site_id, c.site_id), d.name, d.id IS NOT NULL, d.deleted_at IS NOT NULL
			FROM metric_series s
			LEFT JOIN devices d ON d.id = s.device_id AND d.org_id = s.org_id
			LEFT JOIN collectors c ON c.id = s.collector_id AND c.org_id = s.org_id
			WHERE s.org_id = $1 AND s.id = ANY($2::bigint[])`,
			q.OrgID, ids)
		if err != nil {
			return nil, 0, false, fmt.Errorf("metrics: resolve series ids: %w", err)
		}
		for rows.Next() {
			row, err := scanMatrixSeries(rows)
			if err != nil {
				rows.Close()
				return nil, 0, false, err
			}
			if row.visible(q.Scope) {
				found[row.ID] = row
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, 0, false, fmt.Errorf("metrics: iterate series ids: %w", err)
		}
		// Item semantics (M7 enumeration resistance): missing, foreign and
		// out-of-scope ids are an identical not-found for the whole request.
		if len(found) != len(wanted) {
			return nil, 0, false, ErrSeriesNotFound
		}
	}

	selectorCapped := false
	for _, sel := range q.Selectors {
		rows, err := tx.Query(ctx, `
			SELECT s.id, s.device_id, s.collector_id, s.metric_key, s.dimensions::text, s.unit,
			       d.site_id, d.name, true, false
			FROM metric_series s
			JOIN devices d ON d.id = s.device_id AND d.org_id = s.org_id AND d.deleted_at IS NULL
			WHERE s.org_id = $1 AND s.device_id = $2 AND s.metric_key = $3
			  AND s.dimensions @> $4::jsonb
			  AND ($5::boolean OR d.site_id = ANY($6::uuid[]))
			ORDER BY s.id
			LIMIT $7`,
			q.OrgID, sel.DeviceID, sel.MetricKey, canonicalDimsJSON(sel.Dimensions),
			q.Scope.Unrestricted, q.Scope.Sites, MaxSeries+1)
		if err != nil {
			return nil, 0, false, fmt.Errorf("metrics: resolve selector: %w", err)
		}
		matched := 0
		for rows.Next() {
			row, err := scanMatrixSeries(rows)
			if err != nil {
				rows.Close()
				return nil, 0, false, err
			}
			matched++
			if _, ok := found[row.ID]; !ok {
				found[row.ID] = row
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, 0, false, fmt.Errorf("metrics: iterate selector: %w", err)
		}
		if matched > MaxSeries {
			selectorCapped = true
		}
	}

	out := make([]matrixSeriesRow, 0, len(found))
	for _, row := range found {
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, len(out), selectorCapped, nil
}

// scanMatrixSeries scans the shared identity columns of both resolution
// queries. `dimensions::text` is parsed to the canonical string map.
func scanMatrixSeries(rows pgx.Rows) (matrixSeriesRow, error) {
	var (
		row        matrixSeriesRow
		dimsRaw    string
		siteID     *uuid.UUID
		deviceName *string
		deviceSeen bool
		deviceGone bool
	)
	if err := rows.Scan(&row.ID, &row.DeviceID, &row.CollectorID, &row.MetricKey, &dimsRaw, &row.Unit,
		&siteID, &deviceName, &deviceSeen, &deviceGone); err != nil {
		return matrixSeriesRow{}, fmt.Errorf("metrics: scan series: %w", err)
	}
	dims, err := parseDimensions(dimsRaw)
	if err != nil {
		return matrixSeriesRow{}, err
	}
	row.Dimensions = dims
	row.siteID = siteID
	row.DeviceName = deviceName
	row.deviceFound = deviceSeen
	row.deviceGone = deviceGone
	return row, nil
}

// canonicalDimsJSON renders a selector dimension map with the same canonical
// encoding used at series creation (sorted keys); {} matches every series.
func canonicalDimsJSON(dims map[string]string) string {
	if len(dims) == 0 {
		return "{}"
	}
	canonical, _, err := CanonicalizeDimensions(dims)
	if err != nil {
		// Selector validation happens before resolution; this cannot happen.
		return "{}"
	}
	return string(canonical)
}

// parseDimensions decodes the stored canonical JSON object. Non-string values
// cannot occur (ingest validates them); they are coerced defensively.
func parseDimensions(raw string) (map[string]string, error) {
	out := map[string]string{}
	if raw == "" || raw == "{}" || raw == "null" {
		return out, nil
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return nil, fmt.Errorf("metrics: decode dimensions: %w", err)
	}
	for k, v := range decoded {
		s, ok := v.(string)
		if !ok {
			continue
		}
		out[k] = s
	}
	return out, nil
}

// queryMatrixBucketedSeries fills one series' dense bucket grid. Rollup steps
// read the CAGG for the materialized span and raw samples for the recent span
// (or everything when nothing is materialized); p95 always reads raw samples.
func queryMatrixBucketedSeries(ctx context.Context, tx pgx.Tx, q MatrixQuery, seriesID int64, keep int, ms *MatrixSeries, result *MatrixResult) error {
	observed := make(map[time.Time]float64)
	if q.Agg == AggP95 {
		if err := queryRawAgg(ctx, tx, q, seriesID, q.From, q.To, q.Agg, observed); err != nil {
			return err
		}
		if IsRollupStep(q.Step) {
			// Truthful flag: the rollup was bypassed because p95 is not
			// materialized (documented limitation).
			result.RawFallback = true
		}
	} else if pol, ok := rollupPolicies[q.Step]; ok {
		boundary := time.Now().UTC().Add(-(pol.EndOffset + pol.Schedule))
		cut := boundary.Truncate(q.Step.Interval())
		// The CAGG read is [from, caggEnd) exclusive when the raw fallback
		// starts at the cut (so the boundary bucket is never counted twice);
		// when the whole window is materialized the CAGG read is inclusive so
		// a bucket aligned exactly at `to` is not lost.
		caggEnd := q.To
		caggInclusive := true
		if !cut.After(q.To) {
			caggEnd = cut
			caggInclusive = false
		}
		rollupRows := 0
		if q.From.Before(caggEnd) {
			n, err := queryCAGGAgg(ctx, tx, pol, q, seriesID, q.From, caggEnd, caggInclusive, q.Agg, observed)
			if err != nil {
				return err
			}
			rollupRows = n
		}
		rawStart := q.From
		if cut.After(rawStart) {
			rawStart = cut
		}
		if rollupRows == 0 && rawStart.After(q.From) {
			// Nothing materialized for the older span (e.g. immediately after
			// migration): recompute it from raw so the answer is truthful.
			result.RollupMissing = true
			rawStart = q.From
		}
		if !rawStart.After(q.To) {
			if err := queryRawAgg(ctx, tx, q, seriesID, rawStart, q.To, q.Agg, observed); err != nil {
				return err
			}
			result.RawFallback = true
		}
	} else {
		if err := queryRawAgg(ctx, tx, q, seriesID, q.From, q.To, q.Agg, observed); err != nil {
			return err
		}
	}

	points, gaps, truncated := densifyBuckets(q.From, q.To, q.Step.Interval(), observed, q.Fill, keep)
	ms.Points = points
	ms.Gaps = gaps
	ms.Truncated = truncated
	return nil
}

// rawAggExpr is the per-bucket SQL aggregate for raw samples. Only fixed
// strings from this function reach the SQL text.
func rawAggExpr(agg Aggregation) string {
	switch agg {
	case AggMax:
		return "max(value)"
	case AggSum:
		return "sum(value)"
	case AggP95:
		return "percentile_cont(0.95) WITHIN GROUP (ORDER BY value)"
	default: // avg and rate
		return "avg(value)"
	}
}

// queryRawAgg computes one aggregate value per bucket from raw samples,
// merging into observed. Only called for bucketed steps.
func queryRawAgg(ctx context.Context, tx pgx.Tx, q MatrixQuery, seriesID int64, from, to time.Time, agg Aggregation, observed map[time.Time]float64) error {
	rows, err := tx.Query(ctx, fmt.Sprintf(`
		SELECT time_bucket($1::interval, ts) AS bucket, %s AS value
		FROM metric_samples
		WHERE org_id = $2 AND series_id = $3 AND ts >= $4 AND ts <= $5
		GROUP BY bucket`, rawAggExpr(agg)),
		q.Step.sqlInterval(), q.OrgID, seriesID, from, to)
	if err != nil {
		return fmt.Errorf("metrics: query matrix buckets: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			ts    time.Time
			value *float64
		)
		if err := rows.Scan(&ts, &value); err != nil {
			return fmt.Errorf("metrics: scan matrix bucket: %w", err)
		}
		if value != nil {
			observed[ts.UTC()] = *value
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("metrics: iterate matrix buckets: %w", err)
	}
	return nil
}

// caggAggExpr selects the materialized column per bucket. Each tenant-view row
// is already one (series, bucket) aggregation, so no SQL aggregation is
// applied here: avg/rate read the sample-weighted mean, max the bucket max and
// sum the bucket sum (all propagated through the CAGG hierarchy).
func caggAggExpr(agg Aggregation) string {
	switch agg {
	case AggMax:
		return `"max"::float8`
	case AggSum:
		return `"sum"::float8`
	default: // avg and rate
		return `"avg"::float8`
	}
}

// queryCAGGAgg reads materialized buckets in [from, to) (or [from, to] when
// inclusive), returning the number of rows read so the caller can detect an
// empty materialization.
func queryCAGGAgg(ctx context.Context, tx pgx.Tx, pol RollupPolicy, q MatrixQuery, seriesID int64, from, to time.Time, inclusive bool, agg Aggregation, observed map[time.Time]float64) (int, error) {
	op := "<"
	if inclusive {
		op = "<="
	}
	rows, err := tx.Query(ctx, fmt.Sprintf(
		`SELECT bucket, %s AS value FROM %s
		 WHERE org_id = $1 AND series_id = $2 AND bucket >= $3 AND bucket %s $4`,
		caggAggExpr(agg), pol.TenantView, op),
		q.OrgID, seriesID, from, to)
	if err != nil {
		return 0, fmt.Errorf("metrics: query matrix %s: %w", pol.CAGG, err)
	}
	defer rows.Close()
	total := 0
	for rows.Next() {
		var (
			ts    time.Time
			value *float64
		)
		if err := rows.Scan(&ts, &value); err != nil {
			return 0, fmt.Errorf("metrics: scan matrix %s bucket: %w", pol.CAGG, err)
		}
		total++
		if value != nil {
			observed[ts.UTC()] = *value
		}
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("metrics: iterate matrix %s buckets: %w", pol.CAGG, err)
	}
	return total, nil
}

// queryMatrixRawSeries returns the newest `keep` exact samples (ascending),
// marking the series truncated when more samples existed.
func queryMatrixRawSeries(ctx context.Context, tx pgx.Tx, q MatrixQuery, seriesID int64, keep int, ms *MatrixSeries) error {
	rows, err := tx.Query(ctx, `
		SELECT ts, value
		FROM metric_samples
		WHERE org_id = $1 AND series_id = $2 AND ts >= $3 AND ts <= $4
		ORDER BY ts DESC
		LIMIT $5`,
		q.OrgID, seriesID, q.From, q.To, keep+1)
	if err != nil {
		return fmt.Errorf("metrics: query matrix raw: %w", err)
	}
	defer rows.Close()
	points := make([]MatrixPoint, 0, keep)
	for rows.Next() {
		var (
			ts    time.Time
			value float64
		)
		if err := rows.Scan(&ts, &value); err != nil {
			return fmt.Errorf("metrics: scan matrix raw: %w", err)
		}
		v := value
		points = append(points, MatrixPoint{Ts: ts.UTC(), Value: &v})
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("metrics: iterate matrix raw: %w", err)
	}
	if len(points) > keep {
		points = points[:keep]
		ms.Truncated = true
	}
	for i, j := 0, len(points)-1; i < j; i, j = i+1, j-1 {
		points[i], points[j] = points[j], points[i]
	}
	ms.Points = points
	return nil
}

// densifyBuckets expands the observed buckets into the full expected grid
// [from.Truncate(interval), to.Truncate(interval)], keeping the newest `keep`
// buckets when the grid is larger. Missing buckets are explicit gaps: null
// (default), 0 (zero) or the previous observed value (previous; leading gaps
// stay null). Gaps are counted before filling so `meta.quality.gaps` reports
// missing data, not the fill policy.
func densifyBuckets(from, to time.Time, interval time.Duration, observed map[time.Time]float64, fill FillMode, keep int) ([]MatrixPoint, int, bool) {
	if interval <= 0 {
		return nil, 0, false
	}
	start := from.UTC().Truncate(interval)
	end := to.UTC().Truncate(interval)
	total := int(end.Sub(start)/interval) + 1
	if total < 0 {
		total = 0
	}
	truncated := false
	if total > keep {
		start = start.Add(time.Duration(total-keep) * interval)
		total = keep
		truncated = true
	}
	points := make([]MatrixPoint, 0, total)
	gaps := 0
	var prev *float64
	for ts := start; !ts.After(end); ts = ts.Add(interval) {
		if v, ok := observed[ts]; ok {
			vv := v
			points = append(points, MatrixPoint{Ts: ts, Value: &vv})
			prev = &vv
			continue
		}
		gaps++
		switch fill {
		case FillZero:
			zero := 0.0
			points = append(points, MatrixPoint{Ts: ts, Value: &zero})
		case FillPrevious:
			if prev != nil {
				vv := *prev
				points = append(points, MatrixPoint{Ts: ts, Value: &vv})
			} else {
				points = append(points, MatrixPoint{Ts: ts})
			}
		default:
			points = append(points, MatrixPoint{Ts: ts})
		}
	}
	return points, gaps, truncated
}
