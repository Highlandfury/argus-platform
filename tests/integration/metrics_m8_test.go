package integration

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
	"github.com/argus-platform/argus/internal/modules/metrics"
	"github.com/argus-platform/argus/internal/platform/database"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

type m8Env struct {
	OrgID       string
	SiteID      string
	CollectorID string
	DeviceID    string
}

// m8SeedEnv creates one org + site + collector + device directly (owner role:
// superuser in the testcontainer, same as the other harness fixtures).
func m8SeedEnv(t *testing.T, slug string) m8Env {
	t.Helper()
	ctx := context.Background()
	env := m8Env{
		OrgID:       newUUID(),
		SiteID:      newUUID(),
		CollectorID: newUUID(),
		DeviceID:    newUUID(),
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		_, err := ownerPool.Exec(ctx, sql, args...)
		must(t, err)
	}
	exec(`INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $3)`, env.OrgID, "Org "+slug, slug)
	exec(`INSERT INTO sites (id, org_id, name) VALUES ($1, $2, 'HQ')`, env.SiteID, env.OrgID)
	exec(`INSERT INTO collectors (id, org_id, site_id, name, status) VALUES ($1, $2, $3, $4, 'active')`,
		env.CollectorID, env.OrgID, env.SiteID, "collector-"+slug)
	exec(`INSERT INTO devices (id, org_id, site_id, name, kind) VALUES ($1, $2, $3, $4, 'switch')`,
		env.DeviceID, env.OrgID, env.SiteID, "device-"+slug)
	return env
}

// m8Series inserts a collector-scoped series and returns its id.
func m8Series(t *testing.T, env m8Env, key string, dimHash int64, unit, dimsJSON string) int64 {
	t.Helper()
	ctx := context.Background()
	var id int64
	must(t, ownerPool.QueryRow(ctx,
		`INSERT INTO metric_series (org_id, collector_id, metric_key, dimensions, dim_hash, unit)
		 VALUES ($1, $2, $3, $4::jsonb, $5, $6) RETURNING id`,
		env.OrgID, env.CollectorID, key, dimsJSON, dimHash, unit).Scan(&id))
	return id
}

// m8InsertSamples bulk-inserts value(i) at start+i*step.
func m8InsertSamples(t *testing.T, orgID string, seriesID int64, start time.Time, n int, step time.Duration, value func(i int) float64) {
	t.Helper()
	ctx := context.Background()
	ts := make([]time.Time, n)
	vs := make([]float64, n)
	for i := 0; i < n; i++ {
		ts[i] = start.Add(time.Duration(i) * step)
		vs[i] = value(i)
	}
	_, err := ownerPool.Exec(ctx,
		`INSERT INTO metric_samples (org_id, series_id, ts, value)
		 SELECT $1, $2, * FROM unnest($3::timestamptz[], $4::float8[])`,
		orgID, seriesID, ts, vs)
	must(t, err)
}

// m8Refresh refreshes one CAGG over the window (owner role; refresh policies
// run as the owner in production too).
func m8Refresh(t *testing.T, cagg string, from, to time.Time) {
	t.Helper()
	_, err := ownerPool.Exec(context.Background(),
		`CALL refresh_continuous_aggregate($1::regclass, $2::timestamptz, $3::timestamptz)`, cagg, from, to)
	must(t, err)
}

// m8RefreshAll refreshes the hierarchy in dependency order.
func m8RefreshAll(t *testing.T, from, to time.Time) {
	t.Helper()
	for _, cagg := range []string{"metric_1m", "metric_5m", "metric_1h", "metric_1d"} {
		m8Refresh(t, cagg, from, to)
	}
}

type captureCardinality struct{ events []metrics.CardinalityEvent }

func (c *captureCardinality) Record(ev metrics.CardinalityEvent) { c.events = append(c.events, ev) }

func m8WithTenant(t *testing.T, orgID string, fn func(ctx context.Context, tx pgx.Tx) error) {
	t.Helper()
	must(t, database.WithTenant(context.Background(), appPool, mustUUID(t, orgID), fn))
}

// ---------------------------------------------------------------------------
// Policy verification + maintenance
// ---------------------------------------------------------------------------

func TestMetricsPolicyVerification(t *testing.T) {
	ctx := context.Background()
	raw := 30 * 24 * time.Hour

	if err := metrics.VerifyPolicies(ctx, ownerPool, metrics.VerifyOptions{RawRetention: raw}); err != nil {
		t.Fatalf("baseline verification must pass on the migrated schema: %v", err)
	}

	// Tamper the canonical 1m refresh end_offset; verification must fail
	// loudly and name the policy.
	_, err := ownerPool.Exec(ctx, `
		SELECT alter_job(job_id, config_merge => jsonb_build_object('end_offset', interval '9 minutes'))
		FROM timescaledb_information.jobs
		WHERE proc_name = 'policy_refresh_continuous_aggregate' AND hypertable_name = 'metric_1m'`)
	must(t, err)
	restore := func() {
		_, _ = ownerPool.Exec(context.Background(), `
			SELECT alter_job(job_id, config_merge => jsonb_build_object('end_offset', interval '2 minutes'))
			FROM timescaledb_information.jobs
			WHERE proc_name = 'policy_refresh_continuous_aggregate' AND hypertable_name = 'metric_1m'`)
	}
	t.Cleanup(restore)
	err = metrics.VerifyPolicies(ctx, ownerPool, metrics.VerifyOptions{RawRetention: raw})
	if err == nil {
		t.Fatal("tampered refresh policy must fail verification")
	}
	if !strings.Contains(err.Error(), "metric_1m") || !strings.Contains(err.Error(), "refresh_policy") {
		t.Fatalf("violation must name the relation and kind, got: %v", err)
	}
	restore()
	if err := metrics.VerifyPolicies(ctx, ownerPool, metrics.VerifyOptions{RawRetention: raw}); err != nil {
		t.Fatalf("verification must pass after restore: %v", err)
	}
}

func TestMetricsRawRetentionConfig(t *testing.T) {
	ctx := context.Background()
	if err := metrics.ApplyRawRetention(ctx, ownerPool, 45*24*time.Hour); err != nil {
		t.Fatalf("apply raw retention: %v", err)
	}
	t.Cleanup(func() { _ = metrics.ApplyRawRetention(context.Background(), ownerPool, 30*24*time.Hour) })

	var drop string
	must(t, ownerPool.QueryRow(ctx, `
		SELECT config->>'drop_after' FROM timescaledb_information.jobs
		WHERE proc_name = 'policy_retention' AND hypertable_name = 'metric_samples'`).Scan(&drop))
	if drop != "45 days" {
		t.Fatalf("raw drop_after = %q, want \"45 days\"", drop)
	}
	if err := metrics.VerifyPolicies(ctx, ownerPool, metrics.VerifyOptions{RawRetention: 45 * 24 * time.Hour}); err != nil {
		t.Fatalf("verification with configured 45 d raw retention: %v", err)
	}
	// The configured window is part of the contract: a mismatch fails.
	err := metrics.VerifyPolicies(ctx, ownerPool, metrics.VerifyOptions{RawRetention: 30 * 24 * time.Hour})
	if err == nil || !strings.Contains(err.Error(), "metric_samples") {
		t.Fatalf("expected raw retention mismatch violation, got %v", err)
	}
	// Re-apply the on-prem default.
	must(t, metrics.ApplyRawRetention(ctx, ownerPool, 30*24*time.Hour))
	if err := metrics.VerifyPolicies(ctx, ownerPool, metrics.VerifyOptions{RawRetention: 30 * 24 * time.Hour}); err != nil {
		t.Fatalf("verification after reset: %v", err)
	}
}

// TestMetricsRLSUntouchedInMigration pins the Phase-1 tenancy floor: the RLS
// handshake around the CAGG DDL restores ENABLE + FORCE, the app role cannot
// read aggregates directly, and raw compression stays off (platform conflict).
func TestMetricsRLSUntouchedInMigration(t *testing.T) {
	ctx := context.Background()
	var rls, forced bool
	must(t, ownerPool.QueryRow(ctx, `
		SELECT relrowsecurity, relforcerowsecurity FROM pg_class
		WHERE relnamespace = 'public'::regnamespace AND relname = 'metric_samples'`).Scan(&rls, &forced))
	if !rls || !forced {
		t.Fatalf("metric_samples RLS state: enabled=%v forced=%v (must stay ENABLE+FORCE)", rls, forced)
	}
	var rawCompression int
	must(t, ownerPool.QueryRow(ctx, `
		SELECT count(*) FROM timescaledb_information.compression_settings
		WHERE hypertable_schema = 'public' AND hypertable_name = 'metric_samples'`).Scan(&rawCompression))
	if rawCompression != 0 {
		t.Fatalf("raw compression settings = %d, want 0 (blocked by RLS on the pinned TimescaleDB)", rawCompression)
	}
	// Direct aggregate access as the runtime role is denied.
	var n int
	err := appPool.QueryRow(ctx, `SELECT count(*) FROM metric_1m`).Scan(&n)
	if err == nil {
		t.Fatal("argus_app must not read metric_1m directly (matviews cannot carry RLS)")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "permission denied") {
		t.Fatalf("expected permission denied, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// CAGG correctness (canonical aggregation policy)
// ---------------------------------------------------------------------------

func TestMetricsCAGGComputation(t *testing.T) {
	env := m8SeedEnv(t, "m8-cagg-"+newUUID()[:8])
	base := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Hour)

	gauge := m8Series(t, env, "test.gauge", 101, "percent", `{"kind":"gauge"}`)
	counter := m8Series(t, env, "test.counter_rate", 102, "B/s", `{"kind":"counter"}`)
	state := m8Series(t, env, "test.state", 103, "state", `{"kind":"state"}`)

	// Gauge: avg/max/min/sum/n (docs/08 §13.4).
	m8InsertSamples(t, env.OrgID, gauge, base, 3, 20*time.Second, func(i int) float64 {
		return []float64{10, 20, 30}[i]
	})
	// Counter: values are already rates; avg/sum are meaningful.
	m8InsertSamples(t, env.OrgID, counter, base, 3, 20*time.Second, func(i int) float64 {
		return []float64{100, 200, 300}[i]
	})
	// State: max (worst) + time-weighted avg; uniform cadence => tw_avg = avg.
	m8InsertSamples(t, env.OrgID, state, base, 4, 15*time.Second, func(i int) float64 {
		return []float64{2, 2, 0, 2}[i]
	})

	from, to := base.Add(-2*24*time.Hour), base.Add(2*24*time.Hour)
	m8RefreshAll(t, from, to)

	type agg struct {
		avg, max, min, sum, twAvg float64
		n                         int64
	}
	read1m := func(seriesID int64, bucket time.Time) agg {
		t.Helper()
		var a agg
		must(t, ownerPool.QueryRow(context.Background(), `
			SELECT avg, max, min, sum, tw_avg, n FROM public.metric_1m
			WHERE series_id = $1 AND bucket = $2`, seriesID, bucket).
			Scan(&a.avg, &a.max, &a.min, &a.sum, &a.twAvg, &a.n))
		return a
	}

	ga := read1m(gauge, base)
	if ga.avg != 20 || ga.max != 30 || ga.min != 10 || ga.sum != 60 || ga.n != 3 || ga.twAvg != 20 {
		t.Fatalf("gauge 1m aggregate = %+v (want avg 20, max 30, min 10, sum 60, n 3, tw 20)", ga)
	}
	ca := read1m(counter, base)
	if ca.avg != 200 || ca.sum != 600 || ca.n != 3 {
		t.Fatalf("counter 1m aggregate = %+v (want avg 200, sum 600, n 3)", ca)
	}
	sa := read1m(state, base)
	if sa.max != 2 || sa.twAvg != 1.5 || sa.avg != 1.5 || sa.n != 4 {
		t.Fatalf("state 1m aggregate = %+v (want max 2, tw_avg 1.5, n 4)", sa)
	}

	// Hierarchical propagation: 5m must aggregate the 1m materialization
	// (sample-weighted, so sum/n stays exact across uneven bucket counts).
	var (
		avg5, sum5, tw5 float64
		n5              int64
	)
	must(t, ownerPool.QueryRow(context.Background(), `
		SELECT avg, sum, tw_avg, n FROM public.metric_5m
		WHERE series_id = $1 AND bucket = $2`, gauge, base.Truncate(5*time.Minute)).
		Scan(&avg5, &sum5, &tw5, &n5))
	if avg5 != 20 || sum5 != 60 || tw5 != 20 || n5 != 3 {
		t.Fatalf("gauge 5m propagation = avg %v sum %v tw %v n %v (want 20/60/20/3)", avg5, sum5, tw5, n5)
	}
	var (
		avg1d float64
		n1d   int64
	)
	must(t, ownerPool.QueryRow(context.Background(), `
		SELECT avg, n FROM public.metric_1d
		WHERE series_id = $1 AND bucket = $2`, gauge, base.Truncate(24*time.Hour)).
		Scan(&avg1d, &n1d))
	if avg1d != 20 || n1d != 3 {
		t.Fatalf("gauge 1d propagation = avg %v n %v (want 20/3)", avg1d, n1d)
	}

	// Tenant view isolation: own org sees rows, a foreign context sees none.
	var own int
	m8WithTenant(t, env.OrgID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM metric_1m_tenant WHERE series_id = $1`, gauge).Scan(&own)
	})
	if own == 0 {
		t.Fatal("tenant view returned no rows for the owning org")
	}
	other := m8SeedEnv(t, "m8-cagg-other-"+newUUID()[:8])
	var foreign int
	m8WithTenant(t, other.OrgID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM metric_1m_tenant WHERE series_id = $1`, gauge).Scan(&foreign)
	})
	if foreign != 0 {
		t.Fatalf("tenant view leaked %d foreign rows", foreign)
	}
}

// ---------------------------------------------------------------------------
// Query API: picker, meta.resolution, fallback, caps
// ---------------------------------------------------------------------------

func m8Meta(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	meta, ok := body["meta"].(map[string]any)
	if !ok {
		t.Fatalf("meta missing: %v", body)
	}
	return meta
}

func TestMetricsResolutionPickerMetaAndCaps(t *testing.T) {
	f := newM4CFixture(t, "m8-picker-"+newUUID()[:8])
	now := time.Now().UTC()

	cases := []struct {
		name      string
		from      time.Time
		wantStep  string
		wantClass string
	}{
		{"2h", now.Add(-2 * time.Hour), "1m", "rollup_1m"},
		{"3d", now.Add(-3 * 24 * time.Hour), "5m", "rollup_5m"},
		{"30d", now.Add(-30 * 24 * time.Hour), "1h", "rollup_1h"},
		{"120d", now.Add(-120 * 24 * time.Hour), "1d", "rollup_1d"},
	}
	for _, tc := range cases {
		status, body := f.query(t, map[string]string{
			"metric": "collector_cpu_percent",
			"from":   m4cRFC3339(tc.from),
			"to":     m4cRFC3339(now.Add(-time.Second)),
		})
		if status != http.StatusOK {
			t.Fatalf("%s picker query: status %d body %v", tc.name, status, body)
		}
		if body["resolution"] != tc.wantStep {
			t.Fatalf("%s picker: resolution = %v, want %s", tc.name, body["resolution"], tc.wantStep)
		}
		if got := m8Meta(t, body)["resolution"]; got != tc.wantClass {
			t.Fatalf("%s picker: meta.resolution = %v, want %s", tc.name, got, tc.wantClass)
		}
	}

	// Explicit finer-than-recommended overrides still work but carry the
	// canonical warning (docs/08 §13.5 "user override with warning").
	status, body := f.query(t, map[string]string{
		"metric": "collector_cpu_percent",
		"from":   m4cRFC3339(now.Add(-3 * 24 * time.Hour)),
		"to":     m4cRFC3339(now.Add(-time.Second)),
		"step":   "1m",
	})
	if status != http.StatusOK {
		t.Fatalf("explicit 1m: %d", status)
	}
	meta := m8Meta(t, body)
	if meta["resolution_warning"] == nil || meta["resolution_warning"] == "" {
		t.Fatalf("explicit 1m on a 3d range must warn: %v", meta)
	}
	if meta["partial"] != false {
		t.Fatalf("empty result must not be flagged partial: %v", meta)
	}
}

func TestMetricsRawFallbackServesMaterializedAndRecent(t *testing.T) {
	f := newM4CFixture(t, "m8-fallback-"+newUUID()[:8])
	old := time.Now().UTC().Add(-45 * time.Minute).Truncate(time.Minute)

	f.ingest(t, 1, []*collectorv1.MetricSample{
		m4Sample(10, map[string]string{"cpu": "total"}, old),
		m4Sample(30, map[string]string{"cpu": "total"}, old.Add(20*time.Second)),
	})
	recent := time.Now().UTC().Add(-5 * time.Second)
	f.ingest(t, 2, []*collectorv1.MetricSample{
		m4Sample(70, map[string]string{"cpu": "total"}, recent),
	})

	var seriesID int64
	must(t, ownerPool.QueryRow(context.Background(), `
		SELECT id FROM metric_series WHERE org_id = $1 AND collector_id = $2 AND metric_key = 'collector_cpu_percent'`,
		f.orgID, f.collectorID).Scan(&seriesID))

	// Materialize the old span (before the raw fallback boundary).
	m8Refresh(t, "metric_1m", old.Add(-time.Minute), old.Add(2*time.Minute))

	// Remove the old raw rows: the old bucket can only come from the CAGG.
	_, delErr := ownerPool.Exec(context.Background(), `
		DELETE FROM metric_samples
		WHERE org_id = $1 AND series_id = $2 AND ts < $3`,
		f.orgID, seriesID, time.Now().UTC().Add(-10*time.Minute))
	must(t, delErr)

	// Fully materialized window: CAGG only, no raw fallback.
	status, body := f.query(t, map[string]string{
		"metric": "collector_cpu_percent",
		"from":   m4cRFC3339(old.Add(-time.Minute)),
		"to":     m4cRFC3339(time.Now().UTC().Add(-10 * time.Minute)),
		"step":   "1m",
	})
	if status != http.StatusOK {
		t.Fatalf("materialized query: %d %v", status, body)
	}
	meta := m8Meta(t, body)
	if meta["raw_fallback"] != false {
		t.Fatalf("fully materialized window must not use raw fallback: %v", meta)
	}
	points := m4cPoints(t, body)
	if len(points) != 1 || points[0][1] != 20 {
		t.Fatalf("materialized points = %v (want the CAGG bucket value 20 despite deleted raw rows)", points)
	}

	// Window touching "now": old span from the CAGG, recent tail from raw.
	status, body = f.query(t, map[string]string{
		"metric": "collector_cpu_percent",
		"from":   m4cRFC3339(old.Add(-time.Minute)),
		"to":     m4cRFC3339(time.Now().UTC()),
		"step":   "1m",
	})
	if status != http.StatusOK {
		t.Fatalf("fallback query: %d %v", status, body)
	}
	meta = m8Meta(t, body)
	if meta["raw_fallback"] != true {
		t.Fatalf("window ending now must use the raw tail: %v", meta)
	}
	points = m4cPoints(t, body)
	if len(points) != 2 {
		t.Fatalf("fallback points = %v (want CAGG old bucket + raw recent bucket)", points)
	}
	if points[0][1] != 20 || points[1][1] != 70 {
		t.Fatalf("fallback values = %v (want [20, 70])", points)
	}
}

func TestMetricsPointsAndSeriesCaps(t *testing.T) {
	f := newM4CFixture(t, "m8-caps-"+newUUID()[:8])
	ctx := context.Background()

	// Series cap: 101 matching series -> deterministic 100 returned, flagged.
	_, err := ownerPool.Exec(ctx, `
		INSERT INTO metric_series (org_id, collector_id, metric_key, dimensions, dim_hash, unit)
		SELECT $1, $2, 'collector_cpu_percent', jsonb_build_object('cpu', g::text), g, 'percent'
		FROM generate_series(1000, 1100) g`,
		f.orgID, f.collectorID)
	must(t, err)

	now := time.Now().UTC()
	status, body := f.query(t, map[string]string{
		"metric": "collector_cpu_percent",
		"from":   m4cRFC3339(now.Add(-time.Hour)),
		"to":     m4cRFC3339(now),
	})
	if status != http.StatusOK {
		t.Fatalf("series cap query: %d %v", status, body)
	}
	meta := m8Meta(t, body)
	if meta["series_returned"].(float64) != 100 {
		t.Fatalf("series_returned = %v, want 100", meta["series_returned"])
	}
	if meta["series_total"].(float64) < 101 {
		t.Fatalf("series_total = %v, want >= 101", meta["series_total"])
	}
	if meta["partial"] != true {
		t.Fatalf("series truncation must flag partial: %v", meta)
	}

	// Points cap: ~55 h at 10 s is ~20k buckets -> newest 10k, flagged.
	// A dedicated collector keeps the series cap out of the way.
	fp := newM4CFixture(t, "m8-points-"+newUUID()[:8])
	truncSeries := m8Series(t, m8Env{
		OrgID: fp.orgID, CollectorID: fp.collectorID,
	}, "collector_cpu_percent", 9999, "percent", `{"cpu":"trunc"}`)
	_, err = ownerPool.Exec(ctx, `
		INSERT INTO metric_samples (org_id, series_id, ts, value)
		SELECT $1, $2, now() - (g * interval '10 seconds'), 1
		FROM generate_series(0, 19800) g`,
		fp.orgID, truncSeries)
	must(t, err)

	// Query only that series via an exact window covering the samples.
	status, body = fp.query(t, map[string]string{
		"metric": "collector_cpu_percent",
		"from":   m4cRFC3339(now.Add(-56 * time.Hour)),
		"to":     m4cRFC3339(now),
		"step":   "10s",
	})
	if status != http.StatusOK {
		t.Fatalf("points cap query: %d %v", status, body)
	}
	meta = m8Meta(t, body)
	if meta["points_truncated"] != true || meta["partial"] != true {
		t.Fatalf("points truncation must flag partial: %v", meta)
	}
	if meta["returned_points"].(float64) != 10000 {
		t.Fatalf("returned_points = %v, want 10000", meta["returned_points"])
	}
}

// ---------------------------------------------------------------------------
// Cardinality guards: quarantine, device/site/rate caps, retirement
// ---------------------------------------------------------------------------

func TestMetricsQuarantineStopsSeriesOnly(t *testing.T) {
	f := newM4CFixture(t, "m8-quarantine-"+newUUID()[:8])
	ctx := context.Background()
	now := time.Now().UTC()

	f.ingest(t, 1, []*collectorv1.MetricSample{
		m4Sample(1, map[string]string{"cpu": "total"}, now.Add(-10*time.Second)),
		m4Sample(2, map[string]string{"cpu": "0"}, now.Add(-10*time.Second)),
	})

	seriesID := func(dim string) int64 {
		t.Helper()
		var id int64
		must(t, ownerPool.QueryRow(ctx, `
			SELECT id FROM metric_series
			WHERE org_id = $1 AND collector_id = $2 AND dimensions->>'cpu' = $3`,
			f.orgID, f.collectorID, dim).Scan(&id))
		return id
	}
	zeroID, totalID := seriesID("0"), seriesID("total")

	sink := &captureCardinality{}
	m8WithTenant(t, f.orgID, func(ctx context.Context, tx pgx.Tx) error {
		ok, err := metrics.QuarantineSeries(ctx, tx, mustUUID(t, f.orgID), zeroID, "", sink)
		if err != nil {
			return err
		}
		if !ok {
			t.Fatal("quarantine must transition a live series")
		}
		ok, err = metrics.QuarantineSeries(ctx, tx, mustUUID(t, f.orgID), zeroID, "", sink)
		if err != nil {
			return err
		}
		if ok {
			t.Fatal("second quarantine must be a no-op")
		}
		return nil
	})
	if len(sink.events) != 1 || sink.events[0].Event != metrics.EventName {
		t.Fatalf("expected exactly one %s event, got %+v", metrics.EventName, sink.events)
	}

	var before int
	must(t, ownerPool.QueryRow(ctx, `SELECT count(*) FROM metric_samples WHERE series_id = $1`, zeroID).Scan(&before))

	// The next batch carries both series: only the quarantined one is dropped.
	f.stream.send(t, 2, []*collectorv1.MetricSample{
		m4Sample(11, map[string]string{"cpu": "total"}, now),
		m4Sample(22, map[string]string{"cpu": "0"}, now),
	})
	res := f.stream.result(t)
	if res.GetStatus() != collectorv1.BatchResult_STATUS_OK {
		t.Fatalf("batch status = %v (%s)", res.GetStatus(), res.GetReason())
	}
	if res.GetAcceptedSamples() != 1 || res.GetRejectedSamples() != 1 {
		t.Fatalf("accounting: accepted=%d rejected=%d (want 1/1)", res.GetAcceptedSamples(), res.GetRejectedSamples())
	}
	var after, totalAfter int
	must(t, ownerPool.QueryRow(ctx, `SELECT count(*) FROM metric_samples WHERE series_id = $1`, zeroID).Scan(&after))
	must(t, ownerPool.QueryRow(ctx, `SELECT count(*) FROM metric_samples WHERE series_id = $1`, totalID).Scan(&totalAfter))
	if after != before {
		t.Fatalf("quarantined series accepted samples: %d -> %d", before, after)
	}
	if totalAfter != 2 {
		t.Fatalf("healthy series samples = %d, want 2 (device keeps ingesting)", totalAfter)
	}
}

func TestMetricsDeviceSeriesGuards(t *testing.T) {
	// Per-device cap.
	devCap := m8SeedEnv(t, "m8-devcap-"+newUUID()[:8])
	sink := &captureCardinality{}
	opts := metrics.GuardOptions{MaxPerDevice: 3, MaxPerSite: 1000, MaxPerMinute: 1000, Sink: sink}
	var results []metrics.DeviceSeriesResult
	m8WithTenant(t, devCap.OrgID, func(ctx context.Context, tx pgx.Tx) error {
		for i := 0; i < 4; i++ {
			r, err := metrics.EnsureDeviceSeries(ctx, tx, metrics.DeviceSeriesSpec{
				OrgID: mustUUID(t, devCap.OrgID), DeviceID: mustUUID(t, devCap.DeviceID),
				MetricKey: "sys.cpu.util", Unit: "percent",
				Canonical: []byte(fmt.Sprintf(`{"cpu":"%d"}`, i)), DimHash: int64(i + 1),
			}, opts)
			if err != nil {
				return err
			}
			results = append(results, r)
		}
		// Idempotent resolution of the quarantined series keeps its state.
		r, err := metrics.EnsureDeviceSeries(ctx, tx, metrics.DeviceSeriesSpec{
			OrgID: mustUUID(t, devCap.OrgID), DeviceID: mustUUID(t, devCap.DeviceID),
			MetricKey: "sys.cpu.util", Unit: "percent",
			Canonical: []byte(`{"cpu":"3"}`), DimHash: 4,
		}, opts)
		if err != nil {
			return err
		}
		if r.ID != results[3].ID || !r.Quarantined {
			t.Fatalf("quarantined series must resolve idempotently: %+v vs %+v", r, results[3])
		}
		return nil
	})
	for i := 0; i < 3; i++ {
		if results[i].Quarantined {
			t.Fatalf("series %d must not be quarantined: %+v", i, results[i])
		}
	}
	if !results[3].Quarantined || results[3].Reason != metrics.QuarantineReasonDeviceCap {
		t.Fatalf("4th series must be quarantined by the device cap: %+v", results[3])
	}
	if len(sink.events) != 1 || sink.events[0].Scope != "device" || sink.events[0].Cap != 3 {
		t.Fatalf("device cap event: %+v", sink.events)
	}

	// Per-site cap (single device, low site cap).
	siteCap := m8SeedEnv(t, "m8-sitecap-"+newUUID()[:8])
	siteSink := &captureCardinality{}
	siteOpts := metrics.GuardOptions{MaxPerDevice: 100, MaxPerSite: 2, MaxPerMinute: 1000, Sink: siteSink}
	var siteResults []metrics.DeviceSeriesResult
	m8WithTenant(t, siteCap.OrgID, func(ctx context.Context, tx pgx.Tx) error {
		for i := 0; i < 3; i++ {
			r, err := metrics.EnsureDeviceSeries(ctx, tx, metrics.DeviceSeriesSpec{
				OrgID: mustUUID(t, siteCap.OrgID), DeviceID: mustUUID(t, siteCap.DeviceID),
				MetricKey: "sys.cpu.util", Unit: "percent",
				Canonical: []byte(fmt.Sprintf(`{"cpu":"%d"}`, i)), DimHash: int64(i + 1),
			}, siteOpts)
			if err != nil {
				return err
			}
			siteResults = append(siteResults, r)
		}
		return nil
	})
	if siteResults[2].Reason != metrics.QuarantineReasonSiteCap {
		t.Fatalf("site cap reason = %q, want %q", siteResults[2].Reason, metrics.QuarantineReasonSiteCap)
	}

	// Runaway creation rate (canonical threshold is platform-defined: 60/min).
	rateCap := m8SeedEnv(t, "m8-ratecap-"+newUUID()[:8])
	rateSink := &captureCardinality{}
	rateOpts := metrics.GuardOptions{MaxPerDevice: 1000, MaxPerSite: 1000, MaxPerMinute: 2, Sink: rateSink}
	var rateResults []metrics.DeviceSeriesResult
	m8WithTenant(t, rateCap.OrgID, func(ctx context.Context, tx pgx.Tx) error {
		for i := 0; i < 3; i++ {
			r, err := metrics.EnsureDeviceSeries(ctx, tx, metrics.DeviceSeriesSpec{
				OrgID: mustUUID(t, rateCap.OrgID), DeviceID: mustUUID(t, rateCap.DeviceID),
				MetricKey: "sys.cpu.util", Unit: "percent",
				Canonical: []byte(fmt.Sprintf(`{"cpu":"%d"}`, i)), DimHash: int64(i + 1),
			}, rateOpts)
			if err != nil {
				return err
			}
			rateResults = append(rateResults, r)
		}
		return nil
	})
	if rateResults[2].Reason != metrics.QuarantineReasonCreationRate {
		t.Fatalf("rate cap reason = %q, want %q", rateResults[2].Reason, metrics.QuarantineReasonCreationRate)
	}
}

func TestMetricsSeriesRetirement(t *testing.T) {
	ctx := context.Background()
	env := m8SeedEnv(t, "m8-retire-"+newUUID()[:8])

	oldSeries := m8Series(t, env, "sys.mem.used", 201, "percent", `{"i":"old"}`)
	liveSeries := m8Series(t, env, "sys.mem.used", 202, "percent", `{"i":"live"}`)
	_, err := ownerPool.Exec(ctx,
		`UPDATE metric_series SET last_seen_at = now() - interval '31 days' WHERE id = $1`, oldSeries)
	must(t, err)
	_, err = ownerPool.Exec(ctx,
		`UPDATE metric_series SET last_seen_at = now() WHERE id = $1`, liveSeries)
	must(t, err)

	retired, err := metrics.RetireInactiveSeries(ctx, ownerPool, metrics.SeriesRetirementAge)
	must(t, err)
	if retired < 1 {
		t.Fatalf("retired = %d, want >= 1", retired)
	}
	var oldRetired, liveRetired *time.Time
	must(t, ownerPool.QueryRow(ctx, `SELECT retired_at FROM metric_series WHERE id = $1`, oldSeries).Scan(&oldRetired))
	must(t, ownerPool.QueryRow(ctx, `SELECT retired_at FROM metric_series WHERE id = $1`, liveSeries).Scan(&liveRetired))
	if oldRetired == nil {
		t.Fatal("inactive series must be tombstoned")
	}
	if liveRetired != nil {
		t.Fatal("active series must not be retired")
	}

	// New activity un-retires: the collector is authoritative about liveness.
	m8WithTenant(t, env.OrgID, func(ctx context.Context, tx pgx.Tx) error {
		return metrics.TimescaleStore{}.TouchSeries(ctx, tx, mustUUID(t, env.OrgID), []int64{oldSeries}, time.Now().UTC())
	})
	must(t, ownerPool.QueryRow(ctx, `SELECT retired_at FROM metric_series WHERE id = $1`, oldSeries).Scan(&oldRetired))
	if oldRetired != nil {
		t.Fatal("new samples must reactivate a retired series")
	}
}
