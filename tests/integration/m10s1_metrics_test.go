package integration

// M10-S1 (Phase 2): the canonical multi-series metrics query API.
// POST /v1/metrics/query is validated for the canonical contract (series
// ids/selectors, from/to, step, agg, fill, caps, gap markers) and the GET
// convenience form is validated for ETag/If-None-Match caching. Scope and
// tenant isolation follow the M7 patterns: selectors are scope-filtered,
// explicit series ids are uniformly 404 outside the caller's scope.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/api"
	"github.com/argus-platform/argus/internal/modules/collectors"
	"github.com/argus-platform/argus/internal/modules/identity"
	"github.com/argus-platform/argus/internal/modules/inventory"
	"github.com/argus-platform/argus/internal/modules/metrics"
	"github.com/argus-platform/argus/internal/modules/pollhealth"
	"github.com/argus-platform/argus/internal/modules/tenancy"
	"github.com/argus-platform/argus/internal/platform/telemetry"
)

// newM10S1Env wires the full public router with inventory, poll health and the
// M10-S1 metrics query service (the production wiring).
func newM10S1Env(t *testing.T, slug string) *inventoryEnv {
	t.Helper()
	seed := seedLoginUser(t, slug, "HQ-"+slug)

	tenancySvc := tenancy.New(appPool, authPool)
	identitySvc, err := identity.New(appPool, authPool, tenancySvc)
	must(t, err)
	inv := inventory.New(appPool, nil)
	router := api.NewRouter(api.Options{
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Telemetry:    telemetry.New("it-m10s1", "0", "0"),
		Version:      "it",
		Commit:       "it",
		Identity:     identitySvc,
		Tenancy:      tenancySvc,
		Inventory:    inv,
		PollHealth:   pollhealth.New(appPool),
		MetricsQuery: metrics.NewQueryService(appPool, collectors.New(appPool, authPool, nil, nil), nil),
	})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	jar, err := cookiejar.New(nil)
	must(t, err)
	client := &http.Client{Jar: jar, Timeout: 15 * time.Second}
	res := doRequest(t, client, http.MethodPost, srv.URL+"/v1/auth/login", loginBody(slug, "it-password"), nil)
	if res.Status != http.StatusOK {
		t.Fatalf("login: status %d body %v", res.Status, res.Body)
	}
	csrf := cookieByName(res, "argus_csrf")
	if csrf == nil {
		t.Fatal("login did not set argus_csrf")
	}
	return &inventoryEnv{
		srv:    srv,
		client: client,
		slug:   slug,
		orgID:  seed.OrgID,
		siteID: seed.SiteID,
		csrf:   csrf.Value,
	}
}

// m10DeviceSeries inserts one device-scoped series and returns its storage id.
func m10DeviceSeries(t *testing.T, orgID string, deviceID uuid.UUID, key string, dims map[string]string, unit string) int64 {
	t.Helper()
	canonical, dimHash, err := metrics.CanonicalizeDimensions(dims)
	must(t, err)
	var id int64
	must(t, ownerPool.QueryRow(context.Background(), `
		INSERT INTO metric_series (org_id, device_id, metric_key, dimensions, dim_hash, unit)
		VALUES ($1, $2, $3, $4::jsonb, $5, $6) RETURNING id`,
		orgID, deviceID, key, string(canonical), dimHash, unit).Scan(&id))
	return id
}

// m10Samples inserts explicit (ts, value) pairs for one series.
func m10Samples(t *testing.T, orgID string, seriesID int64, points [][2]any) {
	t.Helper()
	ts := make([]time.Time, 0, len(points))
	vs := make([]float64, 0, len(points))
	for _, p := range points {
		ts = append(ts, p[0].(time.Time))
		vs = append(vs, p[1].(float64))
	}
	_, err := ownerPool.Exec(context.Background(),
		`INSERT INTO metric_samples (org_id, series_id, ts, value)
		 SELECT $1, $2, * FROM unnest($3::timestamptz[], $4::float8[])`,
		orgID, seriesID, ts, vs)
	must(t, err)
}

func stringMustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	must(t, err)
	return string(raw)
}

func (e *inventoryEnv) postMatrix(t *testing.T, body map[string]any) apiResponse {
	t.Helper()
	return e.do(t, http.MethodPost, "/v1/metrics/query", stringMustJSON(t, body))
}

func matrixSeriesList(t *testing.T, body map[string]any) []map[string]any {
	t.Helper()
	raw, ok := body["series"].([]any)
	if !ok {
		t.Fatalf("body has no series array: %v", body)
	}
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		obj, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("series item is not an object: %v", item)
		}
		out = append(out, obj)
	}
	return out
}

func matrixMeta(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	meta, ok := body["meta"].(map[string]any)
	if !ok {
		t.Fatalf("body has no meta: %v", body)
	}
	return meta
}

// matrixPoints decodes [[unix_seconds, value|null], ...].
func matrixPoints(t *testing.T, series map[string]any) [][2]any {
	t.Helper()
	raw, ok := series["points"].([]any)
	if !ok {
		t.Fatalf("series has no points: %v", series)
	}
	out := make([][2]any, 0, len(raw))
	for _, item := range raw {
		pair, ok := item.([]any)
		if !ok || len(pair) != 2 {
			t.Fatalf("point malformed: %v", item)
		}
		out = append(out, [2]any{pair[0], pair[1]})
	}
	return out
}

func matrixValue(t *testing.T, p [2]any) any {
	t.Helper()
	return p[1]
}

func TestM10S1MetricsQueryPostContract(t *testing.T) {
	env := newM10S1Env(t, "m10s1-post-"+newUUID()[:8])
	deviceID := mustUUID(t, env.createDevice(t, "m10s1-r1", nil))

	base := time.Now().UTC().Add(-30 * time.Minute).Truncate(time.Minute)
	rtt := m10DeviceSeries(t, env.orgID, deviceID, "net.icmp.rtt_ms", map[string]string{"if": "ether1"}, "ms")
	m10Samples(t, env.orgID, rtt, [][2]any{
		{base.Add(5 * time.Second), 10.0},
		{base.Add(65 * time.Second), 20.0},
	})
	loss := m10DeviceSeries(t, env.orgID, deviceID, "net.icmp.loss_pct", map[string]string{}, "percent")
	m10Samples(t, env.orgID, loss, [][2]any{
		{base.Add(5 * time.Second), 0.5},
		{base.Add(2 * time.Minute), 1.5},
	})
	m8Refresh(t, "metric_1m", base.Add(-2*time.Minute), base.Add(4*time.Minute))

	from, to := base, base.Add(2*time.Minute)
	res := env.postMatrix(t, map[string]any{
		"series": []any{
			map[string]any{"device_id": deviceID.String(), "metric_key": "net.icmp.rtt_ms", "dimensions": map[string]string{"if": "ether1"}},
			metrics.EncodeSeriesID(loss),
		},
		"from": from.Format(time.RFC3339),
		"to":   to.Format(time.RFC3339),
		"step": "1m",
		"agg":  "avg",
		"fill": "null",
	})
	if res.Status != http.StatusOK {
		t.Fatalf("POST query: status %d body %v", res.Status, res.Body)
	}
	series := matrixSeriesList(t, res.Body)
	if len(series) != 2 {
		t.Fatalf("series len = %d, want 2", len(series))
	}
	if series[0]["id"] != metrics.EncodeSeriesID(rtt) || series[1]["id"] != metrics.EncodeSeriesID(loss) {
		t.Fatalf("series ids = %v %v", series[0]["id"], series[1]["id"])
	}
	first := series[0]
	if first["device_id"] != deviceID.String() || first["metric_key"] != "net.icmp.rtt_ms" || first["unit"] != "ms" {
		t.Fatalf("series identity = %v", first)
	}
	dims := first["dimensions"].(map[string]any)
	if dims["if"] != "ether1" {
		t.Fatalf("dimensions = %v", dims)
	}
	labels := first["labels"].(map[string]any)
	if labels["device"] != "m10s1-r1" || labels["metric"] != "net.icmp.rtt_ms" || labels["unit"] != "ms" || labels["if"] != "ether1" {
		t.Fatalf("labels = %v", labels)
	}
	if first["truncated"] != false {
		t.Fatalf("truncated = %v, want false", first["truncated"])
	}
	// 3 buckets: 10, 20, explicit null gap (never interpolated).
	points := matrixPoints(t, first)
	if len(points) != 3 {
		t.Fatalf("rtt points = %d, want 3", len(points))
	}
	if matrixValue(t, points[0]) != 10.0 || matrixValue(t, points[1]) != 20.0 || matrixValue(t, points[2]) != nil {
		t.Fatalf("rtt point values = %v", points)
	}
	lossPoints := matrixPoints(t, series[1])
	if len(lossPoints) != 3 || matrixValue(t, lossPoints[0]) != 0.5 || matrixValue(t, lossPoints[1]) != nil || matrixValue(t, lossPoints[2]) != 1.5 {
		t.Fatalf("loss point values = %v", lossPoints)
	}

	meta := matrixMeta(t, res.Body)
	if meta["resolution"] != "rollup_1m" || meta["partial"] != false || meta["points_truncated"] != false {
		t.Fatalf("meta = %v", meta)
	}
	if meta["series_total"] != float64(2) || meta["series_returned"] != float64(2) {
		t.Fatalf("series meta = %v", meta)
	}
	if meta["raw_fallback"] != false || meta["rollup_missing"] != false {
		t.Fatalf("fallback meta = %v", meta)
	}
	quality := meta["quality"].(map[string]any)
	if quality["gaps"] != float64(2) || quality["dropped_samples"] != float64(0) {
		t.Fatalf("quality = %v", quality)
	}
	if _, has := meta["resolution_warning"]; has {
		t.Fatalf("unexpected resolution warning: %v", meta)
	}
	if body := res.Header.Get("ETag"); body != "" {
		t.Fatalf("POST must not set an ETag, got %q", body)
	}
}

func TestM10S1MetricsQueryAggregationsAndFill(t *testing.T) {
	env := newM10S1Env(t, "m10s1-agg-"+newUUID()[:8])
	deviceID := mustUUID(t, env.createDevice(t, "m10s1-agg", nil))
	base := time.Now().UTC().Add(-40 * time.Minute).Truncate(time.Minute)
	seriesID := m10DeviceSeries(t, env.orgID, deviceID, "net.icmp.loss_pct", map[string]string{}, "percent")
	m10Samples(t, env.orgID, seriesID, [][2]any{
		{base.Add(5 * time.Second), 1.0},
		{base.Add(15 * time.Second), 3.0},
		{base.Add(2 * time.Minute), 7.0},
	})
	from, to := base, base.Add(2*time.Minute)

	query := func(agg, fill string) map[string]any {
		t.Helper()
		res := env.postMatrix(t, map[string]any{
			"series": []any{metrics.EncodeSeriesID(seriesID)},
			"from":   from.Format(time.RFC3339),
			"to":     to.Format(time.RFC3339),
			"step":   "1m",
			"agg":    agg,
			"fill":   fill,
		})
		if res.Status != http.StatusOK {
			t.Fatalf("agg=%s fill=%s: status %d body %v", agg, fill, res.Status, res.Body)
		}
		return res.Body
	}

	if v := matrixValue(t, matrixPoints(t, matrixSeriesList(t, query("avg", "null"))[0])[0]); v != 2.0 {
		t.Fatalf("avg = %v, want 2", v)
	}
	if v := matrixValue(t, matrixPoints(t, matrixSeriesList(t, query("max", "null"))[0])[0]); v != 3.0 {
		t.Fatalf("max = %v, want 3", v)
	}
	if v := matrixValue(t, matrixPoints(t, matrixSeriesList(t, query("sum", "null"))[0])[0]); v != 4.0 {
		t.Fatalf("sum = %v, want 4", v)
	}
	// rate is the mean of normalized values (counters arrive as rates).
	if v := matrixValue(t, matrixPoints(t, matrixSeriesList(t, query("rate", "null"))[0])[0]); v != 2.0 {
		t.Fatalf("rate = %v, want 2", v)
	}
	// p95 is computed from raw samples (not materialized): 1,3 -> 2.9.
	p95Body := query("p95", "null")
	p95Points := matrixPoints(t, matrixSeriesList(t, p95Body)[0])
	if v := matrixValue(t, p95Points[0]); v == nil {
		t.Fatal("p95 bucket is null")
	} else if diff := v.(float64) - 2.9; diff > 1e-9 || diff < -1e-9 {
		t.Fatalf("p95 = %v, want 2.9", v)
	}
	if matrixMeta(t, p95Body)["raw_fallback"] != true {
		t.Fatalf("p95 on a rollup step must flag raw_fallback: %v", matrixMeta(t, p95Body))
	}

	// Fill modes on the gap bucket (base+1m).
	zero := matrixPoints(t, matrixSeriesList(t, query("avg", "zero"))[0])
	if v := matrixValue(t, zero[1]); v != 0.0 {
		t.Fatalf("fill=zero gap = %v, want 0", v)
	}
	previous := matrixPoints(t, matrixSeriesList(t, query("avg", "previous"))[0])
	if v := matrixValue(t, previous[1]); v != 2.0 {
		t.Fatalf("fill=previous gap = %v, want 2 (the previous bucket)", v)
	}
	// The value bucket after the gap is observed again, not carried.
	if v := matrixValue(t, previous[2]); v != 7.0 {
		t.Fatalf("fill=previous observed bucket = %v, want 7", v)
	}

	// Auto step resolves via the M8 picker: 3 days -> 5m.
	autoRes := env.postMatrix(t, map[string]any{
		"series": []any{metrics.EncodeSeriesID(seriesID)},
		"from":   time.Now().UTC().Add(-72 * time.Hour).Format(time.RFC3339),
		"to":     time.Now().UTC().Format(time.RFC3339),
		"step":   "auto",
	})
	if autoRes.Status != http.StatusOK {
		t.Fatalf("auto query: status %d body %v", autoRes.Status, autoRes.Body)
	}
	if got := matrixMeta(t, autoRes.Body)["resolution"]; got != "rollup_5m" {
		t.Fatalf("auto resolution = %v, want rollup_5m", got)
	}
	// Explicit finer-than-recommended steps are honored with a warning.
	warn := env.postMatrix(t, map[string]any{
		"series": []any{metrics.EncodeSeriesID(seriesID)},
		"from":   time.Now().UTC().Add(-72 * time.Hour).Format(time.RFC3339),
		"to":     time.Now().UTC().Format(time.RFC3339),
		"step":   "1m",
		"agg":    "avg",
	})
	if warn.Status != http.StatusOK {
		t.Fatalf("explicit fine step: status %d", warn.Status)
	}
	if _, has := matrixMeta(t, warn.Body)["resolution_warning"]; !has {
		t.Fatalf("explicit 1m over 3 d must warn: %v", matrixMeta(t, warn.Body))
	}
}

func TestM10S1MetricsQueryValidation(t *testing.T) {
	env := newM10S1Env(t, "m10s1-val-"+newUUID()[:8])
	deviceID := mustUUID(t, env.createDevice(t, "m10s1-val", nil))
	now := time.Now().UTC()
	seriesID := m10DeviceSeries(t, env.orgID, deviceID, "net.icmp.rtt_ms", map[string]string{}, "ms")
	base := map[string]any{
		"series": []any{metrics.EncodeSeriesID(seriesID)},
		"from":   now.Add(-time.Hour).Format(time.RFC3339),
		"to":     now.Format(time.RFC3339),
		"step":   "1m",
	}

	cases := []struct {
		name   string
		mutate func(m map[string]any)
		status int
		code   string
	}{
		{"unknown agg", func(m map[string]any) { m["agg"] = "median" }, http.StatusUnprocessableEntity, "query.agg_unsupported"},
		{"unknown fill", func(m map[string]any) { m["fill"] = "linear" }, http.StatusBadRequest, "validation.failed"},
		{"unknown step", func(m map[string]any) { m["step"] = "2h" }, http.StatusBadRequest, "validation.failed"},
		{"empty series", func(m map[string]any) { m["series"] = []any{} }, http.StatusBadRequest, "validation.failed"},
		{"bad selector dims", func(m map[string]any) {
			m["series"] = []any{map[string]any{"device_id": deviceID.String(), "metric_key": "net.icmp.rtt_ms", "dimensions": map[string]any{"if": 7}}}
		}, http.StatusBadRequest, "validation.failed"},
		{"unknown field", func(m map[string]any) { m["agg"] = "avg"; m["bogus"] = true }, http.StatusBadRequest, "validation.failed"},
		{"raw with agg", func(m map[string]any) { m["step"] = "raw"; m["agg"] = "max" }, http.StatusBadRequest, "validation.failed"},
	}
	for _, tc := range cases {
		body := map[string]any{}
		for k, v := range base {
			body[k] = v
		}
		tc.mutate(body)
		res := env.postMatrix(t, body)
		requireProblem(t, res, tc.status, tc.code)
	}

	// from >= to and future `to` are range errors.
	for _, mutate := range []func(m map[string]any){
		func(m map[string]any) { m["to"] = m["from"] },
		func(m map[string]any) { m["to"] = now.Add(time.Hour).Format(time.RFC3339) },
	} {
		body := map[string]any{}
		for k, v := range base {
			body[k] = v
		}
		mutate(body)
		res := env.postMatrix(t, body)
		requireProblem(t, res, http.StatusBadRequest, "validation.failed")
	}

	// Unknown opaque ids are uniform 404 series.not_found.
	bad := map[string]any{
		"series": []any{"s_zzzz1"},
		"from":   base["from"], "to": base["to"],
	}
	res := env.postMatrix(t, bad)
	requireProblem(t, res, http.StatusNotFound, "series.not_found")
}

func TestM10S1MetricsQueryCaps(t *testing.T) {
	env := newM10S1Env(t, "m10s1-caps-"+newUUID()[:8])
	deviceID := mustUUID(t, env.createDevice(t, "m10s1-caps", nil))
	base := time.Now().UTC().Add(-60 * time.Minute).Truncate(time.Minute)

	// 101 explicit series: the response caps at 100 with partial=true and an
	// exact series_total.
	ids := make([]any, 0, 101)
	for i := 0; i < 101; i++ {
		id := m10DeviceSeries(t, env.orgID, deviceID, fmt.Sprintf("net.test.series_%03d", i), map[string]string{}, "count")
		m10Samples(t, env.orgID, id, [][2]any{{base.Add(5 * time.Second), float64(i)}})
		ids = append(ids, metrics.EncodeSeriesID(id))
	}
	res := env.postMatrix(t, map[string]any{
		"series": ids,
		"from":   base.Format(time.RFC3339),
		"to":     base.Add(time.Minute).Format(time.RFC3339),
		"step":   "1m",
	})
	if res.Status != http.StatusOK {
		t.Fatalf("series cap query: status %d body %v", res.Status, res.Body)
	}
	if got := len(matrixSeriesList(t, res.Body)); got != 100 {
		t.Fatalf("series returned = %d, want 100", got)
	}
	meta := matrixMeta(t, res.Body)
	if meta["series_total"] != float64(101) || meta["series_returned"] != float64(100) || meta["partial"] != true {
		t.Fatalf("series cap meta = %v", meta)
	}

	// 10,050 one-minute buckets on one series: the 10k response cap keeps the
	// newest buckets and flags per-series truncation.
	pointBase := time.Now().UTC().Add(-8 * 24 * time.Hour).Truncate(time.Minute)
	pointSeries := m10DeviceSeries(t, env.orgID, deviceID, "net.test.dense", map[string]string{}, "count")
	m8InsertSamples(t, env.orgID, pointSeries, pointBase, 10050, time.Minute, func(i int) float64 { return float64(i) })
	res = env.postMatrix(t, map[string]any{
		"series": []any{metrics.EncodeSeriesID(pointSeries)},
		"from":   pointBase.Format(time.RFC3339),
		"to":     pointBase.Add(10049 * time.Minute).Format(time.RFC3339),
		"step":   "1m",
	})
	if res.Status != http.StatusOK {
		t.Fatalf("point cap query: status %d body %v", res.Status, res.Body)
	}
	points := matrixPoints(t, matrixSeriesList(t, res.Body)[0])
	if len(points) != 10000 {
		t.Fatalf("points = %d, want the 10k cap", len(points))
	}
	if last := matrixValue(t, points[len(points)-1]); last != float64(10049) {
		// The newest bucket is the last inserted sample (value 10049).
		t.Fatalf("newest kept point = %v, want 10049", last)
	}
	if matrixSeriesList(t, res.Body)[0]["truncated"] != true {
		t.Fatalf("series truncated flag missing: %v", matrixSeriesList(t, res.Body)[0])
	}
	meta = matrixMeta(t, res.Body)
	if meta["points_truncated"] != true || meta["partial"] != true {
		t.Fatalf("point cap meta = %v", meta)
	}
}

func TestM10S1MetricsQueryGetETag(t *testing.T) {
	env := newM10S1Env(t, "m10s1-get-"+newUUID()[:8])
	deviceID := mustUUID(t, env.createDevice(t, "m10s1-get", nil))
	base := time.Now().UTC().Add(-30 * time.Minute).Truncate(time.Minute)
	seriesID := m10DeviceSeries(t, env.orgID, deviceID, "net.icmp.rtt_ms", map[string]string{"if": "ether1"}, "ms")
	m10Samples(t, env.orgID, seriesID, [][2]any{{base.Add(5 * time.Second), 12.0}})

	q := url.Values{}
	q.Set("series", metrics.EncodeSeriesID(seriesID))
	q.Set("from", base.Format(time.RFC3339))
	q.Set("to", base.Add(time.Minute).Format(time.RFC3339))
	q.Set("step", "1m")
	q.Set("agg", "avg")
	q.Set("fill", "null")
	path := "/v1/metrics/query?" + q.Encode()

	res := env.do(t, http.MethodGet, path, "")
	if res.Status != http.StatusOK {
		t.Fatalf("GET query: status %d body %v", res.Status, res.Body)
	}
	etag := res.Header.Get("ETag")
	if etag == "" {
		t.Fatal("GET response missing ETag")
	}
	if cc := res.Header.Get("Cache-Control"); cc == "" {
		t.Fatal("GET response missing Cache-Control")
	}
	points := matrixPoints(t, matrixSeriesList(t, res.Body)[0])
	if len(points) != 2 || matrixValue(t, points[0]) != 12.0 || matrixValue(t, points[1]) != nil {
		t.Fatalf("GET points = %v", points)
	}

	// Same compiled query with the ETag: 304 with no body, same validator.
	second := doRequest(t, env.client, http.MethodGet, env.srv.URL+path, "", map[string]string{"If-None-Match": etag})
	if second.Status != http.StatusNotModified {
		t.Fatalf("If-None-Match status = %d, want 304 (body %v)", second.Status, second.Body)
	}
	if second.Header.Get("ETag") != etag {
		t.Fatalf("304 ETag = %q, want %q", second.Header.Get("ETag"), etag)
	}
	// A non-matching validator revalidates to 200 without changing the ETag.
	third := doRequest(t, env.client, http.MethodGet, env.srv.URL+path, "", map[string]string{"If-None-Match": `"other"`})
	if third.Status != http.StatusOK || third.Header.Get("ETag") != etag {
		t.Fatalf("non-matching validator: status %d etag %q", third.Status, third.Header.Get("ETag"))
	}

	// The compact selector form returns the same series with no explicit ids.
	sel := url.Values{}
	sel.Set("device_id", deviceID.String())
	sel.Set("metric", "net.icmp.rtt_ms")
	sel.Set("dimensions", "if=ether1")
	sel.Set("from", q.Get("from"))
	sel.Set("to", q.Get("to"))
	sel.Set("step", "1m")
	selRes := env.do(t, http.MethodGet, "/v1/metrics/query?"+sel.Encode(), "")
	if selRes.Status != http.StatusOK || len(matrixSeriesList(t, selRes.Body)) != 1 {
		t.Fatalf("selector GET: status %d body %v", selRes.Status, selRes.Body)
	}
	if matrixSeriesList(t, selRes.Body)[0]["id"] != metrics.EncodeSeriesID(seriesID) {
		t.Fatalf("selector GET returned the wrong series: %v", matrixSeriesList(t, selRes.Body)[0])
	}

	// 401 before capability, 404 for unknown ids (uniform, no oracle).
	anon := &http.Client{Timeout: 10 * time.Second}
	if res := doRequest(t, anon, http.MethodGet, env.srv.URL+path, "", nil); res.Status != http.StatusUnauthorized {
		t.Fatalf("anonymous GET status = %d, want 401", res.Status)
	}
	bad := url.Values{}
	bad.Set("series", "s_zzzz1")
	bad.Set("from", q.Get("from"))
	bad.Set("to", q.Get("to"))
	requireProblem(t, env.do(t, http.MethodGet, "/v1/metrics/query?"+bad.Encode(), ""), http.StatusNotFound, "series.not_found")
}

func TestM10S1MetricsQueryScopeAndTenancy(t *testing.T) {
	envA := newM10S1Env(t, "m10s1-scope-a-"+newUUID()[:8])
	envB := newM10S1Env(t, "m10s1-scope-b-"+newUUID()[:8])
	deviceA := mustUUID(t, envA.createDevice(t, "m10s1-scope-a", nil))
	base := time.Now().UTC().Add(-30 * time.Minute).Truncate(time.Minute)
	seriesA := m10DeviceSeries(t, envA.orgID, deviceA, "net.icmp.rtt_ms", map[string]string{}, "ms")
	m10Samples(t, envA.orgID, seriesA, [][2]any{{base.Add(5 * time.Second), 5.0}})

	// B's org cannot see A's series: uniform 404 for explicit ids.
	body := map[string]any{
		"series": []any{metrics.EncodeSeriesID(seriesA)},
		"from":   base.Format(time.RFC3339),
		"to":     base.Add(time.Minute).Format(time.RFC3339),
		"step":   "1m",
	}
	requireProblem(t, envB.postMatrix(t, body), http.StatusNotFound, "series.not_found")
	// B's selector for A's device returns an empty matrix (filtered, no oracle).
	selRes := envB.postMatrix(t, map[string]any{
		"series": []any{map[string]any{"device_id": deviceA.String(), "metric_key": "net.icmp.rtt_ms"}},
		"from":   base.Format(time.RFC3339),
		"to":     base.Add(time.Minute).Format(time.RFC3339),
		"step":   "1m",
	})
	if selRes.Status != http.StatusOK || len(matrixSeriesList(t, selRes.Body)) != 0 {
		t.Fatalf("cross-tenant selector: status %d body %v", selRes.Status, selRes.Body)
	}

	// Site-scoped viewer in A: selector filtered out, explicit id 404.
	site2 := createSite(t, envA.orgID, "S2-"+envA.slug)
	viewerEmail := seedViewerForSite(t, envA, site2)
	viewer, _ := loginAs(t, envA, viewerEmail)
	res := doRequest(t, viewer, http.MethodPost, envA.srv.URL+"/v1/metrics/query", stringMustJSON(t, body), map[string]string{"Content-Type": "application/json"})
	requireProblem(t, res, http.StatusNotFound, "series.not_found")
	selRes = doRequest(t, viewer, http.MethodPost, envA.srv.URL+"/v1/metrics/query", stringMustJSON(t, map[string]any{
		"series": []any{map[string]any{"device_id": deviceA.String(), "metric_key": "net.icmp.rtt_ms"}},
		"from":   base.Format(time.RFC3339),
		"to":     base.Add(time.Minute).Format(time.RFC3339),
		"step":   "1m",
	}), map[string]string{"Content-Type": "application/json"})
	if selRes.Status != http.StatusOK || len(matrixSeriesList(t, selRes.Body)) != 0 {
		t.Fatalf("out-of-scope selector: status %d body %v", selRes.Status, selRes.Body)
	}
	// The unrestricted admin still sees it.
	adminRes := envA.postMatrix(t, body)
	if adminRes.Status != http.StatusOK || len(matrixSeriesList(t, adminRes.Body)) != 1 {
		t.Fatalf("admin query: status %d body %v", adminRes.Status, adminRes.Body)
	}
}
