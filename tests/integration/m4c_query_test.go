package integration

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
	"github.com/argus-platform/argus/internal/api"
	collectoridentity "github.com/argus-platform/argus/internal/collector/identity"
	"github.com/argus-platform/argus/internal/modules/collectors"
	identitymod "github.com/argus-platform/argus/internal/modules/identity"
	"github.com/argus-platform/argus/internal/modules/metrics"
	"github.com/argus-platform/argus/internal/modules/tenancy"
	"github.com/argus-platform/argus/internal/platform/telemetry"
)

// newTestAPIWithQueryService builds the full router with collectors + metrics
// query wired (the M4c HTTP surface).
func newTestAPIWithQueryService(t *testing.T, qs *metrics.QueryService) (*httptest.Server, *http.Client) {
	t.Helper()
	tenancySvc := tenancy.New(appPool, authPool)
	identitySvc, err := identitymod.New(appPool, authPool, tenancySvc)
	must(t, err)
	collectorsSvc := collectors.New(appPool, authPool, nil, nil)
	router := api.NewRouter(api.Options{
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Telemetry:         telemetry.New("it-m4c", "0", "0"),
		Version:           "it",
		Commit:            "it",
		Identity:          identitySvc,
		Tenancy:           tenancySvc,
		Collectors:        collectorsSvc,
		CollectorSessions: collectors.NewSessionRegistry(),
		MetricsQuery:      qs,
	})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	must(t, err)
	return srv, &http.Client{Jar: jar, Timeout: 10 * time.Second}
}

func newTestAPIWithMetrics(t *testing.T) (*httptest.Server, *http.Client) {
	t.Helper()
	return newTestAPIWithQueryService(t, metrics.NewQueryService(appPool, collectors.New(appPool, authPool, nil, nil), nil))
}

// m4cFixture is one tenant with an enrolled collector, a logged-in session,
// and an open raw batch stream for deterministic data injection.
type m4cFixture struct {
	env         *m3Env
	id          collectoridentity.Identity
	store       *collectoridentity.Store
	stream      *rawBatchStream
	srv         *httptest.Server
	client      *http.Client
	slug        string
	collectorID string
}

func newM4CFixture(t *testing.T, slug string) *m4cFixture {
	t.Helper()
	env, id, store, _ := m4Env(t, slug)
	srv, client := newTestAPIWithMetrics(t)
	res := doRequest(t, client, http.MethodPost, srv.URL+"/v1/auth/login", loginBody(slug, "it-password"), nil)
	if res.Status != http.StatusOK {
		t.Fatalf("login: status %d body %v", res.Status, res.Body)
	}
	return &m4cFixture{
		env:         env,
		id:          id,
		store:       store,
		stream:      dialBatchStream(t, env, id, store),
		srv:         srv,
		client:      client,
		slug:        slug,
		collectorID: id.CollectorID,
	}
}

// ingest sends one batch of samples and requires STATUS_OK.
func (f *m4cFixture) ingest(t *testing.T, seq int64, samples []*collectorv1.MetricSample) {
	t.Helper()
	f.stream.send(t, seq, samples)
	res := f.stream.result(t)
	if res.GetStatus() != collectorv1.BatchResult_STATUS_OK {
		t.Fatalf("ingest batch %d: status=%v reason=%q", seq, res.GetStatus(), res.GetReason())
	}
}

// query performs a metrics GET and returns the decoded body.
func (f *m4cFixture) query(t *testing.T, params map[string]string) (int, map[string]any) {
	t.Helper()
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	path := fmt.Sprintf("/v1/collectors/%s/metrics?%s", f.collectorID, q.Encode())
	res := doRequest(t, f.client, http.MethodGet, f.srv.URL+path, "", nil)
	return res.Status, res.Body
}

func m4cPoints(t *testing.T, body map[string]any) [][2]float64 {
	t.Helper()
	raw, ok := body["points"].([]any)
	if !ok {
		t.Fatalf("points missing/odd: %v", body["points"])
	}
	out := make([][2]float64, 0, len(raw))
	for _, item := range raw {
		pair, ok := item.([]any)
		if !ok || len(pair) != 2 {
			t.Fatalf("point item malformed: %v", item)
		}
		out = append(out, [2]float64{pair[0].(float64), pair[1].(float64)})
	}
	return out
}

func m4cRFC3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func TestM4CQueryHappyRawAggregationOrdering(t *testing.T) {
	f := newM4CFixture(t, "m4c-happy-"+newUUID()[:8])
	base := time.Now().UTC().Add(-30 * time.Minute).Truncate(time.Minute)
	// Two samples in the base minute bucket (avg 20), one in the next (70).
	f.ingest(t, 1, []*collectorv1.MetricSample{
		m4Sample(10, map[string]string{"cpu": "total"}, base.Add(5*time.Second)),
		m4Sample(30, map[string]string{"cpu": "total"}, base.Add(15*time.Second)),
		m4Sample(70, map[string]string{"cpu": "total"}, base.Add(65*time.Second)),
	})

	// Raw: exact values, ascending order, sample_count.
	status, body := f.query(t, map[string]string{
		"metric": "collector_cpu_percent",
		"from":   m4cRFC3339(base.Add(-time.Second)),
		"to":     m4cRFC3339(base.Add(2 * time.Minute)),
		"step":   "raw",
	})
	if status != http.StatusOK {
		t.Fatalf("raw query: status %d body %v", status, body)
	}
	points := m4cPoints(t, body)
	if len(points) != 3 {
		t.Fatalf("raw points = %d, want 3 (%v)", len(points), points)
	}
	wantValues := []float64{10, 30, 70}
	for i, p := range points {
		if p[1] != wantValues[i] {
			t.Fatalf("raw point %d value = %v, want %v", i, p[1], wantValues[i])
		}
		if i > 0 && points[i-1][0] >= p[0] {
			t.Fatalf("raw points not ascending: %v", points)
		}
	}
	if body["unit"] != "percent" || body["resolution"] != "raw" || body["metric"] != "collector_cpu_percent" {
		t.Fatalf("raw metadata: %v", body)
	}
	meta := body["meta"].(map[string]any)
	if meta["sample_count"].(float64) != 3 || meta["returned_points"].(float64) != 3 {
		t.Fatalf("raw meta: %v", meta)
	}

	// Aggregation: 1m buckets ??? avg 20 (base), 70 (base+1m); one gap bucket.
	status, body = f.query(t, map[string]string{
		"metric": "collector_cpu_percent",
		"from":   m4cRFC3339(base),
		"to":     m4cRFC3339(base.Add(2 * time.Minute)),
		"step":   "1m",
	})
	if status != http.StatusOK {
		t.Fatalf("agg query: status %d body %v", status, body)
	}
	points = m4cPoints(t, body)
	if len(points) != 2 {
		t.Fatalf("agg points = %d, want 2 (%v)", len(points), points)
	}
	if math.Abs(points[0][1]-20) > 1e-9 || math.Abs(points[1][1]-70) > 1e-9 {
		t.Fatalf("agg values = %v, want [20, 70]", points)
	}
	meta = body["meta"].(map[string]any)
	if meta["expected_points"].(float64) != 3 || meta["gaps"].(float64) != 1 {
		t.Fatalf("agg meta: %v (want expected=3 gaps=1)", meta)
	}
	if body["resolution"] != "1m" {
		t.Fatalf("agg resolution: %v", body["resolution"])
	}
}

func TestM4CQueryEmptyAndMalformed(t *testing.T) {
	f := newM4CFixture(t, "m4c-empty-"+newUUID()[:8])
	now := time.Now().UTC()

	// Empty range: clean 200 with no points/no latest.
	status, body := f.query(t, map[string]string{
		"metric": "collector_cpu_percent",
		"from":   m4cRFC3339(now.Add(-20 * time.Hour)),
		"to":     m4cRFC3339(now.Add(-19 * time.Hour)),
		"step":   "1m",
	})
	if status != http.StatusOK {
		t.Fatalf("empty query: status %d", status)
	}
	if len(m4cPoints(t, body)) != 0 || body["status"] != "no_data" {
		t.Fatalf("empty body: %v", body)
	}
	if _, hasLatest := body["latest"]; hasLatest {
		t.Fatalf("empty query must omit latest: %v", body)
	}

	// Unknown collector id ??? 404 (no existence oracle).
	other := "00000000-0000-7000-8000-000000000000"
	path := fmt.Sprintf("/v1/collectors/%s/metrics?metric=collector_cpu_percent&from=%s&to=%s", other,
		url.QueryEscape(m4cRFC3339(now.Add(-time.Hour))), url.QueryEscape(m4cRFC3339(now)))
	res := doRequest(t, f.client, http.MethodGet, f.srv.URL+path, "", nil)
	if res.Status != http.StatusNotFound || res.Body["code"] != "collector.not_found" {
		t.Fatalf("unknown collector: %d %v", res.Status, res.Body)
	}
	badID := "/v1/collectors/not-a-uuid/metrics?metric=collector_cpu_percent"
	res = doRequest(t, f.client, http.MethodGet, f.srv.URL+badID, "", nil)
	if res.Status != http.StatusNotFound {
		t.Fatalf("malformed id: %d", res.Status)
	}

	// Unspported metric key, malformed timestamps, bad step ??? 400.
	status, _ = f.query(t, map[string]string{
		"metric": "ifHCInOctets",
		"from":   m4cRFC3339(now.Add(-time.Hour)), "to": m4cRFC3339(now),
	})
	if status != http.StatusBadRequest {
		t.Fatalf("unsupported metric: %d", status)
	}
	status, _ = f.query(t, map[string]string{
		"metric": "collector_cpu_percent", "from": "yesterday", "to": m4cRFC3339(now),
	})
	if status != http.StatusBadRequest {
		t.Fatalf("malformed from: %d", status)
	}
	status, _ = f.query(t, map[string]string{
		"metric": "collector_cpu_percent", "from": m4cRFC3339(now.Add(-time.Hour)),
		"to": m4cRFC3339(now), "step": "1h",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("bad step: %d", status)
	}
}

func TestM4CQueryBoundsAndPointLimit(t *testing.T) {
	f := newM4CFixture(t, "m4c-bounds-"+newUUID()[:8])
	now := time.Now().UTC()

	// from >= to.
	status, _ := f.query(t, map[string]string{
		"metric": "collector_cpu_percent", "from": m4cRFC3339(now), "to": m4cRFC3339(now),
	})
	if status != http.StatusBadRequest {
		t.Fatalf("from==to: %d", status)
	}
	// Range wider than 24h.
	status, _ = f.query(t, map[string]string{
		"metric": "collector_cpu_percent", "from": m4cRFC3339(now.Add(-25 * time.Hour)), "to": m4cRFC3339(now),
	})
	if status != http.StatusBadRequest {
		t.Fatalf("25h range: %d", status)
	}
	// Future `to`.
	status, _ = f.query(t, map[string]string{
		"metric": "collector_cpu_percent", "from": m4cRFC3339(now), "to": m4cRFC3339(now.Add(time.Hour)),
	})
	if status != http.StatusBadRequest {
		t.Fatalf("future to: %d", status)
	}
	// 24h @ 10s exceeds the 2000-point cap ??? 422.
	status, body := f.query(t, map[string]string{
		"metric": "collector_cpu_percent", "from": m4cRFC3339(now.Add(-24 * time.Hour)),
		"to": m4cRFC3339(now), "step": "10s",
	})
	if status != http.StatusUnprocessableEntity || body["code"] != "query.points_exceeded" {
		t.Fatalf("24h@10s: %d %v", status, body)
	}
	// 24h @ 1m fits.
	status, _ = f.query(t, map[string]string{
		"metric": "collector_cpu_percent", "from": m4cRFC3339(now.Add(-24 * time.Hour)),
		"to": m4cRFC3339(now), "step": "1m",
	})
	if status != http.StatusOK {
		t.Fatalf("24h@1m: %d", status)
	}
}

func TestM4CQueryTenantIsolation(t *testing.T) {
	now := time.Now().UTC()
	base := now.Add(-10 * time.Minute).Truncate(time.Minute)

	fa := newM4CFixture(t, "m4c-iso-a-"+newUUID()[:8])
	fa.ingest(t, 1, []*collectorv1.MetricSample{
		m4Sample(42, map[string]string{"cpu": "total"}, base),
	})

	fb := newM4CFixture(t, "m4c-iso-b-"+newUUID()[:8])

	// B querying A's collector: 404, no data, no oracle.
	q := url.Values{}
	q.Set("metric", "collector_cpu_percent")
	q.Set("from", m4cRFC3339(base.Add(-time.Minute)))
	q.Set("to", m4cRFC3339(base.Add(time.Minute)))
	res := doRequest(t, fb.client, http.MethodGet,
		fb.srv.URL+fmt.Sprintf("/v1/collectors/%s/metrics?%s", fa.collectorID, q.Encode()), "", nil)
	if res.Status != http.StatusNotFound {
		t.Fatalf("cross-tenant query: status %d body %v", res.Status, res.Body)
	}

	// B's own collector exists but has no data: 200 empty (scoping, not denial).
	status, body := fb.query(t, map[string]string{
		"metric": "collector_cpu_percent",
		"from":   m4cRFC3339(base.Add(-time.Minute)),
		"to":     m4cRFC3339(base.Add(time.Minute)),
	})
	if status != http.StatusOK || body["status"] != "no_data" {
		t.Fatalf("own empty query: %d %v", status, body)
	}
}

func TestM4CQueryFreshnessSemantics(t *testing.T) {
	now := time.Now().UTC()

	// Stale: latest sample is 5 minutes old.
	stale := newM4CFixture(t, "m4c-stale-"+newUUID()[:8])
	oldTs := now.Add(-5 * time.Minute)
	stale.ingest(t, 1, []*collectorv1.MetricSample{m4Sample(11, map[string]string{"cpu": "total"}, oldTs)})
	status, body := stale.query(t, map[string]string{
		"metric": "collector_cpu_percent",
		"from":   m4cRFC3339(oldTs.Add(-time.Minute)),
		"to":     m4cRFC3339(now),
		"step":   "raw",
	})
	if status != http.StatusOK || body["status"] != "stale" {
		t.Fatalf("stale query: %d status=%v", status, body["status"])
	}
	latest := body["latest"].(map[string]any)
	if latest["status"] != "stale" || latest["age_seconds"].(float64) < 290 {
		t.Fatalf("stale latest: %v", latest)
	}

	// Fresh: latest sample is seconds old.
	fresh := newM4CFixture(t, "m4c-fresh-"+newUUID()[:8])
	freshTs := time.Now().UTC().Add(-2 * time.Second)
	fresh.ingest(t, 1, []*collectorv1.MetricSample{m4Sample(22, map[string]string{"cpu": "total"}, freshTs)})
	status, body = fresh.query(t, map[string]string{
		"metric": "collector_cpu_percent",
		"from":   m4cRFC3339(freshTs.Add(-time.Minute)),
		"to":     m4cRFC3339(time.Now().UTC()),
		"step":   "raw",
	})
	if status != http.StatusOK || body["status"] != "fresh" {
		t.Fatalf("fresh query: %d status=%v", status, body["status"])
	}
	latest = body["latest"].(map[string]any)
	if latest["status"] != "fresh" || latest["value"].(float64) != 22 {
		t.Fatalf("fresh latest: %v", latest)
	}
}

func TestM4CQueryCancellationAndDBUnavailable(t *testing.T) {
	ctx := context.Background()

	// Canceled context terminates the query promptly and safely.
	env, id, _, orgID := m4Env(t, "m4c-cancel-"+newUUID()[:8])
	_ = env
	svc := metrics.NewQueryService(appPool, nil, nil)
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	_, err := svc.QueryRange(cctx, metrics.RangeQuery{
		OrgID: mustUUID(t, orgID), CollectorID: mustUUID(t, id.CollectorID),
		MetricKey: "collector_cpu_percent",
		From:      time.Now().Add(-time.Minute), To: time.Now(),
		Step: metrics.StepRaw,
	})
	if err == nil {
		t.Fatal("canceled context must abort the query")
	}

	// Unreachable database: clean error, no panic, no partial result.
	badPool, err := pgxpool.New(ctx, "postgres://nobody:nopass@127.0.0.1:1/argus?sslmode=disable&connect_timeout=1")
	must(t, err)
	t.Cleanup(badPool.Close)
	badSvc := metrics.NewQueryService(badPool, nil, nil)
	_, err = badSvc.QueryRange(ctx, metrics.RangeQuery{
		OrgID: mustUUID(t, orgID), CollectorID: mustUUID(t, id.CollectorID),
		MetricKey: "collector_cpu_percent",
		From:      time.Now().Add(-time.Minute), To: time.Now(),
		Step: metrics.StepRaw,
	})
	if err == nil {
		t.Fatal("unreachable database must error")
	}
}

func TestM4CQueryCollectorTemporarilyDisconnected(t *testing.T) {
	f := newM4CFixture(t, "m4c-dc-"+newUUID()[:8])
	ts := time.Now().UTC().Add(-3 * time.Second)
	f.ingest(t, 1, []*collectorv1.MetricSample{m4Sample(33, map[string]string{"cpu": "total"}, ts)})

	f.env.stopStream() // collector transport drops; stored data must remain queryable

	status, body := f.query(t, map[string]string{
		"metric": "collector_cpu_percent",
		"from":   m4cRFC3339(ts.Add(-time.Minute)),
		"to":     m4cRFC3339(time.Now().UTC()),
		"step":   "raw",
	})
	if status != http.StatusOK {
		t.Fatalf("query while disconnected: %d", status)
	}
	if pts := m4cPoints(t, body); len(pts) != 1 || pts[0][1] != 33 {
		t.Fatalf("data lost while disconnected: %v", pts)
	}
}
