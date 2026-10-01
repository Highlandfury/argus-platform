package metrics

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/platform/authz"
)

func TestSeriesIDCodecRoundTrip(t *testing.T) {
	for _, id := range []int64{1, 42, 1000, 1 << 40, 1<<62 + 7} {
		encoded := EncodeSeriesID(id)
		if encoded[0:2] != "s_" {
			t.Fatalf("EncodeSeriesID(%d) = %q, want s_ prefix", id, encoded)
		}
		got, err := ParseSeriesID(encoded)
		if err != nil {
			t.Fatalf("ParseSeriesID(%q): %v", encoded, err)
		}
		if got != id {
			t.Fatalf("round trip %d -> %q -> %d", id, encoded, got)
		}
	}
	for _, bad := range []string{"", "s_", "42", "s_!", "s_-1", "s_zzzzzzzzzzzzzzzzzzzzzzzz", "x_1"} {
		if _, err := ParseSeriesID(bad); !errors.Is(err, ErrInvalidSeriesID) {
			t.Errorf("ParseSeriesID(%q) err = %v, want ErrInvalidSeriesID", bad, err)
		}
	}
}

func TestParseAggregationAndFill(t *testing.T) {
	for raw, want := range map[string]Aggregation{"": AggAvg, "avg": AggAvg, "max": AggMax, "p95": AggP95, "rate": AggRate, "sum": AggSum} {
		got, err := ParseAggregation(raw)
		if err != nil || got != want {
			t.Errorf("ParseAggregation(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	if _, err := ParseAggregation("median"); !errors.Is(err, ErrAggUnsupported) {
		t.Fatalf("unknown agg err = %v, want ErrAggUnsupported", err)
	}
	for raw, want := range map[string]FillMode{"": FillNull, "null": FillNull, "zero": FillZero, "previous": FillPrevious} {
		got, err := ParseFill(raw)
		if err != nil || got != want {
			t.Errorf("ParseFill(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	if _, err := ParseFill("interpolate"); !errors.Is(err, ErrQueryInvalid) {
		t.Fatalf("unknown fill err = %v, want ErrQueryInvalid", err)
	}
}

func TestParseStepAcceptsCanonical30s(t *testing.T) {
	step, err := ParseStep("30s")
	if err != nil || step != Step30s || step.Interval() != 30*time.Second {
		t.Fatalf("ParseStep(30s) = %q, %v", step, err)
	}
	if ResolutionName(Step30s) != "raw" {
		t.Fatalf("ResolutionName(30s) = %q, want raw (computed from raw samples)", ResolutionName(Step30s))
	}
	// An explicit 30s step is finer than the picker's 1m for a short range:
	// the warning is the canonical "user override with warning".
	if got := resolutionWarning(Step30s, Step1m); got == "" {
		t.Fatal("resolutionWarning(30s, 1m) is empty, want an override warning")
	}
}

func TestDensifyBucketsFillModes(t *testing.T) {
	from := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	to := from.Add(3 * time.Minute)
	observed := map[time.Time]float64{from.Add(time.Minute): 5}

	points, gaps, truncated := densifyBuckets(from, to, time.Minute, observed, FillNull, MaxPoints)
	if len(points) != 4 || gaps != 3 || truncated {
		t.Fatalf("null fill: len=%d gaps=%d truncated=%v", len(points), gaps, truncated)
	}
	if points[0].Value != nil || points[1].Value == nil || *points[1].Value != 5 || points[2].Value != nil || points[3].Value != nil {
		t.Fatalf("null fill values wrong: %+v", points)
	}

	points, _, _ = densifyBuckets(from, to, time.Minute, observed, FillZero, MaxPoints)
	for i, want := range []float64{0, 5, 0, 0} {
		if points[i].Value == nil || *points[i].Value != want {
			t.Fatalf("zero fill point %d = %v, want %v", i, points[i].Value, want)
		}
	}

	points, _, _ = densifyBuckets(from, to, time.Minute, observed, FillPrevious, MaxPoints)
	if points[0].Value != nil {
		t.Fatalf("previous fill leading gap = %v, want null", *points[0].Value)
	}
	for i := 1; i < 4; i++ {
		if points[i].Value == nil || *points[i].Value != 5 {
			t.Fatalf("previous fill point %d = %v, want 5", i, points[i].Value)
		}
	}
}

func TestDensifyBucketsTruncatesNewest(t *testing.T) {
	from := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	to := from.Add(4 * time.Minute)
	observed := map[time.Time]float64{
		from.Add(1 * time.Minute): 1,
		from.Add(3 * time.Minute): 3,
	}
	points, gaps, truncated := densifyBuckets(from, to, time.Minute, observed, FillNull, 3)
	if !truncated {
		t.Fatal("expected truncation")
	}
	if len(points) != 3 {
		t.Fatalf("len = %d, want 3", len(points))
	}
	if !points[0].Ts.Equal(from.Add(2*time.Minute)) || !points[2].Ts.Equal(from.Add(4*time.Minute)) {
		t.Fatalf("kept window %v..%v, want newest 3 buckets", points[0].Ts, points[2].Ts)
	}
	// Gaps are counted inside the returned window only (10:02 missing, 10:04
	// missing; 10:03 observed).
	if gaps != 2 {
		t.Fatalf("gaps = %d, want 2", gaps)
	}
}

func TestQueryMatrixValidationBeforeDB(t *testing.T) {
	svc := &QueryService{} // validation happens before any pool use
	now := time.Now().UTC()
	base := MatrixQuery{
		OrgID:     uuid.New(),
		Selectors: []Selector{{DeviceID: uuid.New(), MetricKey: "net.icmp.rtt_ms"}},
		From:      now.Add(-time.Hour),
		To:        now,
	}
	if _, err := svc.QueryMatrix(t.Context(), MatrixQuery{From: base.From, To: base.To}); !errors.Is(err, ErrQueryInvalid) {
		t.Errorf("empty series err = %v, want ErrQueryInvalid", err)
	}
	bad := base
	bad.From, bad.To = now, now
	if _, err := svc.QueryMatrix(t.Context(), bad); !errors.Is(err, ErrRangeInvalid) {
		t.Errorf("from==to err = %v, want ErrRangeInvalid", err)
	}
	bad = base
	bad.From = now.Add(-4 * 365 * 24 * time.Hour)
	if _, err := svc.QueryMatrix(t.Context(), bad); !errors.Is(err, ErrRangeInvalid) {
		t.Errorf("4y range err = %v, want ErrRangeInvalid", err)
	}
	bad = base
	bad.To = now.Add(time.Hour)
	if _, err := svc.QueryMatrix(t.Context(), bad); !errors.Is(err, ErrRangeInvalid) {
		t.Errorf("future to err = %v, want ErrRangeInvalid", err)
	}
	bad = base
	bad.Agg = "median"
	if _, err := svc.QueryMatrix(t.Context(), bad); !errors.Is(err, ErrAggUnsupported) {
		t.Errorf("bad agg err = %v, want ErrAggUnsupported", err)
	}
	bad = base
	bad.Fill = "interpolate"
	if _, err := svc.QueryMatrix(t.Context(), bad); !errors.Is(err, ErrQueryInvalid) {
		t.Errorf("bad fill err = %v, want ErrQueryInvalid", err)
	}
	bad = base
	bad.Step, bad.Agg = StepRaw, AggP95
	if _, err := svc.QueryMatrix(t.Context(), bad); !errors.Is(err, ErrQueryInvalid) {
		t.Errorf("raw+p95 err = %v, want ErrQueryInvalid", err)
	}
	// A pathological explicit scan is refused loudly before touching the DB.
	bad = base
	bad.Step = Step10s
	bad.From = now.Add(-200 * 24 * time.Hour)
	if _, err := svc.QueryMatrix(t.Context(), bad); !errors.Is(err, ErrPointsExceeded) {
		t.Errorf("hard budget err = %v, want ErrPointsExceeded", err)
	}
}

func TestMatrixCacheScopeAndOrgIsolation(t *testing.T) {
	org := uuid.New()
	siteA, siteB := uuid.New(), uuid.New()
	q := MatrixQuery{From: time.Unix(1000, 0), To: time.Unix(2000, 0), Step: Step1m, Agg: AggAvg, Fill: FillNull}

	k1 := matrixCacheKey(org, authz.Scope{Unrestricted: true}, q)
	k2 := matrixCacheKey(uuid.New(), authz.Scope{Unrestricted: true}, q)
	k3 := matrixCacheKey(org, authz.Scope{Sites: []uuid.UUID{siteA}}, q)
	k4 := matrixCacheKey(org, authz.Scope{Sites: []uuid.UUID{siteB}}, q)
	if k1 == k2 {
		t.Error("cache keys must differ by org")
	}
	if k1 == k3 || k3 == k4 {
		t.Error("cache keys must differ by scope")
	}
	// Ordering of series ids must not matter.
	qA := q
	qA.SeriesIDs = []int64{7, 3}
	qB := q
	qB.SeriesIDs = []int64{3, 7}
	if matrixCacheKey(org, authz.Scope{Unrestricted: true}, qA) != matrixCacheKey(org, authz.Scope{Unrestricted: true}, qB) {
		t.Error("cache keys must be order-insensitive for ids")
	}
	if !etagMatches(`W/"abc", "def"`, `"def"`) || etagMatches(`"abc"`, `"def"`) || !etagMatches("*", `"x"`) {
		t.Error("etagMatches semantics wrong")
	}
}

func TestMatrixCacheExpiryAndEviction(t *testing.T) {
	c := NewMatrixCache(20*time.Millisecond, 2)
	c.Put("a", []byte("A"), `"a"`)
	if body, etag, ok := c.Get("a"); !ok || string(body) != "A" || etag != `"a"` {
		t.Fatalf("cache hit = %q %q %v", body, etag, ok)
	}
	c.Put("b", []byte("B"), `"b"`)
	c.Put("c", []byte("C"), `"c"`) // evicts a
	if _, _, ok := c.Get("a"); ok {
		t.Fatal("oldest entry not evicted")
	}
	if _, _, ok := c.Get("c"); !ok {
		t.Fatal("newest entry missing")
	}
	time.Sleep(30 * time.Millisecond)
	if _, _, ok := c.Get("c"); ok {
		t.Fatal("expired entry still cached")
	}
	var nilCache *MatrixCache
	if _, _, ok := nilCache.Get("x"); ok {
		t.Fatal("nil cache must miss")
	}
	nilCache.Put("x", nil, "")
}
