package telemetry

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/argus-platform/argus/internal/collector/spool"
)

func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	m.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape status %d", rec.Code)
	}
	return rec.Body.String()
}

// metricValue returns the sample value for a canonical collector metric (no
// labels for these families).
func metricValue(t *testing.T, body, name string) float64 {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, name+" ") {
			v, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimPrefix(line, name+" ")), 64)
			if err != nil {
				t.Fatalf("parse %q: %v", line, err)
			}
			return v
		}
	}
	t.Fatalf("metric %s not found in scrape", name)
	return 0
}

func openTestSpool(t *testing.T) *spool.Spool {
	t.Helper()
	sp, err := spool.Open(spool.Options{Dir: filepath.Join(t.TempDir(), "spool"), MaxBytes: 1 << 20, FsyncInterval: 0})
	if err != nil {
		t.Fatalf("spool: %v", err)
	}
	t.Cleanup(func() { _ = sp.Close() })
	return sp
}

func appendBatch(t *testing.T, sp *spool.Spool, value float64) {
	t.Helper()
	_, err := sp.Append(&spool.Batch{
		At: time.Now().UTC(),
		Samples: []spool.Sample{{
			MetricKey: "collector_cpu_percent", Unit: "percent", Value: value,
			Ts: time.Now().UTC(), Dimensions: map[string]string{"cpu": "total"},
		}},
	})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
}

func TestCanonicalMetricSetCardinalityAndLabels(t *testing.T) {
	m := New(nil)
	m.SetStreamConnected(true)
	m.SetBackoff(4 * time.Second)
	m.SetClockSkew(-37)
	m.SetCPUPercent(27.5)
	m.ObserveSendDuration(120 * time.Millisecond)
	body := scrape(t, m)

	canonical := []string{
		"argus_collector_spool_bytes",
		"argus_collector_spool_records",
		"argus_collector_highest_seq",
		"argus_collector_acked_seq",
		"argus_collector_dropped_total",
		"argus_collector_corrupt_total",
		"argus_collector_stream_connected",
		"argus_collector_send_batch_duration_seconds",
		"argus_collector_backoff_seconds",
		"argus_collector_clock_skew_ms",
		"collector_cpu_percent",
	}
	for _, name := range canonical {
		if !strings.Contains(body, name) {
			t.Fatalf("canonical metric %s missing", name)
		}
	}
	if v := metricValue(t, body, "argus_collector_stream_connected"); v != 1 {
		t.Fatalf("stream_connected = %v", v)
	}
	if v := metricValue(t, body, "argus_collector_backoff_seconds"); v != 4 {
		t.Fatalf("backoff = %v", v)
	}
	if v := metricValue(t, body, "argus_collector_clock_skew_ms"); v != -37 {
		t.Fatalf("skew = %v", v)
	}
	if v := metricValue(t, body, "collector_cpu_percent"); v != 27.5 {
		t.Fatalf("cpu = %v", v)
	}
	if !strings.Contains(body, "argus_collector_send_batch_duration_seconds_count 1") {
		t.Fatal("send duration observation missing")
	}

	// Label safety / cardinality: every collector-owned family has no labels
	// (the histogram's le is its bucket boundary, expected). Nothing outside
	// the canonical set plus the standard go_/process_ collectors is exposed.
	allowed := map[string]bool{"le": true}
	var familyRE = regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})? `)
	seen := map[string]bool{}
	for _, line := range strings.Split(body, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		match := familyRE.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		name := match[1]
		base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(name, "_bucket"), "_sum"), "_count")
		seen[base] = true
		if strings.HasPrefix(base, "go_") || strings.HasPrefix(base, "process_") {
			// Standard runtime/process collectors keep their own (bounded)
			// labels such as quantile; they are allowed as-is.
			continue
		}
		ok := false
		for _, c := range canonical {
			if base == c {
				ok = true
				break
			}
		}
		if !ok {
			t.Fatalf("unexpected metric family %s (cardinality policy)", base)
		}
		if match[2] != "" && base != "argus_collector_send_batch_duration_seconds" {
			t.Fatalf("collector metric %s must be label-free, got {%s}", base, match[2])
		}
		for _, lp := range strings.Split(match[2], ",") {
			key := strings.TrimSpace(strings.SplitN(lp, "=", 2)[0])
			if key != "" && !allowed[key] {
				t.Fatalf("unexpected label %q on %s", key, base)
			}
		}
	}
	for _, c := range canonical {
		if !seen[c] && c != "argus_collector_send_batch_duration_seconds" {
			t.Fatalf("family %s not observed in scrape", c)
		}
	}

	// Backoff reset (reconnect success): the gauge returns to zero.
	m.SetStreamConnected(false)
	m.SetBackoff(0)
	body = scrape(t, m)
	if v := metricValue(t, body, "argus_collector_stream_connected"); v != 0 {
		t.Fatalf("stream_connected after loss = %v", v)
	}
	if v := metricValue(t, body, "argus_collector_backoff_seconds"); v != 0 {
		t.Fatalf("backoff after reset = %v", v)
	}
}

// TestSpoolSnapshotTransitions is the single-source-of-truth proof: the
// heartbeat snapshot and the scraped endpoint agree at every lifecycle stage
// (empty → new record → unsent → acked/retired).
func TestSpoolSnapshotTransitions(t *testing.T) {
	sp := openTestSpool(t)
	m := New(sp)

	assertAgreement := func(stage string) SpoolSnapshot {
		t.Helper()
		snap := m.SpoolSnapshot()
		body := scrape(t, m)
		if v := metricValue(t, body, "argus_collector_spool_bytes"); v != float64(snap.Bytes) {
			t.Fatalf("%s: bytes endpoint=%v snapshot=%v", stage, v, snap.Bytes)
		}
		if v := metricValue(t, body, "argus_collector_spool_records"); v != float64(snap.Records) {
			t.Fatalf("%s: records endpoint=%v snapshot=%v", stage, v, snap.Records)
		}
		if v := metricValue(t, body, "argus_collector_highest_seq"); v != float64(snap.HighestSeq) {
			t.Fatalf("%s: highest endpoint=%v snapshot=%v", stage, v, snap.HighestSeq)
		}
		if v := metricValue(t, body, "argus_collector_acked_seq"); v != float64(snap.AckedSeq) {
			t.Fatalf("%s: acked endpoint=%v snapshot=%v", stage, v, snap.AckedSeq)
		}
		// Cross-check against the spool itself (no second source of truth).
		direct := sp.Stats()
		if snap.Bytes != direct.Bytes || snap.Records != direct.Records ||
			snap.HighestSeq != direct.HighestSeq || snap.AckedSeq != direct.AckedSeq ||
			snap.DroppedTotal != direct.DroppedRecordsTotal || snap.CorruptTotal != direct.CorruptRecordsTotal {
			t.Fatalf("%s: snapshot diverges from spool.Stats: %+v vs %+v", stage, snap, direct)
		}
		return snap
	}

	if snap := assertAgreement("empty"); snap.Records != 0 || snap.HighestSeq != 0 {
		t.Fatalf("empty spool: %+v", snap)
	}
	appendBatch(t, sp, 10)
	appendBatch(t, sp, 20)
	if snap := assertAgreement("unsent"); snap.Records != 2 || snap.HighestSeq != 2 || snap.Bytes == 0 || snap.AckedSeq != 0 {
		t.Fatalf("unsent: %+v", snap)
	}
	if err := sp.Ack(1); err != nil {
		t.Fatalf("ack 1: %v", err)
	}
	if snap := assertAgreement("acked-1"); snap.Records != 1 || snap.AckedSeq != 1 {
		t.Fatalf("acked-1: %+v", snap)
	}
	if err := sp.Ack(2); err != nil {
		t.Fatalf("ack 2: %v", err)
	}
	if snap := assertAgreement("retired"); snap.Records != 0 || snap.AckedSeq != 2 {
		t.Fatalf("retired: %+v", snap)
	}
}

func TestLoopbackEnforcementAndServe(t *testing.T) {
	m := New(nil)
	if err := m.Start("0.0.0.0:0", nil); err == nil {
		t.Fatal("0.0.0.0 must be refused (loopback-only)")
	}
	if err := m.Start(":9091", nil); err == nil {
		t.Fatal("wildcard bind must be refused")
	}
	if err := m.Start("127.0.0.1:0", nil); err != nil {
		t.Fatalf("loopback bind: %v", err)
	}
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })
	if m.Addr() == "" {
		t.Fatal("no bound address")
	}
	res, err := http.Get("http://" + m.Addr() + "/metrics")
	if err != nil {
		t.Fatalf("scrape: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
}

func TestStartFailureDoesNotPanicAndIsReturned(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	m := New(nil)
	if err := m.Start(ln.Addr().String(), nil); err == nil {
		t.Fatal("expected bind failure on an occupied port")
	}
	// A failed endpoint must leave the process healthy: another Start on a
	// fresh port still works.
	if err := m.Start("127.0.0.1:0", nil); err != nil {
		t.Fatalf("restart after failure: %v", err)
	}
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })
}
