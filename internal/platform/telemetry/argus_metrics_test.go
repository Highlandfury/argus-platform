package telemetry

import (
	"net/http"
	"net/http/httptest"
	"testing"

	dto "github.com/prometheus/client_model/go"
)

func familyNames(t *testing.T, reg *Registry) map[string]*dto.MetricFamily {
	t.Helper()
	fams, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	out := map[string]*dto.MetricFamily{}
	for _, f := range fams {
		out[f.GetName()] = f
	}
	return out
}

func TestArgusInstrumentsRegistered(t *testing.T) {
	reg := New("test", "0", "0")
	a := NewArgus(reg)
	// Vector instruments only export once they have children; touch one of each
	// to assert registration/exposition shape.
	a.DBQueryDuration.WithLabelValues("query").Observe(0.001)
	a.HTTPRequestsTotal.WithLabelValues("/x", "GET", "2xx").Inc()
	a.HTTPRequestDuration.WithLabelValues("/x", "GET", "2xx").Observe(0.001)
	fams := familyNames(t, reg)
	for _, name := range []string{
		"argus_db_query_duration_seconds",
		"argus_http_request_duration_seconds",
		"argus_http_requests_total",
	} {
		if fams[name] == nil {
			t.Fatalf("metric %s not registered", name)
		}
	}
}

func TestCollectorGaugesRegistered(t *testing.T) {
	reg := New("test", "0", "0")
	g := NewCollectorGauges(nil, nil, reg)
	g.heartbeatAge.WithLabelValues("test-collector").Set(1)
	fams := familyNames(t, reg)
	for _, name := range []string{
		"argus_collectors",
		"argus_collector_last_heartbeat_age_seconds",
	} {
		if fams[name] == nil {
			t.Fatalf("metric %s not registered", name)
		}
	}
}

// TestHTTPMiddlewareBoundedRoute is the cardinality guarantee: the route label
// is the matched pattern, never the raw request path (no ID/tenant leakage).
func TestHTTPMiddlewareBoundedRoute(t *testing.T) {
	reg := New("test", "0", "0")
	argus := NewArgus(reg)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/collectors/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	handler := argus.HTTPMiddleware(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/collectors/01a0ee0d-ce03-78af-aa2c-dab4f5da97b4", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rr.Code)
	}

	fams := familyNames(t, reg)
	counters := fams["argus_http_requests_total"]
	if counters == nil {
		t.Fatal("http_requests_total missing")
	}
	var found bool
	for _, m := range counters.GetMetric() {
		labels := map[string]string{}
		for _, lp := range m.GetLabel() {
			labels[lp.GetName()] = lp.GetValue()
		}
		if labels["route"] == "/v1/collectors/{id}" {
			found = true
			if labels["method"] != "GET" || labels["status_class"] != "4xx" {
				t.Fatalf("labels = %v", labels)
			}
			if labels["route"] == req.URL.Path {
				t.Fatal("raw path leaked into the route label")
			}
		}
		if labels["route"] == req.URL.Path {
			t.Fatal("raw path leaked into a route label")
		}
	}
	if !found {
		t.Fatalf("expected the pattern route label; got %v", counters.GetMetric())
	}
}
