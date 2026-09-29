package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/argus-platform/argus/internal/platform/telemetry"
)

func testOptions(checks ...Check) Options {
	return Options{
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Telemetry: telemetry.New("test", "0.0.1", "abc"),
		Version:   "0.0.1",
		Commit:    "abc",
		Readiness: checks,
	}
}

func TestHealthz(t *testing.T) {
	router := NewRouter(testOptions())
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "ok" || body["version"] != "0.0.1" {
		t.Fatalf("unexpected body: %v", body)
	}
	if rec.Header().Get("X-Request-ID") == "" {
		t.Fatal("missing X-Request-ID header")
	}
}

func TestReadyzPassesWithoutChecks(t *testing.T) {
	router := NewRouter(testOptions())
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestReadyzFailsWhenCheckFails(t *testing.T) {
	router := NewRouter(testOptions(Check{
		Name: "database",
		Fn:   func(context.Context) error { return errors.New("connection refused") },
	}))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "connection refused") {
		t.Fatalf("body should surface the failing check: %s", rec.Body.String())
	}
}

func TestOpsRouterServesMetrics(t *testing.T) {
	router := NewOpsRouter(testOptions())
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "argus_build_info") {
		t.Fatal("metrics body missing argus_build_info")
	}
}
