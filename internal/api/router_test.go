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

func TestProtectedRoutesFailClosedWithoutServices(t *testing.T) {
	// Without configured services the middleware fails closed (503) rather
	// than allowing access; the real 401/403 paths are integration-tested.
	router := NewRouter(testOptions())
	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodGet, "/v1/me"},
		{http.MethodGet, "/v1/sites"},
		{http.MethodPost, "/v1/auth/logout"},
	} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s %s: status %d, want 503 (fail closed)", tc.method, tc.path, rec.Code)
		}
	}
}

func TestLoginWithoutServiceReturns503(t *testing.T) {
	router := NewRouter(testOptions())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login",
		strings.NewReader(`{"org_slug":"dev","email":"a@b.c","password":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "service.unavailable") {
		t.Fatalf("unexpected problem body: %s", rec.Body.String())
	}
}

func TestRouteRegistryShape(t *testing.T) {
	routes := Routes()
	if len(routes) == 0 {
		t.Fatal("route registry is empty")
	}
	seen := map[string]bool{}
	for _, rt := range routes {
		key := rt.Method + " " + rt.Path
		if seen[key] {
			t.Fatalf("duplicate route registration: %s", key)
		}
		seen[key] = true
		if rt.CSRF && !rt.Protected {
			t.Fatalf("CSRF route must be protected: %s", key)
		}
	}
	if routes[0].Method != "POST" || routes[0].Path != "/v1/auth/login" {
		t.Fatalf("unexpected first route: %+v", routes[0])
	}
}
