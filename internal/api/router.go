// Package api wires HTTP routes for the public API and the ops surface.
//
// M0 scope: /v1/healthz and /v1/readyz on both surfaces, plus /metrics on the ops
// surface. Module routes (auth, collectors, metrics) are added in M2/M3/M4.
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/argus-platform/argus/internal/platform/httpx"
	"github.com/argus-platform/argus/internal/platform/telemetry"
)

// Check is one readiness probe. Readiness returns 503 while any check fails.
type Check struct {
	Name string
	Fn   func(ctx context.Context) error
}

// Options configures the routers.
type Options struct {
	Logger    *slog.Logger
	Telemetry *telemetry.Registry
	Version   string
	Commit    string
	Readiness []Check
}

type handlers struct{ o Options }

// NewRouter returns the public API router.
func NewRouter(o Options) http.Handler {
	h := handlers{o: o}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/healthz", h.health)
	mux.HandleFunc("GET /v1/readyz", h.ready)
	return httpx.RequestID(httpx.AccessLog(o.Logger, mux))
}

// NewOpsRouter returns the ops router (metrics + health). It is intended for a
// private listener (loopback/network-policy only).
func NewOpsRouter(o Options) http.Handler {
	h := handlers{o: o}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.health)
	mux.HandleFunc("GET /readyz", h.ready)
	mux.Handle("GET /metrics", o.Telemetry.Handler())
	return httpx.RequestID(httpx.AccessLog(o.Logger, mux))
}

func (h handlers) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"version": h.o.Version,
		"commit":  h.o.Commit,
	})
}

func (h handlers) ready(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{}
	failed := false
	for _, c := range h.o.Readiness {
		if err := c.Fn(r.Context()); err != nil {
			checks[c.Name] = err.Error()
			failed = true
		} else {
			checks[c.Name] = "ok"
		}
	}
	status := http.StatusOK
	state := "ok"
	if failed {
		status = http.StatusServiceUnavailable
		state = "unavailable"
	}
	writeJSON(w, status, map[string]any{
		"status":  state,
		"version": h.o.Version,
		"commit":  h.o.Commit,
		"checks":  checks,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
