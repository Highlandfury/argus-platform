package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/argus-platform/argus/internal/platform/database"
)

// Argus bundles the platform-wide instruments from SPEC §15. A single
// registration per metric name is mandatory (Prometheus panics on duplicates),
// so modules share these instruments instead of creating their own.
type Argus struct {
	// Reg is the underlying registry (nil in unit contexts); module-local
	// instruments register through it.
	Reg *Registry
	// DBQueryDuration is shared by every database operation:
	// op ∈ claim|series|samples|query (SPEC §15).
	DBQueryDuration *prometheus.HistogramVec
	// HTTPRequestDuration / HTTPRequestsTotal are recorded by HTTPMiddleware
	// with bounded labels: route (matched ServeMux pattern), method, status
	// class. Raw paths never become label values.
	HTTPRequestDuration *prometheus.HistogramVec
	HTTPRequestsTotal   *prometheus.CounterVec
}

// NewArgus constructs and registers the platform instruments. tel may be nil
// (unit contexts): instruments still work, they are just not exported.
func NewArgus(tel *Registry) *Argus {
	a := &Argus{
		Reg: tel,
		DBQueryDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "argus", Name: "db_query_duration_seconds",
			Help:    "Database operation duration by op.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5},
		}, []string{"op"}),
		HTTPRequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "argus", Name: "http_request_duration_seconds",
			Help:    "HTTP request duration by matched route, method and status class.",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5},
		}, []string{"route", "method", "status_class"}),
		HTTPRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "argus", Name: "http_requests_total",
			Help: "HTTP requests by matched route, method and status class.",
		}, []string{"route", "method", "status_class"}),
	}
	if tel != nil {
		tel.MustRegister(a.DBQueryDuration, a.HTTPRequestDuration, a.HTTPRequestsTotal)
	}
	return a
}

// HTTPMiddleware records §15 HTTP metrics. The route label is the matched
// ServeMux pattern (r.Pattern, with the method prefix stripped — method is its
// own label) — never the raw path — which bounds cardinality.
func (a *Argus) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		route := r.Pattern
		if i := strings.IndexByte(route, ' '); i >= 0 {
			route = route[i+1:]
		}
		if route == "" {
			route = "unmatched"
		}
		class := fmt.Sprintf("%dxx", sw.status/100)
		a.HTTPRequestsTotal.WithLabelValues(route, r.Method, class).Inc()
		a.HTTPRequestDuration.WithLabelValues(route, r.Method, class).Observe(time.Since(start).Seconds())
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// CollectorGauges refreshes the DB-derived collector gauges (SPEC §15,
// 30 s cadence):
//
//	argus_collectors{status="pending|active|stale|revoked"}
//	argus_collector_last_heartbeat_age_seconds{collector_id}
//
// "stale" is computed with the same rule the API uses (active + last heartbeat
// older than 3 × the 30 s policy heartbeat), so a stale collector is never
// reported as healthy merely because telemetry exists. Org iteration uses the
// auth role for the org list and tenant-scoped queries on the app pool: no
// owner DSN at runtime, no cross-tenant leakage.
type CollectorGauges struct {
	app, auth    *pgxpool.Pool
	collectors   *prometheus.GaugeVec
	heartbeatAge *prometheus.GaugeVec
}

// NewCollectorGauges constructs (and registers, when tel != nil) the gauges.
func NewCollectorGauges(app, auth *pgxpool.Pool, tel *Registry) *CollectorGauges {
	g := &CollectorGauges{
		app:  app,
		auth: auth,
		collectors: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "argus", Name: "collectors",
			Help: "Collectors by effective status (stale computed from heartbeat age).",
		}, []string{"status"}),
		heartbeatAge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "argus", Name: "collector_last_heartbeat_age_seconds",
			Help: "Seconds since the collector's last heartbeat (Phase-1 cardinality <= 500).",
		}, []string{"collector_id"}),
	}
	if tel != nil {
		tel.MustRegister(g.collectors, g.heartbeatAge)
	}
	for _, status := range []string{"pending", "active", "stale", "revoked"} {
		g.collectors.WithLabelValues(status).Set(0)
	}
	return g
}

// Refresh updates the gauges once.
func (g *CollectorGauges) Refresh(ctx context.Context) error {
	if g.app == nil || g.auth == nil {
		return nil
	}
	counts := map[string]float64{}
	g.heartbeatAge.Reset()

	var orgIDs []uuid.UUID
	err := database.WithAuthTx(ctx, g.auth, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM organizations`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			orgIDs = append(orgIDs, id)
		}
		return rows.Err()
	})
	if err != nil {
		return fmt.Errorf("telemetry: list orgs for gauges: %w", err)
	}

	now := time.Now()
	for _, orgID := range orgIDs {
		err := database.WithTenant(ctx, g.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `
				SELECT CASE
				         WHEN status = 'active' AND (last_heartbeat_at IS NULL
				              OR last_heartbeat_at < now() - interval '90 seconds') THEN 'stale'
				         ELSE status
				       END AS effective, count(*)
				FROM collectors
				GROUP BY effective`)
			if err != nil {
				return err
			}
			for rows.Next() {
				var (
					status string
					n      int64
				)
				if err := rows.Scan(&status, &n); err != nil {
					rows.Close()
					return err
				}
				counts[status] += float64(n)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}

			ages, err := tx.Query(ctx, `
				SELECT id, last_heartbeat_at FROM collectors
				WHERE last_heartbeat_at IS NOT NULL`)
			if err != nil {
				return err
			}
			for ages.Next() {
				var (
					id uuid.UUID
					hb time.Time
				)
				if err := ages.Scan(&id, &hb); err != nil {
					ages.Close()
					return err
				}
				g.heartbeatAge.WithLabelValues(id.String()).Set(now.Sub(hb).Seconds())
			}
			err = ages.Err()
			ages.Close()
			return err
		})
		if err != nil {
			return err
		}
	}
	for _, status := range []string{"pending", "active", "stale", "revoked"} {
		g.collectors.WithLabelValues(status).Set(counts[status])
	}
	return nil
}

// Run refreshes immediately and then every interval until ctx is done.
// Refresh failures are logged (never silent) and the loop continues.
func (g *CollectorGauges) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	refresh := func() {
		if err := g.Refresh(ctx); err != nil && ctx.Err() == nil {
			slog.Default().Warn("collector gauges refresh failed", "component", "telemetry", "error", err)
		}
	}
	refresh()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refresh()
		}
	}
}
