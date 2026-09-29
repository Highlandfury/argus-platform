package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/argus-platform/argus/internal/platform/telemetry"
)

// seriesCreated counts newly created series rows
// (argus_ingest_series_created_total, SPEC §15). It is package-level because
// EnsureSeries is a hot path on the shared Store implementation; registration
// on the ops registry is explicit (nil-safe).
var seriesCreated = prometheus.NewCounter(prometheus.CounterOpts{
	Namespace: "argus", Subsystem: "ingest", Name: "series_created_total",
	Help: "Metric series rows created (cardinality growth indicator).",
})

// RegisterSeriesMetrics registers the series counter on the ops registry.
func RegisterSeriesMetrics(tel *telemetry.Registry) {
	if tel != nil {
		tel.MustRegister(seriesCreated)
	}
}
