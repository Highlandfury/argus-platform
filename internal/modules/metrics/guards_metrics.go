package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/argus-platform/argus/internal/platform/telemetry"
)

// Cardinality guard instruments (P2-AC-11). Package-level like
// seriesCreated: the guards run on hot paths and unit tests exercise them
// without a registry (nil-safe).
var (
	// cardinalityExceeded counts metric.cardinality.exceeded events by scope
	// (device|site|rate|operator).
	cardinalityExceeded = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "argus", Subsystem: "metrics", Name: "cardinality_exceeded_total",
		Help: "Metric series quarantine events by scope (metric.cardinality.exceeded).",
	}, []string{"scope"})

	// seriesRetired counts series tombstoned by the retirement job.
	seriesRetired = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "argus", Subsystem: "metrics", Name: "series_retired_total",
		Help: "Metric series retired after inactivity (tombstoned, history kept).",
	})
)

// RegisterGuardMetrics registers the cardinality guard instruments on the ops
// registry.
func RegisterGuardMetrics(tel *telemetry.Registry) {
	if tel != nil {
		tel.MustRegister(cardinalityExceeded, seriesRetired)
	}
}
