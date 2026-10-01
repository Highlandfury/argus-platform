package ingest

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/argus-platform/argus/internal/platform/telemetry"
)

// metricsSet holds the ingest-pipeline instruments owned by this module
// (SPEC §15). The shared DB histogram lives in telemetry.Argus.
type metricsSet struct {
	batches       *prometheus.CounterVec
	samples       *prometheus.CounterVec
	health        *prometheus.CounterVec
	batchDuration prometheus.Histogram
}

func newMetricsSet(tel *telemetry.Registry) *metricsSet {
	m := &metricsSet{
		batches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "argus", Subsystem: "ingest", Name: "batches_total",
			Help: "Ingested batches by terminal status.",
		}, []string{"status"}),
		samples: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "argus", Subsystem: "ingest", Name: "samples_total",
			Help: "Samples by status (SPEC §15).",
		}, []string{"status"}),
		health: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "argus", Subsystem: "ingest", Name: "poll_health_total",
			Help: "Poll-health records persisted by status (M9-S1).",
		}, []string{"status"}),
		batchDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "argus", Subsystem: "ingest", Name: "batch_duration_seconds",
			Help:    "End-to-end batch pipeline duration (validate+commit).",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5},
		}),
	}
	if tel != nil {
		tel.MustRegister(m.batches, m.samples, m.health, m.batchDuration)
	}
	return m
}
