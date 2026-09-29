package ingest

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/argus-platform/argus/internal/platform/telemetry"
)

// metricsSet holds ingest pipeline Prometheus instruments (SPEC §15 names).
type metricsSet struct {
	batches       *prometheus.CounterVec
	samples       *prometheus.CounterVec
	batchDuration prometheus.Histogram
	dbDuration    *prometheus.HistogramVec
}

func newMetricsSet(tel *telemetry.Registry) *metricsSet {
	m := &metricsSet{
		batches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "argus", Subsystem: "ingest", Name: "batches_total",
			Help: "Ingested batches by terminal status.",
		}, []string{"status"}),
		samples: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "argus", Subsystem: "ingest", Name: "samples_total",
			Help: "Samples by result (accepted, dropped).",
		}, []string{"result"}),
		batchDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "argus", Subsystem: "ingest", Name: "batch_duration_seconds",
			Help:    "End-to-end batch pipeline duration (validate+commit).",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5},
		}),
		dbDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "argus", Subsystem: "db", Name: "query_duration_seconds",
			Help:    "Database operation duration by op.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5},
		}, []string{"op"}),
	}
	if tel != nil {
		tel.MustRegister(m.batches, m.samples, m.batchDuration, m.dbDuration)
	}
	return m
}
