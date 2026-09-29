package collectors

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/argus-platform/argus/internal/platform/telemetry"
)

// metrics holds the collector-domain Prometheus instruments. They are always
// constructed (usable in tests); registration is best-effort when a registry
// is provided.
type metrics struct {
	enrollments   *prometheus.CounterVec
	streamsActive prometheus.Gauge
	connects      *prometheus.CounterVec
	heartbeats    prometheus.Counter
	policyAcks    *prometheus.CounterVec
	policyPushes  prometheus.Counter
}

func newMetrics(tel *telemetry.Registry) *metrics {
	m := &metrics{
		enrollments: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "argus", Subsystem: "collector", Name: "enrollments_total",
			Help: "Enrollment attempts by result.",
		}, []string{"result"}),
		streamsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "argus", Subsystem: "collector", Name: "streams_active",
			Help: "Currently connected collector streams.",
		}),
		connects: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "argus", Subsystem: "collector", Name: "stream_connects_total",
			Help: "Stream connection attempts by result.",
		}, []string{"result"}),
		heartbeats: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "argus", Subsystem: "collector", Name: "heartbeats_total",
			Help: "Heartbeats processed.",
		}),
		policyAcks: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "argus", Subsystem: "collector", Name: "policy_acks_total",
			Help: "Policy acknowledgements by applied flag.",
		}, []string{"result"}),
		policyPushes: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "argus", Subsystem: "collector", Name: "policy_pushes_total",
			Help: "Policy updates pushed to live streams.",
		}),
	}
	if tel != nil {
		tel.MustRegister(m.enrollments, m.streamsActive, m.connects, m.heartbeats, m.policyAcks, m.policyPushes)
	}
	return m
}
