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
	malformed     prometheus.Counter
	connects      *prometheus.CounterVec
	heartbeats    prometheus.Counter
	policyAcks    *prometheus.CounterVec
	policyPushes  prometheus.Counter
	checkPushes   prometheus.Counter
	checkResults  *prometheus.CounterVec
	checkApplied  prometheus.Counter
}

func newMetrics(tel *telemetry.Registry) *metrics {
	m := &metrics{
		enrollments: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "argus", Name: "enroll_attempts_total",
			Help: "Enrollment attempts by result (SPEC §15; extra values beyond ok|invalid|expired|used|rate_limited are documented extensions).",
		}, []string{"result"}),
		streamsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "argus", Name: "grpc_streams_active",
			Help: "Currently connected collector streams.",
		}),
		malformed: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "argus", Name: "grpc_malformed_total",
			Help: "Streams terminated by malformed/oversized protobuf or unexpected transport errors.",
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
		checkPushes: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "argus", Subsystem: "collector", Name: "check_requests_pushed_total",
			Help: "On-demand check orders pushed to live streams (M10-S0).",
		}),
		checkResults: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "argus", Subsystem: "collector", Name: "check_results_total",
			Help: "On-demand check results received by outcome (M10-S0).",
		}, []string{"outcome"}),
		checkApplied: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "argus", Subsystem: "collector", Name: "check_results_applied_total",
			Help: "On-demand check results that transitioned a pending check (M10-S0; replays are excluded).",
		}),
	}
	if tel != nil {
		tel.MustRegister(m.enrollments, m.streamsActive, m.malformed, m.connects, m.heartbeats,
			m.policyAcks, m.policyPushes, m.checkPushes, m.checkResults, m.checkApplied)
	}
	return m
}
