package alerts

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/argus-platform/argus/internal/platform/telemetry"
)

// Evaluator self-observability (PHASE_2_SPEC cross-cutting §5.5). The
// instruments are package-level and registered explicitly on the ops registry
// (nil-safe; the same pattern as the metrics module).
var (
	alertsEvaluations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "argus", Subsystem: "alerts", Name: "evaluations_total",
		Help: "Alert rule evaluations by result (ok|error).",
	}, []string{"result"})

	alertsTransitions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "argus", Subsystem: "alerts", Name: "transitions_total",
		Help: "Alert state transitions by target state.",
	}, []string{"to"})

	alertsStormSuppressed = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "argus", Subsystem: "alerts", Name: "storm_suppressed_total",
		Help: "New alerts created Suppressed(storm) by the per-device burst limiter.",
	})

	// M11-S3a: alerts entering Suppressed(maintenance|silence).
	alertsSuppressionTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "argus", Subsystem: "alerts", Name: "suppressed_total",
		Help: "Alert suppression entries by reason (maintenance|silence).",
	}, []string{"reason"})

	// M11-S3a SSE alert stream: live connection gauge and the drop policy
	// counter. Drops are recoverable: a client resumes with Last-Event-ID and
	// replays from the retained buffer or PostgreSQL (docs/12 §22.16).
	alertsStreamClients = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "argus", Subsystem: "alerts", Name: "stream_clients",
		Help: "Currently connected /v1/streams/events SSE clients.",
	})

	alertsStreamDropped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "argus", Subsystem: "alerts", Name: "stream_dropped_total",
		Help: "SSE events dropped by reason (buffer_full|write_error).",
	}, []string{"reason"})

	alertsStreamEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "argus", Subsystem: "alerts", Name: "stream_events_total",
		Help: "SSE alert events delivered by canonical event name.",
	}, []string{"event"})

	// M11-S3c: samples-absence alerts auto-resolved by the canonical 24 h
	// no-data max lifetime policy (docs/10 §17.5, P2-AC-28).
	alertsNoDataResolved = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "argus", Subsystem: "alerts", Name: "no_data_auto_resolved_total",
		Help: "Samples-absence alerts auto-resolved after 24 h without data (unknown state).",
	})
)

// RegisterMetrics registers the evaluator instruments on the ops registry.
func RegisterMetrics(tel *telemetry.Registry) {
	if tel == nil {
		return
	}
	tel.MustRegister(
		alertsEvaluations, alertsTransitions, alertsStormSuppressed,
		alertsSuppressionTotal,
		alertsStreamClients, alertsStreamDropped, alertsStreamEvents,
		alertsNoDataResolved,
	)
}
