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
)

// RegisterMetrics registers the evaluator instruments on the ops registry.
func RegisterMetrics(tel *telemetry.Registry) {
	if tel == nil {
		return
	}
	tel.MustRegister(alertsEvaluations, alertsTransitions, alertsStormSuppressed)
}
