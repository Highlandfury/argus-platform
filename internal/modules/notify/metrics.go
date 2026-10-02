package notify

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/argus-platform/argus/internal/platform/telemetry"
)

// Notification self-observability. Package-level instruments registered
// explicitly on the ops registry (nil-safe; same pattern as alerts).
var (
	notifyTransitions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "argus", Subsystem: "notify", Name: "transitions_total",
		Help: "Committed alert transitions consumed by the notification engine by event kind.",
	}, []string{"kind"})

	notifyAttempts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "argus", Subsystem: "notify", Name: "attempts_total",
		Help: "Notification delivery attempts by channel kind and result.",
	}, []string{"channel_kind", "result"})

	notifySuppressed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "argus", Subsystem: "notify", Name: "suppressed_total",
		Help: "Notifications suppressed before delivery by reason (dedup|throttle).",
	}, []string{"reason"})

	notifyBreaker = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "argus", Subsystem: "notify", Name: "breaker_total",
		Help: "Circuit-breaker state changes/denials (opened|denied).",
	}, []string{"event"})

	notifyDeadLetters = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "argus", Subsystem: "notify", Name: "dead_letters_total",
		Help: "Notifications that exhausted retries (or failed permanently) and dead-lettered.",
	})

	notifyWorkerRuns = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "argus", Subsystem: "notify", Name: "worker_runs_total",
		Help: "Retry-worker ProcessDue passes with at least one claim.",
	})

	notifyChannelFailureWatch = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "argus", Subsystem: "notify", Name: "channel_failure_watch_total",
		Help: "Channel observations above the canonical 5% failure rate over 15 min (ops alert wiring is M12).",
	})
)

// RegisterMetrics registers the notification instruments on the ops registry.
func RegisterMetrics(tel *telemetry.Registry) {
	if tel == nil {
		return
	}
	tel.MustRegister(notifyTransitions, notifyAttempts, notifySuppressed, notifyBreaker,
		notifyDeadLetters, notifyWorkerRuns, notifyChannelFailureWatch)
}
