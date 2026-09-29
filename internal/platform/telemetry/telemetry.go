// Package telemetry owns the Prometheus registry and the /metrics handler for
// every binary (see docs/phase-1/PHASE_1_SPEC.md §15).
package telemetry

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
)

// Registry wraps a private Prometheus registry (never the global default, so
// tests are isolated and registration is explicit).
type Registry struct {
	reg *prometheus.Registry
}

// New creates a registry with Go/process collectors and an argus_build_info
// gauge carrying component, version and commit.
func New(component, version, commit string) *Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "argus",
		Name:      "build_info",
		Help:      "Build metadata; the value is always 1.",
	}, []string{"component", "version", "commit"})
	buildInfo.WithLabelValues(component, version, commit).Set(1)
	reg.MustRegister(buildInfo)

	return &Registry{reg: reg}
}

// MustRegister registers additional collectors (panic on duplicate, which is a
// programming error at startup).
func (r *Registry) MustRegister(cs ...prometheus.Collector) {
	r.reg.MustRegister(cs...)
}

// Gather returns all metric families (used by tests and readiness).
func (r *Registry) Gather() ([]*dto.MetricFamily, error) {
	return r.reg.Gather()
}

// Handler serves the Prometheus text exposition format.
func (r *Registry) Handler() http.Handler {
	return promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{})
}
