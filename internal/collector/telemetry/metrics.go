// Package telemetry owns the collector-side self-observability surface
// (SPEC §15): a loopback-only Prometheus endpoint on 127.0.0.1:9091 plus the
// shared state snapshot that the heartbeat payload and the endpoint both read.
//
// Canonical metric set (exact names):
//
//	argus_collector_spool_bytes            gauge   spool segment bytes on disk
//	argus_collector_spool_records          gauge   unacked records in the spool
//	argus_collector_highest_seq            gauge   newest spooled batch sequence
//	argus_collector_acked_seq              gauge   retired (acked or dropped) watermark
//	argus_collector_dropped_total          counter records dropped under capacity pressure
//	argus_collector_corrupt_total          counter corruption events recovered/quarantined
//	argus_collector_stream_connected       gauge   1 while the control stream session is ACTIVE
//	argus_collector_send_batch_duration_seconds histogram transport send → BatchResult (any status)
//	argus_collector_backoff_seconds        gauge   delay before the next reconnect attempt (0 when connected)
//	argus_collector_clock_skew_ms          gauge   collector-clock minus server-clock estimate
//	collector_cpu_percent                  gauge   the produced metric itself (same sample as telemetry)
//
// Label policy: no labels on any of these (bounded by construction); the
// produced value, spool numbers and connection state are all singular per
// collector process.
package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/argus-platform/argus/internal/collector/spool"
)

// SpoolSnapshot is the single spool-state projection. The heartbeat payload
// and the /metrics endpoint both derive their values from this one function so
// the two never diverge (SPEC §15: heartbeat reports the same accounting).
type SpoolSnapshot struct {
	Bytes        int64
	Records      int64
	HighestSeq   int64
	AckedSeq     int64
	DroppedTotal int64
	CorruptTotal int64
	Degraded     bool
}

// Metrics is the collector's telemetry state + loopback endpoint.
type Metrics struct {
	spool *spool.Spool

	reg      *prometheus.Registry
	server   *http.Server
	listener net.Listener

	spoolBytes   *prometheus.Desc
	spoolRecords *prometheus.Desc
	highestSeq   *prometheus.Desc
	ackedSeq     *prometheus.Desc
	droppedTotal *prometheus.Desc
	corruptTotal *prometheus.Desc

	streamConnected prometheus.Gauge
	backoff         prometheus.Gauge
	skewMS          prometheus.Gauge
	cpuPercent      prometheus.Gauge
	sendDuration    prometheus.Histogram
}

// New constructs the collector metrics state. sp may be nil in unit contexts.
func New(sp *spool.Spool) *Metrics {
	m := &Metrics{
		spool: sp,
		reg:   prometheus.NewRegistry(),
		spoolBytes: prometheus.NewDesc("argus_collector_spool_bytes",
			"Spool segment bytes currently on disk.", nil, nil),
		spoolRecords: prometheus.NewDesc("argus_collector_spool_records",
			"Unacked batches in the spool.", nil, nil),
		highestSeq: prometheus.NewDesc("argus_collector_highest_seq",
			"Newest spooled batch sequence.", nil, nil),
		ackedSeq: prometheus.NewDesc("argus_collector_acked_seq",
			"Retired (acked or dropped) batch watermark.", nil, nil),
		droppedTotal: prometheus.NewDesc("argus_collector_dropped_total",
			"Records dropped under capacity pressure.", nil, nil),
		corruptTotal: prometheus.NewDesc("argus_collector_corrupt_total",
			"Corruption events recovered/quarantined.", nil, nil),
		streamConnected: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "argus_collector_stream_connected",
			Help: "1 while the control stream session is ACTIVE.",
		}),
		backoff: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "argus_collector_backoff_seconds",
			Help: "Delay before the next reconnect attempt (0 when connected).",
		}),
		skewMS: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "argus_collector_clock_skew_ms",
			Help: "Collector clock minus server clock estimate, milliseconds.",
		}),
		cpuPercent: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "collector_cpu_percent",
			Help: "The produced collector_cpu_percent value (same sample as telemetry).",
		}),
		sendDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "argus_collector_send_batch_duration_seconds",
			Help:    "Batch transport latency: send write through BatchResult receipt (any status).",
			Buckets: []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		}),
	}
	m.reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		&spoolDescCollector{snapshot: m.SpoolSnapshot, m: m},
		m.streamConnected, m.backoff, m.skewMS, m.cpuPercent, m.sendDuration,
	)
	return m
}

// SpoolSnapshot is the single spool-state source shared by the heartbeat and
// the /metrics endpoint.
func (m *Metrics) SpoolSnapshot() SpoolSnapshot {
	if m.spool == nil {
		return SpoolSnapshot{}
	}
	st := m.spool.Stats()
	return SpoolSnapshot{
		Bytes:        st.Bytes,
		Records:      st.Records,
		HighestSeq:   st.HighestSeq,
		AckedSeq:     st.AckedSeq,
		DroppedTotal: st.DroppedRecordsTotal,
		CorruptTotal: st.CorruptRecordsTotal,
		Degraded:     st.Degraded,
	}
}

// SetStreamConnected records the actual control-stream session state.
func (m *Metrics) SetStreamConnected(connected bool) {
	if connected {
		m.streamConnected.Set(1)
	} else {
		m.streamConnected.Set(0)
	}
}

// SetBackoff records the delay before the next reconnect attempt (0 when
// connected; reset on successful reconnection by the stream client).
func (m *Metrics) SetBackoff(d time.Duration) {
	if d < 0 {
		d = 0
	}
	m.backoff.Set(d.Seconds())
}

// SetClockSkew records the estimated skew (collector minus server, ms).
func (m *Metrics) SetClockSkew(ms int64) {
	m.skewMS.Set(float64(ms))
}

// SetCPUPercent mirrors the produced sample. This is the same measurement the
// telemetry pipeline emits (single canonical source; no re-measurement).
func (m *Metrics) SetCPUPercent(v float64) {
	m.cpuPercent.Set(v)
}

// ObserveSendDuration records one transport send→BatchResult interval.
func (m *Metrics) ObserveSendDuration(d time.Duration) {
	m.sendDuration.Observe(d.Seconds())
}

// Handler returns the metrics HTTP handler (used by tests).
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// Start binds the loopback endpoint. Non-loopback addresses are refused (SPEC
// §15: the endpoint must never be reachable from the customer LAN). A start
// failure is returned to the caller; the collector keeps running without the
// endpoint (telemetry transport must not depend on it).
func (m *Metrics) Start(addr string, log *slog.Logger) error {
	if !isLoopbackAddr(addr) {
		return fmt.Errorf("collector metrics: %q is not a loopback address (loopback-only per SPEC §15)", addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("collector metrics: listen: %w", err)
	}
	m.listener = ln
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", m.Handler())
	m.server = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := m.server.Serve(ln); err != nil && err != http.ErrServerClosed && log != nil {
			log.Warn("collector metrics server stopped", "error", err)
		}
	}()
	if log != nil {
		log.Info("collector metrics listening", "addr", ln.Addr().String())
	}
	return nil
}

// Addr returns the bound address ("" before Start).
func (m *Metrics) Addr() string {
	if m.listener == nil {
		return ""
	}
	return m.listener.Addr().String()
}

// Shutdown stops the endpoint.
func (m *Metrics) Shutdown(ctx context.Context) error {
	if m.server == nil {
		return nil
	}
	return m.server.Shutdown(ctx)
}

// isLoopbackAddr accepts host:port where host is a loopback IP or localhost.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// spoolDescCollector emits one snapshot per scrape: all six spool metrics come
// from a single SpoolSnapshot call, so a scrape can never mix states.
type spoolDescCollector struct {
	snapshot func() SpoolSnapshot
	m        *Metrics
}

func (c *spoolDescCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.m.spoolBytes
	ch <- c.m.spoolRecords
	ch <- c.m.highestSeq
	ch <- c.m.ackedSeq
	ch <- c.m.droppedTotal
	ch <- c.m.corruptTotal
}

func (c *spoolDescCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.snapshot()
	ch <- prometheus.MustNewConstMetric(c.m.spoolBytes, prometheus.GaugeValue, float64(s.Bytes))
	ch <- prometheus.MustNewConstMetric(c.m.spoolRecords, prometheus.GaugeValue, float64(s.Records))
	ch <- prometheus.MustNewConstMetric(c.m.highestSeq, prometheus.GaugeValue, float64(s.HighestSeq))
	ch <- prometheus.MustNewConstMetric(c.m.ackedSeq, prometheus.GaugeValue, float64(s.AckedSeq))
	ch <- prometheus.MustNewConstMetric(c.m.droppedTotal, prometheus.CounterValue, float64(s.DroppedTotal))
	ch <- prometheus.MustNewConstMetric(c.m.corruptTotal, prometheus.CounterValue, float64(s.CorruptTotal))
}
