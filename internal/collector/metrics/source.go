// Package metrics implements the Phase-1 collector-side producer: the
// MetricSource interface with exactly one source (collector_cpu_percent, G13)
// plus the batching layer that feeds the durable spool.
package metrics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"runtime/metrics"
	"strconv"
	"strings"
	"time"
)

// Sample is one produced observation.
type Sample struct {
	MetricKey  string
	Unit       string
	Value      float64
	Ts         time.Time
	Dimensions map[string]string
}

// Source yields one gauge value per read. Implementations own the state needed
// for deltas (CPU counters).
type Source interface {
	Key() string
	Unit() string
	Dimensions() map[string]string
	// Read returns the current value; ok=false while priming (no baseline yet).
	Read(now time.Time) (value float64, ok bool)
}

// CPUSource measures host CPU busy percent from /proc/stat (total across all
// CPUs). Where procfs is unavailable (Windows dev hosts) it falls back to the
// process CPU share from the Go runtime metrics, clamped to [0,100]; the
// fallback is deterministic and documented, not silent.
type CPUSource struct {
	readProcStat func() ([]byte, error)
	lastBusy     uint64
	lastTotal    uint64
	usingProc    bool

	lastProcessCPU float64
	lastProcessAt  time.Time
}

// NewCPUSource returns the canonical Phase-1 source.
func NewCPUSource() *CPUSource {
	return &CPUSource{
		readProcStat: func() ([]byte, error) { return os.ReadFile("/proc/stat") },
		usingProc:    true,
	}
}

// Key implements Source.
func (s *CPUSource) Key() string { return "collector_cpu_percent" }

// Unit implements Source.
func (s *CPUSource) Unit() string { return "percent" }

// Dimensions implements Source.
func (s *CPUSource) Dimensions() map[string]string { return map[string]string{"cpu": "total"} }

// Read implements Source (busy-share over the interval since the last read).
func (s *CPUSource) Read(now time.Time) (float64, bool) {
	if s.usingProc {
		raw, err := s.readProcStat()
		if err == nil {
			busy, total, perr := parseCPUStat(raw)
			if perr == nil {
				if s.lastTotal == 0 || total <= s.lastTotal || busy < s.lastBusy {
					s.lastBusy, s.lastTotal = busy, total
					return 0, false
				}
				deltaBusy := busy - s.lastBusy
				deltaTotal := total - s.lastTotal
				s.lastBusy, s.lastTotal = busy, total
				if deltaTotal == 0 {
					return 0, false
				}
				pct := float64(deltaBusy) / float64(deltaTotal) * 100
				return clampPercent(pct), true
			}
		}
		s.usingProc = false
	}
	return s.readProcessCPU(now)
}

// readProcessCPU is the deterministic fallback: process CPU-seconds delta over
// wall delta, from the Go runtime metrics (available on every platform).
func (s *CPUSource) readProcessCPU(now time.Time) (float64, bool) {
	samples := []metrics.Sample{{Name: "/cpu/classes/total:cpu-seconds"}}
	metrics.Read(samples)
	if samples[0].Value.Kind() != metrics.KindFloat64 {
		return 0, false
	}
	cpu := samples[0].Value.Float64()
	if s.lastProcessAt.IsZero() {
		s.lastProcessCPU, s.lastProcessAt = cpu, now
		return 0, false
	}
	wall := now.Sub(s.lastProcessAt).Seconds()
	delta := cpu - s.lastProcessCPU
	s.lastProcessCPU, s.lastProcessAt = cpu, now
	if wall <= 0 || delta < 0 {
		return 0, false
	}
	return clampPercent(delta / wall * 100), true
}

func clampPercent(v float64) float64 {
	if math.IsNaN(v) || v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// parseCPUStat extracts aggregate busy/total jiffies from /proc/stat content:
//
//	cpu  user nice system idle iowait irq softirq steal guest guest_nice
//
// busy = total - (idle + iowait).
func parseCPUStat(raw []byte) (busy, total uint64, err error) {
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)[1:]
		if len(fields) < 4 {
			return 0, 0, errors.New("metrics: /proc/stat cpu line too short")
		}
		var values [10]uint64
		for i := 0; i < len(fields) && i < len(values); i++ {
			v, perr := strconv.ParseUint(fields[i], 10, 64)
			if perr != nil {
				return 0, 0, fmt.Errorf("metrics: parse cpu field %d: %w", i, perr)
			}
			values[i] = v
		}
		var sum uint64
		for _, v := range values {
			sum += v
		}
		idle := values[3] + values[4]
		return sum - idle, sum, nil
	}
	return 0, 0, errors.New("metrics: no aggregate cpu line in /proc/stat")
}

// Producer drives a Source at the policy interval and hands samples to a sink.
// The first Read only primes the source's delta baseline.
type Producer struct {
	source   Source
	interval func() time.Duration
	onSample func(Sample)
	log      *slog.Logger
	now      func() time.Time
}

// NewProducer wires the producer. interval is consulted on every cycle so
// policy updates take effect without a restart.
func NewProducer(source Source, interval func() time.Duration, onSample func(Sample), log *slog.Logger) *Producer {
	return &Producer{source: source, interval: interval, onSample: onSample, log: log, now: time.Now}
}

// Run produces until ctx is done.
func (p *Producer) Run(ctx context.Context) {
	// Prime the delta baseline before the first interval elapses.
	_, _ = p.source.Read(p.now())
	for {
		d := p.interval()
		if d <= 0 {
			d = 5 * time.Second
		}
		timer := time.NewTimer(d)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		value, ok := p.source.Read(p.now())
		if !ok {
			continue
		}
		sample := Sample{
			MetricKey:  p.source.Key(),
			Unit:       p.source.Unit(),
			Value:      value,
			Ts:         p.now().UTC(),
			Dimensions: p.source.Dimensions(),
		}
		p.onSample(sample)
	}
}
