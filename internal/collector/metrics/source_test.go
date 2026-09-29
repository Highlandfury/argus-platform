package metrics

import (
	"context"
	"math"
	"os"
	"testing"
	"time"
)

func TestCPUSourceGolden(t *testing.T) {
	s := NewCPUSource()
	reads := [][]byte{
		[]byte("cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 50 0 50 400 0 0 0 0 0 0\n"),
		[]byte("cpu  150 0 150 900 0 0 0 0 0 0\n"),
	}
	i := 0
	s.readProcStat = func() ([]byte, error) {
		raw := reads[i]
		i++
		return raw, nil
	}
	now := time.Now()
	if _, ok := s.Read(now); ok {
		t.Fatal("first read must prime and not report")
	}
	v, ok := s.Read(now.Add(5 * time.Second))
	// busy1 = 200, total1 = 1000; busy2 = 300, total2 = 1200
	// delta busy = 100, delta total = 200 => 50%.
	if !ok || math.Abs(v-50) > 1e-9 {
		t.Fatalf("value = %v (ok=%v), want 50", v, ok)
	}
	if s.Key() != "collector_cpu_percent" || s.Unit() != "percent" {
		t.Fatalf("source identity: %s/%s", s.Key(), s.Unit())
	}
	if s.Dimensions()["cpu"] != "total" {
		t.Fatalf("dimensions: %v", s.Dimensions())
	}
}

func TestCPUSourceFallbackWhenProcfsMissing(t *testing.T) {
	s := NewCPUSource()
	s.readProcStat = func() ([]byte, error) { return nil, os.ErrNotExist }
	now := time.Now()
	if _, ok := s.Read(now); ok {
		t.Fatal("fallback first read must prime")
	}
	// Burn a little CPU so the process CPU delta is non-negative.
	deadline := time.Now().Add(30 * time.Millisecond)
	for time.Now().Before(deadline) {
		_ = math.Sqrt(float64(time.Now().UnixNano()))
	}
	v, ok := s.Read(time.Now())
	if !ok {
		t.Fatal("fallback second read must produce a value")
	}
	if v < 0 || v > 100 {
		t.Fatalf("fallback value %v outside [0,100]", v)
	}
}

func TestParseCPUStatErrors(t *testing.T) {
	if _, _, err := parseCPUStat([]byte("intr 0\n")); err == nil {
		t.Fatal("missing cpu line must error")
	}
	if _, _, err := parseCPUStat([]byte("cpu 1 2\n")); err == nil {
		t.Fatal("short cpu line must error")
	}
	busy, total, err := parseCPUStat([]byte("cpu  10 0 10 80 10 0 0 0 0 0\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if busy != 110-90 || total != 110 {
		t.Fatalf("busy=%d total=%d", busy, total)
	}
}

func TestProducerDeliversAtInterval(t *testing.T) {
	reads := [][]byte{
		[]byte("cpu 0 0 0 100 0 0 0 0 0 0\n"),
		[]byte("cpu 10 0 0 100 0 0 0 0 0 0\n"),
		[]byte("cpu 20 0 0 100 0 0 0 0 0 0\n"),
		[]byte("cpu 30 0 0 0 100 0 0 0 0 0\n"),
	}
	i := 0
	src := NewCPUSource()
	src.readProcStat = func() ([]byte, error) {
		raw := reads[i%len(reads)]
		i++
		return raw, nil
	}
	got := make(chan Sample, 4)
	p := NewProducer(src, func() time.Duration { return 10 * time.Millisecond }, func(s Sample) { got <- s }, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	p.Run(ctx)
	if len(got) == 0 {
		t.Fatal("producer emitted no samples")
	}
	s := <-got
	if s.MetricKey != "collector_cpu_percent" || s.Ts.IsZero() {
		t.Fatalf("sample: %+v", s)
	}
	select {
	case extra := <-got:
		if extra.Value < 0 || extra.Value > 100 {
			t.Fatalf("produced value out of range: %v", extra.Value)
		}
	default:
	}
}
