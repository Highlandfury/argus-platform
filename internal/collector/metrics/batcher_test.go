package metrics

import (
	"errors"
	"testing"
	"time"
)

func testSample(v float64) Sample {
	return Sample{MetricKey: "collector_cpu_percent", Unit: "percent", Value: v, Ts: time.Now()}
}

func TestBatcherFlushOnSizeCap(t *testing.T) {
	var flushed [][]Sample
	b := NewBatcher(func() int { return 3 }, func() time.Duration { return time.Hour },
		func(samples []Sample) error { flushed = append(flushed, samples); return nil }, nil)

	for i := 0; i < 2; i++ {
		if err := b.Add(testSample(float64(i))); err != nil {
			t.Fatalf("add: %v", err)
		}
	}
	if len(flushed) != 0 || b.Len() != 2 {
		t.Fatalf("premature flush: flushed=%d buffered=%d", len(flushed), b.Len())
	}
	if err := b.Add(testSample(2)); err != nil {
		t.Fatalf("add: %v", err)
	}
	if len(flushed) != 1 || len(flushed[0]) != 3 {
		t.Fatalf("size-cap flush: %+v", flushed)
	}
}

func TestBatcherFlushOnInterval(t *testing.T) {
	var flushed [][]Sample
	b := NewBatcher(func() int { return 100 }, func() time.Duration { return 5 * time.Millisecond },
		func(samples []Sample) error { flushed = append(flushed, samples); return nil }, nil)

	if err := b.Add(testSample(1)); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := b.Tick(); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if len(flushed) != 0 {
		t.Fatal("flushed before the interval elapsed")
	}
	time.Sleep(10 * time.Millisecond)
	if err := b.Tick(); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if len(flushed) != 1 || len(flushed[0]) != 1 {
		t.Fatalf("interval flush: %+v", flushed)
	}
	if b.Len() != 0 {
		t.Fatalf("buffer after flush: %d", b.Len())
	}
	// Empty flush never happens.
	if err := b.Flush(); err != nil || len(flushed) != 1 {
		t.Fatal("empty flush must be a no-op")
	}
}

func TestBatcherRequeuesOnFailure(t *testing.T) {
	fail := true
	var attempts int
	b := NewBatcher(func() int { return 100 }, func() time.Duration { return time.Millisecond },
		func(_ []Sample) error {
			attempts++
			if fail {
				return errors.New("spool full")
			}
			return nil
		}, nil)

	if err := b.Add(testSample(1)); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := b.Flush(); err == nil {
		t.Fatal("expected flush error")
	}
	if b.Len() != 1 {
		t.Fatalf("samples lost on failed flush: %d", b.Len())
	}
	fail = false
	if err := b.Flush(); err != nil {
		t.Fatalf("retry flush: %v", err)
	}
	if attempts != 2 || b.Len() != 0 {
		t.Fatalf("attempts=%d buffered=%d", attempts, b.Len())
	}
}
