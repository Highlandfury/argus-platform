package poll

import (
	"errors"
	"testing"
	"time"
)

func TestHealthBatcherFlushesAtSizeCap(t *testing.T) {
	var flushed [][]Health
	b := NewHealthBatcher(func() int { return 2 }, func() time.Duration { return time.Hour },
		func(records []Health) error {
			flushed = append(flushed, records)
			return nil
		}, nil)

	_ = b.Add(Health{DeviceID: "a"})
	if len(flushed) != 0 {
		t.Fatal("flush before cap")
	}
	_ = b.Add(Health{DeviceID: "b"})
	if len(flushed) != 1 || len(flushed[0]) != 2 {
		t.Fatalf("flushed = %+v", flushed)
	}
	if b.Len() != 0 {
		t.Fatalf("buffer = %d after flush", b.Len())
	}
}

func TestHealthBatcherRequeuesOnFailure(t *testing.T) {
	fail := true
	var attempts int
	b := NewHealthBatcher(func() int { return 10 }, func() time.Duration { return time.Hour },
		func(_ []Health) error {
			attempts++
			if fail {
				return errors.New("spool full")
			}
			return nil
		}, nil)
	_ = b.Add(Health{DeviceID: "a"})
	if err := b.Flush(); err == nil {
		t.Fatal("expected flush error")
	}
	if b.Len() != 1 {
		t.Fatalf("records requeued = %d, want 1", b.Len())
	}
	fail = false
	if err := b.Flush(); err != nil {
		t.Fatalf("second flush: %v", err)
	}
	if attempts != 2 || b.Len() != 0 {
		t.Fatalf("attempts=%d buffer=%d", attempts, b.Len())
	}
}

func TestHealthBatcherTickRespectsInterval(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	var flushed int
	b := NewHealthBatcher(func() int { return 100 }, func() time.Duration { return 5 * time.Second },
		func(_ []Health) error { flushed++; return nil }, nil)
	b.mu.Lock()
	b.now = func() time.Time { return now }
	b.lastFlush = now
	b.mu.Unlock()
	_ = b.Add(Health{DeviceID: "a"})
	if err := b.Tick(); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if flushed != 0 {
		t.Fatal("tick flushed before the interval")
	}
	now = now.Add(6 * time.Second)
	if err := b.Tick(); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if flushed != 1 {
		t.Fatalf("flushed = %d, want 1", flushed)
	}
}
