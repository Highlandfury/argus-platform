package metrics

import (
	"log/slog"
	"sync"
	"time"
)

// Batcher groups samples into batches (SPEC §11: report interval and
// batch_max_samples come from the signed policy). Flush happens when the
// sample cap is reached or the report interval elapses; empty batches are
// never produced. Failed flushes requeue at the head so a full spool or a
// transient error cannot lose samples.
type Batcher struct {
	mu        sync.Mutex
	buf       []Sample
	lastFlush time.Time
	maxSize   func() int
	interval  func() time.Duration
	flush     func([]Sample) error
	now       func() time.Time
	log       *slog.Logger
}

// NewBatcher wires a batcher. maxSize and interval are consulted per use so
// policy updates apply at runtime.
func NewBatcher(maxSize func() int, interval func() time.Duration, flush func([]Sample) error, log *slog.Logger) *Batcher {
	return &Batcher{
		maxSize:   maxSize,
		interval:  interval,
		flush:     flush,
		now:       time.Now,
		log:       log,
		lastFlush: time.Now(),
	}
}

// Add appends a sample, flushing immediately when the size cap is reached.
func (b *Batcher) Add(s Sample) error {
	b.mu.Lock()
	b.buf = append(b.buf, s)
	limit := b.maxSize()
	if limit <= 0 {
		limit = 5000
	}
	full := len(b.buf) >= limit
	b.mu.Unlock()
	if full {
		return b.Flush()
	}
	return nil
}

// Tick flushes when the report interval elapsed and there is buffered data.
func (b *Batcher) Tick() error {
	b.mu.Lock()
	due := len(b.buf) > 0 && b.now().Sub(b.lastFlush) >= b.interval()
	b.mu.Unlock()
	if due {
		return b.Flush()
	}
	return nil
}

// Flush writes the buffer as one batch. On error the samples are requeued at
// the head (nothing is dropped) and the error is returned for backpressure.
func (b *Batcher) Flush() error {
	b.mu.Lock()
	if len(b.buf) == 0 {
		b.mu.Unlock()
		return nil
	}
	samples := b.buf
	b.buf = nil
	b.lastFlush = b.now()
	b.mu.Unlock()

	if err := b.flush(samples); err != nil {
		b.mu.Lock()
		b.buf = append(append([]Sample(nil), samples...), b.buf...)
		b.mu.Unlock()
		if b.log != nil {
			b.log.Error("batch flush failed; samples requeued", "samples", len(samples), "error", err)
		}
		return err
	}
	return nil
}

// Len returns the number of buffered samples (observability/tests).
func (b *Batcher) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.buf)
}
