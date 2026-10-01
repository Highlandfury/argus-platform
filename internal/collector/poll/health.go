package poll

import (
	"log/slog"
	"sync"
	"time"
)

// HealthBatcher groups poll-health records into the existing durable spool
// batches (M9-S1). Semantics mirror metrics.Batcher (SPEC §11): flush at max
// size or report interval; a failed flush requeues at the head so a full spool
// or transient error never loses health.
type HealthBatcher struct {
	mu        sync.Mutex
	buf       []Health
	lastFlush time.Time
	maxSize   func() int
	interval  func() time.Duration
	flush     func([]Health) error
	now       func() time.Time
	log       *slog.Logger
}

// DefaultHealthBatchSize caps one health batch (records are small; the same
// gRPC batch ceiling applies to the whole MetricBatch).
const DefaultHealthBatchSize = 500

// NewHealthBatcher wires the batcher. maxSize and interval are consulted per
// use so policy updates apply at runtime.
func NewHealthBatcher(maxSize func() int, interval func() time.Duration, flush func([]Health) error, log *slog.Logger) *HealthBatcher {
	return &HealthBatcher{
		maxSize:   maxSize,
		interval:  interval,
		flush:     flush,
		now:       time.Now,
		log:       log,
		lastFlush: time.Now(),
	}
}

// Add appends a record, flushing immediately at the size cap.
func (b *HealthBatcher) Add(h Health) error {
	b.mu.Lock()
	b.buf = append(b.buf, h)
	limit := b.maxSize()
	if limit <= 0 {
		limit = DefaultHealthBatchSize
	}
	full := len(b.buf) >= limit
	b.mu.Unlock()
	if full {
		return b.Flush()
	}
	return nil
}

// Tick flushes when the report interval elapsed and records are buffered.
func (b *HealthBatcher) Tick() error {
	b.mu.Lock()
	due := len(b.buf) > 0 && b.now().Sub(b.lastFlush) >= b.interval()
	b.mu.Unlock()
	if due {
		return b.Flush()
	}
	return nil
}

// Flush writes the buffer as one health batch. On error the records are
// requeued at the head (nothing is dropped) and the error returned for
// backpressure.
func (b *HealthBatcher) Flush() error {
	b.mu.Lock()
	if len(b.buf) == 0 {
		b.mu.Unlock()
		return nil
	}
	records := b.buf
	b.buf = nil
	b.lastFlush = b.now()
	b.mu.Unlock()

	if err := b.flush(records); err != nil {
		b.mu.Lock()
		b.buf = append(append([]Health(nil), records...), b.buf...)
		b.mu.Unlock()
		if b.log != nil {
			b.log.Error("poll health flush failed; records requeued", "records", len(records), "error", err)
		}
		return err
	}
	return nil
}

// Len returns the buffered record count (observability/tests).
func (b *HealthBatcher) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.buf)
}
