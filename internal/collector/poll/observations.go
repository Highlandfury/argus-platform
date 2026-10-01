package poll

import (
	"log/slog"
	"sync"
	"time"
)

// InterfaceObservation is one SNMP-polled interface attribute set (M10-S2),
// rendered by the SNMP prober from one IF-MIB row. It travels with the batch
// spool/stream/ingest path (spool.InterfaceObservation conversion in cmd) so
// the server can associate it with an inventory `interfaces` row. ifIndex is
// carried here but is never part of the interface identity (RFC 2863;
// docs/07 §12.3).
type InterfaceObservation struct {
	DeviceID    string
	IfIndex     int
	IfName      string
	IfAlias     *string
	IfType      *int
	AdminStatus *string
	OperStatus  *string
	SpeedBPS    *int64
	MTU         *int
	MAC         *string
	ObservedAt  time.Time
}

// InterfaceBatcher groups interface observations into the existing durable
// spool batches (M10-S2). Semantics mirror HealthBatcher (SPEC §11): flush at
// max size or report interval; a failed flush requeues at the head so a full
// spool or transient error never loses observations.
type InterfaceBatcher struct {
	mu        sync.Mutex
	buf       []InterfaceObservation
	lastFlush time.Time
	maxSize   func() int
	interval  func() time.Duration
	flush     func([]InterfaceObservation) error
	now       func() time.Time
	log       *slog.Logger
}

// DefaultInterfaceBatchSize caps one observation batch. A batch can span
// devices (observations are small, ~25 per device per poll); 1000 stays well
// inside the same gRPC batch ceiling as the sibling payload kinds. The server
// enforces its own MaxBatchInterfaces bound.
const DefaultInterfaceBatchSize = 1000

// NewInterfaceBatcher wires the batcher. maxSize and interval are consulted
// per use so policy updates apply at runtime.
func NewInterfaceBatcher(maxSize func() int, interval func() time.Duration, flush func([]InterfaceObservation) error, log *slog.Logger) *InterfaceBatcher {
	return &InterfaceBatcher{
		maxSize:   maxSize,
		interval:  interval,
		flush:     flush,
		now:       time.Now,
		log:       log,
		lastFlush: time.Now(),
	}
}

// Add appends observations, flushing immediately at the size cap.
func (b *InterfaceBatcher) Add(obs []InterfaceObservation) error {
	if len(obs) == 0 {
		return nil
	}
	b.mu.Lock()
	b.buf = append(b.buf, obs...)
	limit := b.maxSize()
	if limit <= 0 {
		limit = DefaultInterfaceBatchSize
	}
	full := len(b.buf) >= limit
	b.mu.Unlock()
	if full {
		return b.Flush()
	}
	return nil
}

// Tick flushes when the report interval elapsed and observations are buffered.
func (b *InterfaceBatcher) Tick() error {
	b.mu.Lock()
	due := len(b.buf) > 0 && b.now().Sub(b.lastFlush) >= b.interval()
	b.mu.Unlock()
	if due {
		return b.Flush()
	}
	return nil
}

// Flush writes the buffer as one observation payload. On error the
// observations are requeued at the head (nothing is dropped) and the error
// returned for backpressure.
func (b *InterfaceBatcher) Flush() error {
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
		b.buf = append(append([]InterfaceObservation(nil), records...), b.buf...)
		b.mu.Unlock()
		if b.log != nil {
			b.log.Error("interface observation flush failed; records requeued", "records", len(records), "error", err)
		}
		return err
	}
	return nil
}

// Len returns the buffered observation count (observability/tests).
func (b *InterfaceBatcher) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.buf)
}
