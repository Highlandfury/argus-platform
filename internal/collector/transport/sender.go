// Package transport owns the collector-side telemetry sender: it reads batches
// from the durable spool, allows the stream client to pull them respecting the
// server-advertised in-flight window, and implements the ack/retry/dead-letter
// semantics (SPEC §9.2, §10.4). A batch is retired from the spool only after a
// server BatchResult(OK|DUPLICATE) — or, for REJECTED, after dead-lettering.
package transport

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
	"github.com/argus-platform/argus/internal/collector/spool"
)

// SenderStats is the sender observability projection.
type SenderStats struct {
	BatchesSent      int64
	BatchesOK        int64
	BatchesDuplicate int64
	BatchesRejected  int64
	BatchesRetried   int64
}

// Sender implements the stream client's BatchSource over a spool.
type Sender struct {
	sp            *spool.Spool
	deadletterDir string
	log           *slog.Logger

	batchesSent      atomic.Int64
	batchesOK        atomic.Int64
	batchesDuplicate atomic.Int64
	batchesRejected  atomic.Int64
	batchesRetried   atomic.Int64

	mu      sync.Mutex
	current *session
}

// NewSender wires the sender.
func NewSender(sp *spool.Spool, deadletterDir string, log *slog.Logger) *Sender {
	return &Sender{sp: sp, deadletterDir: deadletterDir, log: log}
}

// SessionStart implements stream.BatchSource: each (re)connection gets a fresh
// session positioned at the spool watermark, so unacked batches are re-sent
// (at-least-once; the server deduplicates).
func (s *Sender) SessionStart(_ *collectorv1.ServerHello) {
	reader, err := s.sp.Reader()
	if err != nil {
		s.logError("spool reader unavailable", err)
	}
	s.mu.Lock()
	if s.current != nil {
		s.current.Close()
	}
	s.current = &session{
		sender:     s,
		reader:     reader,
		retryDelay: time.Second,
		nextAck:    s.sp.Watermark() + 1,
		acks:       map[int64]bool{},
		sent:       map[int64]*spool.Batch{},
	}
	s.mu.Unlock()
}

// NextBatch implements stream.BatchSource.
func (s *Sender) NextBatch() (*collectorv1.MetricBatch, bool) {
	s.mu.Lock()
	sess := s.current
	s.mu.Unlock()
	if sess == nil {
		return nil, false
	}
	return sess.next()
}

// BatchResult implements stream.BatchSource.
func (s *Sender) BatchResult(br *collectorv1.BatchResult) {
	s.mu.Lock()
	sess := s.current
	s.mu.Unlock()
	if sess != nil {
		sess.result(br)
	}
}

// Stats returns the counters.
func (s *Sender) Stats() SenderStats {
	return SenderStats{
		BatchesSent:      s.batchesSent.Load(),
		BatchesOK:        s.batchesOK.Load(),
		BatchesDuplicate: s.batchesDuplicate.Load(),
		BatchesRejected:  s.batchesRejected.Load(),
		BatchesRetried:   s.batchesRetried.Load(),
	}
}

// Close releases the current session's spool reader. Safe to call multiple
// times; a later SessionStart creates a fresh reader.
func (s *Sender) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current != nil {
		s.current.Close()
		s.current = nil
	}
}

func (s *Sender) logError(msg string, err error) {
	if s.log != nil {
		s.log.Error(msg, "error", err)
	}
}

// deadLetter persists a REJECTED batch for operator inspection (JSON, never
// deleted automatically) and counts it.
func (s *Sender) deadLetter(b *spool.Batch, reason string) {
	if b == nil {
		return
	}
	if err := os.MkdirAll(s.deadletterDir, 0o700); err != nil {
		s.logError("deadletter mkdir", err)
		return
	}
	record := map[string]any{
		"rejected_at": time.Now().UTC().Format(time.RFC3339),
		"reason":      reason,
		"batch":       b,
	}
	raw, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		s.logError("deadletter encode", err)
		return
	}
	name := fmt.Sprintf("batch-%09d-%d.json", b.Seq, time.Now().Unix())
	if err := os.WriteFile(filepath.Join(s.deadletterDir, name), raw, 0o600); err != nil {
		s.logError("deadletter write", err)
		return
	}
	if s.log != nil {
		s.log.Warn("batch dead-lettered by server", "seq", b.Seq, "reason", reason, "path", name)
	}
}

// session is the per-connection sending state: a sequential spool reader, the
// retry state for the oldest unacked batch, and the contiguous-ack bookkeeping
// that advances the durable watermark.
type session struct {
	sender     *Sender
	reader     *spool.Reader
	retryDelay time.Duration

	retryBatch     *spool.Batch
	retryNotBefore time.Time

	nextAck int64
	acks    map[int64]bool

	sent map[int64]*spool.Batch

	mu sync.Mutex
}

// next returns the next batch to send, honoring retry backoff. Ordering is
// strict: while a retry is pending, no later batch is pulled.
func (s *session) next() (*collectorv1.MetricBatch, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.retryBatch != nil {
		now := time.Now()
		if now.Before(s.retryNotBefore) {
			return nil, false
		}
		// Re-send the same batch (same bytes, same measurement timestamps).
		b := s.retryBatch
		s.retryNotBefore = now.Add(s.retryDelay)
		return b.ToProto(), true
	}
	if s.reader == nil {
		return nil, false
	}
	b, err := s.reader.Next()
	if err != nil {
		s.sender.logError("spool read", err)
		return nil, false
	}
	if b == nil {
		return nil, false
	}
	s.sent[b.Seq] = b
	s.sender.batchesSent.Add(1)
	return b.ToProto(), true
}

// result consumes one server BatchResult.
func (s *session) result(br *collectorv1.BatchResult) {
	seq := br.GetBatchSeq()
	s.mu.Lock()
	defer s.mu.Unlock()
	batch := s.sent[seq]
	delete(s.sent, seq)

	switch br.GetStatus() {
	case collectorv1.BatchResult_STATUS_OK:
		s.sender.batchesOK.Add(1)
		s.ack(seq)
		s.clearRetry(seq)
	case collectorv1.BatchResult_STATUS_DUPLICATE:
		s.sender.batchesDuplicate.Add(1)
		s.ack(seq) // committed server-side (possibly by a previous attempt)
		s.clearRetry(seq)
	case collectorv1.BatchResult_STATUS_REJECTED:
		s.sender.batchesRejected.Add(1)
		s.sender.deadLetter(batch, br.GetReason())
		s.ack(seq) // retired from the spool; the record lives in deadletter/
		s.clearRetry(seq)
	case collectorv1.BatchResult_STATUS_RETRY:
		s.sender.batchesRetried.Add(1)
		if batch != nil {
			s.retryBatch = batch
			s.retryNotBefore = time.Now().Add(s.retryDelay)
			s.retryDelay *= 2
			if s.retryDelay > time.Minute {
				s.retryDelay = time.Minute
			}
		}
	}
}

// ack advances the contiguous watermark as far as results allow.
func (s *session) ack(seq int64) {
	s.acks[seq] = true
	for s.acks[s.nextAck] {
		delete(s.acks, s.nextAck)
		if err := s.sender.sp.Ack(s.nextAck); err != nil {
			s.sender.logError("spool ack", err)
		}
		s.nextAck++
	}
}

func (s *session) clearRetry(seq int64) {
	if s.retryBatch != nil && s.retryBatch.Seq == seq {
		s.retryBatch = nil
		s.retryDelay = time.Second
	}
}

// Close releases the session reader.
func (s *session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reader != nil {
		s.reader.Close()
		s.reader = nil
	}
}
