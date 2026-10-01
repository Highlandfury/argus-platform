package spool

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
)

// Sample is one observation inside a spooled batch.
type Sample struct {
	MetricKey  string            `json:"metric_key"`
	Unit       string            `json:"unit"`
	Value      float64           `json:"value"`
	Ts         time.Time         `json:"ts"`
	DeviceID   string            `json:"device_id,omitempty"` // M9 device-scoped sample
	Dimensions map[string]string `json:"dimensions,omitempty"`
}

// Health is one poll-health record spooled with a batch (M9-S1). It rides the
// same durable record, batch_seq claim and BatchResult ack as samples.
type Health struct {
	DeviceID            string    `json:"device_id"`
	PollType            string    `json:"poll_type"`
	LatencyMS           int       `json:"latency_ms"`
	Outcome             string    `json:"outcome"`
	ErrorClass          string    `json:"error_class"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	CheckedAt           time.Time `json:"checked_at"`
	// Origin classifies the probe trigger (M10-S0): "scheduled" | "on_demand".
	// Empty is normalized to scheduled by the server (old spool records).
	Origin string `json:"origin,omitempty"`
}

// Batch is the unit of durable storage; payload is the exact wire message.
// A batch carries samples, health records, or both (M9-S1).
type Batch struct {
	Seq     int64     `json:"seq"`
	At      time.Time `json:"created_at"`
	Samples []Sample  `json:"samples,omitempty"`
	Health  []Health  `json:"health,omitempty"`
}

// Empty reports whether the batch has no payload of either kind.
func (b *Batch) Empty() bool { return len(b.Samples) == 0 && len(b.Health) == 0 }

// ToProto converts a stored batch into its wire form.
func (b *Batch) ToProto() *collectorv1.MetricBatch {
	samples := make([]*collectorv1.MetricSample, len(b.Samples))
	for i := range b.Samples {
		s := b.Samples[i]
		samples[i] = &collectorv1.MetricSample{
			MetricKey:  s.MetricKey,
			Unit:       s.Unit,
			Value:      s.Value,
			Dimensions: s.Dimensions,
			Ts:         timestamppb.New(s.Ts),
			DeviceId:   s.DeviceID,
		}
	}
	health := make([]*collectorv1.PollHealth, len(b.Health))
	for i := range b.Health {
		h := b.Health[i]
		health[i] = &collectorv1.PollHealth{
			DeviceId:            h.DeviceID,
			PollType:            h.PollType,
			LatencyMs:           int32(h.LatencyMS), //nolint:gosec // bounded by probe duration
			Outcome:             h.Outcome,
			ErrorClass:          h.ErrorClass,
			ConsecutiveFailures: int32(h.ConsecutiveFailures), //nolint:gosec // bounded by poll cadence
			CheckedAt:           timestamppb.New(h.CheckedAt),
			Origin:              h.Origin,
		}
	}
	return &collectorv1.MetricBatch{
		BatchSeq:  b.Seq,
		Samples:   samples,
		CreatedAt: timestamppb.New(b.At),
		Health:    health,
	}
}

func batchFromPayload(payload []byte) (*Batch, error) {
	var pb collectorv1.MetricBatch
	if err := proto.Unmarshal(payload, &pb); err != nil {
		return nil, fmt.Errorf("spool: decode batch: %w", err)
	}
	b := &Batch{Seq: pb.GetBatchSeq(), At: pb.GetCreatedAt().AsTime()}
	for _, s := range pb.GetSamples() {
		b.Samples = append(b.Samples, Sample{
			MetricKey:  s.GetMetricKey(),
			Unit:       s.GetUnit(),
			Value:      s.GetValue(),
			Ts:         s.GetTs().AsTime(),
			DeviceID:   s.GetDeviceId(),
			Dimensions: s.GetDimensions(),
		})
	}
	for _, h := range pb.GetHealth() {
		b.Health = append(b.Health, Health{
			DeviceID:            h.GetDeviceId(),
			PollType:            h.GetPollType(),
			LatencyMS:           int(h.GetLatencyMs()),
			Outcome:             h.GetOutcome(),
			ErrorClass:          h.GetErrorClass(),
			ConsecutiveFailures: int(h.GetConsecutiveFailures()),
			CheckedAt:           h.GetCheckedAt().AsTime(),
			Origin:              h.GetOrigin(),
		})
	}
	return b, nil
}

// Stats is the heartbeat/observability projection of the spool (SPEC §15).
type Stats struct {
	AckedSeq            int64
	HighestSeq          int64
	Records             int64
	Bytes               int64
	DroppedRecordsTotal int64
	CorruptRecordsTotal int64
	Degraded            bool
}

// Options configures Open.
type Options struct {
	Dir           string
	MaxBytes      int64
	FsyncInterval time.Duration
	Log           *slog.Logger
}

type segMeta struct {
	path     string
	firstSeq int64
	lastSeq  int64
	records  int64
	bytes    int64
}

// Spool is the durable segmented WAL.
type Spool struct {
	mu            sync.Mutex
	dir           string
	maxBytes      int64
	fsyncInterval time.Duration
	log           *slog.Logger

	segs       []*segMeta
	active     *segmentWriter
	ackedSeq   int64
	highestSeq int64
	dropped    int64
	corrupt    int64
	degraded   bool

	pendingSync int64
	lastSync    time.Time
	lastState   time.Time
	closed      bool
}

// Open recovers an existing spool (or creates one) and returns it ready for
// Append. Recovery must complete before any write (SPEC §3.5).
func Open(opts Options) (*Spool, error) {
	if opts.Dir == "" {
		return nil, fmt.Errorf("spool: dir is required")
	}
	if opts.MaxBytes <= 0 {
		return nil, fmt.Errorf("spool: MaxBytes must be > 0")
	}
	if err := os.MkdirAll(filepath.Join(opts.Dir, "deadletter"), 0o700); err != nil {
		return nil, fmt.Errorf("spool: mkdir: %w", err)
	}
	s := &Spool{
		dir:           opts.Dir,
		maxBytes:      opts.MaxBytes,
		fsyncInterval: opts.FsyncInterval,
		log:           opts.Log,
		lastSync:      time.Now(),
		lastState:     time.Now(),
	}
	if err := s.recover(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Spool) infof(msg string, args ...any) {
	if s.log != nil {
		s.log.Info(msg, args...)
	}
}

func (s *Spool) warnf(msg string, args ...any) {
	if s.log != nil {
		s.log.Warn(msg, args...)
	}
}

// Append durably spools one batch and returns its assigned sequence. The
// record is written to the active segment; fsync follows the group policy and
// is guaranteed before the record becomes send-eligible.
func (s *Spool) Append(b *Batch) (int64, error) {
	if b == nil || b.Empty() {
		return 0, ErrEmptyBatch
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, fmt.Errorf("spool: closed")
	}
	b.Seq = s.highestSeq + 1
	if b.At.IsZero() {
		b.At = time.Now().UTC()
	}
	payload, err := proto.Marshal(b.ToProto())
	if err != nil {
		return 0, fmt.Errorf("spool: marshal batch: %w", err)
	}
	if len(payload) > maxRecordPayload {
		return 0, fmt.Errorf("spool: batch payload %d bytes exceeds the %d cap", len(payload), maxRecordPayload)
	}
	rec := encodeRecord(payload)
	if s.totalBytesLocked()+int64(len(rec)) > s.maxBytes {
		if err := s.makeSpaceLocked(int64(len(rec))); err != nil {
			s.degraded = true
			return 0, err
		}
	}
	if s.active == nil {
		w, err := createSegment(s.dir, b.Seq)
		if err != nil {
			return 0, err
		}
		s.active = w
		s.segs = append(s.segs, &segMeta{path: w.path, firstSeq: b.Seq, lastSeq: b.Seq, records: 0})
	}
	if s.active.size+int64(len(rec)) > MaxSegmentBytes && s.active.size > 0 {
		if err := s.sealActiveLocked(); err != nil {
			return 0, err
		}
		w, err := createSegment(s.dir, b.Seq)
		if err != nil {
			return 0, err
		}
		s.active = w
		s.segs = append(s.segs, &segMeta{path: w.path, firstSeq: b.Seq, lastSeq: b.Seq, records: 0})
	}
	if err := s.active.appendRecord(rec); err != nil {
		return 0, err
	}
	s.highestSeq = b.Seq
	active := s.segs[len(s.segs)-1]
	active.lastSeq = b.Seq
	active.records++
	active.bytes += int64(len(rec))
	s.pendingSync++
	s.groupSyncLocked()
	s.maybePersistStateLocked(false)
	return b.Seq, nil
}

// totalBytesLocked sums segment sizes.
func (s *Spool) totalBytesLocked() int64 {
	var total int64
	for _, seg := range s.segs {
		total += seg.bytes
	}
	return total
}

// groupSyncLocked implements the fsync policy: immediate when interval is 0,
// on 100 pending records, or when the interval has elapsed. Reader.Next forces
// this path before a batch becomes send-eligible.
func (s *Spool) groupSyncLocked() {
	if s.active == nil || s.pendingSync == 0 {
		return
	}
	due := s.fsyncInterval <= 0 ||
		s.pendingSync >= 100 ||
		time.Since(s.lastSync) >= s.fsyncInterval
	if !due {
		return
	}
	if err := s.active.sync(); err != nil {
		s.warnf("spool fsync failed", "error", err)
		return
	}
	s.pendingSync = 0
	s.lastSync = time.Now()
}

// ForceSync flushes any pending group commit (used before sending/shutdown).
func (s *Spool) ForceSync() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil || s.pendingSync == 0 {
		return nil
	}
	if err := s.active.sync(); err != nil {
		return err
	}
	s.pendingSync = 0
	s.lastSync = time.Now()
	return nil
}

func (s *Spool) sealActiveLocked() error {
	if s.active == nil {
		return nil
	}
	if err := s.active.sync(); err != nil {
		return err
	}
	err := s.active.close()
	s.active = nil
	s.pendingSync = 0
	return err
}

// Ack retires all batches up to seq (the caller guarantees contiguity).
// Segments fully covered by the watermark are unlinked (SPEC §10.3).
func (s *Spool) Ack(seq int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if seq <= s.ackedSeq {
		return nil
	}
	s.ackedSeq = seq
	s.purgeLocked()
	s.maybePersistStateLocked(false)
	return nil
}

// purgeLocked unlinks segments whose last sequence is fully acked.
func (s *Spool) purgeLocked() {
	for len(s.segs) > 0 && s.segs[0].lastSeq <= s.ackedSeq {
		seg := s.segs[0]
		if s.active != nil && s.active.path == seg.path {
			_ = s.active.close()
			s.active = nil
		}
		if err := os.Remove(seg.path); err != nil && !os.IsNotExist(err) {
			s.warnf("spool purge failed", "segment", seg.path, "error", err)
			return
		}
		s.segs = s.segs[1:]
	}
}

// Watermark returns the highest retired sequence (acked or dropped).
func (s *Spool) Watermark() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ackedSeq
}

// Stats returns the current spool accounting.
func (s *Spool) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	var records, bytes int64
	for i, seg := range s.segs {
		bytes += seg.bytes
		if seg.lastSeq <= s.ackedSeq {
			continue
		}
		if i == 0 && seg.firstSeq <= s.ackedSeq {
			// Partially acked head segment: subtract retired records.
			records += seg.records - (s.ackedSeq - seg.firstSeq + 1)
		} else {
			records += seg.records
		}
	}
	return Stats{
		AckedSeq:            s.ackedSeq,
		HighestSeq:          s.highestSeq,
		Records:             records,
		Bytes:               bytes,
		DroppedRecordsTotal: s.dropped,
		CorruptRecordsTotal: s.corrupt,
		Degraded:            s.degraded,
	}
}

// Close flushes and closes the spool.
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	_ = s.sealActiveLocked()
	return s.saveStateLocked()
}
