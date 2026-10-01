package spool

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
)

func testBatch(value float64) *Batch {
	return &Batch{
		At: time.Now().UTC(),
		Samples: []Sample{{
			MetricKey:  "collector_cpu_percent",
			Unit:       "percent",
			Value:      value,
			Ts:         time.Now().UTC(),
			Dimensions: map[string]string{"cpu": "total"},
		}},
	}
}

func mustOpen(t *testing.T, dir string, maxBytes int64) *Spool {
	t.Helper()
	s, err := Open(Options{Dir: dir, MaxBytes: maxBytes, FsyncInterval: 0})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func TestAppendReadAckPersistRestart(t *testing.T) {
	dir := t.TempDir()
	s := mustOpen(t, dir, 1<<20)

	seq1, err := s.Append(testBatch(1))
	if err != nil || seq1 != 1 {
		t.Fatalf("append 1: seq=%d err=%v", seq1, err)
	}
	seq2, err := s.Append(testBatch(2))
	if err != nil || seq2 != 2 {
		t.Fatalf("append 2: seq=%d err=%v", seq2, err)
	}
	if _, err := s.Append(&Batch{At: time.Now()}); !errors.Is(err, ErrEmptyBatch) {
		t.Fatalf("empty batch: %v", err)
	}

	r, err := s.Reader()
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	b1, err := r.Next()
	if err != nil || b1 == nil || b1.Seq != 1 || b1.Samples[0].Value != 1 {
		t.Fatalf("next 1: %+v err=%v", b1, err)
	}
	b2, _ := r.Next()
	if b2 == nil || b2.Seq != 2 {
		t.Fatalf("next 2: %+v", b2)
	}
	if extra, _ := r.Next(); extra != nil {
		t.Fatalf("expected idle at tail, got %+v", extra)
	}
	r.Close()

	if err := s.Ack(1); err != nil {
		t.Fatalf("ack: %v", err)
	}
	if got := s.Stats(); got.AckedSeq != 1 || got.HighestSeq != 2 || got.Records != 1 {
		t.Fatalf("stats after ack1: %+v", got)
	}
	// Ack does not delete the segment while seq 2 is still pending.
	files, _ := listSegments(dir)
	if len(files) != 1 {
		t.Fatalf("segments after ack1: %v", files)
	}

	// Simulate a crash: close without further acks, reopen, watermark survives.
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	s2 := mustOpen(t, dir, 1<<20)
	stats := s2.Stats()
	if stats.AckedSeq != 1 || stats.HighestSeq != 2 {
		t.Fatalf("restart watermark: %+v", stats)
	}
	r2, _ := s2.Reader()
	next, err := r2.Next()
	if err != nil || next == nil || next.Seq != 2 {
		t.Fatalf("post-restart next: %+v err=%v", next, err)
	}
	r2.Close()

	// Acking the last record unlinks the fully acked segment.
	if err := s2.Ack(2); err != nil {
		t.Fatalf("ack2: %v", err)
	}
	if files, _ := listSegments(dir); len(files) != 0 {
		t.Fatalf("segments after full ack: %v", files)
	}
	if got := s2.Stats(); got.Records != 0 || got.Bytes != 0 {
		t.Fatalf("stats after full ack: %+v", got)
	}
	_ = s2.Close()
}

// TestReaderSeesSegmentsCreatedAfterOpen is the regression for the live
// long-run stall: when fully-acked segments are purged, the next append starts
// a new segment file, and a long-lived reader must discover it.
func TestReaderSeesSegmentsCreatedAfterOpen(t *testing.T) {
	dir := t.TempDir()
	s := mustOpen(t, dir, 1<<20)
	if _, err := s.Append(testBatch(1)); err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := s.Append(testBatch(2)); err != nil {
		t.Fatalf("append: %v", err)
	}
	r, err := s.Reader()
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	defer r.Close()
	for want := int64(1); want <= 2; want++ {
		b, err := r.Next()
		if err != nil || b == nil || b.Seq != want {
			t.Fatalf("pre-purge read %d: %+v err=%v", want, b, err)
		}
	}
	if b, _ := r.Next(); b != nil {
		t.Fatalf("expected idle, got %+v", b)
	}
	// Ack everything: the segment is purged and the next append opens a new one.
	if err := s.Ack(1); err != nil {
		t.Fatalf("ack 1: %v", err)
	}
	if err := s.Ack(2); err != nil {
		t.Fatalf("ack 2: %v", err)
	}
	if files, _ := listSegments(dir); len(files) != 0 {
		t.Fatalf("expected the acked segment purged, have %v", files)
	}
	if _, err := s.Append(testBatch(3)); err != nil {
		t.Fatalf("append 3: %v", err)
	}
	// The same reader session must pick up the new segment.
	b, err := r.Next()
	if err != nil || b == nil || b.Seq != 3 {
		t.Fatalf("post-purge read: %+v err=%v", b, err)
	}
	if err := s.Ack(3); err != nil {
		t.Fatalf("ack 3: %v", err)
	}
	if b4, err := r.Next(); err != nil || b4 != nil {
		t.Fatalf("expected idle after ack, got %+v err=%v", b4, err)
	}
	_ = s.Close()
}

func TestTornTailTruncatedAndCounted(t *testing.T) {
	dir := t.TempDir()
	s := mustOpen(t, dir, 1<<20)
	if _, err := s.Append(testBatch(1)); err != nil {
		t.Fatalf("append: %v", err)
	}
	seg := s.segs[0].path
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Append a torn record: header promising more bytes than exist.
	f, err := os.OpenFile(seg, os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // test fixture path
	if err != nil {
		t.Fatalf("open segment: %v", err)
	}
	if _, err := f.Write([]byte{0x00, 0x00, 0x10, 0x00, 0xde, 0xad}); err != nil {
		t.Fatalf("write torn bytes: %v", err)
	}
	_ = f.Close()

	s2 := mustOpen(t, dir, 1<<20)
	stats := s2.Stats()
	if stats.CorruptRecordsTotal != 1 {
		t.Fatalf("corrupt total = %d (want 1 for torn tail)", stats.CorruptRecordsTotal)
	}
	if stats.HighestSeq != 1 || stats.Records != 1 {
		t.Fatalf("recovered stats: %+v", stats)
	}
	// The valid record is still readable.
	r, _ := s2.Reader()
	if b, err := r.Next(); err != nil || b == nil || b.Seq != 1 {
		t.Fatalf("post-truncate read: %+v err=%v", b, err)
	}
	r.Close()
	_ = s2.Close()
}

func TestSealedSegmentQuarantinePreservesPrefix(t *testing.T) {
	dir := t.TempDir()
	s := mustOpen(t, dir, 1<<20)
	for i := 0; i < 3; i++ {
		if _, err := s.Append(testBatch(float64(i))); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	seg1 := s.segs[0].path
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Create a second, valid segment file manually (batch seq 4), so the first
	// file is no longer the last/active segment.
	pb := &collectorv1.MetricBatch{
		BatchSeq:  4,
		Samples:   []*collectorv1.MetricSample{{MetricKey: "collector_cpu_percent", Unit: "percent", Value: 4, Ts: timestamppb.Now()}},
		CreatedAt: timestamppb.Now(),
	}
	payload, err := proto.Marshal(pb)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	seg2 := segmentPath(dir, 4)
	if err := os.WriteFile(seg2, encodeRecord(payload), 0o600); err != nil {
		t.Fatalf("write seg2: %v", err)
	}

	// Corrupt the MIDDLE of segment 1 (second record's payload).
	data, err := os.ReadFile(seg1) //nolint:gosec // test fixture path
	if err != nil {
		t.Fatalf("read seg1: %v", err)
	}
	// First record length, then flip a byte inside the second record payload.
	first := int(data[0])<<24 | int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	corruptAt := recordHeaderLen + first + recordHeaderLen + 3
	if corruptAt >= len(data) {
		t.Fatalf("segment too small for test corruption: len=%d at=%d", len(data), corruptAt)
	}
	data[corruptAt] ^= 0xFF
	if err := os.WriteFile(seg1, data, 0o600); err != nil { //nolint:gosec // test fixture path
		t.Fatalf("rewrite seg1: %v", err)
	}

	s2 := mustOpen(t, dir, 1<<20)
	stats := s2.Stats()
	if stats.CorruptRecordsTotal != 1 {
		t.Fatalf("corrupt total = %d (want 1 quarantine event)", stats.CorruptRecordsTotal)
	}
	// Prefix (seq 1) plus the untouched later segment (seq 4) are readable.
	seen := map[int64]bool{}
	r, _ := s2.Reader()
	for {
		b, err := r.Next()
		if err != nil {
			t.Fatalf("reader: %v", err)
		}
		if b == nil {
			break
		}
		seen[b.Seq] = true
	}
	r.Close()
	if !seen[1] || !seen[4] {
		t.Fatalf("readable seqs after quarantine: %v (want 1 and 4)", seen)
	}
	// A quarantine file exists (nothing silently discarded).
	quarantined, _ := filepath.Glob(filepath.Join(dir, "*.corrupt*"))
	if len(quarantined) != 1 {
		t.Fatalf("quarantine files: %v", quarantined)
	}
	_ = s2.Close()
}

func TestCapacityDropsOldestAndAdvancesWatermark(t *testing.T) {
	dir := t.TempDir()
	// Small budget so a handful of records forces drop-oldest.
	s := mustOpen(t, dir, 700)
	for i := 0; i < 40; i++ {
		if _, err := s.Append(testBatch(float64(i))); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	stats := s.Stats()
	if stats.DroppedRecordsTotal == 0 {
		t.Fatalf("expected dropped records, stats: %+v", stats)
	}
	if stats.AckedSeq == 0 {
		t.Fatalf("watermark must advance past dropped sequences: %+v", stats)
	}
	if stats.Bytes > 700 {
		t.Fatalf("spool exceeds budget: %+v", stats)
	}
	// The spool still works: newest records are readable and ackable.
	r, _ := s.Reader()
	b, err := r.Next()
	if err != nil || b == nil {
		t.Fatalf("reader after drops: %+v err=%v", b, err)
	}
	if b.Seq <= stats.AckedSeq {
		t.Fatalf("read batch %d at/below watermark %d", b.Seq, stats.AckedSeq)
	}
	r.Close()
	if err := s.Ack(b.Seq); err != nil {
		t.Fatalf("ack: %v", err)
	}
	_ = s.Close()
}

func TestCorruptStateFileQuarantined(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("not-json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	s := mustOpen(t, dir, 1<<20)
	if s.Stats().CorruptRecordsTotal != 1 {
		t.Fatalf("state corruption not counted: %+v", s.Stats())
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json.corrupt")); err != nil {
		t.Fatalf("state file not quarantined: %v", err)
	}
	_ = s.Close()
}

// TestHealthOnlyBatchRoundTrip pins the M9-S1 spool contract: a batch carrying
// only poll-health records is durable, sendable and recoverable exactly like a
// sample batch (health rides the same WAL, claim and ack path).
func TestHealthOnlyBatchRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := mustOpen(t, dir, 1<<20)
	checkedAt := time.Now().UTC().Truncate(time.Second)
	health := Health{
		DeviceID:            "0198d5a3-0000-7000-8000-000000000001",
		PollType:            "icmp",
		LatencyMS:           11,
		Outcome:             "failure",
		ErrorClass:          "timeout",
		ConsecutiveFailures: 2,
		CheckedAt:           checkedAt,
	}
	seq, err := s.Append(&Batch{At: time.Now().UTC(), Health: []Health{health}})
	if err != nil || seq != 1 {
		t.Fatalf("append health-only: seq=%d err=%v", seq, err)
	}
	if _, err := s.Append(&Batch{At: time.Now()}); !errors.Is(err, ErrEmptyBatch) {
		t.Fatalf("empty batch must still be refused: %v", err)
	}

	r, err := s.Reader()
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	b, err := r.Next()
	if err != nil || b == nil || len(b.Samples) != 0 || len(b.Health) != 1 {
		t.Fatalf("read health-only: %+v err=%v", b, err)
	}
	got := b.Health[0]
	if got.DeviceID != health.DeviceID || got.PollType != "icmp" || got.LatencyMS != 11 ||
		got.Outcome != "failure" || got.ErrorClass != "timeout" || got.ConsecutiveFailures != 2 ||
		!got.CheckedAt.Equal(checkedAt) {
		t.Fatalf("health round trip = %+v", got)
	}
	// Restart before ack: recovery must rebuild the health record from the
	// segment (nothing may be lost across a collector restart).
	r.Close() // Windows: release the segment handle before reopening
	_ = s.Close()
	reopened := mustOpen(t, dir, 1<<20)
	defer func() { _ = reopened.Close() }()
	r2, err := reopened.Reader()
	if err != nil {
		t.Fatalf("reader after restart: %v", err)
	}
	b2, err := r2.Next()
	if err != nil || b2 == nil || len(b2.Health) != 1 || b2.Health[0].DeviceID != health.DeviceID {
		t.Fatalf("health after restart: %+v err=%v", b2, err)
	}
	r2.Close()
	if err := reopened.Ack(seq); err != nil {
		t.Fatalf("ack: %v", err)
	}
	if reopened.Stats().Records != 0 {
		t.Fatalf("acked health record still pending: %+v", reopened.Stats())
	}
}
