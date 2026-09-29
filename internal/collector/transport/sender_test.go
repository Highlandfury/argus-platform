package transport

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
	"github.com/argus-platform/argus/internal/collector/spool"
)

func openTestSender(t *testing.T) (*Sender, *spool.Spool, string) {
	t.Helper()
	dir := t.TempDir()
	sp, err := spool.Open(spool.Options{Dir: filepath.Join(dir, "spool"), MaxBytes: 1 << 20, FsyncInterval: 0})
	if err != nil {
		t.Fatalf("spool: %v", err)
	}
	dl := filepath.Join(dir, "spool", "deadletter")
	sender := NewSender(sp, dl, nil)
	t.Cleanup(func() {
		sender.Close()
		_ = sp.Close()
	})
	return sender, sp, dl
}

func appendBatches(t *testing.T, sp *spool.Spool, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		b := &spool.Batch{
			At: time.Now().UTC(),
			Samples: []spool.Sample{{
				MetricKey: "collector_cpu_percent", Unit: "percent",
				Value: float64(i), Ts: time.Now().UTC(),
				Dimensions: map[string]string{"cpu": "total"},
			}},
		}
		if _, err := sp.Append(b); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
}

func TestSenderContiguousAckWatermark(t *testing.T) {
	sender, sp, _ := openTestSender(t)
	appendBatches(t, sp, 3)
	sender.SessionStart(nil)

	b1, ok := sender.NextBatch()
	if !ok || b1.GetBatchSeq() != 1 {
		t.Fatalf("first batch: %+v ok=%v", b1, ok)
	}
	if b2, ok := sender.NextBatch(); !ok || b2.GetBatchSeq() != 2 {
		t.Fatalf("second batch: %+v ok=%v", b2, ok)
	}

	// Out-of-order results must not advance the watermark past a gap.
	sender.BatchResult(&collectorv1.BatchResult{BatchSeq: 2, Status: collectorv1.BatchResult_STATUS_OK})
	if sp.Watermark() != 0 {
		t.Fatalf("watermark advanced past a gap: %d", sp.Watermark())
	}
	sender.BatchResult(&collectorv1.BatchResult{BatchSeq: 1, Status: collectorv1.BatchResult_STATUS_DUPLICATE})
	if sp.Watermark() != 2 {
		t.Fatalf("watermark after contiguous acks: %d", sp.Watermark())
	}
	stats := sender.Stats()
	if stats.BatchesOK != 1 || stats.BatchesDuplicate != 1 {
		t.Fatalf("stats: %+v", stats)
	}
}

func TestSenderRejectedDeadLettersAndRetires(t *testing.T) {
	sender, sp, dl := openTestSender(t)
	appendBatches(t, sp, 1)
	sender.SessionStart(nil)
	if _, ok := sender.NextBatch(); !ok {
		t.Fatal("no batch pulled")
	}
	sender.BatchResult(&collectorv1.BatchResult{
		BatchSeq: 1, Status: collectorv1.BatchResult_STATUS_REJECTED, Reason: "validation.value_out_of_range",
	})
	if sp.Watermark() != 1 {
		t.Fatalf("rejected batch must retire from spool: watermark=%d", sp.Watermark())
	}
	files, err := os.ReadDir(dl)
	if err != nil || len(files) != 1 {
		t.Fatalf("deadletter files: %v err=%v", files, err)
	}
	raw, err := os.ReadFile(filepath.Join(dl, files[0].Name())) //nolint:gosec // test fixture path
	if err != nil || len(raw) == 0 {
		t.Fatalf("deadletter content: %v", err)
	}
	if stats := sender.Stats(); stats.BatchesRejected != 1 {
		t.Fatalf("stats: %+v", stats)
	}
}

func TestSenderRetryPreservesOrdering(t *testing.T) {
	sender, sp, _ := openTestSender(t)
	appendBatches(t, sp, 2)
	sender.SessionStart(nil)
	first, ok := sender.NextBatch()
	if !ok || first.GetBatchSeq() != 1 {
		t.Fatalf("pull 1: %+v", first)
	}
	sender.BatchResult(&collectorv1.BatchResult{BatchSeq: 1, Status: collectorv1.BatchResult_STATUS_RETRY})

	// While the retry backoff is active, nothing is pulled.
	if b, ok := sender.NextBatch(); ok {
		t.Fatalf("pull during retry backoff returned %d", b.GetBatchSeq())
	}
	// After the backoff, the SAME batch is re-sent (not seq 2).
	sender.mu.Lock()
	sender.current.retryNotBefore = time.Now().Add(-time.Millisecond)
	sender.mu.Unlock()
	again, ok := sender.NextBatch()
	if !ok || again.GetBatchSeq() != 1 {
		t.Fatalf("retry pull: %+v ok=%v", again, ok)
	}
	if b, ok := sender.NextBatch(); ok {
		t.Fatalf("ordering violated: pulled %d while retry unacked", b.GetBatchSeq())
	}
	// Clearing the retry resumes in order.
	sender.BatchResult(&collectorv1.BatchResult{BatchSeq: 1, Status: collectorv1.BatchResult_STATUS_OK})
	next, ok := sender.NextBatch()
	if !ok || next.GetBatchSeq() != 2 {
		t.Fatalf("post-retry pull: %+v ok=%v", next, ok)
	}
	if sp.Watermark() != 1 {
		t.Fatalf("watermark: %d", sp.Watermark())
	}
	if stats := sender.Stats(); stats.BatchesRetried != 1 || stats.BatchesOK != 1 {
		t.Fatalf("stats: %+v", stats)
	}
}

func TestSenderResumesFromWatermarkOnNewSession(t *testing.T) {
	sender, sp, _ := openTestSender(t)
	appendBatches(t, sp, 2)
	sender.SessionStart(nil)
	if _, ok := sender.NextBatch(); !ok {
		t.Fatal("pull 1")
	}
	sender.BatchResult(&collectorv1.BatchResult{BatchSeq: 1, Status: collectorv1.BatchResult_STATUS_OK})

	// Reconnect: a fresh session must resume at seq 2, never re-send 1.
	sender.SessionStart(nil)
	b, ok := sender.NextBatch()
	if !ok || b.GetBatchSeq() != 2 {
		t.Fatalf("resume pull: %+v ok=%v", b, ok)
	}
}
