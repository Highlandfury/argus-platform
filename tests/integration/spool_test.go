package integration

import (
	"context"
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
	"github.com/argus-platform/argus/internal/collector"
	collectoridentity "github.com/argus-platform/argus/internal/collector/identity"
	"github.com/argus-platform/argus/internal/collector/spool"
	"github.com/argus-platform/argus/internal/collector/stream"
	"github.com/argus-platform/argus/internal/collector/transport"
)

// stopStream takes the collector stream listener down (server outage
// simulation). The enrollment listener stays up.
func (e *m3Env) stopStream() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.streamSrv.Stop()
}

func openSpool(t *testing.T, dir string) *spool.Spool {
	t.Helper()
	sp, err := spool.Open(spool.Options{Dir: dir, MaxBytes: 8 << 20, FsyncInterval: 0})
	if err != nil {
		t.Fatalf("spool open: %v", err)
	}
	t.Cleanup(func() { _ = sp.Close() })
	return sp
}

func appendTestBatches(t *testing.T, sp *spool.Spool, n int, base time.Time) {
	t.Helper()
	for i := 1; i <= n; i++ {
		_, err := sp.Append(&spool.Batch{
			At: base,
			Samples: []spool.Sample{{
				MetricKey:  "collector_cpu_percent",
				Unit:       "percent",
				Value:      float64(10 + i),
				Ts:         base.Add(time.Duration(i) * time.Second),
				Dimensions: map[string]string{"cpu": "total"},
			}},
		})
		must(t, err)
	}
}

// startTelemetryClient runs the real M3 stream client with the M4b sender as
// its telemetry source. Returns a stop function.
func startTelemetryClient(t *testing.T, env *m3Env, id collectoridentity.Identity, store *collectoridentity.Store, sender *transport.Sender) func() {
	t.Helper()
	machine := collector.NewMachine(collector.StateNew, nil)
	must(t, machine.Transition(collector.StateReconnecting))
	certPath, keyPath, _, _ := store.Paths()
	keyDER, err := base64.StdEncoding.DecodeString(id.PolicyKeyDERB64)
	must(t, err)
	client := stream.New(stream.Config{
		StreamAddr:   env.streamAddr,
		CAFile:       env.caFile,
		CertFile:     certPath,
		KeyFile:      keyPath,
		CollectorID:  id.CollectorID,
		PolicyDir:    t.TempDir(),
		PolicyKeyDER: keyDER,
		Telemetry:    sender,
	}, machine)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = client.Run(ctx)
	}()
	stop := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("telemetry client did not stop in time")
		}
	}
	t.Cleanup(stop)
	return stop
}

func waitSpoolDrained(t *testing.T, sp *spool.Spool, timeout time.Duration) spool.Stats {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var st spool.Stats
	for time.Now().Before(deadline) {
		st = sp.Stats()
		if st.HighestSeq > 0 && st.AckedSeq >= st.HighestSeq && st.Records == 0 {
			return st
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("spool did not drain within %s: %+v", timeout, st)
	return st
}

// TestM4CollectorSpoolSurvivesOutageAndDrains is the mandated T2/T3 proof:
// producer -> spool while the server is down; batches retained (nothing sent
// durably); server returns; spool drains; every batch lands exactly once.
func TestM4CollectorSpoolSurvivesOutageAndDrains(t *testing.T) {
	ctx := context.Background()
	env := startM3Env(t)
	orgID, siteID, userID := devTenant(t, "m4b-outage-"+newUUID()[:8])
	token, _, _, err := env.svc.CreateEnrollmentToken(ctx,
		mustUUID(t, orgID), mustUUID(t, siteID), time.Hour, uuidPtr(mustUUID(t, userID)))
	must(t, err)
	id, store := env.enrollIdentity(t, "collector-outage", token)

	sp := openSpool(t, t.TempDir())
	env.stopStream()

	sender := transport.NewSender(sp, filepath.Join(t.TempDir(), "deadletter"), nil)
	t.Cleanup(sender.Close)
	stop := startTelemetryClient(t, env, id, store, sender)
	defer stop()

	base := time.Now().UTC().Truncate(time.Second)
	appendTestBatches(t, sp, 5, base)

	// While the stream is down nothing can be acknowledged.
	time.Sleep(700 * time.Millisecond)
	st := sp.Stats()
	if st.AckedSeq != 0 {
		t.Fatalf("acked while the server was down: %+v", st)
	}
	if st.Records != 5 || st.DroppedRecordsTotal != 0 {
		t.Fatalf("spool during outage: %+v", st)
	}

	// Server returns; the spool must drain completely.
	env.restartStream(t)
	waitSpoolDrained(t, sp, 25*time.Second)

	var batches, samples int
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM ingested_batches WHERE collector_id = $1`, id.CollectorID).Scan(&batches))
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM metric_samples WHERE org_id = $1`, mustUUID(t, orgID)).Scan(&samples))
	if batches != 5 || samples != 5 {
		t.Fatalf("ingested batches=%d samples=%d (want 5/5)", batches, samples)
	}
	if got := sender.Stats(); got.BatchesOK != 5 || got.BatchesDuplicate != 0 {
		t.Fatalf("sender stats after outage drain: %+v", got)
	}
}

// TestM4CollectorRestartResumesFromWatermark is the T10/AC-13 proof: the
// durable watermark survives a process restart; acked records stay retired;
// new records drain without duplicates.
func TestM4CollectorRestartResumesFromWatermark(t *testing.T) {
	ctx := context.Background()
	env := startM3Env(t)
	orgID, siteID, userID := devTenant(t, "m4b-restart-"+newUUID()[:8])
	token, _, _, err := env.svc.CreateEnrollmentToken(ctx,
		mustUUID(t, orgID), mustUUID(t, siteID), time.Hour, uuidPtr(mustUUID(t, userID)))
	must(t, err)
	id, store := env.enrollIdentity(t, "collector-restart", token)

	dir := t.TempDir()
	base := time.Now().UTC().Truncate(time.Second)

	// Phase 1: first two batches drain.
	sp1 := openSpool(t, dir)
	appendTestBatches(t, sp1, 2, base)
	sender1 := transport.NewSender(sp1, filepath.Join(dir, "deadletter"), nil)
	stop1 := startTelemetryClient(t, env, id, store, sender1)
	waitSpoolDrained(t, sp1, 25*time.Second)
	stop1()
	sender1.Close()
	must(t, sp1.Close())

	// Phase 2: "process restart" reopens the same spool directory.
	sp2 := openSpool(t, dir)
	st := sp2.Stats()
	if st.AckedSeq != 2 || st.HighestSeq != 2 || st.Records != 0 {
		t.Fatalf("watermark not durable across restart: %+v", st)
	}
	appendTestBatches(t, sp2, 2, base.Add(time.Minute))
	sender2 := transport.NewSender(sp2, filepath.Join(dir, "deadletter"), nil)
	t.Cleanup(sender2.Close)
	stop2 := startTelemetryClient(t, env, id, store, sender2)
	waitSpoolDrained(t, sp2, 25*time.Second)
	stop2()

	var batches, samples int
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM ingested_batches WHERE collector_id = $1`, id.CollectorID).Scan(&batches))
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM metric_samples WHERE org_id = $1`, mustUUID(t, orgID)).Scan(&samples))
	if batches != 4 || samples != 4 {
		t.Fatalf("after restart drain: batches=%d samples=%d (want 4/4)", batches, samples)
	}
	if got := sender2.Stats(); got.BatchesDuplicate != 0 || got.BatchesOK != 2 {
		t.Fatalf("second run sender stats: %+v", got)
	}
	// Sequence continuity: 1..4 exactly once.
	var missing int
	must(t, ownerPool.QueryRow(ctx, `
		SELECT count(*) FROM generate_series(1,4) s(seq)
		WHERE NOT EXISTS (
			SELECT 1 FROM ingested_batches b WHERE b.collector_id = $1 AND b.batch_seq = s.seq
		)`, id.CollectorID).Scan(&missing))
	if missing != 0 {
		t.Fatalf("missing batch sequences after restart: %d", missing)
	}
}

// TestM4LostAckReplayedAsDuplicate is the lost-ack proof: the server commits
// and the collector never processes the ack; the next session re-sends the
// same batch bytes, the server reports DUPLICATE, and only then is the record
// retired — original values remain authoritative.
func TestM4LostAckReplayedAsDuplicate(t *testing.T) {
	ctx := context.Background()
	env := startM3Env(t)
	orgID, siteID, userID := devTenant(t, "m4b-lostack-"+newUUID()[:8])
	token, _, _, err := env.svc.CreateEnrollmentToken(ctx,
		mustUUID(t, orgID), mustUUID(t, siteID), time.Hour, uuidPtr(mustUUID(t, userID)))
	must(t, err)
	id, store := env.enrollIdentity(t, "collector-lostack", token)

	sp := openSpool(t, t.TempDir())
	base := time.Now().UTC().Truncate(time.Second)
	appendTestBatches(t, sp, 1, base) // value 11, ts base+1s

	sender := transport.NewSender(sp, filepath.Join(t.TempDir(), "deadletter"), nil)
	t.Cleanup(sender.Close)
	rs := dialBatchStream(t, env, id, store)

	// First delivery: send, receive OK, then "lose" the ack (never call
	// sender.BatchResult).
	sender.SessionStart(nil)
	b1, ok := sender.NextBatch()
	if !ok || b1.GetBatchSeq() != 1 {
		t.Fatalf("first pull: %+v ok=%v", b1, ok)
	}
	rs.send(t, b1.GetBatchSeq(), b1.GetSamples())
	res1 := rs.result(t)
	if res1.GetStatus() != collectorv1.BatchResult_STATUS_OK {
		t.Fatalf("first delivery: %v", res1.GetStatus())
	}
	if sp.Watermark() != 0 {
		t.Fatalf("watermark advanced without a processed ack: %d", sp.Watermark())
	}

	// New session (reconnect): the same durable record is re-sent.
	sender.SessionStart(nil)
	b2, ok := sender.NextBatch()
	if !ok || b2.GetBatchSeq() != 1 {
		t.Fatalf("resend pull: %+v ok=%v", b2, ok)
	}
	rs.send(t, b2.GetBatchSeq(), b2.GetSamples())
	res2 := rs.result(t)
	if res2.GetStatus() != collectorv1.BatchResult_STATUS_DUPLICATE {
		t.Fatalf("replay: %v (want DUPLICATE)", res2.GetStatus())
	}
	// Only the DUPLICATE acknowledgement retires the record.
	sender.BatchResult(res2)
	if sp.Watermark() != 1 {
		t.Fatalf("watermark after duplicate ack: %d", sp.Watermark())
	}
	if got := sender.Stats(); got.BatchesDuplicate != 1 {
		t.Fatalf("sender stats: %+v", got)
	}

	// Exactly one batch row and one sample; the original value is intact.
	var batches, samples int
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM ingested_batches WHERE collector_id = $1`, id.CollectorID).Scan(&batches))
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM metric_samples WHERE org_id = $1`, mustUUID(t, orgID)).Scan(&samples))
	if batches != 1 || samples != 1 {
		t.Fatalf("rows after lost-ack replay: batches=%d samples=%d (want 1/1)", batches, samples)
	}
	var value float64
	must(t, ownerPool.QueryRow(ctx, `
		SELECT ms.value FROM metric_samples ms
		JOIN metric_series s ON s.id = ms.series_id
		WHERE ms.org_id = $1`, mustUUID(t, orgID)).Scan(&value))
	if value != 11 {
		t.Fatalf("sample value = %v (want the original 11)", value)
	}
}
