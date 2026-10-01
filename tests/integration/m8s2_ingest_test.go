package integration

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
	"github.com/argus-platform/argus/internal/modules/ingest"
	"github.com/argus-platform/argus/internal/modules/metrics"
)

// M8-S2a (ADR-016) ingest write-path tests. The optimization is server-side
// batch pipelining: several batches of one collector stream run concurrently
// through the same IngestBatch pipeline. These tests pin the correctness
// guarantees that concurrency must not weaken:
//
//   - concurrent first delivery of a new series never fails on the
//     ensureSeries SELECT/INSERT race (the ADR-016 blocker found on measured
//     evidence);
//   - concurrent duplicate delivery of one batch_seq admits exactly one OK
//     (original wins) and no partial writes;
//   - a failed batch (injected store failure) rolls back its claim and leaves
//     no sample rows, and a retry of the same seq then lands exactly once;
//   - the migration drops only the measured-redundant index.

// TestM8S2ConcurrentFirstDeliveryNoSeriesRace launches several batches for the
// same brand-new collector at once. Before the ADR-016 fix, every losing
// transaction failed with "series ... unresolved after upsert"; now all
// batches must commit OK and share exactly one series row.
func TestM8S2ConcurrentFirstDeliveryNoSeriesRace(t *testing.T) {
	ctx := context.Background()
	env, id, _, orgID := m4Env(t, "m8s2-race-"+newUUID()[:8])
	_ = env
	svc := ingest.New(appPool, nil, nil, nil)
	allowlist := map[string]ingest.MetricDef{
		"collector_cpu_percent": {Key: "collector_cpu_percent", Unit: "percent"},
	}

	const (
		workers = 8
		perW    = 50
	)
	base := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	start := make(chan struct{})
	errs := make(chan string, workers)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			batch := &collectorv1.MetricBatch{BatchSeq: int64(w + 1), CreatedAt: timestamppb.Now()}
			for i := 0; i < perW; i++ {
				batch.Samples = append(batch.Samples, m4Sample(
					float64(i%100), map[string]string{"cpu": "total"},
					base.Add(time.Duration(w*1000+i)*time.Millisecond)))
			}
			out := svc.IngestBatch(ctx, mustUUID(t, orgID), mustUUID(t, id.CollectorID), allowlist, batch)
			if out.Status != collectorv1.BatchResult_STATUS_OK {
				errs <- fmt.Sprintf("worker %d: status=%v reason=%q", w, out.Status, out.Reason)
			}
		}(w)
	}
	close(start)
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}

	var series, samples, batches int
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM metric_series WHERE collector_id = $1`, id.CollectorID).Scan(&series))
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM metric_samples WHERE org_id = $1`, mustUUID(t, orgID)).Scan(&samples))
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM ingested_batches WHERE collector_id = $1`, id.CollectorID).Scan(&batches))
	if series != 1 {
		t.Fatalf("series rows = %d, want exactly 1 (concurrent first delivery must share it)", series)
	}
	if samples != workers*perW {
		t.Fatalf("samples = %d, want %d (no batch may be lost to the race)", samples, workers*perW)
	}
	if batches != workers {
		t.Fatalf("ledger rows = %d, want %d", batches, workers)
	}
}

// TestM8S2ConcurrentDuplicateBatchOriginalWins sends the same batch_seq twice
// concurrently with different payloads. Exactly one delivery may claim it; the
// loser must be DUPLICATE and the stored value must come from the winner.
func TestM8S2ConcurrentDuplicateBatchOriginalWins(t *testing.T) {
	ctx := context.Background()
	env, id, _, orgID := m4Env(t, "m8s2-dup-"+newUUID()[:8])
	_ = env
	svc := ingest.New(appPool, nil, nil, nil)
	allowlist := map[string]ingest.MetricDef{
		"collector_cpu_percent": {Key: "collector_cpu_percent", Unit: "percent"},
	}
	now := time.Now().UTC().Truncate(time.Second)

	values := []float64{11, 77}
	start := make(chan struct{})
	outcomes := make([]ingest.BatchOutcome, len(values))
	var wg sync.WaitGroup
	for i, v := range values {
		wg.Add(1)
		go func(i int, v float64) {
			defer wg.Done()
			<-start
			batch := &collectorv1.MetricBatch{
				BatchSeq:  42,
				CreatedAt: timestamppb.Now(),
				Samples:   []*collectorv1.MetricSample{m4Sample(v, map[string]string{"cpu": "total"}, now)},
			}
			outcomes[i] = svc.IngestBatch(ctx, mustUUID(t, orgID), mustUUID(t, id.CollectorID), allowlist, batch)
		}(i, v)
	}
	close(start)
	wg.Wait()

	ok, dup := 0, 0
	var winner float64
	for i, out := range outcomes {
		switch out.Status {
		case collectorv1.BatchResult_STATUS_OK:
			ok++
			winner = values[i]
		case collectorv1.BatchResult_STATUS_DUPLICATE:
			dup++
		default:
			t.Fatalf("unexpected status %v (reason %q)", out.Status, out.Reason)
		}
	}
	if ok != 1 || dup != 1 {
		t.Fatalf("outcomes: ok=%d duplicate=%d (want exactly 1/1)", ok, dup)
	}

	var samples int
	var value float64
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*), max(value) FROM metric_samples WHERE org_id = $1`,
		mustUUID(t, orgID)).Scan(&samples, &value))
	if samples != 1 {
		t.Fatalf("samples = %d, want exactly 1", samples)
	}
	if value != winner {
		t.Fatalf("stored value = %v, want the winner's %v (original wins, loser must not write)", value, winner)
	}
	var batches int
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM ingested_batches WHERE collector_id = $1`, id.CollectorID).Scan(&batches))
	if batches != 1 {
		t.Fatalf("ledger rows = %d, want exactly 1", batches)
	}
}

// flakyStore fails exactly the first InsertSamples call, then delegates to the
// real TimescaleStore. It models a transient DB failure inside a pipelined
// batch while other batches succeed.
type flakyStore struct {
	metrics.TimescaleStore
	mu    sync.Mutex
	fails int
}

func (f *flakyStore) InsertSamples(ctx context.Context, tx pgx.Tx, samples []metrics.Sample) (int64, error) {
	f.mu.Lock()
	fail := f.fails > 0
	if fail {
		f.fails--
	}
	f.mu.Unlock()
	if fail {
		return 0, errors.New("injected transient insert failure")
	}
	return f.TimescaleStore.InsertSamples(ctx, tx, samples)
}

// TestM8S2FailedBatchLeavesNoStateAndRetryLandsOnce proves the failure cleanup
// contract still holds under the optimized path: a batch whose sample write
// fails must roll back its ledger claim and staged nothing permanently, and a
// retry of the same seq must ingest exactly once.
func TestM8S2FailedBatchLeavesNoStateAndRetryLandsOnce(t *testing.T) {
	ctx := context.Background()
	env, id, _, orgID := m4Env(t, "m8s2-fail-"+newUUID()[:8])
	_ = env
	now := time.Now().UTC().Truncate(time.Second)

	svcFail := ingest.New(appPool, &flakyStore{fails: 1}, nil, nil)
	allowlist := map[string]ingest.MetricDef{
		"collector_cpu_percent": {Key: "collector_cpu_percent", Unit: "percent"},
	}
	failing := &collectorv1.MetricBatch{
		BatchSeq:  7,
		CreatedAt: timestamppb.Now(),
		Samples:   []*collectorv1.MetricSample{m4Sample(5, map[string]string{"cpu": "total"}, now)},
	}
	if out := svcFail.IngestBatch(ctx, mustUUID(t, orgID), mustUUID(t, id.CollectorID), allowlist, failing); out.Status != collectorv1.BatchResult_STATUS_RETRY {
		t.Fatalf("first delivery status = %v (want RETRY)", out.Status)
	}

	var batches, samples int
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM ingested_batches WHERE collector_id = $1 AND batch_seq = 7`, id.CollectorID).Scan(&batches))
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM metric_samples WHERE org_id = $1`, mustUUID(t, orgID)).Scan(&samples))
	if batches != 0 || samples != 0 {
		t.Fatalf("after failed batch: ledger=%d samples=%d (want 0/0 — no claim, no partial write)", batches, samples)
	}

	// Retry the same sequence through the healthy path: exactly once.
	svcOK := ingest.New(appPool, nil, nil, nil)
	retry := &collectorv1.MetricBatch{
		BatchSeq:  7,
		CreatedAt: timestamppb.Now(),
		Samples:   []*collectorv1.MetricSample{m4Sample(9, map[string]string{"cpu": "total"}, now)},
	}
	if out := svcOK.IngestBatch(ctx, mustUUID(t, orgID), mustUUID(t, id.CollectorID), allowlist, retry); out.Status != collectorv1.BatchResult_STATUS_OK {
		t.Fatalf("retry status = %v (want OK)", out.Status)
	}
	var series int
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM metric_series WHERE collector_id = $1`, id.CollectorID).Scan(&series))
	if series != 1 {
		t.Fatalf("series after retry = %d, want 1", series)
	}
	var value float64
	must(t, ownerPool.QueryRow(ctx,
		`SELECT value FROM metric_samples WHERE org_id = $1`, mustUUID(t, orgID)).Scan(&value))
	if value != 9 {
		t.Fatalf("value = %v, want 9", value)
	}
}

// TestM8S2PipelinedGRPCBatchesAckAll exercises the stream-level pipelining:
// several batches are sent back to back before any BatchResult is read; the
// server must accept all of them (any ack order) and ack each exactly once.
func TestM8S2PipelinedGRPCBatchesAckAll(t *testing.T) {
	ctx := context.Background()
	env, id, store, orgID := m4Env(t, "m8s2-pipe-"+newUUID()[:8])
	rs := dialBatchStream(t, env, id, store)
	now := time.Now().UTC().Truncate(time.Second)

	const n = 6
	for seq := int64(1); seq <= n; seq++ {
		rs.send(t, seq, []*collectorv1.MetricSample{
			m4Sample(float64(seq), map[string]string{"cpu": "total"}, now.Add(time.Duration(seq)*time.Second)),
		})
	}
	seen := map[int64]collectorv1.BatchResult_Status{}
	for i := 0; i < n; i++ {
		res := rs.result(t)
		if res.GetStatus() != collectorv1.BatchResult_STATUS_OK {
			t.Fatalf("batch %d: status=%v reason=%q", res.GetBatchSeq(), res.GetStatus(), res.GetReason())
		}
		if _, dup := seen[res.GetBatchSeq()]; dup {
			t.Fatalf("batch %d acked twice", res.GetBatchSeq())
		}
		seen[res.GetBatchSeq()] = res.GetStatus()
	}
	if len(seen) != n {
		t.Fatalf("acked %d distinct batches, want %d", len(seen), n)
	}

	var samples int
	must(t, ownerPool.QueryRow(ctx, `SELECT count(*) FROM metric_samples WHERE org_id = $1`,
		mustUUID(t, orgID)).Scan(&samples))
	if samples != n {
		t.Fatalf("samples = %d, want %d", samples, n)
	}
}

// TestM8S2RedundantIndexDropped pins migration 000014: the duplicate
// (series_id, ts) index is gone; the PK + org/ts indexes remain.
func TestM8S2RedundantIndexDropped(t *testing.T) {
	ctx := context.Background()
	var n int
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM pg_indexes WHERE schemaname='public' AND tablename='metric_samples' AND indexname='metric_samples_series_ts'`).Scan(&n))
	if n != 0 {
		t.Fatalf("metric_samples_series_ts still exists after migration 000014")
	}
	for _, want := range []string{"metric_samples_pk", "metric_samples_org_ts"} {
		must(t, ownerPool.QueryRow(ctx,
			`SELECT count(*) FROM pg_indexes WHERE schemaname='public' AND tablename='metric_samples' AND indexname=$1`, want).Scan(&n))
		if n != 1 {
			t.Fatalf("index %s missing", want)
		}
	}
}
