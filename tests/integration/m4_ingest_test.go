package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
	collectoridentity "github.com/argus-platform/argus/internal/collector/identity"
	"github.com/argus-platform/argus/internal/modules/ingest"
	"github.com/argus-platform/argus/internal/modules/metrics"
	"github.com/argus-platform/argus/internal/platform/database"
)

// rawBatchStream is a minimal M4-era stream client: hello, then metric
// batches, reading BatchResults (used instead of the control-only
// collector/stream client, which does not produce telemetry yet).
type rawBatchStream struct {
	stream collectorv1.CollectorService_StreamClient
}

func m4Env(t *testing.T, slug string) (*m3Env, collectoridentity.Identity, *collectoridentity.Store, string) {
	t.Helper()
	env := startM3Env(t)
	orgID, siteID, userID := devTenant(t, slug)
	raw, _, _, err := env.svc.CreateEnrollmentToken(context.Background(),
		mustUUID(t, orgID), mustUUID(t, siteID), time.Hour, uuidPtr(mustUUID(t, userID)))
	must(t, err)
	id, store := env.enrollIdentity(t, "collector-"+slug, raw)
	return env, id, store, orgID
}

func uuidPtr(id uuid.UUID) *uuid.UUID { return &id }

func dialBatchStream(t *testing.T, env *m3Env, id collectoridentity.Identity, store *collectoridentity.Store) *rawBatchStream {
	t.Helper()
	certPath, keyPath, _, _ := store.Paths()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(env.ca.RootPEM()) {
		t.Fatal("CA PEM parse failed")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	must(t, err)
	conn, err := grpc.NewClient(env.streamAddr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	})))
	must(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	client := collectorv1.NewCollectorServiceClient(conn)
	gstream, err := client.Stream(ctx)
	must(t, err)
	must(t, gstream.Send(&collectorv1.ClientMessage{
		Msg: &collectorv1.ClientMessage_Hello{Hello: &collectorv1.ClientHello{
			CollectorId:     id.CollectorID,
			AgentVersion:    "it-m4",
			ProtocolVersion: 1,
		}},
	}))
	first, err := gstream.Recv()
	must(t, err)
	if first.GetHello() == nil {
		t.Fatalf("expected ServerHello, got %T", first.GetMsg())
	}
	return &rawBatchStream{stream: gstream}
}

func (r *rawBatchStream) send(t *testing.T, seq int64, samples []*collectorv1.MetricSample) {
	t.Helper()
	must(t, r.stream.Send(&collectorv1.ClientMessage{
		Msg: &collectorv1.ClientMessage_Batch{Batch: &collectorv1.MetricBatch{
			BatchSeq:  seq,
			Samples:   samples,
			CreatedAt: timestamppb.Now(),
		}},
	}))
}

func (r *rawBatchStream) result(t *testing.T) *collectorv1.BatchResult {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		msg, err := r.stream.Recv()
		must(t, err)
		if br := msg.GetBatchResult(); br != nil {
			return br
		}
	}
	t.Fatal("no BatchResult within deadline")
	return nil
}

func m4Sample(value float64, dims map[string]string, ts time.Time) *collectorv1.MetricSample {
	return &collectorv1.MetricSample{
		MetricKey:  "collector_cpu_percent",
		Value:      value,
		Unit:       "percent",
		Dimensions: dims,
		Ts:         timestamppb.New(ts),
	}
}

func TestM4BatchIngestHappyPath(t *testing.T) {
	ctx := context.Background()
	env, id, store, orgID := m4Env(t, "m4-happy-"+newUUID()[:8])
	rs := dialBatchStream(t, env, id, store)

	now := time.Now().UTC().Truncate(time.Second)
	rs.send(t, 1, []*collectorv1.MetricSample{
		m4Sample(12.5, map[string]string{"cpu": "total"}, now),
		m4Sample(7.0, map[string]string{"cpu": "total"}, now.Add(-5*time.Second)),
		m4Sample(42.0, map[string]string{"cpu": "0"}, now),
	})
	res := rs.result(t)
	if res.GetStatus() != collectorv1.BatchResult_STATUS_OK {
		t.Fatalf("status = %v, reason = %q", res.GetStatus(), res.GetReason())
	}
	if res.GetAcceptedSamples() != 3 || res.GetRejectedSamples() != 0 {
		t.Fatalf("accounting: accepted=%d rejected=%d", res.GetAcceptedSamples(), res.GetRejectedSamples())
	}
	if !res.GetIngestedAt().IsValid() {
		t.Fatal("ingested_at must be set on OK")
	}

	var batches, series, samples int
	collectorID := id.CollectorID
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM ingested_batches WHERE collector_id = $1`, collectorID).Scan(&batches))
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM metric_series WHERE collector_id = $1`, collectorID).Scan(&series))
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM metric_samples WHERE org_id = $1`, mustUUID(t, orgID)).Scan(&samples))
	if batches != 1 || series != 2 || samples != 3 {
		t.Fatalf("db state: batches=%d series=%d samples=%d (want 1/2/3)", batches, series, samples)
	}

	var first, last time.Time
	var count int
	must(t, ownerPool.QueryRow(ctx, `
		SELECT first_ts, last_ts, sample_count FROM ingested_batches
		WHERE collector_id = $1 AND batch_seq = 1`, collectorID).Scan(&first, &last, &count))
	if count != 3 || last.Sub(first) != 5*time.Second {
		t.Fatalf("batch ledger: count=%d span=%s (want 3, 5s)", count, last.Sub(first))
	}
}

func TestM4DuplicateBatchOriginalWins(t *testing.T) {
	ctx := context.Background()
	env, id, store, orgID := m4Env(t, "m4-dup-"+newUUID()[:8])
	rs := dialBatchStream(t, env, id, store)

	now := time.Now().UTC().Truncate(time.Second)
	rs.send(t, 1, []*collectorv1.MetricSample{m4Sample(5, map[string]string{"cpu": "total"}, now)})
	if res := rs.result(t); res.GetStatus() != collectorv1.BatchResult_STATUS_OK {
		t.Fatalf("first delivery status = %v", res.GetStatus())
	}
	// Same batch_seq, different value: must be DUPLICATE and must not overwrite.
	rs.send(t, 1, []*collectorv1.MetricSample{m4Sample(99, map[string]string{"cpu": "total"}, now)})
	res := rs.result(t)
	if res.GetStatus() != collectorv1.BatchResult_STATUS_DUPLICATE {
		t.Fatalf("replay status = %v (want DUPLICATE)", res.GetStatus())
	}

	var batches int
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM ingested_batches WHERE collector_id = $1`, id.CollectorID).Scan(&batches))
	if batches != 1 {
		t.Fatalf("ledger rows = %d (want exactly 1)", batches)
	}
	var value float64
	must(t, ownerPool.QueryRow(ctx, `
		SELECT ms.value FROM metric_samples ms
		JOIN metric_series s ON s.id = ms.series_id
		WHERE ms.org_id = $1`, mustUUID(t, orgID)).Scan(&value))
	if value != 5 {
		t.Fatalf("sample value = %v (original must win over the replayed payload)", value)
	}
}

func TestM4PoisonBatches(t *testing.T) {
	ctx := context.Background()
	env, id, store, orgID := m4Env(t, "m4-poison-"+newUUID()[:8])
	rs := dialBatchStream(t, env, id, store)
	now := time.Now().UTC().Truncate(time.Second)

	bigBatch := make([]*collectorv1.MetricSample, 0, ingest.MaxBatchSamples+1)
	for i := 0; i <= ingest.MaxBatchSamples; i++ {
		bigBatch = append(bigBatch, m4Sample(1, map[string]string{"cpu": "total"}, now))
	}
	dims20 := map[string]string{}
	for i := 0; i < 20; i++ {
		dims20[string(rune('a'+i))] = "v"
	}
	unknown := m4Sample(1, map[string]string{"cpu": "total"}, now)
	unknown.MetricKey = "not_in_policy"
	badUnit := m4Sample(1, map[string]string{"cpu": "total"}, now)
	badUnit.Unit = "bytes"

	cases := []struct {
		name       string
		seq        int64
		samples    []*collectorv1.MetricSample
		wantReason string
	}{
		{"value_out_of_range", 10, []*collectorv1.MetricSample{m4Sample(101, map[string]string{"cpu": "total"}, now)}, "validation.value_out_of_range"},
		{"value_not_finite", 11, []*collectorv1.MetricSample{m4Sample(math.NaN(), map[string]string{"cpu": "total"}, now)}, "validation.value_not_finite"},
		{"ts_out_of_range", 12, []*collectorv1.MetricSample{m4Sample(1, map[string]string{"cpu": "total"}, now.Add(30*24*time.Hour))}, "validation.sample_ts_out_of_range"},
		{"too_many_dimensions", 13, []*collectorv1.MetricSample{m4Sample(1, dims20, now)}, "validation.dimensions_too_many"},
		{"unknown_metric", 14, []*collectorv1.MetricSample{unknown}, "validation.metric_not_allowed"},
		{"batch_too_large", 15, bigBatch, "validation.batch_too_large"},
		{"unit_mismatch", 16, []*collectorv1.MetricSample{badUnit}, "validation.unit_mismatch"},
	}
	seq := int64(100)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rs.send(t, tc.seq, tc.samples)
			res := rs.result(t)
			if res.GetStatus() != collectorv1.BatchResult_STATUS_REJECTED {
				t.Fatalf("status = %v (want REJECTED), reason = %q", res.GetStatus(), res.GetReason())
			}
			if res.GetReason() != tc.wantReason {
				t.Fatalf("reason = %q, want %q", res.GetReason(), tc.wantReason)
			}
			// The stream stays healthy: a valid batch still ingests. Each
			// follow-up uses a distinct ts so the (series_id, ts) sample-level
			// safety net cannot deduplicate them away.
			followTS := now.Add(time.Duration(seq-100) * time.Second)
			rs.send(t, seq, []*collectorv1.MetricSample{m4Sample(3, map[string]string{"cpu": "total"}, followTS)})
			if ok := rs.result(t); ok.GetStatus() != collectorv1.BatchResult_STATUS_OK {
				t.Fatalf("follow-up batch status = %v (stream must stay healthy)", ok.GetStatus())
			}
			seq++
		})
	}

	var samples int
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM metric_samples WHERE org_id = $1`, mustUUID(t, orgID)).Scan(&samples))
	if want := len(cases); samples != want {
		t.Fatalf("samples = %d, want %d (only the follow-up valid batches)", samples, want)
	}
}

func TestM4SeriesQuotaExceeded(t *testing.T) {
	ctx := context.Background()
	env, id, store, orgID := m4Env(t, "m4-quota-"+newUUID()[:8])
	rs := dialBatchStream(t, env, id, store)
	now := time.Now().UTC().Truncate(time.Second)

	flood := make([]*collectorv1.MetricSample, 0, 1001)
	for i := 0; i < 1001; i++ {
		flood = append(flood, m4Sample(1, map[string]string{"cpu": strconv.Itoa(i)}, now))
	}
	rs.send(t, 1, flood)
	res := rs.result(t)
	if res.GetStatus() != collectorv1.BatchResult_STATUS_REJECTED || res.GetReason() != "validation.series_quota_exceeded" {
		t.Fatalf("quota flood: status=%v reason=%q", res.GetStatus(), res.GetReason())
	}
	var series int
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM metric_series WHERE collector_id = $1`, id.CollectorID).Scan(&series))
	if series != 0 {
		t.Fatalf("series rows = %d (quota rejection must roll back all inserts)", series)
	}
	// Small valid batch still works afterwards.
	rs.send(t, 2, []*collectorv1.MetricSample{m4Sample(1, map[string]string{"cpu": "total"}, now)})
	if ok := rs.result(t); ok.GetStatus() != collectorv1.BatchResult_STATUS_OK {
		t.Fatalf("follow-up status = %v", ok.GetStatus())
	}
	_ = orgID
}

// failingStore injects a persist-stage failure to prove RETRY (no ack) and
// full transaction rollback (no ledger row).
type failingStore struct{}

func (failingStore) EnsureSeries(_ context.Context, _ pgx.Tx, _ []metrics.SeriesSpec) (metrics.SeriesResolution, error) {
	return metrics.SeriesResolution{}, errors.New("injected series failure")
}

func (failingStore) EnsureDeviceSeries(_ context.Context, _ pgx.Tx, _ metrics.DeviceSeriesSpec, _ metrics.GuardOptions) (metrics.DeviceSeriesResult, error) {
	return metrics.DeviceSeriesResult{}, errors.New("injected device series failure")
}

func (failingStore) InsertSamples(_ context.Context, _ pgx.Tx, _ []metrics.Sample) (int64, error) {
	return 0, errors.New("injected insert failure")
}

func (failingStore) TouchSeries(_ context.Context, _ pgx.Tx, _ uuid.UUID, _ []int64, _ time.Time) error {
	return errors.New("injected touch failure")
}

func TestM4NoAckBeforeCommitOnDBFailure(t *testing.T) {
	ctx := context.Background()
	env, id, _, orgID := m4Env(t, "m4-retry-"+newUUID()[:8])
	_ = env
	svc := ingest.New(appPool, failingStore{}, nil, nil)
	allowlist := map[string]ingest.MetricDef{"collector_cpu_percent": {Key: "collector_cpu_percent", Unit: "percent"}}
	batch := &collectorv1.MetricBatch{
		BatchSeq: 1,
		Samples: []*collectorv1.MetricSample{
			m4Sample(5, map[string]string{"cpu": "total"}, time.Now().UTC().Truncate(time.Second)),
		},
	}
	out := svc.IngestBatch(ctx, mustUUID(t, orgID), mustUUID(t, id.CollectorID), allowlist, batch)
	if out.Status != collectorv1.BatchResult_STATUS_RETRY || out.Reason != "ingest.db_error" {
		t.Fatalf("outcome = %v/%q (want RETRY/ingest.db_error)", out.Status, out.Reason)
	}
	var batches int
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM ingested_batches WHERE collector_id = $1`, id.CollectorID).Scan(&batches))
	if batches != 0 {
		t.Fatalf("ledger rows = %d: a failed batch must roll back its claim (no ack before commit)", batches)
	}
}

func TestM4MetricTenantIsolation(t *testing.T) {
	ctx := context.Background()
	env, id, store, orgA := m4Env(t, "m4-iso-a-"+newUUID()[:8])
	rs := dialBatchStream(t, env, id, store)
	now := time.Now().UTC().Truncate(time.Second)
	rs.send(t, 1, []*collectorv1.MetricSample{m4Sample(9, map[string]string{"cpu": "total"}, now)})
	if res := rs.result(t); res.GetStatus() != collectorv1.BatchResult_STATUS_OK {
		t.Fatalf("status = %v", res.GetStatus())
	}

	orgB, _, _ := devTenant(t, "m4-iso-b-"+newUUID()[:8])
	must(t, database.WithTenant(ctx, appPool, mustUUID(t, orgB), func(ctx context.Context, tx pgx.Tx) error {
		for _, table := range []string{"metric_series", "metric_samples", "ingested_batches"} {
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&n); err != nil {
				return err
			}
			if n != 0 {
				return fmt.Errorf("org B sees %d rows in %s", n, table)
			}
		}
		return nil
	}))

	var seriesID int64
	must(t, ownerPool.QueryRow(ctx,
		`SELECT id FROM metric_series WHERE org_id = $1 LIMIT 1`, mustUUID(t, orgA)).Scan(&seriesID))
	err := database.WithTenant(ctx, appPool, mustUUID(t, orgB), func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO metric_samples (org_id, series_id, ts, value) VALUES ($1, $2, now(), 1)`,
			mustUUID(t, orgA), seriesID)
		return err
	})
	if pgErrCode(err) != "42501" {
		t.Fatalf("cross-tenant sample insert: want RLS denial (42501), got %v", err)
	}
}
