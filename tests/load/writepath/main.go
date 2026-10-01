// Command writepath is the ADR-016 measurement harness.
//
// It drives the *real* ingest.Service against a database (dev stack or any
// Postgres with the Argus schema) using the runtime app role, so the measured
// numbers include RLS, the batch claim, series resolution, the sample write,
// series touch and the chunk-RLS sweep — i.e. the exact production path.
//
// Variants (all preserve ack-after-commit and ON CONFLICT idempotency):
//
//	unnest   current path: one INSERT ... SELECT FROM unnest($arrays)
//	staging  candidate: COPY (binary) into a per-session temp table, then
//	         INSERT ... SELECT ... ON CONFLICT DO NOTHING, cleaned per batch
//
// The harness is evidence tooling for docs/phase-2/M8_EVIDENCE.md; it is not
// part of the server.
//
// Example (dev stack, owner DSN for fixtures + app DSN for the measured path):
//
//	go run ./tests/load/writepath \
//	  -owner-dsn "postgres://argus_owner:dev-db-change-me@127.0.0.1:5432/argus?sslmode=disable" \
//	  -app-dsn   "postgres://argus_app_login:dev-db-change-me@127.0.0.1:5432/argus?sslmode=disable" \
//	  -variant unnest -batch 2000 -batches 60 -parallel 1
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
	"github.com/argus-platform/argus/internal/modules/ingest"
	"github.com/argus-platform/argus/internal/modules/metrics"
	"github.com/argus-platform/argus/internal/platform/database"
)

func main() { os.Exit(run()) }

type config struct {
	ownerDSN string
	appDSN   string
	variant  string
	batch    int
	batches  int
	parallel int
	jsonOut  string
	verbose  bool
	recent   bool
}

func run() int {
	var cfg config
	flag.StringVar(&cfg.ownerDSN, "owner-dsn", "", "owner DSN (fixture setup)")
	flag.StringVar(&cfg.appDSN, "app-dsn", "", "runtime app DSN (measured path)")
	flag.StringVar(&cfg.variant, "variant", "unnest", "unnest|staging")
	flag.IntVar(&cfg.batch, "batch", 2000, "samples per batch")
	flag.IntVar(&cfg.batches, "batches", 40, "total batches to ingest")
	flag.IntVar(&cfg.parallel, "parallel", 1, "concurrent batch transactions")
	flag.StringVar(&cfg.jsonOut, "json", "", "write summary JSON")
	flag.BoolVar(&cfg.verbose, "verbose", false, "log ingest errors")
	flag.BoolVar(&cfg.recent, "recent", false, "workers use overlapping recent timestamps (models concurrent batches of one collector)")
	flag.Parse()
	if cfg.ownerDSN == "" || cfg.appDSN == "" {
		fmt.Fprintln(os.Stderr, "-owner-dsn and -app-dsn are required")
		return 2
	}
	if cfg.batch < 1 || cfg.batch > ingest.MaxBatchSamples {
		fmt.Fprintf(os.Stderr, "batch must be within [1,%d]\n", ingest.MaxBatchSamples)
		return 2
	}

	ctx := context.Background()
	owner, err := pgxpool.New(ctx, cfg.ownerDSN)
	if err != nil {
		fmt.Fprintln(os.Stderr, "owner pool:", err)
		return 1
	}
	defer owner.Close()
	app, err := database.NewPool(ctx, cfg.appDSN, "writepath-bench", database.DefaultPoolConfig())
	if err != nil {
		fmt.Fprintln(os.Stderr, "app pool:", err)
		return 1
	}
	defer app.Close()

	orgID, collectorID, err := seedFixture(ctx, owner)
	if err != nil {
		fmt.Fprintln(os.Stderr, "seed:", err)
		return 1
	}

	var store metrics.Store = metrics.TimescaleStore{}
	switch cfg.variant {
	case "unnest":
	case "staging":
		store = stagingStore{}
	default:
		fmt.Fprintf(os.Stderr, "unknown variant %q\n", cfg.variant)
		return 2
	}

	var log *slog.Logger
	if cfg.verbose {
		log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	svc := ingest.New(app, store, nil, log)
	allowlist := map[string]ingest.MetricDef{
		"collector_cpu_percent": {Key: "collector_cpu_percent", Unit: "percent"},
	}

	base := time.Now().UTC().Add(-time.Hour)
	workerWindow := time.Hour
	if cfg.recent {
		// Concurrent batches of one collector carry near-identical timestamps;
		// all workers then race on the same metric_series.last_seen_at row.
		// Microsecond offsets keep every (series_id, ts) row unique while the
		// touch predicate still fires on every batch.
		base = time.Now().UTC().Add(-2 * time.Minute)
		workerWindow = time.Microsecond
	}
	durations := make([]time.Duration, 0, cfg.batches)
	var mu sync.Mutex
	var acceptedSamples int64
	var failed int64

	work := make(chan int, cfg.batches)
	for i := 0; i < cfg.batches; i++ {
		work <- i
	}
	close(work)

	start := time.Now()
	var wg sync.WaitGroup
	for w := 0; w < cfg.parallel; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := range work {
				seq := int64(w)*1_000_000 + int64(i) + 1
				batch := buildBatch(int64(i), seq, cfg.batch, base.Add(time.Duration(w)*workerWindow))
				t0 := time.Now()
				out := svc.IngestBatch(ctx, orgID, collectorID, allowlist, batch)
				d := time.Since(t0)
				mu.Lock()
				durations = append(durations, d)
				mu.Unlock()
				if out.Status != collectorv1.BatchResult_STATUS_OK {
					mu.Lock()
					failed++
					mu.Unlock()
					fmt.Fprintf(os.Stderr, "batch %d: status=%v reason=%q\n", seq, out.Status, out.Reason)
					continue
				}
				mu.Lock()
				acceptedSamples += int64(out.Accepted)
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()
	elapsed := time.Since(start)

	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	pct := func(p float64) float64 {
		if len(durations) == 0 {
			return 0
		}
		idx := int(p / 100 * float64(len(durations)))
		if idx >= len(durations) {
			idx = len(durations) - 1
		}
		return float64(durations[idx].Microseconds()) / 1000
	}
	rate := float64(acceptedSamples) / elapsed.Seconds()
	fmt.Printf("variant=%s batch=%d parallel=%d batches=%d elapsed=%.2fs\n", cfg.variant, cfg.batch, cfg.parallel, cfg.batches, elapsed.Seconds())
	fmt.Printf("samples accepted=%d failed=%d achieved=%.0f samples/s\n", acceptedSamples, failed, rate)
	fmt.Printf("batch latency: p50=%.1fms p95=%.1fms p99=%.1fms max=%.1fms\n",
		pct(50), pct(95), pct(99), float64(durations[len(durations)-1].Microseconds())/1000)
	if cfg.jsonOut != "" {
		out := fmt.Sprintf(`{"variant":%q,"batch":%d,"parallel":%d,"batches":%d,"elapsed_s":%.3f,"samples_accepted":%d,"failed":%d,"achieved_samples_per_s":%.1f,"p50_ms":%.1f,"p95_ms":%.1f,"p99_ms":%.1f}`,
			cfg.variant, cfg.batch, cfg.parallel, cfg.batches, elapsed.Seconds(), acceptedSamples, failed, rate, pct(50), pct(95), pct(99))
		if err := os.WriteFile(cfg.jsonOut, []byte(out+"\n"), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "write json:", err)
			return 1
		}
	}
	if failed > 0 {
		return 1
	}
	return 0
}

// seedFixture creates an isolated org/site/collector/series for one run.
func seedFixture(ctx context.Context, owner *pgxpool.Pool) (uuid.UUID, uuid.UUID, error) {
	orgID, siteID, collectorID := uuid.New(), uuid.New(), uuid.New()
	if _, err := owner.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $3)`,
		orgID, "writepath bench", "writepath-"+orgID.String()[:8]); err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("org: %w", err)
	}
	if _, err := owner.Exec(ctx, `INSERT INTO sites (id, org_id, name) VALUES ($1, $2, 'HQ')`, siteID, orgID); err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("site: %w", err)
	}
	if _, err := owner.Exec(ctx, `INSERT INTO collectors (id, org_id, site_id, name) VALUES ($1, $2, $3, $4)`,
		collectorID, orgID, siteID, "writepath-"+collectorID.String()[:8]); err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("collector: %w", err)
	}
	if _, err := owner.Exec(ctx, `INSERT INTO metric_series (org_id, collector_id, metric_key, dimensions, dim_hash, unit)
		VALUES ($1, $2, 'collector_cpu_percent', '{}'::jsonb, 1, 'percent')`, orgID, collectorID); err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("series: %w", err)
	}
	return orgID, collectorID, nil
}

func buildBatch(i, seq int64, size int, base time.Time) *collectorv1.MetricBatch {
	samples := make([]*collectorv1.MetricSample, size)
	for j := 0; j < size; j++ {
		samples[j] = &collectorv1.MetricSample{
			MetricKey:  "collector_cpu_percent",
			Value:      50 + 20*math.Sin(float64(i*int64(size)+int64(j))/97.0),
			Unit:       "percent",
			Dimensions: map[string]string{"cpu": "total"},
			Ts:         timestamppb.New(base.Add(time.Duration(i*int64(size)+int64(j)) * time.Millisecond)),
		}
	}
	return &collectorv1.MetricBatch{BatchSeq: seq, Samples: samples, CreatedAt: timestamppb.Now()}
}

// stagingStore is the candidate ADR-016 path: binary COPY into a session-local
// temp table, then one set-based INSERT ... SELECT ... ON CONFLICT DO NOTHING
// into the hypertable. The temp table is truncated at the start of every batch
// transaction (so a rolled-back batch can never leak rows into the next one)
// and again cleaned by ON COMMIT DELETE ROWS on success.
type stagingStore struct{ metrics.TimescaleStore }

func (stagingStore) InsertSamples(ctx context.Context, tx pgx.Tx, samples []metrics.Sample) (int64, error) {
	if len(samples) == 0 {
		return 0, nil
	}
	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE IF NOT EXISTS argus_ingest_staging (
		org_id uuid, series_id bigint, ts timestamptz, value double precision
	) ON COMMIT DELETE ROWS`); err != nil {
		return 0, fmt.Errorf("metrics: create staging: %w", err)
	}
	// A previous failed transaction may have left rows behind (rollback does
	// not run ON COMMIT DELETE ROWS); clear them before use.
	if _, err := tx.Exec(ctx, `TRUNCATE argus_ingest_staging`); err != nil {
		return 0, fmt.Errorf("metrics: truncate staging: %w", err)
	}
	src := pgx.CopyFromSlice(len(samples), func(i int) ([]any, error) {
		s := samples[i]
		return []any{s.OrgID, s.SeriesID, s.Ts, s.Value}, nil
	})
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"argus_ingest_staging"},
		[]string{"org_id", "series_id", "ts", "value"}, src); err != nil {
		return 0, fmt.Errorf("metrics: copy staging: %w", err)
	}
	tag, err := tx.Exec(ctx, `INSERT INTO metric_samples (org_id, series_id, ts, value)
		SELECT org_id, series_id, ts, value FROM argus_ingest_staging
		ON CONFLICT (series_id, ts) DO NOTHING`)
	if err != nil {
		return 0, fmt.Errorf("metrics: insert from staging: %w", err)
	}
	return tag.RowsAffected(), nil
}
