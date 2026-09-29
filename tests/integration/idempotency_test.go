package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/argus-platform/argus/internal/platform/database"
)

// The helpers below mirror the exact M4-ingest SQL (SPEC §12.1) so the
// idempotency contract is tested against the real constraints and indexes.

// claimBatch returns (inserted=false, nil) on a duplicate batch.
func claimBatch(ctx context.Context, tx pgx.Tx, collectorID, orgID string, seq int64, sampleCount int, ts time.Time) (bool, error) {
	var got int64
	err := tx.QueryRow(ctx, `
		INSERT INTO ingested_batches (collector_id, batch_seq, org_id, sample_count, first_ts, last_ts)
		VALUES ($1, $2, $3, $4, $5, $5)
		ON CONFLICT (collector_id, batch_seq) DO NOTHING
		RETURNING batch_seq`,
		collectorID, seq, orgID, sampleCount, ts).Scan(&got)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// insertSeries upserts via the partial unique index (device_id IS NULL branch)
// and returns the existing id on conflict — the M4 resolve/insert pattern.
func insertSeries(ctx context.Context, tx pgx.Tx, orgID, collectorID, metricKey string, dimHash int64) (int64, error) {
	var id int64
	err := tx.QueryRow(ctx, `
		INSERT INTO metric_series (org_id, collector_id, metric_key, dimensions, dim_hash, unit)
		VALUES ($1, $2, $3, '{}'::jsonb, $4, 'percent')
		ON CONFLICT (org_id, collector_id, metric_key, dim_hash) WHERE device_id IS NULL DO NOTHING
		RETURNING id`,
		orgID, collectorID, metricKey, dimHash).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `
			SELECT id FROM metric_series
			WHERE org_id = $1 AND collector_id = $2 AND metric_key = $3 AND dim_hash = $4 AND device_id IS NULL`,
			orgID, collectorID, metricKey, dimHash).Scan(&id)
	}
	return id, err
}

// insertSample mirrors the M4 sample write (ON CONFLICT DO NOTHING).
func insertSample(ctx context.Context, tx pgx.Tx, orgID string, seriesID int64, ts time.Time, value float64) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO metric_samples (org_id, series_id, ts, value)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (series_id, ts) DO NOTHING`,
		orgID, seriesID, ts, value)
	return err
}

func TestBatchClaimIdempotency(t *testing.T) {
	ctx := context.Background()
	tn := seedTenant(t, "idem-batch")
	ts := time.Now().UTC().Truncate(time.Second)

	must(t, database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
		inserted, err := claimBatch(ctx, tx, tn.CollectorID, tn.OrgID, 1001, 1, ts)
		if err != nil {
			return err
		}
		if !inserted {
			return errors.New("first claim reported duplicate")
		}
		return nil
	}))

	must(t, database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
		inserted, err := claimBatch(ctx, tx, tn.CollectorID, tn.OrgID, 1001, 1, ts)
		if err != nil {
			return err
		}
		if inserted {
			return errors.New("replayed claim accepted as new")
		}
		return nil
	}))

	var n int
	must(t, database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM ingested_batches WHERE collector_id = $1 AND batch_seq = 1001`,
			tn.CollectorID).Scan(&n)
	}))
	if n != 1 {
		t.Fatalf("batch ledger rows = %d, want exactly 1", n)
	}
}

func TestSampleUpsertIdempotencyOriginalWins(t *testing.T) {
	ctx := context.Background()
	tn := seedTenant(t, "idem-sample")

	// Duplicate delivery of the same logical sample with a different value.
	must(t, database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
		return insertSample(ctx, tx, tn.OrgID, tn.SeriesID, tn.SampleTS, 99)
	}))

	var count int
	var value float64
	must(t, database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*), max(value) FROM metric_samples WHERE series_id = $1 AND ts = $2`,
			tn.SeriesID, tn.SampleTS).Scan(&count, &value)
	}))
	if count != 1 {
		t.Fatalf("sample rows = %d, want 1 (idempotent)", count)
	}
	if value != 42 {
		t.Fatalf("sample value = %v, want the original 42 (duplicate must not overwrite)", value)
	}
}

func TestSeriesUpsertIdempotencyPartialIndexInference(t *testing.T) {
	ctx := context.Background()
	tn := seedTenant(t, "idem-series")

	var existing, other, again int64
	must(t, database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
		var err error
		existing, err = insertSeries(ctx, tx, tn.OrgID, tn.CollectorID, "collector_cpu_percent", 1)
		if err != nil {
			return err
		}
		other, err = insertSeries(ctx, tx, tn.OrgID, tn.CollectorID, "collector_cpu_percent", 2)
		if err != nil {
			return err
		}
		again, err = insertSeries(ctx, tx, tn.OrgID, tn.CollectorID, "collector_cpu_percent", 1)
		return err
	}))

	if existing != tn.SeriesID {
		t.Fatalf("conflicting series id = %d, want the seeded series %d", existing, tn.SeriesID)
	}
	if other == existing {
		t.Fatal("distinct dim_hash must create a distinct series")
	}
	if again != existing {
		t.Fatalf("repeat lookup returned %d, want %d", again, existing)
	}

	var n int
	must(t, database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM metric_series WHERE collector_id = $1`, tn.CollectorID).Scan(&n)
	}))
	if n != 2 {
		t.Fatalf("series rows = %d, want 2", n)
	}
}

func TestFullBatchReplayIsEffectivelyOnce(t *testing.T) {
	ctx := context.Background()
	tn := seedTenant(t, "idem-replay")
	ts := time.Now().UTC().Truncate(time.Second).Add(time.Minute)
	seq := int64(2001)

	unit := func(ctx context.Context, tx pgx.Tx, value float64) error {
		inserted, err := claimBatch(ctx, tx, tn.CollectorID, tn.OrgID, seq, 1, ts)
		if err != nil {
			return err
		}
		if !inserted {
			return nil // duplicate batch: M4 replies STATUS_DUPLICATE and does no sample work
		}
		sid, err := insertSeries(ctx, tx, tn.OrgID, tn.CollectorID, "collector_cpu_percent", 1)
		if err != nil {
			return err
		}
		return insertSample(ctx, tx, tn.OrgID, sid, ts, value)
	}

	must(t, database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
		return unit(ctx, tx, 11)
	}))
	// Replay the identical batch with a different payload.
	must(t, database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
		return unit(ctx, tx, 77)
	}))

	var samples int
	var value float64
	var batches int
	must(t, database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`SELECT count(*), max(value) FROM metric_samples WHERE series_id = $1 AND ts = $2`,
			tn.SeriesID, ts).Scan(&samples, &value); err != nil {
			return err
		}
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM ingested_batches WHERE collector_id = $1 AND batch_seq = $2`,
			tn.CollectorID, seq).Scan(&batches)
	}))
	if samples != 1 || value != 11 || batches != 1 {
		t.Fatalf("replay not effectively-once: samples=%d value=%v batches=%d (want 1/ 11 /1)", samples, value, batches)
	}
}
