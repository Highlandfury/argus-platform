package metrics

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Sample is one persisted observation, mapped to one series.
type Sample struct {
	OrgID    uuid.UUID
	SeriesID int64
	Ts       time.Time
	Value    float64
}

// SeriesResolution is the outcome of series resolution: the resolved ids plus
// the keys whose series are quarantined. Ingest drops samples for quarantined
// series only — never for the whole device or collector (docs/08 §13.3).
type SeriesResolution struct {
	IDs         map[string]int64
	Quarantined map[string]bool
}

// NewSeriesResolution returns an empty resolution.
func NewSeriesResolution() SeriesResolution {
	return SeriesResolution{IDs: map[string]int64{}, Quarantined: map[string]bool{}}
}

// Store is the persistence surface the ingest pipeline depends on. The
// TimescaleStore implementation is the only production implementation in
// Phase 1; tests may substitute failing stores for RETRY semantics.
type Store interface {
	// EnsureSeries resolves or creates the given series and returns the
	// resolved ids plus quarantined keys. Must be called inside the batch
	// transaction.
	EnsureSeries(ctx context.Context, tx pgx.Tx, specs []SeriesSpec) (SeriesResolution, error)
	// InsertSamples inserts samples, skipping (series_id, ts) conflicts.
	// Returns the number of rows actually inserted.
	InsertSamples(ctx context.Context, tx pgx.Tx, samples []Sample) (int64, error)
	// TouchSeries advances last_seen_at (and un-retires) the given series.
	// Series metadata, not sample storage: called once per ingest batch after
	// the samples commit so the retirement job has a truthful activity clock.
	TouchSeries(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, seriesIDs []int64, ts time.Time) error
}

// TimescaleStore stores metric data in the metric_samples hypertable.
type TimescaleStore struct{}

// EnsureSeries implements Store.
func (TimescaleStore) EnsureSeries(ctx context.Context, tx pgx.Tx, specs []SeriesSpec) (SeriesResolution, error) {
	return ensureSeries(ctx, tx, specs)
}

const insertSamplesSQL = `INSERT INTO metric_samples (org_id, series_id, ts, value)
SELECT * FROM unnest($1::uuid[], $2::bigint[], $3::timestamptz[], $4::float8[])
ON CONFLICT (series_id, ts) DO NOTHING`

// InsertSamples implements Store using array-bound unnest (single round trip).
func (TimescaleStore) InsertSamples(ctx context.Context, tx pgx.Tx, samples []Sample) (int64, error) {
	if len(samples) == 0 {
		return 0, nil
	}
	orgIDs := make([]uuid.UUID, len(samples))
	seriesIDs := make([]int64, len(samples))
	timestamps := make([]time.Time, len(samples))
	values := make([]float64, len(samples))
	for i, s := range samples {
		orgIDs[i], seriesIDs[i], timestamps[i], values[i] = s.OrgID, s.SeriesID, s.Ts, s.Value
	}
	tag, err := tx.Exec(ctx, insertSamplesSQL, orgIDs, seriesIDs, timestamps, values)
	if err != nil {
		return 0, fmt.Errorf("metrics: insert samples: %w", err)
	}
	return tag.RowsAffected(), nil
}

// TouchSeries implements Store. New activity is the inverse of retirement:
// a tombstoned series that receives samples again becomes live in the same
// statement (documented in M8_EVIDENCE.md §4).
func (TimescaleStore) TouchSeries(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, seriesIDs []int64, ts time.Time) error {
	if len(seriesIDs) == 0 || ts.IsZero() {
		return nil
	}
	_, err := tx.Exec(ctx, `
		UPDATE metric_series
		SET last_seen_at = GREATEST(COALESCE(last_seen_at, $3), $3),
		    retired_at   = CASE WHEN retired_at IS NOT NULL THEN NULL ELSE retired_at END
		WHERE org_id = $1 AND id = ANY($2)
		  AND (last_seen_at IS NULL OR last_seen_at < $3 OR retired_at IS NOT NULL)`,
		orgID, seriesIDs, ts)
	if err != nil {
		return fmt.Errorf("metrics: touch series: %w", err)
	}
	return nil
}
