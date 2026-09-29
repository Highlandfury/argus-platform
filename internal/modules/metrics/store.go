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

// Store is the persistence surface the ingest pipeline depends on. The
// TimescaleStore implementation is the only production implementation in
// Phase 1; tests may substitute failing stores for RETRY semantics.
type Store interface {
	// EnsureSeries resolves or creates the given series and returns a map
	// keyed by SeriesSpec.Key(). Must be called inside the batch transaction.
	EnsureSeries(ctx context.Context, tx pgx.Tx, specs []SeriesSpec) (map[string]int64, error)
	// InsertSamples inserts samples, skipping (series_id, ts) conflicts.
	// Returns the number of rows actually inserted.
	InsertSamples(ctx context.Context, tx pgx.Tx, samples []Sample) (int64, error)
}

// TimescaleStore stores metric data in the metric_samples hypertable.
type TimescaleStore struct{}

// EnsureSeries implements Store.
func (TimescaleStore) EnsureSeries(ctx context.Context, tx pgx.Tx, specs []SeriesSpec) (map[string]int64, error) {
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
