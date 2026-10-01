package ingest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
	"github.com/argus-platform/argus/internal/modules/metrics"
	"github.com/argus-platform/argus/internal/platform/database"
	"github.com/argus-platform/argus/internal/platform/telemetry"
)

// Sentinel outcomes that unwind the batch transaction without being logged as
// server errors.
var (
	errDuplicateBatch = errors.New("ingest: duplicate batch")
	errSeriesQuota    = errors.New("ingest: series quota exceeded")
	errChunkRLS       = errors.New("ingest: chunk RLS sweep failed")
)

// Service is the ingest pipeline. Durability contract: BatchResult(STATUS_OK)
// is produced only after the batch transaction has COMMITted.
type Service struct {
	app   *pgxpool.Pool
	store metrics.Store
	argus *telemetry.Argus
	log   *slog.Logger
	m     *metricsSet
}

// New wires the pipeline. store may be nil (TimescaleStore is used unless a
// test substitutes one); argus may be nil in unit contexts.
func New(app *pgxpool.Pool, store metrics.Store, argus *telemetry.Argus, log *slog.Logger) *Service {
	if store == nil {
		store = metrics.TimescaleStore{}
	}
	var reg *telemetry.Registry
	if argus != nil {
		reg = argus.Reg
	}
	return &Service{app: app, store: store, argus: argus, log: log, m: newMetricsSet(reg)}
}

// observeDB records one database operation on the shared §15 histogram.
func (s *Service) observeDB(op string, start time.Time) {
	if s.argus != nil {
		s.argus.DBQueryDuration.WithLabelValues(op).Observe(time.Since(start).Seconds())
	}
}

// IngestBatch runs the canonical pipeline for one authenticated batch:
// validate → claim (deduplicate) → resolve series (normalize) → persist →
// chunk-RLS sweep → COMMIT. Any DB failure yields STATUS_RETRY and rolls the
// transaction back: nothing is acknowledged.
func (s *Service) IngestBatch(ctx context.Context, orgID, collectorID uuid.UUID, allowlist map[string]MetricDef, batch *collectorv1.MetricBatch) BatchOutcome {
	start := time.Now()

	validated, rej := ValidateBatch(batch, allowlist, time.Now())
	if rej != nil {
		s.m.batches.WithLabelValues("rejected").Inc()
		rejected := uint32(0)
		if batch != nil {
			rejected = uint32(len(batch.GetSamples())) //nolint:gosec // bounded by MaxBatchSamples
		}
		s.m.samples.WithLabelValues("rejected").Add(float64(rejected))
		if s.log != nil {
			s.log.Warn("batch rejected",
				"reason", rej.Reason, "collector_id", collectorID, "batch_seq", batch.GetBatchSeq())
		}
		return BatchOutcome{Status: collectorv1.BatchResult_STATUS_REJECTED, Reason: rej.Reason, Rejected: rejected}
	}

	outcome := BatchOutcome{}
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		claimStart := time.Now()
		receivedAt, claimed, err := s.claimBatch(ctx, tx, orgID, collectorID, batch, validated)
		s.observeDB("claim", claimStart)
		if err != nil {
			return err
		}
		if !claimed {
			outcome = BatchOutcome{Status: collectorv1.BatchResult_STATUS_DUPLICATE, IngestedAt: time.Now()}
			return errDuplicateBatch
		}

		specs := make([]metrics.SeriesSpec, 0, len(validated))
		for _, v := range validated {
			specs = append(specs, metrics.SeriesSpec{
				OrgID:       orgID,
				CollectorID: collectorID,
				MetricKey:   v.MetricKey,
				Unit:        v.Unit,
				Canonical:   v.Canonical,
				DimHash:     v.DimHash,
			})
		}
		seriesStart := time.Now()
		resolution, err := s.store.EnsureSeries(ctx, tx, specs)
		s.observeDB("series", seriesStart)
		if err != nil {
			if errors.Is(err, metrics.ErrSeriesQuota) {
				return errSeriesQuota
			}
			return err
		}

		samples := make([]metrics.Sample, 0, len(validated))
		touched := make([]int64, 0, len(resolution.IDs))
		var quarantinedDropped uint32
		var batchLastTs time.Time
		for _, v := range validated {
			key := v.MetricKey + "|" + strconv.FormatInt(v.DimHash, 16)
			if resolution.Quarantined[key] {
				// Quarantine stops ingest for this series only; the rest of
				// the batch (and the device) keeps flowing (docs/08 §13.3).
				quarantinedDropped++
				continue
			}
			seriesID, ok := resolution.IDs[key]
			if !ok {
				return fmt.Errorf("ingest: series unresolved for %s", key)
			}
			samples = append(samples, metrics.Sample{OrgID: orgID, SeriesID: seriesID, Ts: v.Ts, Value: v.Value})
			touched = append(touched, seriesID)
			if v.Ts.After(batchLastTs) {
				batchLastTs = v.Ts
			}
		}

		dbStart := time.Now()
		inserted, err := s.store.InsertSamples(ctx, tx, samples)
		s.observeDB("samples", dbStart)
		if err != nil {
			return err
		}
		if err := s.store.TouchSeries(ctx, tx, orgID, touched, batchLastTs); err != nil {
			return err
		}

		// Zero-window chunk-RLS sweep before COMMIT (migration 000006).
		if _, err := tx.Exec(ctx, `SELECT public.argus_ensure_chunk_rls()`); err != nil {
			return fmt.Errorf("%w: %w", errChunkRLS, err)
		}

		outcome = BatchOutcome{
			Status:     collectorv1.BatchResult_STATUS_OK,
			Accepted:   uint32(inserted), //nolint:gosec // bounded by MaxBatchSamples
			Rejected:   quarantinedDropped,
			IngestedAt: receivedAt,
		}
		return nil
	})

	switch {
	case err == nil:
		s.m.batches.WithLabelValues("ok").Inc()
		s.m.samples.WithLabelValues("accepted").Add(float64(outcome.Accepted))
		if outcome.Rejected > 0 {
			s.m.samples.WithLabelValues("quarantined").Add(float64(outcome.Rejected))
			if s.log != nil {
				s.log.Warn("samples dropped for quarantined series",
					"collector_id", collectorID, "batch_seq", batch.GetBatchSeq(),
					"dropped", outcome.Rejected)
			}
		}
		s.m.batchDuration.Observe(time.Since(start).Seconds())
		return outcome
	case errors.Is(err, errDuplicateBatch):
		s.m.batches.WithLabelValues("duplicate").Inc()
		return outcome
	case errors.Is(err, errSeriesQuota):
		s.m.batches.WithLabelValues("rejected").Inc()
		s.m.samples.WithLabelValues("rejected").Add(float64(len(validated)))
		if s.log != nil {
			s.log.Warn("batch rejected", "reason", "validation.series_quota_exceeded",
				"collector_id", collectorID, "batch_seq", batch.GetBatchSeq())
		}
		return BatchOutcome{
			Status:   collectorv1.BatchResult_STATUS_REJECTED,
			Reason:   "validation.series_quota_exceeded",
			Rejected: uint32(len(validated)), //nolint:gosec // bounded by MaxBatchSamples
		}
	default:
		// No acknowledgment before durability: everything rolled back.
		s.m.batches.WithLabelValues("retry").Inc()
		if s.log != nil {
			s.log.Error("ingest batch failed; collector must retry",
				"collector_id", collectorID, "batch_seq", batch.GetBatchSeq(), "error", err)
		}
		return BatchOutcome{Status: collectorv1.BatchResult_STATUS_RETRY, Reason: "ingest.db_error"}
	}
}

// claimBatch inserts the idempotency ledger row. Returns the ledger's
// received_at (DB clock) and whether this delivery claimed the batch.
func (s *Service) claimBatch(ctx context.Context, tx pgx.Tx, orgID, collectorID uuid.UUID, batch *collectorv1.MetricBatch, validated []ValidatedSample) (time.Time, bool, error) {
	firstTs, lastTs := validated[0].Ts, validated[0].Ts
	for _, v := range validated[1:] {
		if v.Ts.Before(firstTs) {
			firstTs = v.Ts
		}
		if v.Ts.After(lastTs) {
			lastTs = v.Ts
		}
	}
	var receivedAt time.Time
	err := tx.QueryRow(ctx, `
		INSERT INTO ingested_batches (collector_id, batch_seq, org_id, sample_count, first_ts, last_ts)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (collector_id, batch_seq) DO NOTHING
		RETURNING received_at`,
		collectorID, batch.GetBatchSeq(), orgID, len(validated), firstTs, lastTs).Scan(&receivedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("ingest: claim batch: %w", err)
	}
	return receivedAt, true, nil
}
