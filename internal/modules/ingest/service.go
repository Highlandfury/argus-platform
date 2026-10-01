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
	"github.com/argus-platform/argus/internal/modules/inventory"
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
	errDeviceMissing  = errors.New("ingest: device not found")
)

// Service is the ingest pipeline. Durability contract: BatchResult(STATUS_OK)
// is produced only after the batch transaction has COMMITted.
type Service struct {
	app   *pgxpool.Pool
	store metrics.Store
	argus *telemetry.Argus
	log   *slog.Logger
	m     *metricsSet
	audit inventory.AuditSink
}

// Option configures optional ingest dependencies.
type Option func(*Service)

// WithAudit wires the audit sink used for SNMP interface association events
// (M10-S2). Events are recorded after the batch transaction commits, so a
// rolled-back or retried batch never leaves audit evidence.
func WithAudit(sink inventory.AuditSink) Option {
	return func(s *Service) { s.audit = sink }
}

// New wires the pipeline. store may be nil (TimescaleStore is used unless a
// test substitutes one); argus may be nil in unit contexts.
func New(app *pgxpool.Pool, store metrics.Store, argus *telemetry.Argus, log *slog.Logger, opts ...Option) *Service {
	if store == nil {
		store = metrics.TimescaleStore{}
	}
	var reg *telemetry.Registry
	if argus != nil {
		reg = argus.Reg
	}
	s := &Service{app: app, store: store, argus: argus, log: log, m: newMetricsSet(reg)}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// observeDB records one database operation on the shared §15 histogram.
func (s *Service) observeDB(op string, start time.Time) {
	if s.argus != nil {
		s.argus.DBQueryDuration.WithLabelValues(op).Observe(time.Since(start).Seconds())
	}
}

// recordInterfaceEvents emits the M10-S2 association audit events through the
// configured sink. The actor is the authenticated collector: the association
// is system-driven, not operator-driven. Called after COMMIT only.
func (s *Service) recordInterfaceEvents(orgID, collectorID uuid.UUID, events []inventory.InterfaceLinkEvent) {
	if s.audit == nil || len(events) == 0 {
		return
	}
	at := time.Now().UTC()
	for _, ev := range events {
		s.audit.Record(inventory.AuditEvent{
			Action:       ev.Action,
			ActorType:    "collector",
			ActorID:      collectorID,
			OrgID:        orgID,
			ResourceType: "interface",
			ResourceID:   ev.ResourceID,
			Data:         ev.Data,
			At:           at,
		})
	}
}

// guardOptions is the M9 cardinality-guard configuration: canonical defaults
// plus the structured metric.cardinality.exceeded sink.
func (s *Service) guardOptions() metrics.GuardOptions {
	return metrics.GuardOptions{Sink: metrics.SlogCardinality{Logger: s.log}}
}

// IngestBatch runs the canonical pipeline for one authenticated batch:
// validate → claim (deduplicate) → resolve series (normalize; device-scoped
// series carry the M9 guards) → persist samples + poll health → chunk-RLS
// sweep → COMMIT. Any DB failure yields STATUS_RETRY and rolls the transaction
// back: nothing is acknowledged.
func (s *Service) IngestBatch(ctx context.Context, orgID, collectorID uuid.UUID, allowlist map[string]MetricDef, batch *collectorv1.MetricBatch) BatchOutcome {
	start := time.Now()
	now := time.Now()

	validated, health, rej := ValidateBatchPayload(batch, allowlist, now)
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
	observed, rej := ValidateInterfaceObservations(batch.GetInterfaces(), now)
	if rej != nil {
		s.m.batches.WithLabelValues("rejected").Inc()
		if s.log != nil {
			s.log.Warn("batch rejected",
				"reason", rej.Reason, "collector_id", collectorID, "batch_seq", batch.GetBatchSeq())
		}
		return BatchOutcome{Status: collectorv1.BatchResult_STATUS_REJECTED, Reason: rej.Reason, Rejected: uint32(len(validated))} //nolint:gosec // bounded by MaxBatchSamples
	}

	outcome := BatchOutcome{}
	var linkResult inventory.InterfaceLinkResult
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		claimStart := time.Now()
		firstTs, lastTs := payloadBounds(validated, health)
		receivedAt, claimed, err := s.claimBatch(ctx, tx, orgID, collectorID, batch, len(validated), firstTs, lastTs)
		s.observeDB("claim", claimStart)
		if err != nil {
			return err
		}
		if !claimed {
			outcome = BatchOutcome{Status: collectorv1.BatchResult_STATUS_DUPLICATE, IngestedAt: time.Now()}
			return errDuplicateBatch
		}

		seriesStart := time.Now()
		samples, touched, quarantinedDropped, err := s.resolveSamples(ctx, tx, orgID, collectorID, validated)
		s.observeDB("series", seriesStart)
		if err != nil {
			return err
		}

		dbStart := time.Now()
		inserted, err := s.store.InsertSamples(ctx, tx, samples)
		s.observeDB("samples", dbStart)
		if err != nil {
			return err
		}
		if err := s.store.TouchSeries(ctx, tx, orgID, touched, lastTs); err != nil {
			return err
		}

		healthInserted := 0
		if len(health) > 0 {
			healthStart := time.Now()
			healthInserted, err = insertPollHealth(ctx, tx, orgID, collectorID, health)
			s.observeDB("poll_health", healthStart)
			if err != nil {
				return err
			}
		}

		// M10-S2 interface association: shares this batch transaction, so a
		// failed association retries the whole batch and a duplicate batch
		// never re-applies. Runs after series resolution so the per-device
		// device lock is held once.
		if len(observed) > 0 {
			linkStart := time.Now()
			linkResult, err = inventory.LinkInterfacesTx(ctx, tx, orgID, observed)
			s.observeDB("interfaces", linkStart)
			if err != nil {
				if errors.Is(err, inventory.ErrInterfaceDeviceNotFound) {
					return errDeviceMissing
				}
				return err
			}
		}

		// Zero-window chunk-RLS sweep before COMMIT (migration 000006).
		if _, err := tx.Exec(ctx, `SELECT public.argus_ensure_chunk_rls()`); err != nil {
			return fmt.Errorf("%w: %w", errChunkRLS, err)
		}

		outcome = BatchOutcome{
			Status:         collectorv1.BatchResult_STATUS_OK,
			Accepted:       uint32(inserted), //nolint:gosec // bounded by MaxBatchSamples
			Rejected:       quarantinedDropped,
			HealthAccepted: healthInserted,
			IngestedAt:     receivedAt,
		}
		return nil
	})

	switch {
	case err == nil:
		s.m.batches.WithLabelValues("ok").Inc()
		s.m.samples.WithLabelValues("accepted").Add(float64(outcome.Accepted))
		if outcome.HealthAccepted > 0 {
			s.m.health.WithLabelValues("accepted").Add(float64(outcome.HealthAccepted))
		}
		if linkResult.Created > 0 {
			s.m.interfaces.WithLabelValues("created").Add(float64(linkResult.Created))
		}
		if linkResult.Rebound > 0 {
			s.m.interfaces.WithLabelValues("rebound").Add(float64(linkResult.Rebound))
		}
		if linkResult.IndexConflicts > 0 || linkResult.Ambiguous > 0 {
			s.m.interfaces.WithLabelValues("skipped").Add(float64(linkResult.IndexConflicts + linkResult.Ambiguous))
		}
		// Audit evidence is recorded only after COMMIT (the sink is not
		// transactional); a rolled-back batch leaves no event.
		s.recordInterfaceEvents(orgID, collectorID, linkResult.Events)
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
	case errors.Is(err, errDeviceMissing):
		s.m.batches.WithLabelValues("rejected").Inc()
		s.m.samples.WithLabelValues("rejected").Add(float64(len(validated)))
		if s.log != nil {
			s.log.Warn("batch rejected", "reason", "validation.device_not_found",
				"collector_id", collectorID, "batch_seq", batch.GetBatchSeq())
		}
		return BatchOutcome{
			Status:   collectorv1.BatchResult_STATUS_REJECTED,
			Reason:   "validation.device_not_found",
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

// resolveSamples resolves every validated sample into a series row:
// collector-scoped samples use the Phase-1 path; device-scoped samples (M9)
// resolve through the device-series cardinality guards. Quarantined series are
// dropped for that series only (counted in the outcome).
func (s *Service) resolveSamples(ctx context.Context, tx pgx.Tx, orgID, collectorID uuid.UUID, validated []ValidatedSample) ([]metrics.Sample, []int64, uint32, error) {
	samples := make([]metrics.Sample, 0, len(validated))
	touched := make([]int64, 0, len(validated))
	var quarantined uint32

	var collectorSpecs []metrics.SeriesSpec
	for _, v := range validated {
		if v.DeviceID == uuid.Nil {
			collectorSpecs = append(collectorSpecs, metrics.SeriesSpec{
				OrgID:       orgID,
				CollectorID: collectorID,
				MetricKey:   v.MetricKey,
				Unit:        v.Unit,
				Canonical:   v.Canonical,
				DimHash:     v.DimHash,
			})
		}
	}
	var collectorRes metrics.SeriesResolution
	if len(collectorSpecs) > 0 {
		var err error
		collectorRes, err = s.store.EnsureSeries(ctx, tx, collectorSpecs)
		if err != nil {
			if errors.Is(err, metrics.ErrSeriesQuota) {
				return nil, nil, 0, errSeriesQuota
			}
			return nil, nil, 0, err
		}
	}

	deviceRes := make(map[string]metrics.DeviceSeriesResult)
	for _, v := range validated {
		if v.DeviceID == uuid.Nil {
			key := v.MetricKey + "|" + strconv.FormatInt(v.DimHash, 16)
			if collectorRes.Quarantined[key] {
				quarantined++
				continue
			}
			seriesID, ok := collectorRes.IDs[key]
			if !ok {
				return nil, nil, 0, fmt.Errorf("ingest: series unresolved for %s", key)
			}
			samples = append(samples, metrics.Sample{OrgID: orgID, SeriesID: seriesID, Ts: v.Ts, Value: v.Value})
			touched = append(touched, seriesID)
			continue
		}

		key := v.DeviceID.String() + "|" + v.MetricKey + "|" + strconv.FormatInt(v.DimHash, 16)
		res, ok := deviceRes[key]
		if !ok {
			var err error
			res, err = s.store.EnsureDeviceSeries(ctx, tx, metrics.DeviceSeriesSpec{
				OrgID:     orgID,
				DeviceID:  v.DeviceID,
				MetricKey: v.MetricKey,
				Unit:      v.Unit,
				Canonical: v.Canonical,
				DimHash:   v.DimHash,
			}, s.guardOptions())
			if err != nil {
				if errors.Is(err, metrics.ErrDeviceNotFound) {
					return nil, nil, 0, errDeviceMissing
				}
				return nil, nil, 0, err
			}
			deviceRes[key] = res
		}
		if res.Quarantined {
			quarantined++
			continue
		}
		samples = append(samples, metrics.Sample{OrgID: orgID, SeriesID: res.ID, Ts: v.Ts, Value: v.Value})
		touched = append(touched, res.ID)
	}
	return samples, touched, quarantined, nil
}

// payloadBounds returns the oldest and newest payload timestamps for the
// batch ledger (samples and poll health).
func payloadBounds(samples []ValidatedSample, health []ValidatedHealth) (time.Time, time.Time) {
	var first, last time.Time
	consider := func(ts time.Time) {
		if first.IsZero() || ts.Before(first) {
			first = ts
		}
		if last.IsZero() || ts.After(last) {
			last = ts
		}
	}
	for _, v := range samples {
		consider(v.Ts)
	}
	for _, h := range health {
		consider(h.CheckedAt)
	}
	return first, last
}

// claimBatch inserts the idempotency ledger row. Returns the ledger's
// received_at (DB clock) and whether this delivery claimed the batch. The
// ledger's sample_count counts metric samples only; poll-health records are
// covered by the same claim (M9-S1).
func (s *Service) claimBatch(ctx context.Context, tx pgx.Tx, orgID, collectorID uuid.UUID, batch *collectorv1.MetricBatch, sampleCount int, firstTs, lastTs time.Time) (time.Time, bool, error) {
	var receivedAt time.Time
	err := tx.QueryRow(ctx, `
		INSERT INTO ingested_batches (collector_id, batch_seq, org_id, sample_count, first_ts, last_ts)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (collector_id, batch_seq) DO NOTHING
		RETURNING received_at`,
		collectorID, batch.GetBatchSeq(), orgID, sampleCount, firstTs, lastTs).Scan(&receivedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("ingest: claim batch: %w", err)
	}
	return receivedAt, true, nil
}
