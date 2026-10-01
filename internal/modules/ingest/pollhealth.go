package ingest

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// insertPollHealth persists validated poll-health records inside the ingest
// batch transaction (M9-S1). Idempotency comes from the batch claim: a
// replayed batch never reaches this insert (the transaction rolls back at
// errDuplicateBatch), so the rows are written exactly once per accepted batch.
// The insert is org-scoped by the surrounding tenant transaction.
func insertPollHealth(ctx context.Context, tx pgx.Tx, orgID, collectorID uuid.UUID, records []ValidatedHealth) (int, error) {
	if len(records) == 0 {
		return 0, nil
	}
	n := len(records)
	ids := make([]uuid.UUID, n)
	orgs := make([]uuid.UUID, n)
	collectors := make([]uuid.UUID, n)
	devices := make([]uuid.UUID, n)
	timestamps := make([]any, n)
	pollTypes := make([]string, n)
	latencies := make([]int32, n)
	outcomes := make([]string, n)
	classes := make([]string, n)
	failures := make([]int32, n)
	for i, r := range records {
		id, err := uuid.NewV7()
		if err != nil {
			return 0, fmt.Errorf("ingest: poll health id: %w", err)
		}
		ids[i] = id
		orgs[i] = orgID
		collectors[i] = collectorID
		devices[i] = r.DeviceID
		timestamps[i] = r.CheckedAt
		pollTypes[i] = r.PollType
		latencies[i] = int32(r.LatencyMS) //nolint:gosec // bounded by validator
		outcomes[i] = r.Outcome
		classes[i] = r.ErrorClass
		failures[i] = int32(r.ConsecutiveFailures) //nolint:gosec // bounded by validator
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO poll_health (id, org_id, collector_id, device_id, ts, poll_type, latency_ms, outcome, error_class, consecutive_failures)
		SELECT * FROM unnest(
			$1::uuid[], $2::uuid[], $3::uuid[], $4::uuid[], $5::timestamptz[],
			$6::text[], $7::int4[], $8::text[], $9::text[], $10::int4[])`,
		ids, orgs, collectors, devices, timestamps, pollTypes, latencies, outcomes, classes, failures)
	if err != nil {
		return 0, fmt.Errorf("ingest: insert poll health: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
