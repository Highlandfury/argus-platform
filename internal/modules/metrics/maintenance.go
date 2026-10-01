package metrics

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Maintenance: deterministic policy verification and the raw retention
// override (PHASE_2_SPEC P2-AC-09, verification path). The nightly
// `metrics-maintenance` CI job and the `argus-server metrics-maintenance`
// command both call VerifyPolicies; the command additionally applies the
// configured raw retention and retires inactive series under the owner role.

// PolicyViolation is one failed expectation.
type PolicyViolation struct {
	Relation string
	Kind     string
	Detail   string
}

// PolicyError aggregates every failed expectation, so verification fails
// loudly with the complete picture instead of the first mismatch.
type PolicyError struct {
	Violations []PolicyViolation
}

func (e *PolicyError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "metrics: %d policy violation(s):", len(e.Violations))
	for _, v := range e.Violations {
		fmt.Fprintf(&b, "\n  - [%s] %s: %s", v.Kind, v.Relation, v.Detail)
	}
	return b.String()
}

// VerifyOptions carries context-dependent expectations.
type VerifyOptions struct {
	// RawRetention is the expected metric_samples drop_after
	// (ARGUS_METRICS_RAW_RETENTION_DAYS, default 30 d).
	RawRetention time.Duration
}

// VerifyPolicies asserts the M8 storage shape against
// timescaledb_information: the four CAGGs exist and are materialized-only,
// their refresh policies carry the canonical offsets, retention and CAGG
// compression policies are active, the raw chunk interval is 1 day, the raw
// hypertable keeps FORCE RLS, and the tenant views are the only aggregate
// surface granted to the runtime role.
//
// Raw compression is asserted absent: on the pinned TimescaleDB it cannot
// coexist with the Phase-1 RLS policy (M8_EVIDENCE.md §5). If a future stack
// enables it, this verification flags the tenancy change loudly.
func VerifyPolicies(ctx context.Context, pool *pgxpool.Pool, opts VerifyOptions) error {
	if opts.RawRetention <= 0 {
		opts.RawRetention = 30 * 24 * time.Hour
	}
	var vs []PolicyViolation
	add := func(relation, kind, detail string) {
		vs = append(vs, PolicyViolation{Relation: relation, Kind: kind, Detail: detail})
	}

	// --- CAGGs exist, materialized-only -----------------------------------
	for _, pol := range RollupPolicies() {
		var materializedOnly bool
		err := pool.QueryRow(ctx, `
			SELECT materialized_only FROM timescaledb_information.continuous_aggregates
			WHERE view_name = $1`, pol.CAGG).Scan(&materializedOnly)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			add(pol.CAGG, "cagg", "continuous aggregate missing")
			continue
		case err != nil:
			return fmt.Errorf("metrics: verify %s: %w", pol.CAGG, err)
		}
		if !materializedOnly {
			add(pol.CAGG, "cagg", "expected materialized_only=true (query engine provides the raw fallback)")
		}

		// Refresh policy offsets (canonical 1m; documented for coarser levels).
		var startSec, endSec, scheduleSec int64
		err = pool.QueryRow(ctx, `
			SELECT EXTRACT(epoch FROM (config->>'start_offset')::interval)::bigint,
			       EXTRACT(epoch FROM (config->>'end_offset')::interval)::bigint,
			       EXTRACT(epoch FROM schedule_interval)::bigint
			FROM timescaledb_information.jobs
			WHERE proc_name = 'policy_refresh_continuous_aggregate' AND hypertable_name = $1`, pol.CAGG).
			Scan(&startSec, &endSec, &scheduleSec)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			add(pol.CAGG, "refresh_policy", "refresh policy missing")
		case err != nil:
			return fmt.Errorf("metrics: verify %s refresh policy: %w", pol.CAGG, err)
		default:
			if want := int64(pol.StartOffset / time.Second); startSec != want {
				add(pol.CAGG, "refresh_policy", fmt.Sprintf("start_offset = %ds, want %ds", startSec, want))
			}
			if want := int64(pol.EndOffset / time.Second); endSec != want {
				add(pol.CAGG, "refresh_policy", fmt.Sprintf("end_offset = %ds, want %ds", endSec, want))
			}
			if want := int64(pol.Schedule / time.Second); scheduleSec != want {
				add(pol.CAGG, "refresh_policy", fmt.Sprintf("schedule_interval = %ds, want %ds", scheduleSec, want))
			}
		}

		// Tenant view exists and is the granted surface; the aggregate is not.
		var (
			tenantExists      bool
			aggregateGranted  bool
			tenantViewGranted bool
		)
		if err := pool.QueryRow(ctx,
			`SELECT to_regclass('public.' || $1 || '_tenant') IS NOT NULL`, pol.CAGG).Scan(&tenantExists); err != nil {
			return fmt.Errorf("metrics: verify %s tenant view: %w", pol.CAGG, err)
		}
		if !tenantExists {
			add(pol.CAGG, "tenant_view", "org-filtered tenant view missing")
		} else {
			if err := pool.QueryRow(ctx, `
				SELECT has_table_privilege('argus_app', 'public.' || $1, 'SELECT'),
				       has_table_privilege('argus_app', 'public.' || $2, 'SELECT')`,
				pol.CAGG, pol.TenantView).Scan(&aggregateGranted, &tenantViewGranted); err != nil {
				return fmt.Errorf("metrics: verify %s grants: %w", pol.CAGG, err)
			}
			if aggregateGranted {
				add(pol.CAGG, "tenant_view", "argus_app must not read the aggregate directly (matviews cannot carry RLS)")
			}
			if !tenantViewGranted {
				add(pol.CAGG, "tenant_view", "argus_app lacks SELECT on the tenant view")
			}
		}
	}

	// --- retention policies ------------------------------------------------
	for _, rp := range RetentionPolicies(opts.RawRetention) {
		var dropSec int64
		err := pool.QueryRow(ctx, `
			SELECT EXTRACT(epoch FROM (config->>'drop_after')::interval)::bigint
			FROM timescaledb_information.jobs
			WHERE proc_name = 'policy_retention' AND hypertable_name = $1`, rp.Relation).Scan(&dropSec)
		if errors.Is(err, pgx.ErrNoRows) {
			add(rp.Relation, "retention_policy", "retention policy missing")
		} else if err != nil {
			return fmt.Errorf("metrics: verify %s retention: %w", rp.Relation, err)
		} else if want := int64(rp.After / time.Second); dropSec != want {
			add(rp.Relation, "retention_policy", fmt.Sprintf("drop_after = %ds, want %ds", dropSec, want))
		}
	}

	// --- compression policies (CAGG materializations) ----------------------
	for _, cp := range CompressionPolicies() {
		var compressSec int64
		err := pool.QueryRow(ctx, `
			SELECT EXTRACT(epoch FROM (config->>'compress_after')::interval)::bigint
			FROM timescaledb_information.jobs
			WHERE proc_name = 'policy_compression' AND hypertable_name = $1`, cp.Relation).Scan(&compressSec)
		if errors.Is(err, pgx.ErrNoRows) {
			add(cp.Relation, "compression_policy", "compression policy missing")
		} else if err != nil {
			return fmt.Errorf("metrics: verify %s compression: %w", cp.Relation, err)
		} else if want := int64(cp.After / time.Second); compressSec != want {
			add(cp.Relation, "compression_policy", fmt.Sprintf("compress_after = %ds, want %ds", compressSec, want))
		}

		var (
			segmentOK, orderOK bool
		)
		err = pool.QueryRow(ctx, `
			SELECT
			  count(*) FILTER (WHERE ms.attname = 'series_id' AND ms.segmentby_column_index IS NOT NULL) > 0,
			  count(*) FILTER (WHERE ms.attname = 'bucket'    AND ms.orderby_column_index IS NOT NULL) > 0
			FROM timescaledb_information.continuous_aggregates ca
			JOIN timescaledb_information.compression_settings ms
			  ON ms.hypertable_schema = ca.materialization_hypertable_schema
			 AND ms.hypertable_name   = ca.materialization_hypertable_name
			WHERE ca.view_name = $1`, cp.Relation).Scan(&segmentOK, &orderOK)
		if err != nil {
			return fmt.Errorf("metrics: verify %s compression settings: %w", cp.Relation, err)
		}
		if !segmentOK {
			add(cp.Relation, "compression_settings", "segmentby series_id missing")
		}
		if !orderOK {
			add(cp.Relation, "compression_settings", "orderby bucket DESC missing")
		}
	}

	// --- raw hypertable: chunk interval, RLS floor, no compression ---------
	var interval string
	err := pool.QueryRow(ctx, `
		SELECT time_interval::text FROM timescaledb_information.dimensions
		WHERE hypertable_schema = 'public' AND hypertable_name = 'metric_samples'`).Scan(&interval)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("metrics: verify chunk interval: %w", err)
	}
	if err != nil || interval != "1 day" {
		add("metric_samples", "chunk_interval", fmt.Sprintf("time_interval = %q, want \"1 day\"", interval))
	}

	var rlsEnabled, rlsForced bool
	err = pool.QueryRow(ctx, `
		SELECT relrowsecurity, relforcerowsecurity FROM pg_class
		WHERE relnamespace = 'public'::regnamespace AND relname = 'metric_samples'`).Scan(&rlsEnabled, &rlsForced)
	if err != nil {
		return fmt.Errorf("metrics: verify raw RLS: %w", err)
	}
	if !rlsEnabled || !rlsForced {
		add("metric_samples", "rls", "expected ENABLE + FORCE row-level security")
	}

	var rawCompressionSettings int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM timescaledb_information.compression_settings
		WHERE hypertable_schema = 'public' AND hypertable_name = 'metric_samples'`).Scan(&rawCompressionSettings); err != nil {
		return fmt.Errorf("metrics: verify raw compression: %w", err)
	}
	if rawCompressionSettings > 0 {
		add("metric_samples", "compression",
			"raw compression is enabled while RLS is required; the pinned TimescaleDB cannot do both (see M8_EVIDENCE.md §5)")
	}

	if len(vs) > 0 {
		return &PolicyError{Violations: vs}
	}
	return nil
}

// ApplyRawRetention sets the metric_samples drop_after to the configured raw
// window. The config layer bounds the value to 30-90 days
// (ARGUS_METRICS_RAW_RETENTION_DAYS); this function accepts any positive
// duration so tests and operators can deviate deliberately.
func ApplyRawRetention(ctx context.Context, owner *pgxpool.Pool, after time.Duration) error {
	if after <= 0 {
		return errors.New("metrics: raw retention must be positive")
	}
	days := int(after.Hours() / 24)
	var jobID int
	err := owner.QueryRow(ctx, `
		SELECT job_id FROM timescaledb_information.jobs
		WHERE proc_name = 'policy_retention' AND hypertable_name = 'metric_samples'`).Scan(&jobID)
	if errors.Is(err, pgx.ErrNoRows) {
		_, err = owner.Exec(ctx, `SELECT add_retention_policy('metric_samples', make_interval(days => $1))`, days)
		if err != nil {
			return fmt.Errorf("metrics: add raw retention policy: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("metrics: find raw retention policy: %w", err)
	}
	_, err = owner.Exec(ctx, `
		SELECT alter_job($1, config_merge => jsonb_build_object('drop_after', make_interval(days => $2)))`,
		jobID, days)
	if err != nil {
		return fmt.Errorf("metrics: update raw retention policy: %w", err)
	}
	return nil
}
