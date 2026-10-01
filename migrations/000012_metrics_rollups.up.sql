-- 000012_metrics_rollups.up.sql
-- Argus Phase 2 M8 — continuous aggregates (metric_1m/5m/1h/1d), refresh
-- policies, and compression for metric_samples (PHASE_2_SPEC P2-AC-07/10/13;
-- canonical docs/08 §13.1-13.5, docs/11 §20.4/§21.2, docs/12 §22.8).
--
-- Aggregation columns: avg/max/min/sum/n plus tw_avg. Metric values are
-- normalized before storage (counters arrive as rates, state metrics as enum
-- values — docs/08 §13.2), so every level materializes all aggregate shapes
-- and the query layer selects per metric definition (docs/08 §13.4:
-- gauge → avg,max,min; rates → avg,sum; state → max + time-weighted avg).
--
-- tw_avg is the sample-count-weighted mean (sum/n). TimescaleDB continuous
-- aggregates cannot contain window functions or FROM sub-queries (verified
-- against the pinned 2.30.1 image), so the true duration-weighted average is
-- not computable inside the CAGG; with the platform's uniform poll cadence the
-- sample-weighted mean equals the duration-weighted average exactly, and for
-- irregular cadences it is the documented conservative approximation
-- (M8_EVIDENCE.md §3).
--
-- Hierarchical chain (incremental CAGGs, docs/08 §13.1): raw → 1m → 5m → 1h
-- → 1d. Coarser levels aggregate the previous materialization, so refresh cost
-- is bounded by the bucket counts, not the raw row counts.
--
-- Refresh policy offsets. 1m is canonical (docs/11 §21.2: start 7 d, end
-- 2 min, schedule 1 min). The coarser levels are not specified by the
-- canonical docs; this migration uses end_offset = 2 × bucket and
-- schedule = bucket (1d refreshes hourly), with start_offset set to the
-- upstream retention horizon so late corrections inside the retained window
-- are picked up (M8_EVIDENCE.md §3):
--   metric_1m  start 7 d   end 2 min   every 1 min   (canonical)
--   metric_5m  start 30 d  end 10 min  every 5 min   (documented choice)
--   metric_1h  start 90 d  end 2 h     every 1 h      (documented choice)
--   metric_1d  start 13 mo end 2 d     every 1 h      (documented choice)
--
-- Tenancy: PostgreSQL materialized views cannot carry row-level security, so
-- each level also ships an owner-owned, org-filtered tenant view
-- (metric_1m_tenant, ...). The runtime role reads only the tenant view;
-- SELECT on the aggregate itself is revoked. The org predicate is exactly the
-- RLS policy predicate (migration 000005): an unset tenant context yields no
-- rows.
--
-- RLS handshake (CAGGs): TimescaleDB refuses to create a continuous aggregate
-- on a hypertable that has row security enabled or forced, so this migration
-- briefly lifts FORCE/ENABLE around the CAGG DDL and restores both before it
-- commits. golang-migrate sends the file as one simple-protocol query, which
-- PostgreSQL wraps in an implicit transaction: no other session can observe
-- the lifted state and the committed state is unchanged (verified by
-- TestMetricsRLSUntouchedInMigration). Operational note: the background
-- refresh policies execute as the table owner, which is subject to FORCE RLS;
-- deployments must run migrations/policies under a BYPASSRLS (or superuser)
-- role — the same role that already owns every tenant table — while the
-- runtime app role stays fully RLS-enforced.
--
-- Compression (P2-AC-10). The canonical target is metric_samples with
-- segmentby series_id / orderby ts DESC after 7 days. On the pinned
-- TimescaleDB 2.30.1 this is structurally impossible: compression and RLS are
-- mutually exclusive (upstream open issue timescale/timescaledb#6827;
-- observed errors: "columnstore cannot be used on table with row security"
-- and "operation not supported on hypertables that have columnstore
-- enabled"). Phase-1 G5 pins RLS on metric_samples, and this slice must not
-- weaken it, so raw compression is deferred to the ADR-016 storage decision
-- (next slice; M8_EVIDENCE.md §5). Compression is applied where the platform
-- allows it without weakening tenancy: the four CAGG materializations
-- (segmentby series_id, orderby bucket DESC, after 7 days) — a partial,
-- documented mitigation that keeps the policy machinery exercised and
-- verified. Raw chunk interval stays the canonical 1 day.

-- ---------------------------------------------------------------------------
-- Continuous aggregates.
-- ---------------------------------------------------------------------------

-- TimescaleDB blocks CAGGs on RLS hypertables; lift FORCE/ENABLE only inside
-- this migration's transaction and restore it below (see header).
ALTER TABLE metric_samples NO FORCE ROW LEVEL SECURITY;
ALTER TABLE metric_samples DISABLE ROW LEVEL SECURITY;

CREATE MATERIALIZED VIEW metric_1m
WITH (timescaledb.continuous, timescaledb.materialized_only = true) AS
SELECT org_id,
       series_id,
       time_bucket('1 minute', ts) AS bucket,
       avg(value) AS avg,
       max(value) AS max,
       min(value) AS min,
       sum(value) AS sum,
       count(*) AS n,
       -- Sample-count-weighted mean (equals duration-weighted for uniform cadence).
       sum(value) / count(*) AS tw_avg
FROM metric_samples
GROUP BY org_id, series_id, bucket
WITH NO DATA;

SELECT add_continuous_aggregate_policy('metric_1m',
    start_offset    => INTERVAL '7 days',
    end_offset      => INTERVAL '2 minutes',
    schedule_interval => INTERVAL '1 minute');

CREATE MATERIALIZED VIEW metric_5m
WITH (timescaledb.continuous, timescaledb.materialized_only = true) AS
SELECT org_id,
       series_id,
       time_bucket('5 minutes', bucket) AS bucket,
       sum(sum) / sum(n) AS avg,
       max(max) AS max,
       min(min) AS min,
       sum(sum) AS sum,
       sum(n) AS n,
       sum(tw_avg * n) / sum(n) AS tw_avg
FROM metric_1m
GROUP BY org_id, series_id, time_bucket('5 minutes', bucket)
WITH NO DATA;

SELECT add_continuous_aggregate_policy('metric_5m',
    start_offset    => INTERVAL '30 days',
    end_offset      => INTERVAL '10 minutes',
    schedule_interval => INTERVAL '5 minutes');

CREATE MATERIALIZED VIEW metric_1h
WITH (timescaledb.continuous, timescaledb.materialized_only = true) AS
SELECT org_id,
       series_id,
       time_bucket('1 hour', bucket) AS bucket,
       sum(sum) / sum(n) AS avg,
       max(max) AS max,
       min(min) AS min,
       sum(sum) AS sum,
       sum(n) AS n,
       sum(tw_avg * n) / sum(n) AS tw_avg
FROM metric_5m
GROUP BY org_id, series_id, time_bucket('1 hour', bucket)
WITH NO DATA;

SELECT add_continuous_aggregate_policy('metric_1h',
    start_offset    => INTERVAL '90 days',
    end_offset      => INTERVAL '2 hours',
    schedule_interval => INTERVAL '1 hour');

CREATE MATERIALIZED VIEW metric_1d
WITH (timescaledb.continuous, timescaledb.materialized_only = true) AS
SELECT org_id,
       series_id,
       time_bucket('1 day', bucket) AS bucket,
       sum(sum) / sum(n) AS avg,
       max(max) AS max,
       min(min) AS min,
       sum(sum) AS sum,
       sum(n) AS n,
       sum(tw_avg * n) / sum(n) AS tw_avg
FROM metric_1h
GROUP BY org_id, series_id, time_bucket('1 day', bucket)
WITH NO DATA;

SELECT add_continuous_aggregate_policy('metric_1d',
    start_offset    => INTERVAL '13 months',
    end_offset      => INTERVAL '2 days',
    schedule_interval => INTERVAL '1 hour');

-- Restore the Phase-1 RLS posture (net state unchanged).
ALTER TABLE metric_samples ENABLE ROW LEVEL SECURITY;
ALTER TABLE metric_samples FORCE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------------------
-- Tenant views: RLS-equivalent org filtering for aggregates.
-- ---------------------------------------------------------------------------

CREATE VIEW metric_1m_tenant AS
SELECT * FROM metric_1m
WHERE org_id = nullif(current_setting('app.current_org', true), '')::uuid;

CREATE VIEW metric_5m_tenant AS
SELECT * FROM metric_5m
WHERE org_id = nullif(current_setting('app.current_org', true), '')::uuid;

CREATE VIEW metric_1h_tenant AS
SELECT * FROM metric_1h
WHERE org_id = nullif(current_setting('app.current_org', true), '')::uuid;

CREATE VIEW metric_1d_tenant AS
SELECT * FROM metric_1d
WHERE org_id = nullif(current_setting('app.current_org', true), '')::uuid;

-- The aggregates are reachable only through the tenant views for the runtime
-- role (default privileges from 000005 grant tables to argus_app; revoke).
REVOKE ALL ON metric_1m FROM argus_app;
REVOKE ALL ON metric_5m FROM argus_app;
REVOKE ALL ON metric_1h FROM argus_app;
REVOKE ALL ON metric_1d FROM argus_app;
REVOKE ALL ON metric_1m_tenant FROM argus_app;
REVOKE ALL ON metric_5m_tenant FROM argus_app;
REVOKE ALL ON metric_1h_tenant FROM argus_app;
REVOKE ALL ON metric_1d_tenant FROM argus_app;

GRANT SELECT ON metric_1m_tenant TO argus_app;
GRANT SELECT ON metric_5m_tenant TO argus_app;
GRANT SELECT ON metric_1h_tenant TO argus_app;
GRANT SELECT ON metric_1d_tenant TO argus_app;

-- ---------------------------------------------------------------------------
-- Compression (partial: CAGG materializations; raw is RLS-blocked, see header)
-- and the canonical raw chunk interval.
-- ---------------------------------------------------------------------------

SELECT set_chunk_time_interval('metric_samples', INTERVAL '1 day');

ALTER MATERIALIZED VIEW metric_1m SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'series_id',
    timescaledb.compress_orderby   = 'bucket DESC'
);
SELECT add_compression_policy('metric_1m', INTERVAL '7 days');

ALTER MATERIALIZED VIEW metric_5m SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'series_id',
    timescaledb.compress_orderby   = 'bucket DESC'
);
SELECT add_compression_policy('metric_5m', INTERVAL '7 days');

ALTER MATERIALIZED VIEW metric_1h SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'series_id',
    timescaledb.compress_orderby   = 'bucket DESC'
);
SELECT add_compression_policy('metric_1h', INTERVAL '7 days');

ALTER MATERIALIZED VIEW metric_1d SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'series_id',
    timescaledb.compress_orderby   = 'bucket DESC'
);
SELECT add_compression_policy('metric_1d', INTERVAL '7 days');
