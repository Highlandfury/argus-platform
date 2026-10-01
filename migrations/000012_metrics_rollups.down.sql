-- 000012_metrics_rollups.down.sql
-- Reverses 000012: removes CAGG compression, the tenant views, continuous
-- aggregates, and refresh policies. metric_samples is untouched (no raw
-- compression was possible on the pinned TimescaleDB; see the up migration
-- header) — only the canonical 1-day chunk interval is re-asserted there.

SELECT remove_compression_policy('metric_1d', if_exists => true);
SELECT remove_compression_policy('metric_1h', if_exists => true);
SELECT remove_compression_policy('metric_5m', if_exists => true);
SELECT remove_compression_policy('metric_1m', if_exists => true);

DROP VIEW IF EXISTS metric_1d_tenant;
DROP VIEW IF EXISTS metric_1h_tenant;
DROP VIEW IF EXISTS metric_5m_tenant;
DROP VIEW IF EXISTS metric_1m_tenant;

SELECT remove_continuous_aggregate_policy('metric_1d', if_exists => true);
SELECT remove_continuous_aggregate_policy('metric_1h', if_exists => true);
SELECT remove_continuous_aggregate_policy('metric_5m', if_exists => true);
SELECT remove_continuous_aggregate_policy('metric_1m', if_exists => true);

DROP MATERIALIZED VIEW IF EXISTS metric_1d;
DROP MATERIALIZED VIEW IF EXISTS metric_1h;
DROP MATERIALIZED VIEW IF EXISTS metric_5m;
DROP MATERIALIZED VIEW IF EXISTS metric_1m;
