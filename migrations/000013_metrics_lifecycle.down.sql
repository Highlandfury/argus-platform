-- 000013_metrics_lifecycle.down.sql
-- Reverses 000013: retention policies, cardinality quarantine state, and the
-- device-series identity index. Retired series rows are kept (registry
-- history, canonical docs/11 §20.4).

SELECT remove_retention_policy('metric_1d',        if_exists => true);
SELECT remove_retention_policy('metric_1h',        if_exists => true);
SELECT remove_retention_policy('metric_5m',        if_exists => true);
SELECT remove_retention_policy('metric_1m',        if_exists => true);
SELECT remove_retention_policy('metric_samples',   if_exists => true);

DROP INDEX IF EXISTS metric_series_device_identity;
DROP INDEX IF EXISTS metric_series_inactive;
DROP INDEX IF EXISTS metric_series_quarantined;

ALTER TABLE metric_series DROP CONSTRAINT IF EXISTS metric_series_quarantine_reason_check;
ALTER TABLE metric_series
    DROP COLUMN IF EXISTS quarantined_at,
    DROP COLUMN IF EXISTS quarantine_reason;
