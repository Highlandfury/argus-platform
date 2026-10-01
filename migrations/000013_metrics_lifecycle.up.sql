-- 000013_metrics_lifecycle.up.sql
-- Argus Phase 2 M8 — on-prem retention defaults, cardinality quarantine state,
-- and the device-series identity branch (PHASE_2_SPEC P2-AC-09/11; canonical
-- docs/08 §13.3, docs/11 §20.4/§21.2, docs/17 §35.1).
--
-- Retention defaults (on-prem profile, PHASE_2_SPEC P2-AC-09):
--   metric_samples (raw)  30 days   (operator-configurable 30-90 via
--                                    ARGUS_METRICS_RAW_RETENTION_DAYS; applied
--                                    by `argus-server metrics-maintenance`)
--   metric_1m             30 days
--   metric_5m             90 days
--   metric_1h             13 months
--   metric_1d             3 years
-- docs/17 §35.1 lists the same matrix; its on-prem column reads 90 d / 180 d
-- for 1m/5m because it also encodes the *maximum* plan lever. The phase spec
-- pins the on-prem defaults above; the divergence is recorded in
-- M8_EVIDENCE.md §3.
--
-- Cardinality lifecycle (docs/08 §13.3, docs/11 §20.4 §21.1):
--   * metric_series.quarantined_at / quarantine_reason — runaway or
--     over-cap series creation is quarantined; ingest stops for that series
--     only, never for the device. The event `metric.cardinality.exceeded` is a
--     structured log line + counter because Phase 2 has no events table yet
--     (M11 adds alert wiring; documented in M8_EVIDENCE.md §4).
--   * retired_at already exists (000003); the retirement job tombstones
--     series whose last_seen_at is older than 30 days.
--   * the device-series identity branch completes the canonical
--     UNIQUE (org_id, device_id, metric_key, dim_hash): Phase 1 deferred this
--     index to the device phase (comment in 000003).

-- ---------------------------------------------------------------------------
-- Retention policies.
-- ---------------------------------------------------------------------------

SELECT add_retention_policy('metric_samples', INTERVAL '30 days');
SELECT add_retention_policy('metric_1m',        INTERVAL '30 days');
SELECT add_retention_policy('metric_5m',        INTERVAL '90 days');
SELECT add_retention_policy('metric_1h',        INTERVAL '13 months');
SELECT add_retention_policy('metric_1d',        INTERVAL '3 years');

-- ---------------------------------------------------------------------------
-- Quarantine state.
-- ---------------------------------------------------------------------------

ALTER TABLE metric_series
    ADD COLUMN quarantined_at timestamptz,
    ADD COLUMN quarantine_reason text;

ALTER TABLE metric_series
    ADD CONSTRAINT metric_series_quarantine_reason_check
    CHECK (quarantine_reason IS NULL OR length(quarantine_reason) <= 100);

-- Indexes for the maintenance scans (owner/BYPASSRLS role).
CREATE INDEX metric_series_quarantined
    ON metric_series (org_id, quarantined_at)
    WHERE quarantined_at IS NOT NULL;

CREATE INDEX metric_series_inactive
    ON metric_series (last_seen_at)
    WHERE retired_at IS NULL AND last_seen_at IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Device series identity (canonical docs/11 §21.2).
-- ---------------------------------------------------------------------------

CREATE UNIQUE INDEX metric_series_device_identity
    ON metric_series (org_id, device_id, metric_key, dim_hash)
    WHERE device_id IS NOT NULL;
