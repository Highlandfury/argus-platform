-- 000003_metrics.up.sql
-- Argus Phase 1 — metric series registry + TimescaleDB samples hypertable.
-- Owner module: metrics.
--
-- Phase-1 amendments (see docs/phase-1/ADR_REVIEW.md):
--  * G5: metric_samples carries a denormalized org_id (NOT NULL) so RLS applies directly
--    to the hypertable. Cost: ~16 B/sample pre-compression; accepted and documented.
--  * Series identity uses partial unique indexes (device_id NULL branch now; the
--    device branch arrives in the device phase) instead of NULLS-NOT-DISTINCT, keeping
--    ON CONFLICT inference portable across PostgreSQL majors.
--  * No foreign key on metric_samples.series_id (ingest hot path); the series row is
--    resolved in the same transaction before samples are written.

CREATE TABLE metric_series (
    id           bigserial   PRIMARY KEY,
    org_id       uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    collector_id uuid        REFERENCES collectors(id) ON DELETE CASCADE,
    device_id    uuid,                                       -- NULL in Phase 1; set in device phase
    metric_key   text        NOT NULL,
    dimensions   jsonb       NOT NULL DEFAULT '{}'::jsonb,
    dim_hash     bigint      NOT NULL,                       -- FNV-1a 64 over canonical dims
    unit         text        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz,
    retired_at   timestamptz,
    CONSTRAINT metric_series_key_not_blank CHECK (length(metric_key) > 0 AND length(metric_key) <= 200),
    CONSTRAINT metric_series_unit_not_blank CHECK (length(btrim(unit)) > 0),
    CONSTRAINT metric_series_dims_object CHECK (jsonb_typeof(dimensions) = 'object')
);
-- Phase-1 identity branch: collector-produced series (device_id IS NULL).
CREATE UNIQUE INDEX metric_series_collector_identity
    ON metric_series (org_id, collector_id, metric_key, dim_hash)
    WHERE device_id IS NULL;
-- Device identity branch index is added by the device-phase migration (WHERE device_id IS NOT NULL).
CREATE INDEX metric_series_lookup ON metric_series (org_id, collector_id, metric_key);

CREATE TABLE metric_samples (
    org_id    uuid             NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    series_id bigint           NOT NULL,
    ts        timestamptz      NOT NULL,
    value     double precision NOT NULL,
    CONSTRAINT metric_samples_pk PRIMARY KEY (series_id, ts),
    -- Reject NaN and ±Infinity at the storage layer (app validation is first line; this is last line).
    CONSTRAINT metric_samples_value_finite CHECK (value = value AND abs(value) < 'Infinity'::float8)
);

SELECT create_hypertable(
    'metric_samples',
    'ts',
    chunk_time_interval => INTERVAL '1 day',
    create_default_indexes => false
);

CREATE INDEX metric_samples_org_ts    ON metric_samples (org_id, ts DESC);
CREATE INDEX metric_samples_series_ts ON metric_samples (series_id, ts DESC);

-- NO compression/retention policies in Phase 1 (G6): they land in Phase 2 with measured data.
