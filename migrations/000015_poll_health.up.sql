-- 000015_poll_health.up.sql
-- Argus Phase 2 M9-S1 — poll health storage (P2-AC-20).
--
-- Canonical shape: argus-platform-spec docs/11-data-database.md §21.1
-- ("poll_health | Poll outcomes | device_id, ts, latency_ms, outcome,
-- error_class, consecutive_failures | 90 d") and the time-series inventory in
-- the same document (poll health is a TimescaleDB hypertable).
--
-- The canonical DDL excerpt does not include poll_health, so this migration
-- follows the platform conventions used by every other tenant table:
--   * org_id + ENABLE/FORCE RLS + app.current_org predicate (000005/000008);
--   * collector_id and device_id FKs (referential integrity; poll-health volume
--     is ~1/latency-bounded per device per tier, so the per-row FK cost is
--     immaterial unlike the metric_samples hot path);
--   * 1-day chunks, matching metric_samples (docs/11 §20.3/§21.2);
--   * 90-day retention via a TimescaleDB retention policy, exactly the
--     canonical retention matrix entry.
--
-- Idempotency: poll-health records ride MetricBatch (proto M9-S1) and are
-- written in the same tenant transaction as the batch claim, so a replayed
-- batch is deduplicated by ingested_batches(collector_id, batch_seq) before
-- any poll_health row is inserted. No second ledger is needed.
--
-- The batch ledger's sample-count check predates health-only batches (000004:
-- `sample_count > 0 AND <= 5000`). M9-S1 carries health on MetricBatch, so a
-- legitimately empty-sample batch must be claimable; the bound is widened to
-- `>= 0` and the ledger keeps its exact shape.

ALTER TABLE ingested_batches DROP CONSTRAINT ingested_batches_count_ok;
ALTER TABLE ingested_batches ADD CONSTRAINT ingested_batches_count_ok
    CHECK (sample_count >= 0 AND sample_count <= 5000);

CREATE TABLE poll_health (
    id                   uuid        NOT NULL,
    org_id               uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    collector_id         uuid        NOT NULL REFERENCES collectors(id) ON DELETE CASCADE,
    device_id            uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ts                   timestamptz NOT NULL,               -- checked_at (collector clock)
    poll_type            text        NOT NULL,               -- icmp | snmp (M9-S2)
    latency_ms           integer     NOT NULL DEFAULT 0,     -- whole-probe duration
    outcome              text        NOT NULL,               -- success | failure
    error_class          text        NOT NULL DEFAULT '',    -- timeout | unreachable | loss | ...
    consecutive_failures integer     NOT NULL DEFAULT 0,
    created_at           timestamptz NOT NULL DEFAULT now(),
    -- The partition column must be part of any unique constraint on a
    -- hypertable; id (UUIDv7) is the row identity and ts is the time dimension.
    PRIMARY KEY (id, ts),
    CONSTRAINT poll_health_poll_type_check   CHECK (poll_type IN ('icmp', 'snmp')),
    CONSTRAINT poll_health_outcome_check     CHECK (outcome IN ('success', 'failure')),
    CONSTRAINT poll_health_latency_check     CHECK (latency_ms >= 0),
    CONSTRAINT poll_health_consecutive_check CHECK (consecutive_failures >= 0),
    CONSTRAINT poll_health_error_class_len   CHECK (length(error_class) <= 100)
);

SELECT create_hypertable('poll_health', 'ts',
       chunk_time_interval => INTERVAL '1 day', create_default_indexes => false);

-- Canonical retention: 90 days (docs/11 §21.1/§21.2 retention matrix).
SELECT add_retention_policy('poll_health', INTERVAL '90 days');

-- API access path: newest poll outcomes for one device (cursor pagination).
CREATE INDEX poll_health_device_ts    ON poll_health (org_id, device_id, ts DESC);
-- Collector self-observability path (M12 lag/failure dashboards).
CREATE INDEX poll_health_collector_ts ON poll_health (org_id, collector_id, ts DESC);

-- Tenant policy: exactly the 000005/000008 contract (unset context denies all).
ALTER TABLE poll_health ENABLE ROW LEVEL SECURITY;
ALTER TABLE poll_health FORCE ROW LEVEL SECURITY;
CREATE POLICY poll_health_tenant ON poll_health
    USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid);
