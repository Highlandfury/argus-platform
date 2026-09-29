-- 000004_ingestion.up.sql
-- Argus Phase 1 — ingestion idempotency ledger.
-- Owner module: ingest.
--
-- PK (collector_id, batch_seq) is the batch-level idempotency key: the ingest transaction
-- inserts first; no row returned => duplicate batch => STATUS_DUPLICATE (no sample work).

CREATE TABLE ingested_batches (
    collector_id uuid        NOT NULL REFERENCES collectors(id) ON DELETE CASCADE,
    batch_seq    bigint      NOT NULL,
    org_id       uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    sample_count integer     NOT NULL,
    first_ts     timestamptz,
    last_ts      timestamptz,
    received_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ingested_batches_pk        PRIMARY KEY (collector_id, batch_seq),
    CONSTRAINT ingested_batches_seq_pos   CHECK (batch_seq > 0),
    CONSTRAINT ingested_batches_count_ok  CHECK (sample_count > 0 AND sample_count <= 5000)
);
CREATE INDEX ingested_batches_org_recent ON ingested_batches (org_id, received_at DESC);
