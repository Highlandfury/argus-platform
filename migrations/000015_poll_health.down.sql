-- 000015_poll_health.down.sql
-- Dev-only reverse of 000015: drop the retention policy and the hypertable
-- (chunks, indexes and the RLS policy go with the table), then restore the
-- Phase-1 sample-count constraint. Health-only ledger rows (sample_count = 0)
-- cannot satisfy the old constraint, so they are removed first; they only
-- describe the dropped table's payloads.

SELECT remove_retention_policy('poll_health', if_exists => true);
DROP TABLE IF EXISTS poll_health;
DELETE FROM ingested_batches WHERE sample_count = 0;
ALTER TABLE ingested_batches DROP CONSTRAINT ingested_batches_count_ok;
ALTER TABLE ingested_batches ADD CONSTRAINT ingested_batches_count_ok
    CHECK (sample_count > 0 AND sample_count <= 5000);
