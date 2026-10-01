-- 000014_drop_redundant_series_ts_index.down.sql
-- Dev-only reverse of the ADR-016 index drop (Phase-1 shape restored).
CREATE INDEX IF NOT EXISTS metric_samples_series_ts
    ON metric_samples (series_id, ts DESC);
