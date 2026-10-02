-- 000020_suppression_stream.down.sql
ALTER TABLE alerts DROP COLUMN IF EXISTS suppression_ref;
DROP TABLE IF EXISTS silences;
DROP TABLE IF EXISTS maintenance_windows;
