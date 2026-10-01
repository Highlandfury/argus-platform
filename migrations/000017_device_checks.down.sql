-- 000017_device_checks.down.sql
ALTER TABLE poll_health DROP CONSTRAINT IF EXISTS poll_health_origin_check;
ALTER TABLE poll_health DROP COLUMN IF EXISTS origin;
DROP TABLE IF EXISTS device_checks;
