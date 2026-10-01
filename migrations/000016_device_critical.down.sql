-- 000016_device_critical.down.sql
ALTER TABLE devices DROP COLUMN IF EXISTS critical;
