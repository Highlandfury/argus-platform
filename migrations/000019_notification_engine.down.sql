-- 000019_notification_engine.down.sql
DROP TABLE IF EXISTS notification_deliveries;
DROP TABLE IF EXISTS notification_routes;
DROP TABLE IF EXISTS notification_channels;
DROP INDEX IF EXISTS alert_rules_default_key;
ALTER TABLE alert_rules DROP COLUMN IF EXISTS default_key;
