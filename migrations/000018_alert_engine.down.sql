-- 000018_alert_engine.down.sql
-- Reverse of 000018: the alert engine tables (events -> alerts -> rules).

DROP TABLE IF EXISTS alert_events;
DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS alert_rules;
