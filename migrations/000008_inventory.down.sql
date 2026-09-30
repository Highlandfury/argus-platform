-- 000008_inventory.down.sql
-- Policies and RLS settings are dropped with their tables.
DROP TABLE IF EXISTS device_identity_history;
DROP TABLE IF EXISTS interfaces;
DROP TABLE IF EXISTS device_groups;
DROP TABLE IF EXISTS devices;
