-- 000001_init_core.down.sql
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS sites;
DROP TABLE IF EXISTS organizations;
-- Roles and the timescaledb extension are intentionally left in place:
-- they may be shared across databases in the same cluster and are re-used on re-up.
