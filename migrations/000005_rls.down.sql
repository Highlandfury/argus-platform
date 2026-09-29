-- 000005_rls.down.sql
-- Removes policies and grants; roles are intentionally kept (cluster-shared, re-used on re-up).

DROP POLICY IF EXISTS ingested_batches_tenant ON ingested_batches;
ALTER TABLE ingested_batches DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS metric_samples_tenant ON metric_samples;
ALTER TABLE metric_samples DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS metric_series_tenant ON metric_series;
ALTER TABLE metric_series DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS collector_policies_tenant ON collector_policies;
ALTER TABLE collector_policies DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS collector_certificates_tenant ON collector_certificates;
ALTER TABLE collector_certificates DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS collectors_tenant ON collectors;
ALTER TABLE collectors DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS enrollment_tokens_tenant ON enrollment_tokens;
ALTER TABLE enrollment_tokens DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS sessions_tenant ON sessions;
ALTER TABLE sessions DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS users_tenant ON users;
ALTER TABLE users DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS sites_tenant ON sites;
ALTER TABLE sites DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS organizations_tenant ON organizations;
ALTER TABLE organizations DISABLE ROW LEVEL SECURITY;

REVOKE SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public FROM argus_app;
REVOKE USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public FROM argus_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM argus_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE USAGE, SELECT ON SEQUENCES FROM argus_app;
REVOKE SELECT ON organizations, users, sessions FROM argus_auth;
REVOKE UPDATE (last_seen_at, revoked_at) ON sessions FROM argus_auth;
REVOKE USAGE ON SCHEMA public FROM argus_app;
REVOKE USAGE ON SCHEMA public FROM argus_auth;
