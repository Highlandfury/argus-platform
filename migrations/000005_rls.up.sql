-- 000005_rls.up.sql
-- Argus Phase 1 — runtime roles, grants, row-level security, tenant context contract.
--
-- Tenant context (normative): every tenant-scoped transaction begins with
--     SET LOCAL app.current_org = '<uuid-v7>';
-- SET LOCAL is transaction-scoped and PgBouncer-transaction-pooling compatible.
-- Both runtime roles are NOLOGIN placeholders; environments provision LOGIN roles
-- and membership (see SPEC §17), never this migration.
--
-- Pre-authentication lookups: login and session resolution happen BEFORE a tenant is
-- known. They are performed with `SET LOCAL ROLE argus_auth` (BYPASSRLS) inside a
-- transaction, and that role's grants are restricted to exactly three tables:
-- organizations, users, sessions. It cannot read collectors or metric data (no grants),
-- even though it bypasses RLS. Verified by test S-07 variant.

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'argus_app') THEN
        CREATE ROLE argus_app NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'argus_auth') THEN
        CREATE ROLE argus_auth NOLOGIN BYPASSRLS;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO argus_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO argus_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO argus_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO argus_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO argus_app;

-- argus_auth: exactly three tables, read-mostly.
GRANT USAGE ON SCHEMA public TO argus_auth;
GRANT SELECT ON organizations, users, sessions TO argus_auth;
GRANT UPDATE (last_seen_at, revoked_at) ON sessions TO argus_auth;

-- Hypertable chunks live in _timescaledb_internal. We deliberately DO NOT grant that
-- schema to argus_app: direct chunk access must remain denied so RLS cannot be bypassed
-- by querying a chunk. Parent (hypertable) access is governed by the policies below and
-- verified in M1 (S-07 variant: direct chunk SELECT as argus_app must fail).

-- ---------------------------------------------------------------------------
-- Row-level security: enable + force + policy per tenant table.
-- Policies use nullif(current_setting(...), '') so an unset context denies all rows.
-- ---------------------------------------------------------------------------

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY organizations_tenant ON organizations
    USING (id = nullif(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (id = nullif(current_setting('app.current_org', true), '')::uuid);

ALTER TABLE sites ENABLE ROW LEVEL SECURITY;
ALTER TABLE sites FORCE ROW LEVEL SECURITY;
CREATE POLICY sites_tenant ON sites
    USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid);

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
CREATE POLICY users_tenant ON users
    USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid);

ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY sessions_tenant ON sessions
    USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid);

ALTER TABLE enrollment_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE enrollment_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY enrollment_tokens_tenant ON enrollment_tokens
    USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid);

ALTER TABLE collectors ENABLE ROW LEVEL SECURITY;
ALTER TABLE collectors FORCE ROW LEVEL SECURITY;
CREATE POLICY collectors_tenant ON collectors
    USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid);

ALTER TABLE collector_certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE collector_certificates FORCE ROW LEVEL SECURITY;
CREATE POLICY collector_certificates_tenant ON collector_certificates
    USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid);

ALTER TABLE collector_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE collector_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY collector_policies_tenant ON collector_policies
    USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid);

ALTER TABLE metric_series ENABLE ROW LEVEL SECURITY;
ALTER TABLE metric_series FORCE ROW LEVEL SECURITY;
CREATE POLICY metric_series_tenant ON metric_series
    USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid);

ALTER TABLE metric_samples ENABLE ROW LEVEL SECURITY;
ALTER TABLE metric_samples FORCE ROW LEVEL SECURITY;
CREATE POLICY metric_samples_tenant ON metric_samples
    USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid);

ALTER TABLE ingested_batches ENABLE ROW LEVEL SECURITY;
ALTER TABLE ingested_batches FORCE ROW LEVEL SECURITY;
CREATE POLICY ingested_batches_tenant ON ingested_batches
    USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid);
