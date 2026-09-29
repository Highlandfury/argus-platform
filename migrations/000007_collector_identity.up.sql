-- 000007_collector_identity.up.sql
-- M3: pre-authentication hooks for the collector identity path.
--
-- 1) The enrollment handler must resolve a one-time token hash BEFORE a tenant
--    is known (the token carries the org). Grant the auth role SELECT on
--    enrollment_tokens (opaque 256-bit hash lookup; single-use claim stays on
--    the app role inside the tenant transaction). This widens the documented
--    argus_auth surface from three tables to four — recorded as a deliberate
--    M3 amendment in SPEC §7.2 and SECURITY.md.
--
-- 2) The mTLS stream authenticates by certificate fingerprint before any tenant
--    context exists. A fixed-behavior SECURITY DEFINER function resolves
--    fingerprint -> collector/org/site/status, granted only to argus_auth, so
--    the auth role still cannot read arbitrary collector rows or metric data.

GRANT SELECT ON enrollment_tokens TO argus_auth;

CREATE OR REPLACE FUNCTION public.argus_resolve_collector_certificate(p_fingerprint bytea)
RETURNS TABLE (
    collector_id   uuid,
    org_id         uuid,
    site_id        uuid,
    collector_name text,
    status         text,
    cert_id        uuid,
    revoked_at     timestamptz,
    not_after      timestamptz
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT c.id, c.org_id, c.site_id, c.name, c.status, cc.id, cc.revoked_at, cc.not_after
    FROM collector_certificates cc
    JOIN collectors c ON c.id = cc.collector_id
    WHERE cc.fingerprint_sha256 = p_fingerprint
$$;

REVOKE ALL ON FUNCTION public.argus_resolve_collector_certificate(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.argus_resolve_collector_certificate(bytea) TO argus_auth;
