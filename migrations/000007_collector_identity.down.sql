-- 000007_collector_identity.down.sql
DROP FUNCTION IF EXISTS public.argus_resolve_collector_certificate(bytea);
REVOKE SELECT ON enrollment_tokens FROM argus_auth;
