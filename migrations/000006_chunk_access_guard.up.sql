-- 000006_chunk_access_guard.up.sql
-- Chunk-level RLS for metric_samples (M1 security finding).
--
-- History of this fix (all three approaches were tested against the real image):
--   1. Revoking USAGE on _timescaledb_internal: REJECTED — TimescaleDB requires
--      chunk privileges for normal parent-hypertable queries; the app broke.
--   2. DDL event trigger on chunk creation: REJECTED — TimescaleDB creates chunks
--      through an internal path; the trigger never fired (empirically verified).
--   3. FINAL: an idempotent SECURITY DEFINER function `argus_ensure_chunk_rls()`
--      secures any chunk of metric_samples lacking RLS, applied by
--        (a) a TimescaleDB job every minute (backstop for all write paths), and
--        (b) the ingest transaction itself from M4 onward (normative requirement:
--            call it post-insert, pre-commit — zero exposure window for our writes).
--      Migration-time backfill covers existing chunks.
--
-- Chunk RLS is enabled WITHOUT FORCE: the table owner keeps its owner bypass so
-- TimescaleDB maintenance jobs (compression, retention; run as owner) are
-- unaffected; the app role is fully subject to the tenant policy.

-- 0) Cleanup of artifacts from the rejected event-trigger revision (idempotent).
DROP EVENT TRIGGER IF EXISTS argus_secure_chunk_trigger;
DROP FUNCTION IF EXISTS public.argus_secure_chunk_trigger_fn();

-- 1) Internal-schema usage is required for parent queries (Timescale grants it);
--    restore it in case an earlier revision of this migration revoked it.
GRANT USAGE ON SCHEMA _timescaledb_internal TO PUBLIC;
GRANT USAGE ON SCHEMA _timescaledb_internal TO argus_app;

-- 2) Guard for one chunk (idempotent; no user input).
CREATE OR REPLACE FUNCTION public.argus_secure_chunk(p_schema text, p_name text, p_relid oid)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    IF p_schema <> '_timescaledb_internal' THEN
        RETURN;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_attribute
        WHERE attrelid = p_relid AND attname = 'org_id' AND NOT attisdropped
    ) THEN
        RETURN;
    END IF;

    EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY', p_schema, p_name);
    EXECUTE format('DROP POLICY IF EXISTS argus_chunk_tenant ON %I.%I', p_schema, p_name);
    EXECUTE format($fmt$
        CREATE POLICY argus_chunk_tenant ON %I.%I
            USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
            WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
    $fmt$, p_schema, p_name);
END;
$$;

REVOKE ALL ON FUNCTION public.argus_secure_chunk(text, text, oid) FROM PUBLIC;

-- 3) Sweep function: secures every unsecured chunk of metric_samples.
--    SECURITY DEFINER (fixed behavior, catalog-driven, no parameters) so the app
--    role can invoke it from the ingest path; execute is revoked from PUBLIC.
CREATE OR REPLACE FUNCTION public.argus_ensure_chunk_rls()
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    c record;
    secured integer := 0;
BEGIN
    FOR c IN
        SELECT ch.chunk_schema, ch.chunk_name, cls.oid AS relid
        FROM timescaledb_information.chunks ch
        JOIN pg_namespace ns ON ns.nspname = ch.chunk_schema
        JOIN pg_class cls ON cls.relnamespace = ns.oid AND cls.relname = ch.chunk_name
        WHERE ch.hypertable_name = 'metric_samples'
          AND cls.relrowsecurity = false
    LOOP
        PERFORM public.argus_secure_chunk(c.chunk_schema, c.chunk_name, c.relid);
        secured := secured + 1;
    END LOOP;
    RETURN secured;
END;
$$;

REVOKE ALL ON FUNCTION public.argus_ensure_chunk_rls() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.argus_ensure_chunk_rls() TO argus_app;

-- 4) Backstop job: run the sweep every minute (minimum supported cadence).
CREATE OR REPLACE FUNCTION public.argus_secure_chunk_job(job_id integer, config jsonb)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    PERFORM public.argus_ensure_chunk_rls();
END;
$$;

REVOKE ALL ON FUNCTION public.argus_secure_chunk_job(integer, jsonb) FROM PUBLIC;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM timescaledb_information.jobs WHERE proc_name = 'argus_secure_chunk_job'
    ) THEN
        PERFORM add_job('public.argus_secure_chunk_job', INTERVAL '1 minute');
    END IF;
END;
$$;

-- 5) Backfill existing chunks now.
SELECT public.argus_ensure_chunk_rls();
