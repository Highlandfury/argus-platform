-- 000006_chunk_access_guard.down.sql
-- Reverts chunk-level RLS, the sweep/job functions, and the backstop job.
-- Used by dev/test down-up cycles; production never steps back into an
-- unprotected state.

DROP EVENT TRIGGER IF EXISTS argus_secure_chunk_trigger;
DROP FUNCTION IF EXISTS public.argus_secure_chunk_trigger_fn();

DO $$
DECLARE
    j record;
BEGIN
    FOR j IN SELECT job_id FROM timescaledb_information.jobs WHERE proc_name = 'argus_secure_chunk_job' LOOP
        PERFORM delete_job(j.job_id);
    END LOOP;
END;
$$;

DROP FUNCTION IF EXISTS public.argus_secure_chunk_job(integer, jsonb);
DROP FUNCTION IF EXISTS public.argus_ensure_chunk_rls();

DO $$
DECLARE
    c record;
BEGIN
    FOR c IN
        SELECT ch.chunk_schema, ch.chunk_name
        FROM timescaledb_information.chunks ch
        WHERE ch.hypertable_name = 'metric_samples'
    LOOP
        EXECUTE format('DROP POLICY IF EXISTS argus_chunk_tenant ON %I.%I', c.chunk_schema, c.chunk_name);
        EXECUTE format('ALTER TABLE %I.%I DISABLE ROW LEVEL SECURITY', c.chunk_schema, c.chunk_name);
    END LOOP;
END;
$$;

DROP FUNCTION IF EXISTS public.argus_secure_chunk(text, text, oid);
