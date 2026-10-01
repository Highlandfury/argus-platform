-- 000017_device_checks.up.sql
-- Argus Phase 2 M10-S0 — on-demand device checks (P2-AC-14 "scheduled and
-- on-demand runs"), idempotency-keyed, plus the on-demand classification on
-- poll_health.
--
-- The canonical documents specify the *behavior* (docs/07 §12.3 polling, docs/06
-- §10.4 cadences, docs/12 §22.1 Idempotency-Key / 202+status_url, docs/12 §9.6.3
-- diagnostic-run dispatch) but do not define a check table, so this migration
-- follows the platform conventions (000008/000015): org_id + app.current_org
-- RLS, composite org-scoped uniqueness, explicit CHECKs, app-generated UUIDv7
-- identity, cursor-friendly index.
--
-- device_checks lifecycle:
--   pending   -> the collector has (or will get on reconnect) a CheckRequest
--   completed -> the collector reported CheckResult (outcome success|failure)
--   failed    -> the server could not execute it (pending TTL expired)
-- The unique (org_id, request_key) is the durable idempotency ledger for
-- POST /v1/devices/{id}/checks: a replay returns the original row.
--
-- poll_health.origin marks on-demand probes ("on_demand") against scheduled
-- polls ("scheduled", the default for existing rows and old collectors). The
-- task instruction asked for the on-demand classification on the health row;
-- a dedicated column is the honest form of that marker (error_class keeps its
-- outcome classification semantics).

CREATE TABLE device_checks (
    id           uuid        PRIMARY KEY,
    org_id       uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    device_id    uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    -- The collector selected at request time (site's most recently connected
    -- non-revoked collector). NULL only for rows that predate a collector
    -- (never today: creation fails without one); ON DELETE SET NULL keeps the
    -- check row as an operator record if the collector is removed.
    collector_id uuid        REFERENCES collectors(id) ON DELETE SET NULL,
    poll_type    text        NOT NULL,
    status       text        NOT NULL DEFAULT 'pending',
    requested_by uuid        REFERENCES users(id) ON DELETE SET NULL,
    -- Caller-supplied idempotency key (Idempotency-Key header), org-scoped.
    request_key  text        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    outcome      text        NOT NULL DEFAULT '',            -- success | failure (terminal)
    error_class  text        NOT NULL DEFAULT '',
    latency_ms   integer,                                    -- whole-probe duration
    CONSTRAINT device_checks_poll_type_check CHECK (poll_type IN ('icmp', 'snmp')),
    CONSTRAINT device_checks_status_check    CHECK (status IN ('pending', 'completed', 'failed')),
    CONSTRAINT device_checks_outcome_check   CHECK (outcome IN ('', 'success', 'failure')),
    CONSTRAINT device_checks_latency_check   CHECK (latency_ms IS NULL OR latency_ms >= 0),
    CONSTRAINT device_checks_class_len       CHECK (length(error_class) <= 100),
    CONSTRAINT device_checks_key_len         CHECK (length(request_key) BETWEEN 1 AND 128),
    -- Terminal rows always carry completed_at; completed rows always carry an
    -- outcome; pending rows never do.
    CONSTRAINT device_checks_state_check CHECK (
        (status = 'pending'   AND completed_at IS NULL     AND outcome = '')
     OR (status = 'completed' AND completed_at IS NOT NULL AND outcome IN ('success', 'failure'))
     OR (status = 'failed'    AND completed_at IS NOT NULL)
    ),
    CONSTRAINT device_checks_org_request_key_uniq UNIQUE (org_id, request_key)
);

-- API access path: newest checks for one device.
CREATE INDEX device_checks_device_created  ON device_checks (org_id, device_id, created_at DESC);
-- Collector reconnect redelivery path (pending rows per collector).
CREATE INDEX device_checks_pending         ON device_checks (collector_id, created_at) WHERE status = 'pending';

ALTER TABLE device_checks ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_checks FORCE ROW LEVEL SECURITY;
CREATE POLICY device_checks_tenant ON device_checks
    USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid);

-- On-demand classification on poll health (M10-S0). Existing rows and old
-- collectors keep 'scheduled'; the collector marks on-demand probes explicitly.
ALTER TABLE poll_health ADD COLUMN origin text NOT NULL DEFAULT 'scheduled';
ALTER TABLE poll_health ADD CONSTRAINT poll_health_origin_check
    CHECK (origin IN ('scheduled', 'on_demand'));
