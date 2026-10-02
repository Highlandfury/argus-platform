-- 000019_notification_engine.up.sql
-- Argus Phase 2 M11-S2 — notification pipeline storage: channels, routing,
-- and the at-least-once delivery log.
--
-- Owner modules: notify (internal/modules/notify); alerts gains a nullable
-- `default_key` used by the curated default rule pack (P2-AC-32).
--
-- Canonical shape (argus-platform-spec):
--   * docs/10 §17.7 — pipeline transition -> route -> policy -> render ->
--     adapter -> delivery log -> retries/breaker. Channels MVP: SMTP,
--     generic webhook (HMAC), Slack, Teams. Audit: every attempt logged with
--     response code/excerpt; message bodies retained 90 d, metadata 13 mo.
--   * docs/12 §22.14 — /notification/channels (secrets write-only),
--     /notification/routes, /notification/deliveries.
--   * docs/11 §21.2 — table catalog: notification_channels (type, config,
--     secret, enabled), notification_routes (matcher, channel_ids, policy,
--     priority, enabled), notification_deliveries (channel_id, kind, ref_id,
--     status, attempts, next_retry_at, response_code, excerpt; 13 mo).
--   * docs/17 §35.1 — delivery logs: 90 d bodies / 13 mo metadata.
--
-- Authoring decisions (recorded in docs/phase-2/M11_EVIDENCE.md §S2):
--   * Secrets live only in the SecretsVault envelope columns (data_enc /
--     kms_key_id / key_version / encryption_context), exactly the M7
--     device_credentials shape; `config` holds non-secret destination fields
--     only. The API is write-only for secrets (read returns has_secret).
--   * Routes carry an ordered `channel_ids uuid[]` (canonical priority is
--     implied by array order) and a `match` JSON
--     {severity:[...], scope:{sites,device_ids,device_kinds}}. Unknown match
--     keys are rejected at the API; the array is validated against existing
--     channels at write time (no array FKs in PostgreSQL).
--   * `notification_deliveries` stores the rendered subject/body/payload
--     snapshot: retries replay the exact rendered message (at-least-once with
--     an immutable dedup header), and the 90 d body pruning is a documented
--     maintenance job (M13 retention owns enforcement).
--   * Retry scheduling (next_attempt_at) is written by the engine with the
--     canonical backoff 1m/5m/30m/2h/6h, max 24 h total and 12 attempts,
--     then dead_letter. The partial due index serves the retry worker.
--   * DELETE on a channel is a soft disable (deliveries FK CASCADE would
--     otherwise destroy the audit trail); routes are hard-deleted.
--   * `alert_rules.default_key` marks rules installed from the curated
--     default pack; it is not unique per (org,key) because later immutable
--     versions copy it. Install skips a key that already exists once.
--
-- Tenancy: RLS ENABLE + FORCE + the exact 000005 `app.current_org` predicate
-- on all three tables. Unset context denies all rows. All runtime access goes
-- through tenant transactions.

-- ---------------------------------------------------------------------------
-- alert_rules: curated default-pack provenance (P2-AC-32).
-- ---------------------------------------------------------------------------

ALTER TABLE alert_rules ADD COLUMN default_key text;

CREATE INDEX alert_rules_default_key ON alert_rules (org_id, default_key)
    WHERE default_key IS NOT NULL;

-- ---------------------------------------------------------------------------
-- notification_channels: destinations + write-only sealed secrets.
-- ---------------------------------------------------------------------------

CREATE TABLE notification_channels (
    id                 uuid        PRIMARY KEY,
    org_id             uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind               text        NOT NULL,
    name               text        NOT NULL,
    enabled            boolean     NOT NULL DEFAULT true,
    -- Non-secret destination config, per kind:
    --   smtp    {host, port, username?, from, to[], starttls?}
    --   webhook {url, payload: "ids"|"summary", timeout_ms?}
    --   slack   {channel?}
    --   teams   {}
    config             jsonb       NOT NULL DEFAULT '{}'::jsonb,
    -- SecretsVault envelope (write-only; NULL when the kind needs no secret).
    --   smtp    {password?}
    --   webhook {signing_secret}
    --   slack   {webhook_url}
    --   teams   {webhook_url}
    secret_enc         bytea,
    kms_key_id         text,
    key_version        integer,
    encryption_context jsonb,
    created_by         uuid        REFERENCES users(id) ON DELETE SET NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT notification_channels_kind_check CHECK (kind IN ('smtp', 'webhook', 'slack', 'teams')),
    CONSTRAINT notification_channels_name_not_blank CHECK (length(btrim(name)) > 0),
    CONSTRAINT notification_channels_name_len       CHECK (length(name) <= 200),
    CONSTRAINT notification_channels_config_object  CHECK (jsonb_typeof(config) = 'object'),
    CONSTRAINT notification_channels_secret_shape CHECK (
        (secret_enc IS NULL AND kms_key_id IS NULL AND key_version IS NULL AND encryption_context IS NULL)
     OR (secret_enc IS NOT NULL AND kms_key_id IS NOT NULL AND key_version > 0
         AND encryption_context IS NOT NULL AND jsonb_typeof(encryption_context) = 'object')
    )
);

CREATE UNIQUE INDEX notification_channels_org_name_key
    ON notification_channels (org_id, lower(name));
CREATE INDEX notification_channels_list ON notification_channels (org_id, id DESC);

-- ---------------------------------------------------------------------------
-- notification_routes: transition -> (severity, scope) -> channels + policy.
-- ---------------------------------------------------------------------------

CREATE TABLE notification_routes (
    id                 uuid        PRIMARY KEY,
    org_id             uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name               text        NOT NULL,
    -- {severity: ["critical", ...] | omitted = all,
    --  scope: {sites: [uuid], device_ids: [uuid], device_kinds: [text]}}
    match              jsonb       NOT NULL DEFAULT '{}'::jsonb,
    -- Ordered channel list; delivery attempts follow this order (canonical
    -- priority; escalation policies are V2).
    channel_ids        uuid[]      NOT NULL,
    -- Rendering knobs: currently {subject_prefix?} (canonical per-route
    -- templates/grouping are V2; plain-text fallback is always rendered).
    template_overrides jsonb       NOT NULL DEFAULT '{}'::jsonb,
    enabled            boolean     NOT NULL DEFAULT true,
    created_by         uuid        REFERENCES users(id) ON DELETE SET NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT notification_routes_name_not_blank  CHECK (length(btrim(name)) > 0),
    CONSTRAINT notification_routes_name_len        CHECK (length(name) <= 200),
    CONSTRAINT notification_routes_match_object    CHECK (jsonb_typeof(match) = 'object'),
    CONSTRAINT notification_routes_template_object CHECK (jsonb_typeof(template_overrides) = 'object'),
    CONSTRAINT notification_routes_channels_check  CHECK (coalesce(array_length(channel_ids, 1), 0) >= 1)
);

CREATE INDEX notification_routes_list ON notification_routes (org_id, id DESC);

-- ---------------------------------------------------------------------------
-- notification_deliveries: one row per (transition, route, channel) attempt
-- history. Rendered subject/body/payload are snapshots so retries are exact.
-- ---------------------------------------------------------------------------

CREATE TABLE notification_deliveries (
    id               uuid        PRIMARY KEY,
    org_id           uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    alert_id         uuid        REFERENCES alerts(id) ON DELETE SET NULL,
    event_id         uuid        REFERENCES alert_events(id) ON DELETE SET NULL,
    event_kind       text        NOT NULL DEFAULT '',
    severity         text        NOT NULL DEFAULT '',
    route_id         uuid        REFERENCES notification_routes(id) ON DELETE SET NULL,
    channel_id       uuid        NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    status           text        NOT NULL,
    attempts         integer     NOT NULL DEFAULT 0,
    next_attempt_at  timestamptz,
    response_code    integer,
    response_excerpt text        NOT NULL DEFAULT '',
    dedup_key        text        NOT NULL,
    subject          text        NOT NULL DEFAULT '',
    -- 90 d retention (docs/17 §35.1); metadata below is 13 mo. Enforcement is
    -- the M13 retention maintenance job (documented in M11_EVIDENCE §S2).
    body             text        NOT NULL DEFAULT '',
    payload          jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    delivered_at     timestamptz,
    CONSTRAINT notification_deliveries_status_check CHECK (status IN ('pending', 'delivered', 'failed', 'dead_letter')),
    CONSTRAINT notification_deliveries_attempts_check CHECK (attempts >= 0 AND attempts <= 12),
    CONSTRAINT notification_deliveries_payload_object CHECK (jsonb_typeof(payload) = 'object'),
    CONSTRAINT notification_deliveries_dedup_len CHECK (length(dedup_key) = 64),
    CONSTRAINT notification_deliveries_delivered_shape CHECK (
        (status = 'delivered' AND delivered_at IS NOT NULL)
     OR (status <> 'delivered')
    )
);

-- Retry worker scan: only in-flight rows are indexed.
CREATE INDEX notification_deliveries_due
    ON notification_deliveries (next_attempt_at, id)
    WHERE status IN ('pending', 'failed');
-- Delivery-log list (newest first, cursor keyset) and per-channel views.
CREATE INDEX notification_deliveries_list
    ON notification_deliveries (org_id, created_at DESC, id DESC);
CREATE INDEX notification_deliveries_channel
    ON notification_deliveries (org_id, channel_id, created_at DESC, id DESC);
CREATE INDEX notification_deliveries_alert
    ON notification_deliveries (org_id, alert_id, created_at DESC);
-- Duplicate-content suppression window (5 min) lookup.
CREATE INDEX notification_deliveries_dedup
    ON notification_deliveries (org_id, dedup_key, created_at DESC);

-- ---------------------------------------------------------------------------
-- Row-level security: ENABLE + FORCE + the 000005 predicate on all three.
-- ---------------------------------------------------------------------------

ALTER TABLE notification_channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_channels FORCE ROW LEVEL SECURITY;
CREATE POLICY notification_channels_tenant ON notification_channels
    USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid);

ALTER TABLE notification_routes ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_routes FORCE ROW LEVEL SECURITY;
CREATE POLICY notification_routes_tenant ON notification_routes
    USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid);

ALTER TABLE notification_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY notification_deliveries_tenant ON notification_deliveries
    USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid);
