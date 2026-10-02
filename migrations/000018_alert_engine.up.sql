-- 000018_alert_engine.up.sql
-- Argus Phase 2 M11-S1 — alert engine v1 storage: versioned rules, the alert
-- state-machine rows, and the alert_events timeline.
--
-- Owner module: alerts (internal/modules/alerts).
--
-- Canonical shape (argus-platform-spec):
--   * docs/10 §17.2  — rule model: structured/versioned JSON; every edit is a
--     new immutable version; alerts pin the version that fired them.
--   * docs/10 §17.3  — state machine: one `alerts` row per (rule, resource
--     fingerprint) with explicit states; transitions append alert_events.
--   * docs/10 §17.4  — dedup fingerprint hash(rule_id, resource_type,
--     resource_id, dimension_subset) with a unique partial index (one open
--     alert per fingerprint); repeat firing updates (value,
--     last_evaluated_at) and appends an event.
--   * docs/11 §21.2  — table catalog: alert_rules (versioned), alerts
--     (fingerprint UQ partial, rule_id, resource_type/id, severity, state,
--     acked, snoozed_until, value, started_at, resolved_at,
--     last_evaluated_at), alert_events (alert_id, kind, actor, payload).
--   * docs/12 §22.9  — API surface (rules CRUD + lifecycle ops).
--
-- Authoring decisions (recorded in docs/phase-2/M11_EVIDENCE.md §S1):
--   * `alert_rules` stores every version as its own row keyed
--     (org_id, rule_id, version); "the rule" is the highest version. The
--     `enabled` flag lives on each version row, so DELETE (disable) is a new
--     immutable version with enabled=false — definition text is never mutated.
--   * `alerts.state` follows the slice deliverable vocabulary
--     pending|active|acknowledged|snoozed|suppressed|resolved. Inactive is
--     represented by the absence of a row (canonical state diagram).
--   * `alerts.dimension_subset` carries the matched series' canonical
--     dimensions: the dimension subset is part of the fingerprint, so two
--     series of one metric on one device are two alerts, never one.
--   * `alert_events` is a regular table (still RLS + org scoped). The
--     canonical monthly partitioning is a retention-shape concern that lands
--     with the M13 retention pass; the 13-month window is documented there.
--   * `alerts.started_at` records when the condition FIRST became true (the
--     Pending onset); activation/completion are timeline events. This keeps
--     the deliverable's fixed column set and makes "continuously true for
--     for_duration" auditable from alert_events + started_at.
--
-- Tenancy: RLS ENABLE + FORCE + the exact 000005 `app.current_org` predicate
-- on all three tables. Unset context denies all rows. The runtime role writes
-- and reads through tenant transactions only (no owner DSN at runtime).

-- ---------------------------------------------------------------------------
-- alert_rules: rule identity + immutable versions.
-- ---------------------------------------------------------------------------

CREATE TABLE alert_rules (
    org_id         uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    rule_id        uuid        NOT NULL,
    version        integer     NOT NULL,
    name           text        NOT NULL,
    type           text        NOT NULL,
    severity       text        NOT NULL,
    -- Structured condition JSON (see internal/modules/alerts): for threshold /
    -- rate_of_change {agg, op, value, window, for_duration, allow_partial?,
    -- recovery?}; for absence {source, window?, consecutive_failures?,
    -- recovery_successes?, check_interval?, recovery?}.
    condition      jsonb       NOT NULL,
    -- Target selection {sites?, device_ids?, device_kinds?, metric_key,
    -- dimensions?} (canonical scope_selector; metric sits in the selector).
    scope_selector jsonb       NOT NULL DEFAULT '{}'::jsonb,
    enabled        boolean     NOT NULL DEFAULT true,
    created_by     uuid        REFERENCES users(id) ON DELETE SET NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, rule_id, version),
    CONSTRAINT alert_rules_version_positive CHECK (version >= 1),
    CONSTRAINT alert_rules_name_not_blank     CHECK (length(btrim(name)) > 0),
    CONSTRAINT alert_rules_name_len           CHECK (length(name) <= 200),
    CONSTRAINT alert_rules_type_check         CHECK (type IN ('threshold', 'absence', 'rate_of_change')),
    CONSTRAINT alert_rules_severity_check     CHECK (severity IN ('info', 'warning', 'critical')),
    CONSTRAINT alert_rules_condition_object   CHECK (jsonb_typeof(condition) = 'object'),
    CONSTRAINT alert_rules_selector_object    CHECK (jsonb_typeof(scope_selector) = 'object')
);

-- ---------------------------------------------------------------------------
-- alerts: the state machine (one row per rule/resource/dimension fingerprint).
-- ---------------------------------------------------------------------------

CREATE TABLE alerts (
    id                 uuid        PRIMARY KEY,
    org_id             uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    rule_id            uuid        NOT NULL,
    rule_version       integer     NOT NULL,
    fingerprint        text        NOT NULL,
    resource_type      text        NOT NULL,
    resource_id        uuid        NOT NULL,
    dimension_subset   jsonb       NOT NULL DEFAULT '{}'::jsonb,
    state              text        NOT NULL,
    severity           text        NOT NULL,
    value              jsonb       NOT NULL DEFAULT '{}'::jsonb,
    -- Condition-first-true (Pending onset). Activation/resolution are events.
    started_at         timestamptz NOT NULL,
    last_evaluated_at  timestamptz NOT NULL,
    resolved_at        timestamptz,
    ack_by             uuid        REFERENCES users(id) ON DELETE SET NULL,
    ack_at             timestamptz,
    snooze_until       timestamptz,
    suppression_reason text        NOT NULL DEFAULT '',
    created_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT alerts_rule_version_fk FOREIGN KEY (org_id, rule_id, rule_version)
        REFERENCES alert_rules (org_id, rule_id, version) ON DELETE CASCADE,
    CONSTRAINT alerts_state_check CHECK (state IN ('pending', 'active', 'acknowledged', 'snoozed', 'suppressed', 'resolved')),
    CONSTRAINT alerts_severity_check CHECK (severity IN ('info', 'warning', 'critical')),
    CONSTRAINT alerts_fingerprint_len CHECK (length(fingerprint) = 64),
    CONSTRAINT alerts_resource_type_not_blank CHECK (length(btrim(resource_type)) > 0),
    CONSTRAINT alerts_dimension_object CHECK (jsonb_typeof(dimension_subset) = 'object'),
    CONSTRAINT alerts_value_object     CHECK (jsonb_typeof(value) = 'object'),
    -- Resolved rows always carry resolved_at and never a snooze; open rows never carry resolved_at.
    CONSTRAINT alerts_resolved_shape CHECK (
        (state = 'resolved' AND resolved_at IS NOT NULL)
     OR (state <> 'resolved' AND resolved_at IS NULL)
    ),
    CONSTRAINT alerts_snooze_shape CHECK (state = 'snoozed' OR snooze_until IS NULL)
);

-- Dedup (docs/10 §17.4): at most ONE open alert per fingerprint. `resolved` is
-- the terminal state, so every non-resolved state participates.
CREATE UNIQUE INDEX alerts_open_fingerprint ON alerts (org_id, fingerprint)
    WHERE state <> 'resolved';
-- Fingerprint history lookup (dedup checks + manual-resolve reopen).
CREATE INDEX alerts_fingerprint ON alerts (org_id, fingerprint, started_at DESC);
-- Operator list: open queue first by state then onset recency (partial index
-- keeps the hot open-queue scan small).
CREATE INDEX alerts_open_list ON alerts (org_id, severity, started_at DESC)
    WHERE state <> 'resolved';
CREATE INDEX alerts_state_list ON alerts (org_id, state, started_at DESC);
CREATE INDEX alerts_device      ON alerts (org_id, resource_type, resource_id, started_at DESC);
-- Storm control counts new alerts per device in a 5-minute window.
CREATE INDEX alerts_storm       ON alerts (org_id, resource_type, resource_id, created_at DESC);
CREATE INDEX alerts_rule        ON alerts (org_id, rule_id, started_at DESC);

-- ---------------------------------------------------------------------------
-- alert_events: the state-transition timeline.
-- ---------------------------------------------------------------------------

CREATE TABLE alert_events (
    id       uuid        PRIMARY KEY,
    org_id   uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    alert_id uuid        NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    kind     text        NOT NULL,                    -- pending | activated | updated | acknowledged | snoozed | unsnoozed | reactivated | suppressed | resolved | manual_resolved | comment | reopened
    actor_id uuid        REFERENCES users(id) ON DELETE SET NULL,
    data     jsonb       NOT NULL DEFAULT '{}'::jsonb,
    ts       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT alert_events_kind_not_blank CHECK (length(btrim(kind)) > 0),
    CONSTRAINT alert_events_data_object    CHECK (jsonb_typeof(data) = 'object')
);

CREATE INDEX alert_events_alert ON alert_events (org_id, alert_id, ts DESC, id DESC);

-- ---------------------------------------------------------------------------
-- Row-level security: ENABLE + FORCE + the 000005 predicate (unset context
-- denies all rows) on all three tables.
-- ---------------------------------------------------------------------------

ALTER TABLE alert_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY alert_rules_tenant ON alert_rules
    USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid);

ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts FORCE ROW LEVEL SECURITY;
CREATE POLICY alerts_tenant ON alerts
    USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid);

ALTER TABLE alert_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_events FORCE ROW LEVEL SECURITY;
CREATE POLICY alert_events_tenant ON alert_events
    USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid);
