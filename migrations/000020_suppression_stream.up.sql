-- 000020_suppression_stream.up.sql
-- Argus Phase 2 M11-S3a — suppression storage: maintenance windows, operator
-- silences, and the suppression projection columns on alerts.
--
-- Owner module: alerts (internal/modules/alerts).
--
-- Canonical shape (argus-platform-spec):
--   * docs/10 §17.6 — maintenance windows are scoped (org/site/...), active
--     windows make matching alerts `Suppressed (maintenance)`: still recorded,
--     still evaluated, never notified; silences are ad-hoc exact matchers with
--     a mandatory expiry (max 30 d) and a required reason; every suppression
--     records why (window/silence/storm/parent) so "why didn't it page?" is
--     answerable.
--   * docs/12 §22.9 — CRUD `/silences` and `/maintenance-windows`, capability
--     `alert.silence`.
--   * docs/11 §21.2 — table catalog: `silences` / `maintenance_windows`
--     (scope jsonb, starts_at, duration/ends_at; past rows retained 13 mo).
--
-- Authoring decisions (recorded in docs/phase-2/M11_EVIDENCE.md §S3a):
--   * Recurrence (RFC 5545 subset) is V2, so a window is a single
--     [starts_at, ends_at) interval. The canonical building/floor/device-group
--     target nodes are not materialized in the M11 model yet; the window and
--     silence scope mirrors the rule selector's site/device/kind vocabulary.
--   * A silence carries one `match` jsonb with at most one target form
--     ({alert_id} | {fingerprint} | {scope:{sites,device_ids,device_kinds}});
--     the API validates that at least one matcher is non-empty. The 30-day
--     expiry bound is a DB CHECK as well as API validation.
--   * `alerts.suppression_ref` records WHICH window/silence caused the
--     suppression (nullable, no FK: it references maintenance_windows or
--     silences; the alert timeline remains the durable audit trail).
--     `alerts.suppression_reason` itself is the M11-S1 column.
--   * DELETE on a window or silence hard-deletes the object; the suppression
--     history lives on alerts/alert_events (docs/10 §17.6 audit requirement).
--
-- Tenancy: RLS ENABLE + FORCE + the exact 000005 `app.current_org` predicate
-- on both tables. Unset context denies all rows. All runtime access goes
-- through tenant transactions.

-- ---------------------------------------------------------------------------
-- maintenance_windows: [starts_at, ends_at) suppression scopes.
-- ---------------------------------------------------------------------------

CREATE TABLE maintenance_windows (
    id         uuid        PRIMARY KEY,
    org_id     uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name       text        NOT NULL,
    -- {sites: [uuid], device_ids: [uuid], device_kinds: [text]}; empty object
    -- = org-wide window. Matching is OR across the present lists (the same
    -- shape and semantics as alert_rules.scope_selector).
    scope      jsonb       NOT NULL DEFAULT '{}'::jsonb,
    enabled    boolean     NOT NULL DEFAULT true,
    starts_at  timestamptz NOT NULL,
    ends_at    timestamptz NOT NULL,
    created_by uuid        REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT maintenance_windows_name_not_blank CHECK (length(btrim(name)) > 0),
    CONSTRAINT maintenance_windows_name_len       CHECK (length(name) <= 200),
    CONSTRAINT maintenance_windows_scope_object   CHECK (jsonb_typeof(scope) = 'object'),
    CONSTRAINT maintenance_windows_period         CHECK (ends_at > starts_at)
);

-- Operator list (newest first).
CREATE INDEX maintenance_windows_list ON maintenance_windows (org_id, starts_at DESC, id DESC);
-- Active-window lookup at evaluation time: enabled rows whose interval may
-- contain "now". Partial index keeps the evaluator scan small.
CREATE INDEX maintenance_windows_active ON maintenance_windows (org_id, starts_at, ends_at)
    WHERE enabled;

-- ---------------------------------------------------------------------------
-- silences: ad-hoc exact matchers with a mandatory <= 30 d expiry.
-- ---------------------------------------------------------------------------

CREATE TABLE silences (
    id         uuid        PRIMARY KEY,
    org_id     uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- Exactly one target form, validated at the API:
    --   {"alert_id": "uuid"}
    --   {"fingerprint": "64-hex"}
    --   {"scope": {"sites": [...], "device_ids": [...], "device_kinds": [...]}}
    match      jsonb       NOT NULL,
    reason     text        NOT NULL,
    starts_at  timestamptz NOT NULL DEFAULT now(),
    ends_at    timestamptz NOT NULL,
    created_by uuid        REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT silences_match_object      CHECK (jsonb_typeof(match) = 'object'),
    CONSTRAINT silences_match_has_matcher CHECK (
        match ? 'alert_id' OR match ? 'fingerprint'
     OR (match ? 'scope' AND match->'scope' <> '{}'::jsonb)
    ),
    CONSTRAINT silences_reason_not_blank  CHECK (length(btrim(reason)) > 0),
    CONSTRAINT silences_reason_len        CHECK (length(reason) <= 2000),
    CONSTRAINT silences_period            CHECK (ends_at > starts_at),
    CONSTRAINT silences_max_expiry        CHECK (ends_at <= starts_at + interval '30 days')
);

-- Operator list (newest first); the same (org_id, starts_at, ends_at) shape
-- serves the evaluator's active-silence scan. Expiry is time-based so the
-- scan predicate is `starts_at <= now < ends_at`.
CREATE INDEX silences_list   ON silences (org_id, starts_at DESC, id DESC);
CREATE INDEX silences_active ON silences (org_id, starts_at, ends_at);

-- ---------------------------------------------------------------------------
-- alerts: suppression provenance projection (M11-S3a).
-- ---------------------------------------------------------------------------

ALTER TABLE alerts ADD COLUMN suppression_ref uuid;

-- ---------------------------------------------------------------------------
-- Row-level security: ENABLE + FORCE + the 000005 predicate on both tables.
-- ---------------------------------------------------------------------------

ALTER TABLE maintenance_windows ENABLE ROW LEVEL SECURITY;
ALTER TABLE maintenance_windows FORCE ROW LEVEL SECURITY;
CREATE POLICY maintenance_windows_tenant ON maintenance_windows
    USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid);

ALTER TABLE silences ENABLE ROW LEVEL SECURITY;
ALTER TABLE silences FORCE ROW LEVEL SECURITY;
CREATE POLICY silences_tenant ON silences
    USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid);
