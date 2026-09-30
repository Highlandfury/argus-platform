-- 000010_user_scope_bindings.up.sql
-- Argus Phase 2 (M7-S3 remediation, P2-D5) — server-side scope bindings for
-- the incremental RBAC-SC layer.
--
-- Semantics (docs/04 §6.3-6.6, docs/14 §24.4):
--  * A user with NO bindings has org-wide access per their role capabilities
--    (preserves the pre-P2-D5 behavior; RLS still isolates tenants).
--  * A user WITH bindings is restricted to the bound scopes; bindings inherit
--    down the resource tree: an org binding covers everything, a site binding
--    covers that site's devices (and their interfaces), a device_group binding
--    covers listing/reading that group itself.
--  * Device-level bindings are not representable in this increment (the
--    remediation spec fixes the CHECK to org|site|device_group); device access
--    resolves through the device's site binding.
--
-- scope_id is polymorphic (site id / device_group id / the org id) exactly like
-- credential_bindings (000009): the FK target varies by scope_type, so scope
-- integrity is enforced by the authorizer at request time (and by the org-scope
-- CHECK below). Unlike credential_bindings, bindings are per user and capped at
-- one row per (user, scope_type, scope_id).
--
-- Tenant policy: org_id + app.current_org, exactly the 000005 contract;
-- 000005 default privileges already grant argus_app DML on new tables.

CREATE TABLE user_scope_bindings (
    id         uuid        PRIMARY KEY,
    org_id     uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope_type text        NOT NULL,                        -- org | site | device_group
    scope_id   uuid        NOT NULL,                        -- id of the scoped row (org scope: the org id)
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT user_scope_bindings_key        UNIQUE (user_id, scope_type, scope_id),
    CONSTRAINT user_scope_bindings_scope_check CHECK (scope_type IN ('org', 'site', 'device_group')),
    CONSTRAINT user_scope_bindings_org_scope   CHECK (scope_type <> 'org' OR scope_id = org_id)
);
CREATE INDEX user_scope_bindings_user ON user_scope_bindings (org_id, user_id);

-- ---------------------------------------------------------------------------
-- Row-level security: enable + force + tenant policy (000005 pattern).
-- Policies use nullif(current_setting(...), '') so an unset context denies all rows.
-- ---------------------------------------------------------------------------

ALTER TABLE user_scope_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_scope_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY user_scope_bindings_tenant ON user_scope_bindings
    USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid);
