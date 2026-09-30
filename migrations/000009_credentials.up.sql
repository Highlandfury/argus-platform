-- 000009_credentials.up.sql
-- Argus Phase 2 (M7-S1) — write-only device credentials + scope bindings.
-- Owner module: credentials (the envelope is written by the M7-S2 secrets vault).
--
-- Canonical shape: argus-platform-spec docs/11-data-database.md §21.1 catalog
-- (name, kind, data_enc bytea, kms_key_id, metadata jsonb, rotated_at) plus the
-- docs/14 §24.5 envelope storage contract: data_enc + kms_key_id + key_version
-- and the encryption context (AAD) {org_id, secret_type, secret_id, version}.
--  * data_enc carries the AES-256-GCM ciphertext envelope; the per-secret wrapped
--    DEK and nonce live inside it (single-column envelope, canonical storage row).
--  * encryption_context is the AAD binding; a wrapped DEK cannot be replayed
--    across tenants/records.
--  * Plaintext never reaches this schema; metadata is the readable surface
--    (write-only is an API-layer guarantee, M7-S4).
--
-- credential_bindings is polymorphic by construction (scope_type, scope_id);
-- scope FKs are enforced at dispatch (M9), not by the schema. Multiple
-- credentials may bind the same scope — priority orders them for rotation and
-- dispatch. Uniqueness is per canonical catalog: (credential_id, scope_type, scope_id).

CREATE TABLE device_credentials (
    id                 uuid        PRIMARY KEY,
    org_id             uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name               text        NOT NULL,
    kind               text        NOT NULL,                -- snmp_v2c | snmp_v3 | ssh_paramiko | ... (extensible)
    data_enc           bytea       NOT NULL,                -- AES-256-GCM envelope (ciphertext + wrapped DEK + nonce)
    kms_key_id         text        NOT NULL,                -- wrapping key identifier (dev KMS binding in Phase 2)
    key_version        integer     NOT NULL,                -- KEK/DEK envelope version; rotation re-wraps
    encryption_context jsonb       NOT NULL DEFAULT '{}'::jsonb, -- AAD {org_id, secret_type, secret_id, version}
    metadata           jsonb       NOT NULL DEFAULT '{}'::jsonb, -- non-secret descriptor (username, community hint policy, ...)
    rotated_at         timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT device_credentials_org_name_key     UNIQUE (org_id, name),
    CONSTRAINT device_credentials_name_not_blank   CHECK (length(btrim(name)) > 0),
    CONSTRAINT device_credentials_name_len         CHECK (length(name) <= 200),
    CONSTRAINT device_credentials_kind_not_blank   CHECK (length(btrim(kind)) > 0),
    CONSTRAINT device_credentials_key_id_not_blank CHECK (length(btrim(kms_key_id)) > 0),
    CONSTRAINT device_credentials_key_version_pos  CHECK (key_version > 0),
    CONSTRAINT device_credentials_context_object   CHECK (jsonb_typeof(encryption_context) = 'object'),
    CONSTRAINT device_credentials_metadata_object  CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE TABLE credential_bindings (
    id            uuid        PRIMARY KEY,
    org_id        uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    credential_id uuid        NOT NULL REFERENCES device_credentials(id) ON DELETE CASCADE,
    scope_type    text        NOT NULL,                     -- org | site | device_group | device
    scope_id      uuid        NOT NULL,                     -- id of the scoped row (org scope: the org id)
    priority      integer     NOT NULL DEFAULT 0,           -- higher wins at dispatch resolution (M9)
    created_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT credential_bindings_scope_key   UNIQUE (credential_id, scope_type, scope_id),
    CONSTRAINT credential_bindings_scope_check CHECK (scope_type IN ('org', 'site', 'device_group', 'device')),
    CONSTRAINT credential_bindings_org_scope   CHECK (scope_type <> 'org' OR scope_id = org_id)
);
-- Dispatch resolution: bindings that apply to a device (direct, group, site, org).
CREATE INDEX credential_bindings_scope ON credential_bindings (org_id, scope_type, scope_id);

-- ---------------------------------------------------------------------------
-- Row-level security: enable + force + tenant policy per table (000005 pattern).
-- Policies use nullif(current_setting(...), '') so an unset context denies all rows.
-- ---------------------------------------------------------------------------

ALTER TABLE device_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY device_credentials_tenant ON device_credentials
    USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid);

ALTER TABLE credential_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE credential_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY credential_bindings_tenant ON credential_bindings
    USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid);
