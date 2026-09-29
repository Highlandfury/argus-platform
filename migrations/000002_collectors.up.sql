-- 000002_collectors.up.sql
-- Argus Phase 1 — collector registry, one-time enrollment tokens, certificates, policies.
-- Owner module: collectors.

CREATE TABLE collectors (
    id                uuid        PRIMARY KEY,
    org_id            uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    site_id           uuid        NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    name              text        NOT NULL,
    status            text        NOT NULL DEFAULT 'pending',
    agent_version     text,
    hostname          text,
    os                text,
    policy_version    bigint      NOT NULL DEFAULT 0,      -- last policy version issued
    last_heartbeat_at timestamptz,
    last_stream_at    timestamptz,
    reported_stats    jsonb       NOT NULL DEFAULT '{}'::jsonb,
    enrolled_at       timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT collectors_status_check    CHECK (status IN ('pending', 'active', 'stale', 'revoked')),
    CONSTRAINT collectors_name_not_blank  CHECK (length(btrim(name)) > 0),
    CONSTRAINT collectors_name_len        CHECK (length(name) <= 128),
    CONSTRAINT collectors_org_name_key    UNIQUE (org_id, name)
);
CREATE INDEX collectors_org_site  ON collectors (org_id, site_id);
CREATE INDEX collectors_status    ON collectors (org_id, status);
CREATE INDEX collectors_heartbeat ON collectors (org_id, last_heartbeat_at DESC NULLS LAST);

CREATE TABLE enrollment_tokens (
    id                    uuid        PRIMARY KEY,
    org_id                uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    site_id               uuid        REFERENCES sites(id) ON DELETE SET NULL,
    token_hash            bytea       NOT NULL,             -- SHA-256; raw token never stored
    created_by            uuid        REFERENCES users(id) ON DELETE SET NULL,
    expires_at            timestamptz NOT NULL,
    used_at               timestamptz,
    used_by_collector_id  uuid        REFERENCES collectors(id) ON DELETE SET NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT enrollment_tokens_hash_key  UNIQUE (token_hash),
    CONSTRAINT enrollment_tokens_expiry    CHECK (expires_at > created_at)
);
CREATE INDEX enrollment_tokens_open ON enrollment_tokens (org_id, expires_at) WHERE used_at IS NULL;

CREATE TABLE collector_certificates (
    id                 uuid        PRIMARY KEY,
    org_id             uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    collector_id       uuid        NOT NULL REFERENCES collectors(id) ON DELETE CASCADE,
    serial             text        NOT NULL,
    fingerprint_sha256 bytea       NOT NULL,                -- mTLS identity map key
    not_before         timestamptz NOT NULL,
    not_after          timestamptz NOT NULL,
    revoked_at         timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT collector_certificates_serial_key UNIQUE (serial),
    CONSTRAINT collector_certificates_fp_key     UNIQUE (fingerprint_sha256),
    CONSTRAINT collector_certificates_validity   CHECK (not_after > not_before)
);
CREATE INDEX collector_certificates_collector ON collector_certificates (collector_id);
CREATE INDEX collector_certificates_org       ON collector_certificates (org_id);

CREATE TABLE collector_policies (
    id             uuid        PRIMARY KEY,
    org_id         uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    collector_id   uuid        NOT NULL REFERENCES collectors(id) ON DELETE CASCADE,
    version        bigint      NOT NULL,
    document       bytea       NOT NULL,                    -- exact signed bytes (UTF-8 JSON)
    signature      bytea       NOT NULL,                    -- Ed25519 over document
    signing_key_id text        NOT NULL,
    created_by     uuid        REFERENCES users(id) ON DELETE SET NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT collector_policies_version_positive CHECK (version > 0),
    CONSTRAINT collector_policies_version_key      UNIQUE (collector_id, version)
);
CREATE INDEX collector_policies_collector ON collector_policies (collector_id, version DESC);
