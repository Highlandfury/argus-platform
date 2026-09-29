-- 000001_init_core.up.sql
-- Argus Phase 1 — core tenancy and identity.
-- Owner modules: tenancy, identity.
--
-- Notes:
--  * Requires the timescaledb extension to be available (present in the pinned image;
--    managed environments pre-install it). Runs as the database owner (argus_owner).
--  * Runtime roles (argus_app, argus_auth) are created in migration 000005; LOGIN +
--    passwords are provisioned by the environment (compose init script / testcontainers /
--    production secret management), never by migrations.
--  * IDs are UUIDv7 generated in the application (google/uuid); no DB-side id defaults.

CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE organizations (
    id         uuid        PRIMARY KEY,
    name       text        NOT NULL,
    slug       text        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT organizations_name_not_blank CHECK (length(btrim(name)) > 0),
    CONSTRAINT organizations_slug_format   CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    CONSTRAINT organizations_slug_key      UNIQUE (slug)
);

CREATE TABLE sites (
    id         uuid        PRIMARY KEY,
    org_id     uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name       text        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT sites_name_not_blank CHECK (length(btrim(name)) > 0),
    CONSTRAINT sites_org_name_key   UNIQUE (org_id, name)
);
CREATE INDEX sites_org ON sites (org_id);

CREATE TABLE users (
    id            uuid        PRIMARY KEY,
    org_id        uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email         text        NOT NULL,
    password_hash text        NOT NULL,           -- Argon2id PHC string
    role          text        NOT NULL DEFAULT 'viewer',
    disabled_at   timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_role_check    CHECK (role IN ('admin', 'viewer')),
    CONSTRAINT users_email_not_blank CHECK (position('@' in email) > 1)
);
CREATE UNIQUE INDEX users_org_email_lower_uniq ON users (org_id, lower(email));
CREATE INDEX users_org ON users (org_id);

CREATE TABLE sessions (
    id           uuid        PRIMARY KEY,
    org_id       uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id      uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash   bytea       NOT NULL,            -- SHA-256 of the 256-bit session token
    csrf_hash    bytea       NOT NULL,            -- SHA-256 of the CSRF token (double submit)
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    revoked_at   timestamptz,
    CONSTRAINT sessions_token_hash_key UNIQUE (token_hash),
    CONSTRAINT sessions_expiry_check   CHECK (expires_at > created_at)
);
CREATE INDEX sessions_user_active ON sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX sessions_org         ON sessions (org_id);
