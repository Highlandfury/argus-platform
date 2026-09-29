-- scripts/db-init/01-roles.sql
-- DEV-ONLY bootstrap executed by the TimescaleDB container on first initialization
-- (/docker-entrypoint-initdb.d). It converges the base role attributes to exactly what
-- migrations/000005_rls.up.sql expects (which uses IF NOT EXISTS and is verified by the
-- M1 role-attribute test) and creates dev LOGIN roles with throwaway passwords.
--
-- NEVER use this file in production. Production provisions roles through secret
-- management, with SSL-required connections and rotated credentials.

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'argus_app') THEN
        CREATE ROLE argus_app;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'argus_auth') THEN
        CREATE ROLE argus_auth;
    END IF;
END
$$;

-- Converge attributes regardless of prior state.
ALTER ROLE argus_app  NOLOGIN NOBYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE;
ALTER ROLE argus_auth NOLOGIN BYPASSRLS  NOSUPERUSER NOCREATEDB NOCREATEROLE;

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'argus_app_login') THEN
        CREATE ROLE argus_app_login LOGIN PASSWORD 'devpass';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'argus_auth_login') THEN
        CREATE ROLE argus_auth_login LOGIN PASSWORD 'devpass';
    END IF;
END
$$;

GRANT argus_app  TO argus_app_login;
GRANT argus_auth TO argus_auth_login;
