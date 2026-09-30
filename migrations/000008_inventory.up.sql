-- 000008_inventory.up.sql
-- Argus Phase 2 (M7-S1) — inventory core: devices, interfaces, identity history,
-- dynamic device groups.
-- Owner module: inventory.
--
-- Canonical shape: argus-platform-spec docs/11-data-database.md §21.2 (010_inventory.sql)
-- and the §21.1 table catalog. Column names/types follow the canonical DDL.
-- Deferrals (the referenced registry tables do not exist yet; recorded, not hidden):
--  * devices.kind — the canonical device_types(key) FK lands with the taxonomy
--    (Phase 3 discovery); kind stays a NOT NULL text key meanwhile.
--  * devices.vendor_id / model_id / zone_id — reserved canonical columns; their
--    FK targets (vendors, device_models, zones) arrive with discovery / floor plans.
--
-- Tenant policy: org_id + app.current_org, exactly the 000005 contract
-- (roles already exist; 000005 default privileges grant argus_app DML on new tables).

CREATE TABLE devices (
    id            uuid        PRIMARY KEY,
    org_id        uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    site_id       uuid        NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    zone_id       uuid,                                     -- zones(id) FK deferred (floor plans)
    name          text        NOT NULL,
    kind          text        NOT NULL,                     -- device_types(key) FK deferred (Phase 3)
    vendor_id     uuid,                                     -- vendors(id) FK deferred (Phase 3)
    model_id      uuid,                                     -- device_models(id) FK deferred (Phase 3)
    sys_object_id text,
    serial        text,
    firmware      text,
    mgmt_ip       inet,
    status        text        NOT NULL DEFAULT 'new',
    poll_profile  text        NOT NULL DEFAULT 'standard',
    confidence    smallint    NOT NULL DEFAULT 100,
    metadata      jsonb       NOT NULL DEFAULT '{}'::jsonb,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz,
    deleted_at    timestamptz,                              -- soft delete / retirement (14 d unreachable, unpinned)
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT devices_status_check           CHECK (status IN ('new', 'up', 'down', 'degraded', 'maintenance', 'retired')),
    CONSTRAINT devices_name_not_blank         CHECK (length(btrim(name)) > 0),
    CONSTRAINT devices_name_len               CHECK (length(name) <= 200),
    CONSTRAINT devices_kind_not_blank         CHECK (length(btrim(kind)) > 0),
    CONSTRAINT devices_poll_profile_not_blank CHECK (length(btrim(poll_profile)) > 0),
    CONSTRAINT devices_confidence_range       CHECK (confidence BETWEEN 0 AND 100),
    CONSTRAINT devices_metadata_object        CHECK (jsonb_typeof(metadata) = 'object')
);
-- Canonical identity: unique device name within a site, live rows only.
CREATE UNIQUE INDEX devices_org_site_name_uniq ON devices (org_id, site_id, name) WHERE deleted_at IS NULL;
CREATE INDEX devices_org_site   ON devices (org_id, site_id) WHERE deleted_at IS NULL;
CREATE INDEX devices_org_ip     ON devices (org_id, mgmt_ip)  WHERE deleted_at IS NULL;
CREATE INDEX devices_org_kind   ON devices (org_id, kind)     WHERE deleted_at IS NULL;
CREATE INDEX devices_org_status ON devices (org_id, status)   WHERE deleted_at IS NULL;

CREATE TABLE interfaces (
    id            uuid        PRIMARY KEY,
    org_id        uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    device_id     uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    if_index      integer     NOT NULL,                     -- SNMP ifIndex; stored, never the identity [RFC 2863]
    if_name       text        NOT NULL,
    if_alias      text,
    if_type       integer,
    admin_status  text,
    oper_status   text,
    speed_bps     bigint,
    mtu           integer,
    mac           macaddr,
    description   text,
    role          text        NOT NULL DEFAULT 'unknown',
    monitored     boolean     NOT NULL DEFAULT true,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz,
    CONSTRAINT interfaces_device_if_index_key UNIQUE (device_id, if_index),
    CONSTRAINT interfaces_role_check          CHECK (role IN ('uplink', 'access', 'trunk', 'unused', 'unknown')),
    CONSTRAINT interfaces_if_name_not_blank   CHECK (length(btrim(if_name)) > 0)
);
CREATE INDEX interfaces_org_role ON interfaces (org_id, role);

CREATE TABLE device_identity_history (
    id               uuid        PRIMARY KEY,
    org_id           uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    device_id        uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    identifier_type  text        NOT NULL,                  -- identity key hierarchy (docs/07 §11.4)
    identifier_value text        NOT NULL,
    source           text        NOT NULL,                  -- manual | snmp | lldp | discovery
    first_seen_at    timestamptz NOT NULL DEFAULT now(),
    last_seen_at     timestamptz,                           -- NULL = open window
    created_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT device_identity_history_type_check CHECK (identifier_type IN ('serial', 'chassis_id', 'sys_object_id', 'mac', 'hostname', 'mgmt_ip')),
    CONSTRAINT device_identity_history_value_not_blank CHECK (length(btrim(identifier_value)) > 0),
    CONSTRAINT device_identity_history_source_not_blank CHECK (length(btrim(source)) > 0)
);
CREATE INDEX device_identity_history_org_ident ON device_identity_history (org_id, identifier_type, identifier_value);
CREATE INDEX device_identity_history_device    ON device_identity_history (device_id);

CREATE TABLE device_groups (
    id         uuid        PRIMARY KEY,
    org_id     uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name       text        NOT NULL,
    selector   jsonb       NOT NULL DEFAULT '{}'::jsonb,    -- dynamic membership rule; usable as credential/rule scope
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT device_groups_org_name_key     UNIQUE (org_id, name),
    CONSTRAINT device_groups_name_not_blank   CHECK (length(btrim(name)) > 0),
    CONSTRAINT device_groups_name_len         CHECK (length(name) <= 200),
    CONSTRAINT device_groups_selector_object  CHECK (jsonb_typeof(selector) = 'object')
);

-- ---------------------------------------------------------------------------
-- Row-level security: enable + force + tenant policy per table (000005 pattern).
-- Policies use nullif(current_setting(...), '') so an unset context denies all rows.
-- ---------------------------------------------------------------------------

ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices FORCE ROW LEVEL SECURITY;
CREATE POLICY devices_tenant ON devices
    USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid);

ALTER TABLE interfaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE interfaces FORCE ROW LEVEL SECURITY;
CREATE POLICY interfaces_tenant ON interfaces
    USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid);

ALTER TABLE device_identity_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_identity_history FORCE ROW LEVEL SECURITY;
CREATE POLICY device_identity_history_tenant ON device_identity_history
    USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid);

ALTER TABLE device_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_groups FORCE ROW LEVEL SECURITY;
CREATE POLICY device_groups_tenant ON device_groups
    USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid);
