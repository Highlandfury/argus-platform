package inventory

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Sentinel errors are mapped to HTTP problems at the edge. Not-found covers
// out-of-scope resources too (RLS makes foreign rows invisible), so responses
// expose no existence oracle.
var (
	ErrDeviceNotFound    = errors.New("inventory: device not found")
	ErrInterfaceNotFound = errors.New("inventory: interface not found")
	ErrGroupNotFound     = errors.New("inventory: device group not found")
	ErrIdentityNotFound  = errors.New("inventory: identity history row not found")
	ErrSiteNotFound      = errors.New("inventory: site not found")
	ErrNameConflict      = errors.New("inventory: name already in use")
	ErrIFIndexConflict   = errors.New("inventory: interface index already in use")
	ErrMergeConflict     = errors.New("inventory: merge conflicts with existing device data")
	ErrIdentityConflict  = errors.New("inventory: identity already assigned to another device")
	ErrInvalidCursor     = errors.New("inventory: invalid cursor")
)

// sqlstateUniqueViolation is the PostgreSQL class code for unique conflicts.
const sqlstateUniqueViolation = "23505"

// identityOpenUniqueIndex is the partial unique index over open identity
// windows (migration 000011).
const identityOpenUniqueIndex = "device_identity_history_open_uniq"

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == sqlstateUniqueViolation
}

// isIdentityConflict reports whether err is the open-identity-window unique
// violation. Other 23505s (device name, if_index) map to their own conflicts.
func isIdentityConflict(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) &&
		pgErr.Code == sqlstateUniqueViolation &&
		pgErr.ConstraintName == identityOpenUniqueIndex
}

// Columns are explicitly listed (text casts for inet/macaddr so scans are
// driver-encoding independent) and shared by SELECT/RETURNING paths.
const deviceColumns = `d.id, d.org_id, d.site_id, d.zone_id, d.name, d.kind, d.vendor_id, d.model_id,
	d.sys_object_id, d.serial, d.firmware, host(d.mgmt_ip), d.status, d.poll_profile, d.critical, d.confidence,
	d.metadata, d.first_seen_at, d.last_seen_at, d.deleted_at, d.created_at, d.updated_at`

const interfaceColumns = `i.id, i.org_id, i.device_id, i.if_index, i.if_name, i.if_alias, i.if_type,
	i.admin_status, i.oper_status, i.speed_bps, i.mtu, i.mac::text, i.description, i.role, i.monitored,
	i.first_seen_at, i.last_seen_at`

const identityColumns = `h.id, h.org_id, h.device_id, h.identifier_type, h.identifier_value, h.source,
	h.first_seen_at, h.last_seen_at, h.created_at`

const groupColumns = `g.id, g.org_id, g.name, g.selector, g.created_at, g.updated_at`

func scanDevice(row pgx.Row) (Device, error) {
	var d Device
	err := row.Scan(&d.ID, &d.OrgID, &d.SiteID, &d.ZoneID, &d.Name, &d.Kind, &d.VendorID, &d.ModelID,
		&d.SysObjectID, &d.Serial, &d.Firmware, &d.MgmtIP, &d.Status, &d.PollProfile, &d.Critical, &d.Confidence,
		&d.Metadata, &d.FirstSeenAt, &d.LastSeenAt, &d.DeletedAt, &d.CreatedAt, &d.UpdatedAt)
	return d, err
}

func scanInterface(row pgx.Row) (Interface, error) {
	var i Interface
	err := row.Scan(&i.ID, &i.OrgID, &i.DeviceID, &i.IfIndex, &i.IfName, &i.IfAlias, &i.IfType,
		&i.AdminStatus, &i.OperStatus, &i.SpeedBPS, &i.MTU, &i.MAC, &i.Description, &i.Role, &i.Monitored,
		&i.FirstSeenAt, &i.LastSeenAt)
	return i, err
}

func scanIdentity(row pgx.Row) (IdentityRecord, error) {
	var h IdentityRecord
	err := row.Scan(&h.ID, &h.OrgID, &h.DeviceID, &h.IdentifierType, &h.IdentifierValue, &h.Source,
		&h.FirstSeenAt, &h.LastSeenAt, &h.CreatedAt)
	return h, err
}

func scanGroup(row pgx.Row) (DeviceGroup, error) {
	var g DeviceGroup
	err := row.Scan(&g.ID, &g.OrgID, &g.Name, &g.Selector, &g.CreatedAt, &g.UpdatedAt)
	return g, err
}

func siteExists(ctx context.Context, tx pgx.Tx, siteID uuid.UUID) (bool, error) {
	var ok bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM sites WHERE id = $1)`, siteID).Scan(&ok)
	return ok, err
}

// findDevice returns one device; includeDeleted selects the auditor view. RLS
// scopes the lookup to the transaction's org.
func findDevice(ctx context.Context, tx pgx.Tx, id uuid.UUID, includeDeleted bool) (Device, error) {
	d, err := scanDevice(tx.QueryRow(ctx,
		`SELECT `+deviceColumns+` FROM devices d WHERE d.id = $1 AND ($2::boolean OR d.deleted_at IS NULL)`,
		id, includeDeleted))
	if errors.Is(err, pgx.ErrNoRows) {
		return Device{}, ErrDeviceNotFound
	}
	return d, err
}

// lockDeviceIDs locks the given live devices FOR UPDATE and returns the ids
// that exist in scope (merge validation + serialization).
func lockDeviceIDs(ctx context.Context, tx pgx.Tx, ids []uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `
		SELECT d.id FROM devices d
		WHERE d.id = ANY($1) AND d.deleted_at IS NULL
		FOR UPDATE`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	found := make([]uuid.UUID, 0, len(ids))
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		found = append(found, id)
	}
	return found, rows.Err()
}

func listDevices(ctx context.Context, tx pgx.Tx, limit int, after *uuid.UUID, f DeviceFilter, desc bool) ([]Device, error) {
	// Newest-first walks descending ids (UUIDv7 is time-ordered); the cursor
	// comparison flips with the direction so pages stay stable.
	cmp, dir := ">", ""
	if desc {
		cmp, dir = "<", " DESC"
	}
	rows, err := tx.Query(ctx, `SELECT `+deviceColumns+` FROM devices d
		WHERE ($1::uuid IS NULL OR d.id `+cmp+` $1)
		  AND ($2::uuid IS NULL OR d.site_id = $2)
		  AND ($3::text IS NULL OR d.status = $3)
		  AND ($4::text IS NULL OR d.kind = $4)
		  AND ($5::boolean OR d.deleted_at IS NULL)
		  AND ($7::boolean OR d.site_id = ANY($8::uuid[]))
		ORDER BY d.id`+dir+`
		LIMIT $6`, after, f.SiteID, f.Status, f.Kind, f.IncludeDeleted, limit,
		f.Scope.Unrestricted, f.Scope.SiteIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Device, 0, limit)
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func insertDevice(ctx context.Context, tx pgx.Tx, d Device) (Device, error) {
	row := tx.QueryRow(ctx, `
		INSERT INTO devices AS d
			(id, org_id, site_id, name, kind, sys_object_id, serial, firmware, mgmt_ip, status, poll_profile, critical, confidence, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::inet, $10, $11, $12, $13, $14::jsonb)
		RETURNING `+deviceColumns,
		d.ID, d.OrgID, d.SiteID, d.Name, d.Kind, d.SysObjectID, d.Serial, d.Firmware, d.MgmtIP,
		d.Status, d.PollProfile, d.Critical, d.Confidence, d.Metadata)
	return scanDevice(row)
}

// updateDeviceTx applies a partial update. Each field is guarded by a presence
// boolean and nullable columns use CASE ... ELSE column, so omitted fields are
// untouched and explicit null clears.
func updateDeviceTx(ctx context.Context, tx pgx.Tx, id uuid.UUID, p DevicePatch) (Device, error) {
	row := tx.QueryRow(ctx, `
		UPDATE devices d SET
			name          = CASE WHEN $2::boolean  THEN $1::text    ELSE d.name END,
			kind          = CASE WHEN $4::boolean  THEN $3::text    ELSE d.kind END,
			site_id       = CASE WHEN $6::boolean  THEN $5::uuid    ELSE d.site_id END,
			status        = CASE WHEN $8::boolean  THEN $7::text    ELSE d.status END,
			poll_profile  = CASE WHEN $10::boolean THEN $9::text    ELSE d.poll_profile END,
			sys_object_id = CASE WHEN $12::boolean THEN $11::text   ELSE d.sys_object_id END,
			serial        = CASE WHEN $14::boolean THEN $13::text   ELSE d.serial END,
			firmware      = CASE WHEN $16::boolean THEN $15::text   ELSE d.firmware END,
			mgmt_ip       = CASE WHEN $18::boolean THEN $17::inet   ELSE d.mgmt_ip END,
			metadata      = CASE WHEN $20::boolean THEN $19::jsonb  ELSE d.metadata END,
			critical      = CASE WHEN $22::boolean THEN $21::boolean ELSE d.critical END,
			updated_at    = now()
		WHERE d.id = $23 AND d.deleted_at IS NULL
		RETURNING `+deviceColumns,
		p.Name, p.HasName,
		p.Kind, p.HasKind,
		p.SiteID, p.HasSiteID,
		p.Status, p.HasStatus,
		p.PollProfile, p.HasPollProfile,
		p.SysObjectID.Value, p.SysObjectID.Set,
		p.Serial.Value, p.Serial.Set,
		p.Firmware.Value, p.Firmware.Set,
		p.MgmtIP.Value, p.MgmtIP.Set,
		p.Metadata, p.HasMetadata,
		p.Critical, p.HasCritical,
		id)
	d, err := scanDevice(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Device{}, ErrDeviceNotFound
	}
	return d, err
}

func softDeleteDevice(ctx context.Context, tx pgx.Tx, id uuid.UUID) (bool, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE devices SET deleted_at = now(), updated_at = now()
		WHERE id = $1 AND deleted_at IS NULL`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// closeOpenIdentities closes every open identity window of a device with one
// transactionally consistent server timestamp. Called when a device is
// soft-deleted so its identities can be re-claimed (canonical reuse
// semantics); the closed rows stay as history.
func closeOpenIdentities(ctx context.Context, tx pgx.Tx, deviceID uuid.UUID) error {
	_, err := tx.Exec(ctx, `
		UPDATE device_identity_history SET last_seen_at = now()
		WHERE device_id = $1 AND last_seen_at IS NULL`, deviceID)
	return err
}

// closeOpenIdentity closes the open window for one identity key of a device, if
// present (device PATCH transitions).
func closeOpenIdentity(ctx context.Context, tx pgx.Tx, deviceID uuid.UUID, identifierType, value string) error {
	_, err := tx.Exec(ctx, `
		UPDATE device_identity_history SET last_seen_at = now()
		WHERE device_id = $1 AND identifier_type = $2 AND identifier_value = $3 AND last_seen_at IS NULL`,
		deviceID, identifierType, value)
	return err
}

// openIdentity inserts a new open identity window for a device unless the same
// device already has that exact key open (same-value corner: no redundant row).
// A conflict with ANOTHER device's open window raises 23505 on the partial
// unique index (migration 000011) and surfaces as ErrIdentityConflict. The
// boolean result reports whether a new row was actually inserted (idempotent
// repeats return false).
func openIdentity(ctx context.Context, tx pgx.Tx, orgID, deviceID uuid.UUID, identifierType, value, source string) (bool, error) {
	id, err := newID()
	if err != nil {
		return false, err
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO device_identity_history
			(id, org_id, device_id, identifier_type, identifier_value, source, first_seen_at)
		SELECT $1, $2, $3, $4, $5, $6, now()
		WHERE NOT EXISTS (
			SELECT 1 FROM device_identity_history
			WHERE device_id = $3 AND identifier_type = $4 AND identifier_value = $5 AND last_seen_at IS NULL
		)`,
		id, orgID, deviceID, identifierType, value, source)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// findOpenIdentity returns the device's open window for one identity key.
func findOpenIdentity(ctx context.Context, tx pgx.Tx, deviceID uuid.UUID, identifierType, value string) (IdentityRecord, error) {
	h, err := scanIdentity(tx.QueryRow(ctx, `SELECT `+identityColumns+` FROM device_identity_history h
		WHERE h.device_id = $1 AND h.identifier_type = $2 AND h.identifier_value = $3 AND h.last_seen_at IS NULL
		ORDER BY h.id DESC
		LIMIT 1`, deviceID, identifierType, value))
	if errors.Is(err, pgx.ErrNoRows) {
		return IdentityRecord{}, ErrIdentityNotFound
	}
	return h, err
}

// findIdentityByID returns one identity-history row belonging to a device. RLS
// scopes the lookup to the transaction's org; a foreign/missing row is
// ErrIdentityNotFound (no existence oracle).
func findIdentityByID(ctx context.Context, tx pgx.Tx, deviceID, historyID uuid.UUID) (IdentityRecord, error) {
	h, err := scanIdentity(tx.QueryRow(ctx, `SELECT `+identityColumns+` FROM device_identity_history h
		WHERE h.id = $1 AND h.device_id = $2`, historyID, deviceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return IdentityRecord{}, ErrIdentityNotFound
	}
	return h, err
}

// closeIdentityByID closes one open identity window by history id and returns
// the row plus whether this call performed the close. An already-closed row is
// returned unchanged with closed=false, making repeat closes idempotent; an
// unknown/foreign row is ErrIdentityNotFound.
func closeIdentityByID(ctx context.Context, tx pgx.Tx, deviceID, historyID uuid.UUID) (IdentityRecord, bool, error) {
	h, err := scanIdentity(tx.QueryRow(ctx, `
		UPDATE device_identity_history h SET last_seen_at = now()
		WHERE h.id = $1 AND h.device_id = $2 AND h.last_seen_at IS NULL
		RETURNING `+identityColumns, historyID, deviceID))
	if err == nil {
		return h, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return IdentityRecord{}, false, err
	}
	h, err = findIdentityByID(ctx, tx, deviceID, historyID)
	if err != nil {
		return IdentityRecord{}, false, err
	}
	return h, false, nil
}

// mergeDevicesTx re-points identity history and interfaces of sources into
// target and soft-deletes the sources. Interface if_index collisions abort the
// whole merge (no partial state): the UQ(device_id, if_index) contract cannot
// be silently rewritten.
func mergeDevicesTx(ctx context.Context, tx pgx.Tx, target uuid.UUID, sources []uuid.UUID) (identityMoved, interfacesMoved int64, err error) {
	var conflict bool
	if err = tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM interfaces src
			JOIN interfaces tgt ON tgt.device_id = $1 AND tgt.if_index = src.if_index
			WHERE src.device_id = ANY($2)
		)`, target, sources).Scan(&conflict); err != nil {
		return 0, 0, err
	}
	if conflict {
		return 0, 0, ErrMergeConflict
	}
	tag, err := tx.Exec(ctx, `UPDATE interfaces SET device_id = $1 WHERE device_id = ANY($2)`, target, sources)
	if err != nil {
		return 0, 0, err
	}
	interfacesMoved = tag.RowsAffected()

	tag, err = tx.Exec(ctx, `UPDATE device_identity_history SET device_id = $1 WHERE device_id = ANY($2)`, target, sources)
	if err != nil {
		return 0, 0, err
	}
	identityMoved = tag.RowsAffected()

	// Open-window uniqueness (migration 000011) is enforced by the partial
	// unique index at every statement; this explicit pre-commit evaluation
	// pins the merge contract and aborts on legacy duplicate rows instead of
	// committing a device with two open windows for one identity key.
	var duplicateOpenIdentity bool
	if err = tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM device_identity_history
			WHERE device_id = $1 AND last_seen_at IS NULL
			GROUP BY org_id, identifier_type, identifier_value
			HAVING count(*) > 1
		)`, target).Scan(&duplicateOpenIdentity); err != nil {
		return 0, 0, err
	}
	if duplicateOpenIdentity {
		return 0, 0, ErrIdentityConflict
	}

	tag, err = tx.Exec(ctx, `
		UPDATE devices SET deleted_at = now(), updated_at = now()
		WHERE id = ANY($1) AND deleted_at IS NULL`, sources)
	if err != nil {
		return 0, 0, err
	}
	if tag.RowsAffected() != int64(len(sources)) {
		return 0, 0, ErrDeviceNotFound
	}
	if _, err = tx.Exec(ctx, `UPDATE devices SET updated_at = now() WHERE id = $1`, target); err != nil {
		return 0, 0, err
	}
	return identityMoved, interfacesMoved, nil
}

// selectDeviceIdentity returns the identity rows among ids that belong to
// deviceID. A length mismatch means the caller tried to detach unknown/foreign
// rows (no oracle: RLS hides foreign rows entirely).
func selectDeviceIdentity(ctx context.Context, tx pgx.Tx, deviceID uuid.UUID, ids []uuid.UUID) ([]IdentityRecord, error) {
	rows, err := tx.Query(ctx, `SELECT `+identityColumns+` FROM device_identity_history h
		WHERE h.device_id = $1 AND h.id = ANY($2)
		ORDER BY h.id`, deviceID, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]IdentityRecord, 0, len(ids))
	for rows.Next() {
		h, err := scanIdentity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func repointIdentity(ctx context.Context, tx pgx.Tx, from, to uuid.UUID, ids []uuid.UUID) (int64, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE device_identity_history SET device_id = $1
		WHERE device_id = $2 AND id = ANY($3)`, to, from, ids)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func listIdentity(ctx context.Context, tx pgx.Tx, deviceID uuid.UUID, limit int, after *uuid.UUID) ([]IdentityRecord, error) {
	rows, err := tx.Query(ctx, `SELECT `+identityColumns+` FROM device_identity_history h
		WHERE h.device_id = $1 AND ($2::uuid IS NULL OR h.id > $2)
		ORDER BY h.id
		LIMIT $3`, deviceID, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]IdentityRecord, 0, limit)
	for rows.Next() {
		h, err := scanIdentity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func insertIdentity(ctx context.Context, tx pgx.Tx, h IdentityRecord) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO device_identity_history (id, org_id, device_id, identifier_type, identifier_value, source, first_seen_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		h.ID, h.OrgID, h.DeviceID, h.IdentifierType, h.IdentifierValue, h.Source, h.FirstSeenAt)
	return err
}

func findInterface(ctx context.Context, tx pgx.Tx, id uuid.UUID) (Interface, error) {
	i, err := scanInterface(tx.QueryRow(ctx,
		`SELECT `+interfaceColumns+` FROM interfaces i WHERE i.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Interface{}, ErrInterfaceNotFound
	}
	return i, err
}

func listInterfaces(ctx context.Context, tx pgx.Tx, deviceID uuid.UUID, limit int, after *uuid.UUID) ([]Interface, error) {
	rows, err := tx.Query(ctx, `SELECT `+interfaceColumns+` FROM interfaces i
		WHERE i.device_id = $1 AND ($2::uuid IS NULL OR i.id > $2)
		ORDER BY i.id
		LIMIT $3`, deviceID, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Interface, 0, limit)
	for rows.Next() {
		i, err := scanInterface(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

func insertInterface(ctx context.Context, tx pgx.Tx, i Interface) (Interface, error) {
	row := tx.QueryRow(ctx, `
		INSERT INTO interfaces AS i
			(id, org_id, device_id, if_index, if_name, if_alias, if_type, admin_status, oper_status,
			 speed_bps, mtu, mac, description, role, monitored)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::macaddr, $13, $14, $15)
		RETURNING `+interfaceColumns,
		i.ID, i.OrgID, i.DeviceID, i.IfIndex, i.IfName, i.IfAlias, i.IfType, i.AdminStatus, i.OperStatus,
		i.SpeedBPS, i.MTU, i.MAC, i.Description, i.Role, i.Monitored)
	return scanInterface(row)
}

// updateInterfaceTx applies a partial update of editable metadata. if_index is
// deliberately not operator-editable; SNMP rebinding updates it through the
// audited M10-S2 association path instead.
func updateInterfaceTx(ctx context.Context, tx pgx.Tx, id uuid.UUID, p InterfacePatch) (Interface, error) {
	row := tx.QueryRow(ctx, `
		UPDATE interfaces i SET
			if_name      = CASE WHEN $2::boolean  THEN $1::text    ELSE i.if_name END,
			if_alias     = CASE WHEN $4::boolean  THEN $3::text    ELSE i.if_alias END,
			if_type      = CASE WHEN $6::boolean  THEN $5::integer ELSE i.if_type END,
			admin_status = CASE WHEN $8::boolean  THEN $7::text    ELSE i.admin_status END,
			oper_status  = CASE WHEN $10::boolean THEN $9::text    ELSE i.oper_status END,
			speed_bps    = CASE WHEN $12::boolean THEN $11::bigint ELSE i.speed_bps END,
			mtu          = CASE WHEN $14::boolean THEN $13::integer ELSE i.mtu END,
			mac          = CASE WHEN $16::boolean THEN $15::macaddr ELSE i.mac END,
			description  = CASE WHEN $18::boolean THEN $17::text   ELSE i.description END,
			role         = CASE WHEN $20::boolean THEN $19::text   ELSE i.role END,
			monitored    = CASE WHEN $22::boolean THEN $21::boolean ELSE i.monitored END
		WHERE i.id = $23
		RETURNING `+interfaceColumns,
		p.IfName, p.IfName != nil,
		p.IfAlias.Value, p.IfAlias.Set,
		p.IfType, p.IfType != nil,
		p.AdminStatus.Value, p.AdminStatus.Set,
		p.OperStatus.Value, p.OperStatus.Set,
		p.SpeedBPS, p.SpeedBPS != nil,
		p.MTU, p.MTU != nil,
		p.MAC.Value, p.MAC.Set,
		p.Description.Value, p.Description.Set,
		p.Role, p.Role != nil,
		p.Monitored, p.Monitored != nil,
		id)
	i, err := scanInterface(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Interface{}, ErrInterfaceNotFound
	}
	return i, err
}

func deleteInterface(ctx context.Context, tx pgx.Tx, id uuid.UUID) (bool, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM interfaces WHERE id = $1`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func findGroup(ctx context.Context, tx pgx.Tx, id uuid.UUID) (DeviceGroup, error) {
	g, err := scanGroup(tx.QueryRow(ctx,
		`SELECT `+groupColumns+` FROM device_groups g WHERE g.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return DeviceGroup{}, ErrGroupNotFound
	}
	return g, err
}

func listGroups(ctx context.Context, tx pgx.Tx, scope ScopeFilter, limit int, after *uuid.UUID) ([]DeviceGroup, error) {
	rows, err := tx.Query(ctx, `SELECT `+groupColumns+` FROM device_groups g
		WHERE ($1::uuid IS NULL OR g.id > $1)
		  AND ($3::boolean OR g.id = ANY($4::uuid[]))
		ORDER BY g.id
		LIMIT $2`, after, limit, scope.Unrestricted, scope.GroupIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]DeviceGroup, 0, limit)
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func insertGroup(ctx context.Context, tx pgx.Tx, g DeviceGroup) (DeviceGroup, error) {
	row := tx.QueryRow(ctx, `
		INSERT INTO device_groups AS g (id, org_id, name, selector)
		VALUES ($1, $2, $3, $4::jsonb)
		RETURNING `+groupColumns,
		g.ID, g.OrgID, g.Name, g.Selector)
	return scanGroup(row)
}

func updateGroupTx(ctx context.Context, tx pgx.Tx, id uuid.UUID, p GroupPatch) (DeviceGroup, error) {
	row := tx.QueryRow(ctx, `
		UPDATE device_groups g SET
			name       = CASE WHEN $2::boolean THEN $1::text    ELSE g.name END,
			selector   = CASE WHEN $4::boolean THEN $3::jsonb   ELSE g.selector END,
			updated_at = now()
		WHERE g.id = $5
		RETURNING `+groupColumns,
		p.Name, p.Name != nil,
		p.Selector, p.HasSelector,
		id)
	g, err := scanGroup(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return DeviceGroup{}, ErrGroupNotFound
	}
	return g, err
}

func deleteGroup(ctx context.Context, tx pgx.Tx, id uuid.UUID) (bool, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM device_groups WHERE id = $1`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}
