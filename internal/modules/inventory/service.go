package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/argus-platform/argus/internal/platform/authz"
	"github.com/argus-platform/argus/internal/platform/database"
)

// defaultPollProfile matches the 000008 column default for manual adds.
const defaultPollProfile = "standard"

// Service implements the inventory lifecycle over the database. Every method
// is org-scoped: it opens a database.WithTenant transaction (RLS + WITH CHECK
// as the isolation and integrity floor). ScopeFor resolves the caller's
// server-side scope bindings (P2-D5).
type Service struct {
	app   *pgxpool.Pool
	audit AuditSink
	authz *authz.Authorizer
}

// New wires the inventory service. audit may be nil in unit contexts; the
// server passes SlogAudit so mutations always leave structured evidence.
func New(app *pgxpool.Pool, audit AuditSink) *Service {
	return &Service{app: app, audit: audit, authz: authz.New(app)}
}

// ScopeFor resolves the caller's scope bindings inside a tenant transaction.
func (s *Service) ScopeFor(ctx context.Context, orgID, userID uuid.UUID) (authz.Scope, error) {
	return s.authz.ScopeFor(ctx, orgID, userID)
}

func parseCursor(cursor string) (*uuid.UUID, error) {
	if cursor == "" {
		return nil, nil
	}
	id, err := uuid.Parse(cursor)
	if err != nil {
		return nil, ErrInvalidCursor
	}
	return &id, nil
}

func newID() (uuid.UUID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, fmt.Errorf("inventory: generate id: %w", err)
	}
	return id, nil
}

// record writes one audit event through the configured sink (nil = disabled).
func (s *Service) record(orgID uuid.UUID, actor Actor, action, resourceType string, resourceID uuid.UUID, reason string, data map[string]any) {
	if s.audit == nil {
		return
	}
	s.audit.Record(AuditEvent{
		Action:       action,
		ActorType:    "user",
		ActorID:      actor.UserID,
		OrgID:        orgID,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Reason:       reason,
		Data:         data,
		RequestID:    actor.RequestID,
		ClientIP:     actor.ClientIP,
		At:           time.Now().UTC(),
	})
}

// ListDevices returns one cursor page ordered by id (UUIDv7, time-sortable).
func (s *Service) ListDevices(ctx context.Context, orgID uuid.UUID, f DeviceFilter, limit int, cursor string, desc bool) (DevicePage, error) {
	after, err := parseCursor(cursor)
	if err != nil {
		return DevicePage{}, err
	}
	var page DevicePage
	err = database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := listDevices(ctx, tx, limit+1, after, f, desc)
		if err != nil {
			return err
		}
		if len(rows) > limit {
			page.NextCursor = rows[limit-1].ID.String()
			page.HasMore = true
			rows = rows[:limit]
		}
		page.Devices = rows
		return nil
	})
	return page, err
}

// GetDevice returns one device (live unless includeDeleted).
func (s *Service) GetDevice(ctx context.Context, orgID, id uuid.UUID, includeDeleted bool) (Device, error) {
	var d Device
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		d, err = findDevice(ctx, tx, id, includeDeleted)
		return err
	})
	return d, err
}

// CreateDevice inserts a manual device and records the identity keys it was
// declared with as device_identity_history rows (source=manual, open window).
func (s *Service) CreateDevice(ctx context.Context, orgID uuid.UUID, in CreateDeviceInput, actor Actor) (Device, error) {
	id, err := newID()
	if err != nil {
		return Device{}, err
	}
	metadata := in.Metadata
	if len(metadata) == 0 {
		metadata = json.RawMessage(`{}`)
	}
	pollProfile := in.PollProfile
	if pollProfile == "" {
		pollProfile = defaultPollProfile
	}
	d := Device{
		ID:          id,
		OrgID:       orgID,
		SiteID:      in.SiteID,
		Name:        in.Name,
		Kind:        in.Kind,
		SysObjectID: in.SysObjectID,
		Serial:      in.Serial,
		Firmware:    in.Firmware,
		MgmtIP:      in.MgmtIP,
		Status:      "new",
		PollProfile: pollProfile,
		Critical:    in.Critical,
		Confidence:  100,
		Metadata:    metadata,
	}
	var created Device
	err = database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		ok, err := siteExists(ctx, tx, in.SiteID)
		if err != nil {
			return err
		}
		if !ok {
			return ErrSiteNotFound
		}
		created, err = insertDevice(ctx, tx, d)
		if err != nil {
			return err
		}
		records, err := identityRecordsFor(orgID, id, d, in.Identities)
		if err != nil {
			return err
		}
		for _, h := range records {
			if err := insertIdentity(ctx, tx, h); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		if isIdentityConflict(err) {
			return Device{}, ErrIdentityConflict
		}
		if isUniqueViolation(err) {
			return Device{}, ErrNameConflict
		}
		return Device{}, err
	}
	s.record(orgID, actor, ActionDeviceCreate, "device", created.ID, "", map[string]any{
		"name":    created.Name,
		"site_id": created.SiteID.String(),
	})
	return created, nil
}

// identityRecordsFor deduplicates the declared identity keys: device columns
// (serial, sysObjectID, management IP) plus explicit entries from the request.
func identityRecordsFor(orgID, deviceID uuid.UUID, d Device, explicit []IdentityInput) ([]IdentityRecord, error) {
	now := time.Now().UTC()
	seen := map[string]bool{}
	out := make([]IdentityRecord, 0, len(explicit)+3)
	add := func(typ, value string) error {
		if value == "" {
			return nil
		}
		value = canonicalIdentityValue(typ, value)
		key := typ + "\x00" + value
		if seen[key] {
			return nil
		}
		seen[key] = true
		id, err := newID()
		if err != nil {
			return err
		}
		out = append(out, IdentityRecord{
			ID:              id,
			OrgID:           orgID,
			DeviceID:        deviceID,
			IdentifierType:  typ,
			IdentifierValue: value,
			Source:          identitySourceManual,
			FirstSeenAt:     now,
		})
		return nil
	}
	if d.Serial != nil {
		if err := add(IdentityTypeSerial, *d.Serial); err != nil {
			return nil, err
		}
	}
	if d.SysObjectID != nil {
		if err := add(IdentityTypeSysObjectID, *d.SysObjectID); err != nil {
			return nil, err
		}
	}
	if d.MgmtIP != nil {
		if err := add(IdentityTypeMgmtIP, *d.MgmtIP); err != nil {
			return nil, err
		}
	}
	for _, e := range explicit {
		if err := add(e.Type, e.Value); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// UpdateDevice applies a partial update. When a canonical identity column
// (serial, sys_object_id, mgmt_ip) changes, the device's identity history is
// maintained in the SAME transaction: the old open window is closed and a new
// open window opened, both stamped with the transaction's server now().
func (s *Service) UpdateDevice(ctx context.Context, orgID, id uuid.UUID, p DevicePatch, actor Actor) (Device, error) {
	var updated Device
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		if p.HasSiteID {
			ok, err := siteExists(ctx, tx, p.SiteID)
			if err != nil {
				return err
			}
			if !ok {
				return ErrSiteNotFound
			}
		}
		cur, err := findDevice(ctx, tx, id, false)
		if err != nil {
			return err
		}
		for _, tr := range identityTransitions(cur, p) {
			if tr.Close != nil {
				if err := closeOpenIdentity(ctx, tx, id, tr.Type, *tr.Close); err != nil {
					return err
				}
			}
			if tr.Open != nil {
				if _, err := openIdentity(ctx, tx, orgID, id, tr.Type, *tr.Open, identitySourceManual); err != nil {
					return err
				}
			}
		}
		updated, err = updateDeviceTx(ctx, tx, id, p)
		return err
	})
	if err != nil {
		if isIdentityConflict(err) {
			return Device{}, ErrIdentityConflict
		}
		if isUniqueViolation(err) {
			return Device{}, ErrNameConflict
		}
		return Device{}, err
	}
	s.record(orgID, actor, ActionDeviceUpdate, "device", id, "", map[string]any{
		"name": updated.Name,
	})
	return updated, nil
}

// DeleteDevice soft-deletes a device (deleted_at; the row is kept for
// auditors and the canonical 14-day retirement path). Open identity windows
// are closed in the same transaction so the identity values can be re-claimed
// by a replacement device (docs/07 §11.4).
func (s *Service) DeleteDevice(ctx context.Context, orgID, id uuid.UUID, actor Actor) error {
	var d Device
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		d, err = findDevice(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if d.DeletedAt != nil {
			return ErrDeviceNotFound
		}
		if err := closeOpenIdentities(ctx, tx, id); err != nil {
			return err
		}
		deleted, err := softDeleteDevice(ctx, tx, id)
		if err != nil {
			return err
		}
		if !deleted {
			return ErrDeviceNotFound
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.record(orgID, actor, ActionDeviceDelete, "device", id, "", map[string]any{"name": d.Name})
	return nil
}

// ListIdentityHistory returns one cursor page of a live device's identity
// rows.
func (s *Service) ListIdentityHistory(ctx context.Context, orgID, deviceID uuid.UUID, limit int, cursor string) (IdentityPage, error) {
	after, err := parseCursor(cursor)
	if err != nil {
		return IdentityPage{}, err
	}
	var page IdentityPage
	err = database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := findDevice(ctx, tx, deviceID, false); err != nil {
			return err
		}
		rows, err := listIdentity(ctx, tx, deviceID, limit+1, after)
		if err != nil {
			return err
		}
		if len(rows) > limit {
			page.NextCursor = rows[limit-1].ID.String()
			page.HasMore = true
			rows = rows[:limit]
		}
		page.Identities = rows
		return nil
	})
	return page, err
}

// AddIdentity opens an identity-history window for one key on an existing live
// device (M10-S3b-1). The window lifecycle is the canonical one: source=manual,
// first_seen_at=now(), last_seen_at NULL (open). Repeating the same key for the
// same device is idempotent (openIdentity inserts nothing; the existing open
// row is returned). A key already open on ANOTHER live device is a
// deterministic ErrIdentityConflict via the partial unique index. The device
// row is not modified: canonical device columns (serial/sysObjectID/mgmt IP)
// change through PATCH transitions only.
func (s *Service) AddIdentity(ctx context.Context, orgID, deviceID uuid.UUID, in IdentityInput, actor Actor) (IdentityRecord, error) {
	var out IdentityRecord
	var created bool
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := findDevice(ctx, tx, deviceID, false); err != nil {
			return err
		}
		value := canonicalIdentityValue(in.Type, in.Value)
		var err error
		created, err = openIdentity(ctx, tx, orgID, deviceID, in.Type, value, identitySourceManual)
		if err != nil {
			return err
		}
		out, err = findOpenIdentity(ctx, tx, deviceID, in.Type, value)
		return err
	})
	if err != nil {
		if isIdentityConflict(err) {
			return IdentityRecord{}, ErrIdentityConflict
		}
		return IdentityRecord{}, err
	}
	// Idempotent repeats do not add a redundant audit event: only an actual
	// window opening is evidence.
	if created {
		s.record(orgID, actor, ActionDeviceIdentityAdd, "device", deviceID, "", map[string]any{
			"identity_history_id": out.ID.String(),
			"identifier_type":     out.IdentifierType,
			"identifier_value":    out.IdentifierValue,
		})
	}
	return out, nil
}

// CloseIdentity closes one identity-history window of a live device by row id
// (M10-S3b-1). Closing is idempotent: an already-closed row is returned
// unchanged and is not re-audited. Unknown or foreign rows (RLS hides foreign
// tenants) are ErrIdentityNotFound.
func (s *Service) CloseIdentity(ctx context.Context, orgID, deviceID, historyID uuid.UUID, actor Actor) (IdentityRecord, error) {
	var out IdentityRecord
	var closed bool
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := findDevice(ctx, tx, deviceID, false); err != nil {
			return err
		}
		var err error
		out, closed, err = closeIdentityByID(ctx, tx, deviceID, historyID)
		return err
	})
	if err != nil {
		return IdentityRecord{}, err
	}
	if closed {
		s.record(orgID, actor, ActionDeviceIdentityClose, "device", deviceID, "", map[string]any{
			"identity_history_id": out.ID.String(),
			"identifier_type":     out.IdentifierType,
			"identifier_value":    out.IdentifierValue,
		})
	}
	return out, nil
}

// MergeDevices merges source devices into target (P2-D7): identity history and
// interfaces are re-pointed, sources are soft-deleted, and the mutation is
// audited. The whole merge is one transaction — a conflict (interface if_index
// collision) leaves every device untouched.
func (s *Service) MergeDevices(ctx context.Context, orgID uuid.UUID, actor Actor, targetID uuid.UUID, sourceIDs []uuid.UUID, reason string) (Device, error) {
	var target Device
	var identityMoved, interfacesMoved int64
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		ids := make([]uuid.UUID, 0, len(sourceIDs)+1)
		ids = append(ids, targetID)
		ids = append(ids, sourceIDs...)
		found, err := lockDeviceIDs(ctx, tx, ids)
		if err != nil {
			return err
		}
		if len(found) != len(ids) {
			return ErrDeviceNotFound
		}
		identityMoved, interfacesMoved, err = mergeDevicesTx(ctx, tx, targetID, sourceIDs)
		if err != nil {
			return err
		}
		target, err = findDevice(ctx, tx, targetID, false)
		return err
	})
	if err != nil {
		if isIdentityConflict(err) {
			return Device{}, ErrIdentityConflict
		}
		return Device{}, err
	}
	sourceStrings := make([]string, 0, len(sourceIDs))
	for _, id := range sourceIDs {
		sourceStrings = append(sourceStrings, id.String())
	}
	s.record(orgID, actor, ActionDeviceMerge, "device", targetID, reason, map[string]any{
		"source_device_ids": sourceStrings,
		"identity_moved":    identityMoved,
		"interfaces_moved":  interfacesMoved,
	})
	return target, nil
}

// SplitDevice detaches identity-history rows from the source device into a
// newly created device (P2-D7): the new device inherits kind/site from the
// source unless overridden, and device columns (serial, sysObjectID, mgmt IP)
// are derived from the detached OPEN identity windows (closed windows are
// history and never become a live device's current identity). Source columns
// whose open identity moved are cleared so both devices stay consistent with
// their history. Uniqueness is untouched: rows are re-pointed, never cloned,
// so no duplicate open window can result.
func (s *Service) SplitDevice(ctx context.Context, orgID uuid.UUID, actor Actor, sourceID uuid.UUID, identityIDs []uuid.UUID, name, kind string, siteID *uuid.UUID, reason string) (Device, error) {
	newDeviceID, err := newID()
	if err != nil {
		return Device{}, err
	}
	var created Device
	err = database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		src, err := findDevice(ctx, tx, sourceID, false)
		if err != nil {
			return err
		}
		if kind == "" {
			kind = src.Kind
		}
		if siteID == nil {
			siteID = &src.SiteID
		}
		ok, err := siteExists(ctx, tx, *siteID)
		if err != nil {
			return err
		}
		if !ok {
			return ErrSiteNotFound
		}
		detached, err := selectDeviceIdentity(ctx, tx, sourceID, identityIDs)
		if err != nil {
			return err
		}
		if len(detached) != len(identityIDs) {
			return ErrIdentityNotFound
		}
		d := Device{
			ID:          newDeviceID,
			OrgID:       orgID,
			SiteID:      *siteID,
			Name:        name,
			Kind:        kind,
			Status:      "new",
			PollProfile: src.PollProfile,
			Confidence:  100,
			Metadata:    json.RawMessage(`{}`),
		}
		clearPatch := DevicePatch{}
		for _, h := range detached {
			if h.LastSeenAt != nil {
				continue // closed window: historical, not the new device's identity
			}
			value := h.IdentifierValue
			switch h.IdentifierType {
			case IdentityTypeSerial:
				if d.Serial == nil {
					d.Serial = &value
				}
				if src.Serial != nil && *src.Serial == value {
					clearPatch.Serial = NullableString{Set: true}
				}
			case IdentityTypeSysObjectID:
				if d.SysObjectID == nil {
					d.SysObjectID = &value
				}
				if src.SysObjectID != nil && *src.SysObjectID == value {
					clearPatch.SysObjectID = NullableString{Set: true}
				}
			case IdentityTypeMgmtIP:
				if d.MgmtIP == nil {
					v := canonicalIdentityValue(IdentityTypeMgmtIP, value)
					d.MgmtIP = &v
				}
				if src.MgmtIP != nil && canonicalIdentityValue(IdentityTypeMgmtIP, *src.MgmtIP) == canonicalIdentityValue(IdentityTypeMgmtIP, value) {
					clearPatch.MgmtIP = NullableString{Set: true}
				}
			}
		}
		created, err = insertDevice(ctx, tx, d)
		if err != nil {
			return err
		}
		moved, err := repointIdentity(ctx, tx, sourceID, newDeviceID, identityIDs)
		if err != nil {
			return err
		}
		if moved != int64(len(identityIDs)) {
			return ErrIdentityNotFound
		}
		if clearPatch.Serial.Set || clearPatch.SysObjectID.Set || clearPatch.MgmtIP.Set {
			if _, err := updateDeviceTx(ctx, tx, sourceID, clearPatch); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		if isIdentityConflict(err) {
			return Device{}, ErrIdentityConflict
		}
		if isUniqueViolation(err) {
			return Device{}, ErrNameConflict
		}
		return Device{}, err
	}
	ids := make([]string, 0, len(identityIDs))
	for _, id := range identityIDs {
		ids = append(ids, id.String())
	}
	s.record(orgID, actor, ActionDeviceSplit, "device", newDeviceID, reason, map[string]any{
		"source_device_id":     sourceID.String(),
		"identity_history_ids": ids,
	})
	return created, nil
}

// ListInterfaces returns one cursor page of a live device's interfaces.
func (s *Service) ListInterfaces(ctx context.Context, orgID, deviceID uuid.UUID, limit int, cursor string) (InterfacePage, error) {
	after, err := parseCursor(cursor)
	if err != nil {
		return InterfacePage{}, err
	}
	var page InterfacePage
	err = database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := findDevice(ctx, tx, deviceID, false); err != nil {
			return err
		}
		rows, err := listInterfaces(ctx, tx, deviceID, limit+1, after)
		if err != nil {
			return err
		}
		if len(rows) > limit {
			page.NextCursor = rows[limit-1].ID.String()
			page.HasMore = true
			rows = rows[:limit]
		}
		page.Interfaces = rows
		return nil
	})
	return page, err
}

// GetInterface returns one interface by id.
func (s *Service) GetInterface(ctx context.Context, orgID, id uuid.UUID) (Interface, error) {
	var out Interface
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = findInterface(ctx, tx, id)
		return err
	})
	return out, err
}

// CreateInterface adds a manual interface to a live device. The
// UQ(device_id, if_index) contract is enforced by the database and surfaced as
// a named conflict.
func (s *Service) CreateInterface(ctx context.Context, orgID, deviceID uuid.UUID, in CreateInterfaceInput, actor Actor) (Interface, error) {
	id, err := newID()
	if err != nil {
		return Interface{}, err
	}
	role := in.Role
	if role == "" {
		role = "unknown"
	}
	monitored := true
	if in.Monitored != nil {
		monitored = *in.Monitored
	}
	i := Interface{
		ID:          id,
		OrgID:       orgID,
		DeviceID:    deviceID,
		IfIndex:     in.IfIndex,
		IfName:      in.IfName,
		IfAlias:     in.IfAlias,
		IfType:      in.IfType,
		AdminStatus: in.AdminStatus,
		OperStatus:  in.OperStatus,
		SpeedBPS:    in.SpeedBPS,
		MTU:         in.MTU,
		MAC:         in.MAC,
		Description: in.Description,
		Role:        role,
		Monitored:   monitored,
	}
	var created Interface
	err = database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := findDevice(ctx, tx, deviceID, false); err != nil {
			return err
		}
		var err error
		created, err = insertInterface(ctx, tx, i)
		return err
	})
	if err != nil {
		if isUniqueViolation(err) {
			return Interface{}, ErrIFIndexConflict
		}
		return Interface{}, err
	}
	s.record(orgID, actor, ActionInterfaceCreate, "interface", created.ID, "", map[string]any{
		"device_id": created.DeviceID.String(),
		"if_index":  created.IfIndex,
	})
	return created, nil
}

// UpdateInterface applies a partial update of editable metadata.
func (s *Service) UpdateInterface(ctx context.Context, orgID, id uuid.UUID, p InterfacePatch, actor Actor) (Interface, error) {
	var updated Interface
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		updated, err = updateInterfaceTx(ctx, tx, id, p)
		return err
	})
	if err != nil {
		return Interface{}, err
	}
	s.record(orgID, actor, ActionInterfaceUpdate, "interface", id, "", map[string]any{
		"device_id": updated.DeviceID.String(),
	})
	return updated, nil
}

// DeleteInterface hard-deletes one interface (the 000008 shape has no
// deleted_at column).
func (s *Service) DeleteInterface(ctx context.Context, orgID, id uuid.UUID, actor Actor) error {
	var existing Interface
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		existing, err = findInterface(ctx, tx, id)
		if err != nil {
			return err
		}
		deleted, err := deleteInterface(ctx, tx, id)
		if err != nil {
			return err
		}
		if !deleted {
			return ErrInterfaceNotFound
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.record(orgID, actor, ActionInterfaceDelete, "interface", id, "", map[string]any{
		"device_id": existing.DeviceID.String(),
		"if_index":  existing.IfIndex,
	})
	return nil
}

// ListGroups returns one cursor page of device groups, narrowed by the
// caller's scope filter (P2-D5).
func (s *Service) ListGroups(ctx context.Context, orgID uuid.UUID, scope ScopeFilter, limit int, cursor string) (GroupPage, error) {
	after, err := parseCursor(cursor)
	if err != nil {
		return GroupPage{}, err
	}
	var page GroupPage
	err = database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := listGroups(ctx, tx, scope, limit+1, after)
		if err != nil {
			return err
		}
		if len(rows) > limit {
			page.NextCursor = rows[limit-1].ID.String()
			page.HasMore = true
			rows = rows[:limit]
		}
		page.Groups = rows
		return nil
	})
	return page, err
}

// GetGroup returns one device group.
func (s *Service) GetGroup(ctx context.Context, orgID, id uuid.UUID) (DeviceGroup, error) {
	var g DeviceGroup
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		g, err = findGroup(ctx, tx, id)
		return err
	})
	return g, err
}

// CreateGroup inserts a dynamic device group (selector is a jsonb object).
func (s *Service) CreateGroup(ctx context.Context, orgID uuid.UUID, in CreateGroupInput, actor Actor) (DeviceGroup, error) {
	id, err := newID()
	if err != nil {
		return DeviceGroup{}, err
	}
	selector := in.Selector
	if len(selector) == 0 {
		selector = json.RawMessage(`{}`)
	}
	g := DeviceGroup{ID: id, OrgID: orgID, Name: in.Name, Selector: selector}
	var created DeviceGroup
	err = database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		created, err = insertGroup(ctx, tx, g)
		return err
	})
	if err != nil {
		if isUniqueViolation(err) {
			return DeviceGroup{}, ErrNameConflict
		}
		return DeviceGroup{}, err
	}
	s.record(orgID, actor, ActionGroupCreate, "device_group", created.ID, "", map[string]any{"name": created.Name})
	return created, nil
}

// UpdateGroup applies a partial update.
func (s *Service) UpdateGroup(ctx context.Context, orgID, id uuid.UUID, p GroupPatch, actor Actor) (DeviceGroup, error) {
	var updated DeviceGroup
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		updated, err = updateGroupTx(ctx, tx, id, p)
		return err
	})
	if err != nil {
		if isUniqueViolation(err) {
			return DeviceGroup{}, ErrNameConflict
		}
		return DeviceGroup{}, err
	}
	s.record(orgID, actor, ActionGroupUpdate, "device_group", id, "", map[string]any{"name": updated.Name})
	return updated, nil
}

// DeleteGroup removes a device group (hard delete; bindings referencing it are
// a later-slice concern per M7-S4).
func (s *Service) DeleteGroup(ctx context.Context, orgID, id uuid.UUID, actor Actor) error {
	var existing DeviceGroup
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		existing, err = findGroup(ctx, tx, id)
		if err != nil {
			return err
		}
		deleted, err := deleteGroup(ctx, tx, id)
		if err != nil {
			return err
		}
		if !deleted {
			return ErrGroupNotFound
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.record(orgID, actor, ActionGroupDelete, "device_group", id, "", map[string]any{"name": existing.Name})
	return nil
}
