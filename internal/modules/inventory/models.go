// Package inventory owns the device / interface / device-group API surface:
// inventory rows (migrations 000008), identity history, and the manual
// merge/split flows (P2-AC-01..03, P2-D7).
//
// Every store call runs inside one database.WithTenant transaction, so RLS
// (devices_tenant et al.) enforces isolation even when a query forgets an
// org filter; the service layer never touches the pools directly.
package inventory

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Device is one devices row (migration 000008). Columns reserved for later
// milestones (zone/vendor/model) are read-only passthroughs.
type Device struct {
	ID          uuid.UUID
	OrgID       uuid.UUID
	SiteID      uuid.UUID
	ZoneID      *uuid.UUID
	Name        string
	Kind        string
	VendorID    *uuid.UUID
	ModelID     *uuid.UUID
	SysObjectID *string
	Serial      *string
	Firmware    *string
	MgmtIP      *string
	Status      string
	PollProfile string
	Confidence  int
	Metadata    json.RawMessage
	FirstSeenAt time.Time
	LastSeenAt  *time.Time
	DeletedAt   *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Interface is one interfaces row. if_index is the SNMP identity key scoped to
// the device (UQ(device_id, if_index), RFC 2863) and is never updated.
type Interface struct {
	ID          uuid.UUID
	OrgID       uuid.UUID
	DeviceID    uuid.UUID
	IfIndex     int
	IfName      string
	IfAlias     *string
	IfType      *int
	AdminStatus *string
	OperStatus  *string
	SpeedBPS    *int64
	MTU         *int
	MAC         *string
	Description *string
	Role        string
	Monitored   bool
	FirstSeenAt time.Time
	LastSeenAt  *time.Time
}

// IdentityRecord is one device_identity_history row. An open window has
// last_seen_at IS NULL; merge/split re-point device_id without rewriting the
// observation timestamps.
type IdentityRecord struct {
	ID              uuid.UUID
	OrgID           uuid.UUID
	DeviceID        uuid.UUID
	IdentifierType  string
	IdentifierValue string
	Source          string
	FirstSeenAt     time.Time
	LastSeenAt      *time.Time
	CreatedAt       time.Time
}

// DeviceGroup is one device_groups row; selector is the dynamic membership
// rule (jsonb object) usable as a credential/rule scope.
type DeviceGroup struct {
	ID        uuid.UUID
	OrgID     uuid.UUID
	Name      string
	Selector  json.RawMessage
	CreatedAt time.Time
	UpdatedAt time.Time
}

// IdentityType* are the identifier_type values allowed by the 000008 CHECK.
const (
	IdentityTypeSerial      = "serial"
	IdentityTypeChassisID   = "chassis_id"
	IdentityTypeSysObjectID = "sys_object_id"
	IdentityTypeMAC         = "mac"
	IdentityTypeHostname    = "hostname"
	IdentityTypeMgmtIP      = "mgmt_ip"
)

// IdentityTypes lists the allowed identifier_type values.
var IdentityTypes = []string{
	IdentityTypeSerial, IdentityTypeChassisID, IdentityTypeSysObjectID,
	IdentityTypeMAC, IdentityTypeHostname, IdentityTypeMgmtIP,
}

// DeviceStatuses lists the status values allowed by the 000008 CHECK.
var DeviceStatuses = []string{"new", "up", "down", "degraded", "maintenance", "retired"}

// InterfaceRoles lists the role values allowed by the 000008 CHECK.
var InterfaceRoles = []string{"uplink", "access", "trunk", "unused", "unknown"}

// DeviceFilter narrows a device listing. IncludeDeleted is the auditor view
// (?include_deleted=true, canonical soft-delete convention). Scope carries the
// caller's resolved scope bindings (P2-D5): it is fail-closed when set.
type DeviceFilter struct {
	SiteID         *uuid.UUID
	Status         *string
	Kind           *string
	IncludeDeleted bool
	Scope          ScopeFilter
}

// ScopeFilter narrows list queries to the caller's scope bindings. The zero
// value (Unrestricted=false, empty slices) matches nothing; callers with no
// bindings (or an org binding) set Unrestricted=true to preserve org-wide
// access.
type ScopeFilter struct {
	Unrestricted bool
	SiteIDs      []uuid.UUID
	GroupIDs     []uuid.UUID
}

// NullableString distinguishes an omitted value from an explicit JSON null in
// PATCH bodies: Set selects the column, a nil Value writes SQL NULL.
type NullableString struct {
	Set   bool
	Value *string
}

// DevicePatch is a partial device update. Presence booleans map to the
// canonical PATCH semantics: omitted fields keep their value, explicit null
// clears nullable fields.
type DevicePatch struct {
	Name           string
	HasName        bool
	Kind           string
	HasKind        bool
	SiteID         uuid.UUID
	HasSiteID      bool
	Status         string
	HasStatus      bool
	PollProfile    string
	HasPollProfile bool
	SysObjectID    NullableString
	Serial         NullableString
	Firmware       NullableString
	MgmtIP         NullableString
	Metadata       json.RawMessage
	HasMetadata    bool
}

// InterfacePatch is a partial interface update (editable metadata only).
type InterfacePatch struct {
	IfName      *string
	IfAlias     NullableString
	IfType      *int
	AdminStatus NullableString
	OperStatus  NullableString
	SpeedBPS    *int64
	MTU         *int
	MAC         NullableString
	Description NullableString
	Role        *string
	Monitored   *bool
}

// GroupPatch is a partial device-group update.
type GroupPatch struct {
	Name        *string
	Selector    json.RawMessage
	HasSelector bool
}

// IdentityInput is one identity key supplied on device create.
type IdentityInput struct {
	Type  string
	Value string
}

// CreateDeviceInput is the validated input for a manual device add.
type CreateDeviceInput struct {
	SiteID      uuid.UUID
	Name        string
	Kind        string
	PollProfile string
	SysObjectID *string
	Serial      *string
	Firmware    *string
	MgmtIP      *string
	Metadata    json.RawMessage
	Identities  []IdentityInput
}

// CreateInterfaceInput is the validated input for a manual interface add.
type CreateInterfaceInput struct {
	IfIndex     int
	IfName      string
	IfAlias     *string
	IfType      *int
	AdminStatus *string
	OperStatus  *string
	SpeedBPS    *int64
	MTU         *int
	MAC         *string
	Description *string
	Role        string
	Monitored   *bool
}

// CreateGroupInput is the validated input for a device-group create.
type CreateGroupInput struct {
	Name     string
	Selector json.RawMessage
}

// DevicePage is one cursor page of devices.
type DevicePage struct {
	Devices    []Device
	NextCursor string
	HasMore    bool
}

// InterfacePage is one cursor page of interfaces.
type InterfacePage struct {
	Interfaces []Interface
	NextCursor string
	HasMore    bool
}

// IdentityPage is one cursor page of identity-history rows.
type IdentityPage struct {
	Identities []IdentityRecord
	NextCursor string
	HasMore    bool
}

// GroupPage is one cursor page of device groups.
type GroupPage struct {
	Groups     []DeviceGroup
	NextCursor string
	HasMore    bool
}
