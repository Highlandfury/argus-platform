// Package authz implements the incremental RBAC-SC authorization layer that
// M7-S3 inventory endpoints enforce (P2-D5, docs/04 §6, docs/14 §24.4):
//
//   - Capability checks are derived from the Phase-1 role model until roles
//     become data-driven: admin holds every inventory capability, viewer holds
//     the inventory read capabilities only.
//   - Scope checks use server-side user_scope_bindings (migration 000010). A
//     user with NO bindings has org-wide access; a user WITH bindings is
//     restricted to the bound org/site/device_group subtrees, which inherit
//     down the resource tree.
//
// This is deliberately NOT a general authorization framework: it is the
// smallest component that lets the inventory module declare and enforce
// capability + scope without touching the session/CSRF model.
package authz

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/argus-platform/argus/internal/platform/database"
)

// Inventory capability vocabulary (M7-S3). Canonical capability names from the
// catalog in docs/04 §6.5 are used where they exist (device.read, device.write,
// interface.read, interface.write); the remaining names are the fallback
// vocabulary fixed by the M7-S3 remediation spec because the canonical catalog
// does not name those operations. The canonical catalog also defines
// device.delete; this increment collapses device deletion under device.write
// (documented in docs/phase-2/M7_EVIDENCE.md).
const (
	CapDeviceRead         = "device.read"
	CapDeviceWrite        = "device.write"
	CapDeviceIdentityRead = "device.identity.read"
	CapDeviceMerge        = "device.merge"
	CapDeviceSplit        = "device.split"
	CapInterfaceRead      = "interface.read"
	CapInterfaceWrite     = "interface.write"
	CapDeviceGroupRead    = "device_group.read"
	CapDeviceGroupWrite   = "device_group.write"
)

// Scope types: nodes of the resource tree the authorizer resolves at. Device
// scope resolves through the device's site binding (device-level bindings are
// not representable in migration 000010).
const (
	ScopeOrg         = "org"
	ScopeSite        = "site"
	ScopeDeviceGroup = "device_group"
	ScopeDevice      = "device"
)

// InventoryCapabilities is the full capability set the inventory routes
// enforce; admin holds all of them.
var InventoryCapabilities = []string{
	CapDeviceRead, CapDeviceWrite, CapDeviceIdentityRead, CapDeviceMerge,
	CapDeviceSplit, CapInterfaceRead, CapInterfaceWrite,
	CapDeviceGroupRead, CapDeviceGroupWrite,
}

// ReadCapabilities are granted to the viewer role (all read-class inventory
// capabilities).
var ReadCapabilities = []string{
	CapDeviceRead, CapDeviceIdentityRead, CapInterfaceRead, CapDeviceGroupRead,
}

func capabilitySet(caps ...string) map[string]bool {
	out := make(map[string]bool, len(caps))
	for _, c := range caps {
		out[c] = true
	}
	return out
}

// roleCapabilities is the Phase-1 role -> capability derivation. Unknown roles
// hold nothing (fail closed). This map is the single place that changes when
// the canonical RBAC-SC catalog lands.
var roleCapabilities = map[string]map[string]bool{
	"admin":  capabilitySet(InventoryCapabilities...),
	"viewer": capabilitySet(ReadCapabilities...),
}

// Allowed reports whether the role holds the capability under the current role
// model.
func Allowed(role, capability string) bool {
	caps, ok := roleCapabilities[role]
	if !ok {
		return false
	}
	return caps[capability]
}

// IsInventoryCapability reports whether name is part of the M7-S3 vocabulary.
func IsInventoryCapability(name string) bool {
	for _, c := range InventoryCapabilities {
		if c == name {
			return true
		}
	}
	return false
}

// IsScope reports whether name is a scope type the route metadata may declare.
func IsScope(name string) bool {
	switch name {
	case ScopeOrg, ScopeSite, ScopeDeviceGroup, ScopeDevice:
		return true
	}
	return false
}

// ErrOutOfScope is returned by the Scope.Require* helpers when a resolved
// target resource is not covered by the caller's bindings. HTTP callers
// translate it to 404 for item access (enumeration resistance).
var ErrOutOfScope = errors.New("authz: resource outside the caller's scope")

// Scope is a caller's resolved scope decision: Unrestricted preserves the
// pre-P2-D5 behavior (no bindings, or an org binding), otherwise only the
// listed sites/device groups are covered.
type Scope struct {
	Unrestricted bool
	Sites        []uuid.UUID
	DeviceGroups []uuid.UUID
}

// AllowsSite reports whether a site (and therefore everything beneath it) is
// in scope.
func (s Scope) AllowsSite(siteID uuid.UUID) bool {
	if s.Unrestricted {
		return true
	}
	return contains(s.Sites, siteID)
}

// AllowsDevice reports whether a device is in scope. The device's site is the
// resolution key: site and org bindings inherit down to devices.
func (s Scope) AllowsDevice(siteID uuid.UUID) bool { return s.AllowsSite(siteID) }

// AllowsDeviceGroup reports whether a device group row is in scope. Selector
// membership resolution is not implemented yet (documented limitation): a
// device_group binding covers the group row itself, not its devices.
func (s Scope) AllowsDeviceGroup(groupID uuid.UUID) bool {
	if s.Unrestricted {
		return true
	}
	return contains(s.DeviceGroups, groupID)
}

// RequireSite returns ErrOutOfScope unless the site is covered.
func (s Scope) RequireSite(siteID uuid.UUID) error {
	if !s.AllowsSite(siteID) {
		return ErrOutOfScope
	}
	return nil
}

// RequireDevice returns ErrOutOfScope unless the device (via its site) is
// covered.
func (s Scope) RequireDevice(siteID uuid.UUID) error {
	if !s.AllowsDevice(siteID) {
		return ErrOutOfScope
	}
	return nil
}

// RequireDeviceGroup returns ErrOutOfScope unless the group is covered.
func (s Scope) RequireDeviceGroup(groupID uuid.UUID) error {
	if !s.AllowsDeviceGroup(groupID) {
		return ErrOutOfScope
	}
	return nil
}

func contains(ids []uuid.UUID, want uuid.UUID) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// Authorizer loads scope bindings server-side. It never trusts a
// request-supplied org: the org comes from the authenticated principal, and the
// query runs under RLS via database.WithTenant.
type Authorizer struct {
	pool *pgxpool.Pool
}

// New wires the authorizer to the app pool (RLS-enforced).
func New(pool *pgxpool.Pool) *Authorizer { return &Authorizer{pool: pool} }

// ScopeFor resolves the user's bindings in a tenant transaction scoped to
// orgID. No bindings (or an org binding) yields an unrestricted org-wide scope.
func (a *Authorizer) ScopeFor(ctx context.Context, orgID, userID uuid.UUID) (Scope, error) {
	if a == nil || a.pool == nil {
		return Scope{}, errors.New("authz: authorizer not configured")
	}
	var scope Scope
	err := database.WithTenant(ctx, a.pool, orgID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		scope, err = LoadScope(ctx, tx, userID)
		return err
	})
	return scope, err
}

// LoadScope reads one user's bindings using an existing tenant transaction
// (RLS scopes the rows to the transaction's org).
func LoadScope(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (Scope, error) {
	rows, err := tx.Query(ctx,
		`SELECT scope_type, scope_id FROM user_scope_bindings WHERE user_id = $1 ORDER BY scope_type, scope_id`,
		userID)
	if err != nil {
		return Scope{}, err
	}
	defer rows.Close()

	scope := Scope{Unrestricted: true}
	found := false
	for rows.Next() {
		var scopeType string
		var scopeID uuid.UUID
		if err := rows.Scan(&scopeType, &scopeID); err != nil {
			return Scope{}, err
		}
		found = true
		switch scopeType {
		case ScopeOrg:
			// An org binding inherits down: the whole org is in scope.
			scope.Unrestricted = true
			scope.Sites = nil
			scope.DeviceGroups = nil
			if err := rows.Err(); err != nil {
				return Scope{}, err
			}
			return scope, nil
		case ScopeSite:
			scope.Sites = append(scope.Sites, scopeID)
		case ScopeDeviceGroup:
			scope.DeviceGroups = append(scope.DeviceGroups, scopeID)
		default:
			// Fail closed on an unknown scope type (DB CHECK makes this
			// unreachable; a corrupt row must not widen access).
			return Scope{}, fmt.Errorf("authz: unknown scope type %q", scopeType)
		}
	}
	if err := rows.Err(); err != nil {
		return Scope{}, err
	}
	if found {
		scope.Unrestricted = false
	}
	return scope, nil
}
