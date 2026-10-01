package inventory

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Interface observation audit actions (M10-S2; the inventory AuditSink family).
const (
	// ActionInterfaceAutoCreate is emitted when an SNMP poll discovers an
	// interface the inventory did not know yet (source evidence in the event).
	ActionInterfaceAutoCreate = "interface.auto_create"
	// ActionInterfaceRebind is emitted when a known interface reports a
	// different if_index. ifIndex is stored, never identity: the row keeps its
	// id and the event carries old_index/new_index (docs/07 §12.3).
	ActionInterfaceRebind = "interface.rebind"
)

// InterfaceObservation is one validated SNMP-discovered interface attribute
// set (M10-S2) about to be associated with an inventory `interfaces` row. The
// canonical identity is (device_id, if_name, if_alias, mac); ifIndex is
// stored, never identity (RFC 2863; docs/07 §12.3).
type InterfaceObservation struct {
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
	ObservedAt  time.Time
}

// InterfaceLinkEvent is one audit-ready mutation produced by the association.
// The caller (ingest) records it through its AuditSink after the enclosing
// transaction commits, so a rolled-back batch never leaves audit evidence.
type InterfaceLinkEvent struct {
	Action     string
	ResourceID uuid.UUID
	DeviceID   uuid.UUID
	Data       map[string]any
}

// InterfaceLinkResult aggregates one association run (bounded diagnostics and
// the audit trail).
type InterfaceLinkResult struct {
	Created int
	Updated int
	// Rebound counts rows whose if_index changed; IndexConflicts counts
	// observations that could not take their reported if_index because another
	// row on the device currently holds it (documented edge, M10-S2 evidence).
	Rebound        int
	IndexConflicts int
	// Ambiguous counts observations whose identity matched several existing
	// rows and no MAC/if_index tie-break resolved them: nothing is written
	// (never guess an identity).
	Ambiguous int
	Events    []InterfaceLinkEvent
}

// ErrInterfaceDeviceNotFound signals that an observation referenced a device
// that is missing or soft-deleted in the tenant; ingest rejects the batch the
// same way it rejects device-scoped samples.
var ErrInterfaceDeviceNotFound = errors.New("inventory: observation device not found")

// LinkInterfacesTx associates SNMP interface observations with inventory rows
// inside the caller's tenant transaction (M10-S2). It must run in the ingest
// batch transaction so the association shares the batch claim, commit and
// retry semantics: nothing is written unless the whole batch commits.
//
// Identity (docs/07 §12.3; M7 interfaces rationale): a known row is matched by
// device + if_name, preferring an exact MAC match, then an if_alias match,
// then the currently reported if_index; never by if_index alone. Unknown
// identities are inserted (auto-create). A changed if_index on a known row is
// updated and reported as a rebind event. Missing interfaces (rows present in
// inventory but absent from the poll) are left untouched (documented
// deferral: no disappearance inference in this slice).
//
// Concurrency: the device rows are locked FOR UPDATE, serializing association
// for one device across concurrent ingest transactions; different devices do
// not block each other. A device that does not exist at all rejects the batch
// (ErrInterfaceDeviceNotFound, same posture as device-scoped samples); a
// soft-deleted device still associates until the policy stops polling it, so
// an in-flight batch is never dead-lettered by the retirement.
func LinkInterfacesTx(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, obs []InterfaceObservation) (InterfaceLinkResult, error) {
	var res InterfaceLinkResult
	if len(obs) == 0 {
		return res, nil
	}

	deviceIDs := make([]uuid.UUID, 0)
	seenDevice := map[uuid.UUID]bool{}
	for _, o := range obs {
		if !seenDevice[o.DeviceID] {
			seenDevice[o.DeviceID] = true
			deviceIDs = append(deviceIDs, o.DeviceID)
		}
	}
	sort.Slice(deviceIDs, func(i, j int) bool { return deviceIDs[i].String() < deviceIDs[j].String() })

	rows, err := tx.Query(ctx, `
		SELECT d.id FROM devices d
		WHERE d.id = ANY($1)
		FOR UPDATE`, deviceIDs)
	if err != nil {
		return res, err
	}
	found := map[uuid.UUID]bool{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return res, err
		}
		found[id] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return res, err
	}
	for _, id := range deviceIDs {
		if !found[id] {
			return res, ErrInterfaceDeviceNotFound
		}
	}

	existing, err := lockDeviceInterfaces(ctx, tx, deviceIDs)
	if err != nil {
		return res, err
	}

	for _, o := range obs {
		target := chooseInterfaceRow(existing[o.DeviceID], o)
		if target == nil {
			if len(interfacesNamed(existing[o.DeviceID], o.IfName)) > 0 {
				// Several rows share the name and no tie-break resolved them:
				// never guess an identity.
				res.Ambiguous++
				continue
			}
			created, err := insertObservedInterface(ctx, tx, orgID, o)
			if err != nil {
				if isUniqueViolation(err) {
					// Another row (different identity) already holds this
					// if_index on the device; UQ(device_id, if_index) wins and
					// the observation is skipped rather than misassigned.
					res.IndexConflicts++
					continue
				}
				return res, err
			}
			existing[o.DeviceID] = append(existing[o.DeviceID], created)
			res.Created++
			res.Events = append(res.Events, InterfaceLinkEvent{
				Action:     ActionInterfaceAutoCreate,
				ResourceID: created.ID,
				DeviceID:   o.DeviceID,
				Data: map[string]any{
					"if_index": o.IfIndex,
					"if_name":  o.IfName,
					"if_alias": aliasString(o.IfAlias),
					"source":   "snmp",
				},
			})
			continue
		}

		changes := mergeObservation(target, o, existing[o.DeviceID])
		if changes.indexConflict {
			res.IndexConflicts++
		}
		if _, err := updateObservedInterface(ctx, tx, target); err != nil {
			if isUniqueViolation(err) {
				// A concurrent manual create grabbed the reported if_index
				// between our lock and this update; UQ(device_id, if_index)
				// wins and the observation is skipped (documented edge).
				res.IndexConflicts++
				continue
			}
			return res, err
		}
		res.Updated++
		if changes.rebound {
			res.Rebound++
			res.Events = append(res.Events, InterfaceLinkEvent{
				Action:     ActionInterfaceRebind,
				ResourceID: target.ID,
				DeviceID:   o.DeviceID,
				Data: map[string]any{
					"if_name":   target.IfName,
					"if_alias":  aliasString(target.IfAlias),
					"old_index": changes.oldIndex,
					"new_index": changes.newIndex,
				},
			})
		}
	}
	return res, nil
}

type observationChanges struct {
	oldIndex      int
	newIndex      int
	rebound       bool
	indexConflict bool
}

// lockDeviceInterfaces loads every interface of the given devices FOR UPDATE
// and returns them grouped by device.
func lockDeviceInterfaces(ctx context.Context, tx pgx.Tx, deviceIDs []uuid.UUID) (map[uuid.UUID][]*Interface, error) {
	rows, err := tx.Query(ctx, `SELECT `+interfaceColumns+` FROM interfaces i
		WHERE i.device_id = ANY($1)
		ORDER BY i.id
		FOR UPDATE`, deviceIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uuid.UUID][]*Interface{}
	for rows.Next() {
		i, err := scanInterface(rows)
		if err != nil {
			return nil, err
		}
		v := i
		out[i.DeviceID] = append(out[i.DeviceID], &v)
	}
	return out, rows.Err()
}

func interfacesNamed(rows []*Interface, name string) []*Interface {
	var out []*Interface
	for _, r := range rows {
		if strings.TrimSpace(r.IfName) == strings.TrimSpace(name) {
			out = append(out, r)
		}
	}
	return out
}

// chooseInterfaceRow resolves one observation against the device's existing
// rows using the canonical identity preference order: exact MAC, then
// null-safe if_alias, then if_index. A single name match is unambiguous even
// without MAC/alias. Returns nil when no row matches or the match is
// ambiguous (several name matches with no tie-break).
func chooseInterfaceRow(rows []*Interface, o InterfaceObservation) *Interface {
	named := interfacesNamed(rows, o.IfName)
	switch len(named) {
	case 0:
		return nil
	case 1:
		return named[0]
	}
	if o.MAC != nil {
		want := canonicalObservationMAC(*o.MAC)
		for _, r := range named {
			if r.MAC != nil && canonicalObservationMAC(*r.MAC) == want {
				return r
			}
		}
	}
	aliasMatches := make([]*Interface, 0, len(named))
	for _, r := range named {
		if aliasEqual(r.IfAlias, o.IfAlias) {
			aliasMatches = append(aliasMatches, r)
		}
	}
	if len(aliasMatches) == 1 {
		return aliasMatches[0]
	}
	if len(aliasMatches) > 1 {
		for _, r := range aliasMatches {
			if r.IfIndex == o.IfIndex {
				return r
			}
		}
		return nil
	}
	return nil
}

func aliasEqual(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func aliasString(a *string) any {
	if a == nil {
		return nil
	}
	return *a
}

// canonicalObservationMAC normalizes a MAC for identity comparison.
func canonicalObservationMAC(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// mergeObservation folds the observation into the existing row, preserving
// operator-set fields when the agent reports nothing: an empty if_alias never
// clears, and absent numeric attributes keep their last known value. A changed
// if_index is applied unless another row on the same device currently holds
// it. The row keeps its id throughout (ifIndex is never identity).
func mergeObservation(row *Interface, o InterfaceObservation, siblings []*Interface) observationChanges {
	ch := observationChanges{oldIndex: row.IfIndex, newIndex: row.IfIndex}
	if o.IfIndex != row.IfIndex && o.IfIndex >= 1 {
		taken := false
		for _, s := range siblings {
			if s != row && s.IfIndex == o.IfIndex {
				taken = true
				break
			}
		}
		if !taken {
			row.IfIndex = o.IfIndex
			ch.newIndex = o.IfIndex
			ch.rebound = true
		} else {
			ch.indexConflict = true
		}
	}
	if o.IfAlias != nil {
		v := *o.IfAlias
		row.IfAlias = &v
	}
	if o.IfType != nil {
		v := *o.IfType
		row.IfType = &v
	}
	if o.AdminStatus != nil {
		v := *o.AdminStatus
		row.AdminStatus = &v
	}
	if o.OperStatus != nil {
		v := *o.OperStatus
		row.OperStatus = &v
	}
	if o.SpeedBPS != nil && *o.SpeedBPS >= 0 {
		v := *o.SpeedBPS
		row.SpeedBPS = &v
	}
	if o.MTU != nil && *o.MTU > 0 {
		v := *o.MTU
		row.MTU = &v
	}
	if o.MAC != nil {
		v := strings.ToLower(*o.MAC)
		row.MAC = &v
	}
	if row.LastSeenAt == nil || o.ObservedAt.After(*row.LastSeenAt) {
		t := o.ObservedAt.UTC()
		row.LastSeenAt = &t
	}
	return ch
}

func insertObservedInterface(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, o InterfaceObservation) (*Interface, error) {
	id, err := newID()
	if err != nil {
		return nil, err
	}
	seen := o.ObservedAt.UTC()
	mac := any(nil)
	if o.MAC != nil {
		mac = strings.ToLower(*o.MAC)
	}
	row := tx.QueryRow(ctx, `
		INSERT INTO interfaces AS i
			(id, org_id, device_id, if_index, if_name, if_alias, if_type, admin_status, oper_status,
			 speed_bps, mtu, mac, role, monitored, first_seen_at, last_seen_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::macaddr, 'unknown', true, $13, $13)
		RETURNING `+interfaceColumns,
		id, orgID, o.DeviceID, o.IfIndex, strings.TrimSpace(o.IfName), o.IfAlias, o.IfType,
		o.AdminStatus, o.OperStatus, o.SpeedBPS, o.MTU, mac, seen)
	inserted, err := scanInterface(row)
	if err != nil {
		return nil, err
	}
	return &inserted, nil
}

// updateObservedInterface writes the merged row back. last_seen_at only moves
// forward (an out-of-order batch can never make a fresh interface look stale).
func updateObservedInterface(ctx context.Context, tx pgx.Tx, row *Interface) (Interface, error) {
	updated, err := scanInterface(tx.QueryRow(ctx, `
		UPDATE interfaces AS i SET
			if_index     = $2,
			if_alias     = $3,
			if_type      = $4,
			admin_status = $5,
			oper_status  = $6,
			speed_bps    = $7,
			mtu          = $8,
			mac          = $9::macaddr,
			last_seen_at = GREATEST(COALESCE(i.last_seen_at, $10), $10)
		WHERE i.id = $1
		RETURNING `+interfaceColumns,
		row.ID, row.IfIndex, row.IfAlias, row.IfType, row.AdminStatus, row.OperStatus,
		row.SpeedBPS, row.MTU, row.MAC, row.LastSeenAt))
	if err != nil {
		return Interface{}, err
	}
	return updated, nil
}
