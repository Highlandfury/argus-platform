package inventory

import (
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// Audit actions emitted by inventory mutations. Resource types follow the
// canonical catalog names (device, interface, device_group).
const (
	ActionDeviceCreate = "device.create"
	ActionDeviceUpdate = "device.update"
	ActionDeviceDelete = "device.delete"
	ActionDeviceMerge  = "device.merge"
	ActionDeviceSplit  = "device.split"

	// M10-S3b-1 identity-window mutations (add/close on an existing device).
	ActionDeviceIdentityAdd   = "device.identity_add"
	ActionDeviceIdentityClose = "device.identity_close"

	ActionInterfaceCreate = "interface.create"
	ActionInterfaceUpdate = "interface.update"
	ActionInterfaceDelete = "interface.delete"

	ActionGroupCreate = "device_group.create"
	ActionGroupUpdate = "device_group.update"
	ActionGroupDelete = "device_group.delete"
)

// Actor identifies the principal behind a mutation (audit evidence today,
// scope checks later).
type Actor struct {
	UserID    uuid.UUID
	ClientIP  string
	RequestID string
}

// AuditEvent is one append-only inventory mutation record. The canonical
// audit_logs table does not exist in this repository yet (Phase-1 security
// notes promised rows; no migration landed), so the sink writes the same
// record shape to the structured log — the existing durable evidence channel.
// Swapping in a DB-backed sink is additive: implement AuditSink against the
// future table and wire it in cmd/argus-server without touching callers.
type AuditEvent struct {
	Action       string
	ActorType    string
	ActorID      uuid.UUID
	OrgID        uuid.UUID
	ResourceType string
	ResourceID   uuid.UUID
	Reason       string
	Data         map[string]any
	RequestID    string
	ClientIP     string
	At           time.Time
}

// AuditSink records audit events. Implementations must not fail a mutation
// (the log sink cannot); a future transactional DB sink tightens this.
type AuditSink interface {
	Record(ev AuditEvent)
}

// SlogAudit is the production sink: one structured audit_event line per
// mutation, carrying the full actor/resource/request correlation context.
type SlogAudit struct {
	Logger *slog.Logger
}

// Record implements AuditSink.
func (s SlogAudit) Record(ev AuditEvent) {
	if s.Logger == nil {
		return
	}
	attrs := []any{
		"action", ev.Action,
		"actor_type", ev.ActorType,
		"actor_id", ev.ActorID.String(),
		"org_id", ev.OrgID.String(),
		"resource_type", ev.ResourceType,
		"resource_id", ev.ResourceID.String(),
		"request_id", ev.RequestID,
		"client_ip", ev.ClientIP,
	}
	if ev.Reason != "" {
		attrs = append(attrs, "reason", ev.Reason)
	}
	if len(ev.Data) > 0 {
		attrs = append(attrs, "data", ev.Data)
	}
	s.Logger.Info("audit_event", attrs...)
}
