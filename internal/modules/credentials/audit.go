package credentials

import (
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// Audit actions emitted by credential mutations. Resource type is the
// canonical catalog name (credential). Action names follow the existing
// resource.action convention (inventory.audit.go); credential.use is reserved
// for the M9 dispatch path and is not emitted by this module yet.
const (
	ActionCredentialCreate = "credential.create" //nolint:gosec // audit action name, not a credential
	ActionCredentialRotate = "credential.rotate" //nolint:gosec // audit action name, not a credential
	ActionCredentialBind   = "credential.bind"   //nolint:gosec // audit action name, not a credential
	ActionCredentialUnbind = "credential.unbind" //nolint:gosec // audit action name, not a credential
)

// Actor identifies the principal behind a mutation (audit evidence today).
type Actor struct {
	UserID    uuid.UUID
	ClientIP  string
	RequestID string
}

// AuditEvent is one append-only credential mutation record, mirroring the
// inventory AuditEvent shape (internal/modules/inventory/audit.go): the
// canonical audit_logs table does not exist in this repository yet, so the
// sink writes the structured record to the log — the existing durable evidence
// channel. Secret material is NEVER placed in Data.
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
// (the log sink cannot).
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
