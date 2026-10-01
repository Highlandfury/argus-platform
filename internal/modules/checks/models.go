// Package checks owns the M10-S0 on-demand device checks (P2-AC-14 "scheduled
// and on-demand runs"): idempotency-keyed creation against a device, routing
// to the device site's collector over the existing control stream, reconnect
// redelivery of pending orders, and idempotent application of collector
// results.
//
// Design constraints (canonical conventions):
//   - the creation POST is unsafe-with-side-effects: session + CSRF +
//     Idempotency-Key (docs/12 §22.1); the durable idempotency ledger is the
//     unique (org_id, request_key) index, not an in-memory cache;
//   - long-running work answers 202 with {check_id,status,status_url};
//   - reads are tenant/scope scoped with enumeration-resistant 404s;
//   - pending work is bounded per device (PendingLimit) and in time (PendingTTL);
//     there is no unbounded queue.
package checks

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Check lifecycle statuses (device_checks.status, 000017).
const (
	StatusPending   = "pending"
	StatusCompleted = "completed"
	StatusFailed    = "failed"
)

// Poll types a check may target (device_checks.poll_type CHECK).
const (
	PollICMP = "icmp"
	PollSNMP = "snmp"
)

const (
	// PendingLimit is the per-device ceiling of pending checks. A new request
	// beyond it is rejected with 409 check.pending_limit (the alternative -
	// unbounded queueing against an offline collector - is forbidden).
	PendingLimit = 10
	// PendingTTL bounds how long a request may stay pending before the server
	// fails it as expired. Reconnect redelivery only delivers rows younger
	// than the TTL; older rows are lazily marked failed on create/read.
	PendingTTL = 10 * time.Minute
	// DeliveryLimit bounds one reconnect redelivery batch.
	DeliveryLimit = 64
	// RequestKeyMaxLen matches device_checks.request_key and the Idempotency-Key
	// header bound (docs/12 §22.1; M3 uses the same 128-char bound).
	RequestKeyMaxLen = 128
	// ClassExpired is the error_class written when a pending check exceeds
	// PendingTTL without a collector result.
	ClassExpired = "expired"
)

// Actor identifies the requesting principal for the audit trail.
type Actor struct {
	UserID uuid.UUID
}

// DeviceCheck is one device_checks row.
type DeviceCheck struct {
	ID          uuid.UUID
	OrgID       uuid.UUID
	DeviceID    uuid.UUID
	CollectorID *uuid.UUID
	PollType    string
	Status      string
	RequestedBy *uuid.UUID
	RequestKey  string
	CreatedAt   time.Time
	CompletedAt *time.Time
	Outcome     string
	ErrorClass  string
	LatencyMS   *int
}

// Sentinel errors mapped to HTTP problems at the edge.
var (
	ErrNotFound          = errors.New("checks: check not found")
	ErrDeviceNotFound    = errors.New("checks: device not found")
	ErrNoMgmtIP          = errors.New("checks: device has no management IP")
	ErrNoCollector       = errors.New("checks: no collector for the device site")
	ErrPendingLimit      = errors.New("checks: pending check limit reached for device")
	ErrInvalidPollType   = errors.New("checks: poll_type must be icmp or snmp")
	ErrInvalidRequestKey = errors.New("checks: invalid idempotency key")
	ErrInvalidCheckID    = errors.New("checks: invalid check id")
	ErrInvalidOutcome    = errors.New("checks: invalid outcome")
	ErrInvalidLatency    = errors.New("checks: invalid latency")
	ErrInvalidErrorClass = errors.New("checks: invalid error class")
)
