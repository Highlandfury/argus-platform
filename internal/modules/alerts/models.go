// Package alerts owns the M11-S1 alert engine: versioned alert rules, the
// in-process evaluator (PHASE_2_SPEC P2-D3: no NATS, no external queue), and
// the rules/alerts lifecycle API.
//
// Canonical semantics implemented here (argus-platform-spec docs/10 §17.2-17.5):
//
//   - rule types threshold / absence / rate_of_change (composite and baseline
//     are explicitly V2) over structured, immutable, versioned JSON;
//   - evaluation cadence max(30 s, window/2) capped at 5 min; absence rules
//     evaluate at 2 × the target check interval; per-rule query timeout 5 s;
//     windows >= 5 m read the continuous aggregates, raw samples otherwise;
//     the newest incomplete rollup bucket is never evaluated unless
//     `allow_partial: true`;
//   - `agg(series.window) op value` must be continuously true for
//     `for_duration` across every evaluation (no "two lucky samples");
//   - dedup: fingerprint = hash(rule_id, resource_type, resource_id,
//     dimension_subset); one open alert per fingerprint (unique partial index);
//     a repeat updates value/last_evaluated_at and appends an event;
//   - state machine Pending -> Active -> Acknowledged/Snoozed/Suppressed ->
//     Resolved with an alert_events timeline; recovery is the logical inverse
//     with a longer default for_duration; snoozing keeps evaluating and
//     reactivates when still true;
//   - storm control: more than 20 new alerts per device per 5 minutes are
//     created Suppressed (storm) but retained.
package alerts

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Rule types (alert_rules.type CHECK).
const (
	TypeThreshold    = "threshold"
	TypeAbsence      = "absence"
	TypeRateOfChange = "rate_of_change"
)

// Severities (alert_rules.severity CHECK).
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Alert states (alerts.state CHECK). Inactive is represented by the absence
// of an alert row.
const (
	StatePending      = "pending"
	StateActive       = "active"
	StateAcknowledged = "acknowledged"
	StateSnoozed      = "snoozed"
	StateSuppressed   = "suppressed"
	StateResolved     = "resolved"
)

// Alert event kinds (alert_events.kind).
const (
	EventPending        = "pending"
	EventActivated      = "activated"
	EventUpdated        = "updated"
	EventAcknowledged   = "acknowledged"
	EventSnoozed        = "snoozed"
	EventUnsnoozed      = "unsnoozed"
	EventReactivated    = "reactivated"
	EventSuppressed     = "suppressed"
	EventUnsuppressed   = "unsuppressed"
	EventResolved       = "resolved"
	EventManualResolved = "manual_resolved"
	EventComment        = "comment"
	EventReopened       = "reopened"
)

// Absence sources.
const (
	SourceSamples    = "samples"
	SourcePollHealth = "poll_health"
)

// Suppression reasons (alerts.suppression_reason).
const (
	SuppressionStorm       = "storm"
	SuppressionMaintenance = "maintenance"
	SuppressionSilence     = "silence"
)

// Condition operators.
const (
	OpGT  = "gt"
	OpGTE = "gte"
	OpLT  = "lt"
	OpLTE = "lte"
	OpEQ  = "eq"
	OpNE  = "ne"
)

// Aggregations supported in v1 (all materialized in the CAGGs).
const (
	AggAvg = "avg"
	AggMax = "max"
	AggMin = "min"
	AggSum = "sum"
)

// Engine constants (documented choices in M11_EVIDENCE.md §S1).
const (
	// MinCadence / MaxCadence bound the per-rule scheduler cadence
	// (docs/10 §17.3: max(30 s, window/2), capped at 5 min).
	MinCadence = 30 * time.Second
	MaxCadence = 5 * time.Minute
	// QueryTimeout bounds one rule evaluation (canonical per-rule timeout).
	QueryTimeout = 5 * time.Second
	// DefaultCheckInterval feeds absence cadence when the rule does not set
	// `check_interval` (2 × this = 120 s).
	DefaultCheckInterval = 60 * time.Second
	// MinWindow / MaxWindow bound condition windows.
	MinWindow = 10 * time.Second
	MaxWindow = 7 * 24 * time.Hour
	// MaxForDuration bounds for_duration and recovery.for_duration.
	MaxForDuration = 7 * 24 * time.Hour
	// MaxGridPoints bounds continuity grid evaluation per transition; when a
	// span needs more points the grid step is widened deterministically
	// (documented judgement call; continuity is still evaluated at every
	// retained grid instant).
	MaxGridPoints = 240
	// MaxTargetsPerRule bounds resolved targets per rule evaluation.
	MaxTargetsPerRule = 1000
	// DefaultStormThreshold / StormWindow implement docs/10 §17.4
	// ("> 20 new alerts/5 min from one device").
	DefaultStormThreshold = 20
	StormWindow           = 5 * time.Minute
	// DefaultReopenCooldown: a manually resolved alert that re-fires within
	// this window is reopened (same row), not duplicated. The canonical docs
	// mandate the behavior but give no number; 10 minutes is the documented
	// choice.
	DefaultReopenCooldown = 10 * time.Minute
	// MaxSnooze bounds a snooze expiry (mirrors the canonical silence bound).
	MaxSnooze = 30 * 24 * time.Hour
	// MaxSilence is the canonical mandatory silence expiry bound (docs/10
	// §17.6: "mandatory expiry (max 30 d)"). It equals MaxSnooze.
	MaxSilence = MaxSnooze
	// MaxMaintenanceWindow bounds a maintenance window period (single
	// interval; the canonical docs give no bound, this is the documented
	// judgement call).
	MaxMaintenanceWindow = 365 * 24 * time.Hour
	// MaxNameLen / MaxCommentLen bound operator-supplied text.
	MaxNameLen    = 200
	MaxCommentLen = 2000
	// MaxEventsInDetail is the recent-timeline window returned by GET detail.
	MaxEventsInDetail = 50
	// MaxRulePageSize / MaxAlertPageSize bound cursor pages.
	MaxRulePageSize  = 100
	MaxAlertPageSize = 100
)

// ValidationError is one deterministic field-level validation failure. The
// HTTP layer maps it to httpx.FieldError; keeping the module free of httpx
// keeps the evaluator usable without HTTP.
type ValidationError struct {
	Field   string
	Code    string
	Message string
}

// ValidationErrors is an ordered list of field errors.
type ValidationErrors []ValidationError

// Error implements error.
func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return "alerts: validation failed"
	}
	return "alerts: validation failed at " + e[0].Field + ": " + e[0].Message
}

// Sentinel errors mapped to HTTP problems at the edge.
var (
	ErrRuleNotFound     = errors.New("alerts: rule not found")
	ErrAlertNotFound    = errors.New("alerts: alert not found")
	ErrInvalidCursor    = errors.New("alerts: invalid cursor")
	ErrVersionConflict  = errors.New("alerts: concurrent rule edit")
	ErrStateConflict    = errors.New("alerts: operation not allowed in the alert's current state")
	ErrScopeRequired    = errors.New("alerts: org-wide rule requires org-wide scope")
	ErrScopeForbidden   = errors.New("alerts: rule target is outside the caller's scope")
	ErrAlertSiteUnknown = errors.New("alerts: alert resource has no resolvable site")
	// M11-S3a suppression objects.
	ErrWindowNotFound  = errors.New("alerts: maintenance window not found")
	ErrSilenceNotFound = errors.New("alerts: silence not found")
)

// ScopeSelector targets the resources a rule evaluates. It mirrors the
// canonical docs/10 §17.2 form (sites / device kinds / device ids / metric)
// with one normalization: the metric key and the dimension subset live in
// the selector, so the condition JSON stays the pure threshold/absence shape
// the M11 slice deliverable fixes.
type ScopeSelector struct {
	Sites       []uuid.UUID
	DeviceIDs   []uuid.UUID
	DeviceKinds []string
	MetricKey   string
	Dimensions  map[string]string
}

// IsOrgWide reports whether the selector targets every device of the org.
func (s ScopeSelector) IsOrgWide() bool {
	return len(s.Sites) == 0 && len(s.DeviceIDs) == 0 && len(s.DeviceKinds) == 0
}

// Recovery is the explicit or default recovery condition.
type Recovery struct {
	Op          string
	Value       *float64
	ForDuration time.Duration
	// Window is the absence recovery presence window (samples source).
	Window time.Duration
}

// Condition is the parsed structured condition JSON.
type Condition struct {
	Source              string
	Agg                 string
	Op                  string
	Value               *float64
	Window              time.Duration
	ForDuration         time.Duration
	AllowPartial        bool
	ConsecutiveFailures int
	RecoverySuccesses   int
	CheckInterval       time.Duration
	Recovery            *Recovery
}

// Rule is one parsed alert_rules row (one immutable version).
type Rule struct {
	OrgID         uuid.UUID
	RuleID        uuid.UUID
	Version       int
	Name          string
	Type          string
	Severity      string
	Condition     Condition
	Selector      ScopeSelector
	ConditionJSON []byte
	SelectorJSON  []byte
	Enabled       bool
	CreatedBy     *uuid.UUID
	CreatedAt     time.Time
}

// Alert is one alerts row.
type Alert struct {
	ID                uuid.UUID
	OrgID             uuid.UUID
	RuleID            uuid.UUID
	RuleVersion       int
	Fingerprint       string
	ResourceType      string
	ResourceID        uuid.UUID
	DimensionSubset   []byte
	State             string
	Severity          string
	Value             []byte
	StartedAt         time.Time
	LastEvaluatedAt   time.Time
	ResolvedAt        *time.Time
	AckBy             *uuid.UUID
	AckAt             *time.Time
	SnoozeUntil       *time.Time
	SuppressionReason string
	// SuppressionRef is the maintenance window or silence id that produced the
	// current suppression (uuid.Nil when none; the column is nullable).
	SuppressionRef *uuid.UUID
	CreatedAt      time.Time
	// SiteID is the resolved device site for scope enforcement (device
	// resources only; uuid.Nil for future non-device resources).
	SiteID uuid.UUID
}

// AlertEvent is one alert_events row.
type AlertEvent struct {
	ID      uuid.UUID
	AlertID uuid.UUID
	Kind    string
	ActorID *uuid.UUID
	Data    []byte
	Ts      time.Time
}

// RulePage is one cursor page of rules (latest version per rule).
type RulePage struct {
	Rules      []Rule
	NextCursor string
	HasMore    bool
}

// AlertPage is one cursor page of alerts.
type AlertPage struct {
	Alerts     []Alert
	NextCursor string
	HasMore    bool
}

// Actor identifies the operator for audit timelines and rule authorship.
type Actor struct {
	UserID uuid.UUID
}

// MaintenanceWindow is one maintenance_windows row: a single [starts_at,
// ends_at) interval that suppresses matching alerts (docs/10 §17.6).
// Recurrence is V2, so there is no rrule column/field.
type MaintenanceWindow struct {
	ID        uuid.UUID
	OrgID     uuid.UUID
	Name      string
	Scope     TargetScope
	ScopeJSON []byte
	Enabled   bool
	StartsAt  time.Time
	EndsAt    time.Time
	CreatedBy *uuid.UUID
	CreatedAt time.Time
	UpdatedAt time.Time
}

// WindowCreateInput is the validated POST /v1/maintenance-windows body.
type WindowCreateInput struct {
	Name      string
	ScopeJSON []byte
	Enabled   *bool
	StartsAt  time.Time
	EndsAt    time.Time
}

// WindowPatchInput is the PATCH /v1/maintenance-windows/{id} body: omitted
// fields keep the current value.
type WindowPatchInput struct {
	Name      *string
	ScopeJSON []byte
	Enabled   *bool
	StartsAt  *time.Time
	EndsAt    *time.Time
}

// SilenceMatch is the parsed silences.match JSON: an exact alert id, an alert
// fingerprint, and/or a resource scope. At least one matcher is non-empty.
type SilenceMatch struct {
	AlertID     *uuid.UUID
	Fingerprint string
	Scope       TargetScope
}

// Any reports whether at least one matcher is present.
func (m SilenceMatch) Any() bool {
	return m.AlertID != nil || m.Fingerprint != "" || !m.Scope.IsEmpty()
}

// Silence is one silences row.
type Silence struct {
	ID        uuid.UUID
	OrgID     uuid.UUID
	Match     SilenceMatch
	MatchJSON []byte
	Reason    string
	StartsAt  time.Time
	EndsAt    time.Time
	CreatedBy *uuid.UUID
	CreatedAt time.Time
	UpdatedAt time.Time
}

// SilenceCreateInput is the validated POST /v1/silences body.
type SilenceCreateInput struct {
	MatchJSON []byte
	Reason    string
	StartsAt  time.Time
	EndsAt    time.Time
}

// WindowPage is one cursor page of maintenance windows.
type WindowPage struct {
	Windows    []MaintenanceWindow
	NextCursor string
	HasMore    bool
}

// SilencePage is one cursor page of silences.
type SilencePage struct {
	Silences   []Silence
	NextCursor string
	HasMore    bool
}

// Transition is one committed alert state transition: the alert snapshot after
// the transition plus the alert_events row that recorded it (docs/10 §17.7:
// the notification pipeline consumes transitions). The alerts module emits
// every state transition to the configured TransitionSink AFTER the tenant
// transaction commits; it never blocks or rolls back the state machine on a
// sink error (the sink is best-effort at-least-once enqueue).
//
// Suppressed marks a transition that must never reach a notification channel
// because the alert was suppressed by a maintenance window or silence at the
// transition instant (M11-S3a, docs/10 §17.6): the notify engine drops it and
// the SSE stream still delivers it as a timeline update.
type Transition struct {
	Alert      Alert
	Event      AlertEvent
	Suppressed bool
}

// TransitionSink consumes committed alert transitions. Implemented by the
// notify engine (internal/modules/notify) and the SSE stream hub; an interface
// here keeps the alerts module free of those imports.
type TransitionSink interface {
	Transitioned(ctx context.Context, t Transition)
}

// NotifyKinds are the transition kinds the notification pipeline dispatches
// (docs/10 §17.7: fired/reactivated and resolved transitions). Pending,
// updated, suppression and operator ack/snooze/comment transitions are
// timeline-only: they never notify on their own.
var NotifyKinds = map[string]bool{
	EventActivated:      true,
	EventReactivated:    true,
	EventResolved:       true,
	EventManualResolved: true,
}

// RuleCreateInput is the validated POST /v1/alert-rules body.
type RuleCreateInput struct {
	Name          string
	Type          string
	Severity      string
	ConditionJSON []byte
	SelectorJSON  []byte
}

// RulePatchInput is the PATCH /v1/alert-rules/{id} body: omitted fields keep
// the current version's value; every applied patch creates version N+1.
type RulePatchInput struct {
	Name          *string
	Type          *string
	Severity      *string
	ConditionJSON []byte
	SelectorJSON  []byte
	Enabled       *bool
}

// AlertFilter narrows ListAlerts.
type AlertFilter struct {
	State    *string
	Severity *string
	RuleID   *uuid.UUID
	DeviceID *uuid.UUID
}
