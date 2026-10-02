// Package notify owns the M11-S2 notification pipeline: channels, routes,
// rendering, delivery with retries/circuit breaker/logs, webhook signing,
// and throttling.
//
// Canonical semantics implemented here (argus-platform-spec docs/10 §17.7):
//
//   - pipeline: alert transition -> route match (severity/labels/scope) ->
//     policy (throttling, dedup) -> render -> channel adapter -> delivery log
//     -> retries/circuit breaker;
//   - channels: SMTP, generic webhook (HMAC v1), Slack, Teams; secrets are
//     write-only through the M7 SecretsVault (never plaintext at rest/logs);
//   - at-least-once delivery with dedup headers; backoff 1m/5m/30m/2h/6h,
//     max 24 h / 12 attempts, then dead-letter;
//   - per-channel circuit breaker: open after 5 consecutive failures,
//     half-open probe every 5 min, messages stay queued while open;
//   - token buckets 60/h critical, 20/h warning, 5/h info + a per-recipient
//     cap (documented 100/h judgement call — the canonical docs give no
//     number); duplicate-content suppression window 5 min (dedup_key);
//   - delivery logs with response code/excerpt; bodies 90 d / metadata 13 mo
//     retention policy (enforcement deferred to the M13 retention job);
//   - channel failure-rate watch: >5 % failures / 15 min emits a platform
//     metric (wiring it to an ops alert is M12).
package notify

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/platform/secrets"
)

// Channel kinds (notification_channels.kind CHECK).
const (
	KindSMTP    = "smtp"
	KindWebhook = "webhook"
	KindSlack   = "slack"
	KindTeams   = "teams"
)

// Delivery statuses (notification_deliveries.status CHECK).
const (
	StatusPending    = "pending"
	StatusDelivered  = "delivered"
	StatusFailed     = "failed"
	StatusDeadLetter = "dead_letter"
)

// Severities (mirrors the alerts vocabulary).
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Engine constants. Retry schedule, breaker and bucket numbers are the
// canonical docs/10 §17.7 / P2-AC-31 values unless noted.
const (
	// RetryDelays is the canonical backoff sequence; after it is exhausted the
	// last delay repeats, bounded by MaxRetryWindow.
	RetryDelays = 5
	// MaxAttempts: 12 attempts then dead-letter (canonical).
	MaxAttempts = 12
	// MaxRetryWindow: retries are never scheduled beyond created_at + 24 h.
	MaxRetryWindow = 24 * time.Hour
	// BreakerThreshold / BreakerHalfOpen: open after 5 consecutive failures,
	// half-open probe every 5 min.
	BreakerThreshold = 5
	BreakerHalfOpen  = 5 * time.Minute
	// DedupWindow is the duplicate-content suppression window.
	DedupWindow = 5 * time.Minute
	// Bucket rates per hour by severity (canonical).
	BucketCritical = 60
	BucketWarning  = 20
	BucketInfo     = 5
	// RecipientHourlyCap is the per-recipient cap. The canonical docs require
	// the cap but give no number; 100/h is the documented choice (for SMTP the
	// key is channel+recipient, otherwise channel).
	RecipientHourlyCap = 100
	// RequestTimeout bounds one outbound attempt (canonical webhook rule:
	// 2xx within 10 s).
	RequestTimeout = 10 * time.Second
	// ReplayWindow is the canonical webhook replay-protection window: a
	// receiver rejects an X-Argus-Signature whose X-Argus-Timestamp is more
	// than this far from its own clock (docs/12 §22.17).
	ReplayWindow = 5 * time.Minute
	// LeaseDuration is how long a claimed delivery is hidden from other
	// workers while its attempt is in flight (single-process today; safe if a
	// second worker appears).
	LeaseDuration = 2 * time.Minute
	// ResponseExcerptMax bounds the persisted provider response excerpt.
	ResponseExcerptMax = 1024
	// MaxPageSize bounds cursor pages.
	MaxPageSize = 100
	// MaxNameLen / MaxConfigLen bound operator input.
	MaxNameLen   = 200
	MaxConfigLen = 64 * 1024
)

// Webhook payload modes.
const (
	PayloadIDs     = "ids"
	PayloadSummary = "summary"
)

// Event types (canonical asyncapi vocabulary).
const (
	EventFired    = "alert.fired"
	EventResolved = "alert.resolved"
)

// RetrySchedule returns the canonical backoff delays.
func RetrySchedule() []time.Duration {
	return []time.Duration{1 * time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 6 * time.Hour}
}

// NextRetryAt computes the next attempt instant for a delivery created at
// `created` that has failed `failures` times (1-based: after the first
// failure failures=1). The schedule repeats its last delay, and the result is
// never later than created+24 h. `now` is the failure instant; when the next
// delay would land after the 24 h window the window boundary is used (the
// attempt at that boundary either succeeds or dead-letters as attempt 12).
func NextRetryAt(created, now time.Time, failures int) time.Time {
	sched := RetrySchedule()
	if failures < 1 {
		failures = 1
	}
	idx := failures - 1
	if idx >= len(sched) {
		idx = len(sched) - 1
	}
	next := now.Add(sched[idx])
	if limit := created.Add(MaxRetryWindow); next.After(limit) {
		next = limit
	}
	if next.Before(now) {
		next = now
	}
	return next.UTC()
}

// ValidationError / ValidationErrors mirror the alerts module shape so the
// HTTP edge maps both to the same problem+json fields.
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
		return "notify: validation failed"
	}
	return "notify: validation failed at " + e[0].Field + ": " + e[0].Message
}

// Sentinel errors mapped to HTTP problems at the edge.
var (
	ErrChannelNotFound  = errors.New("notify: channel not found")
	ErrRouteNotFound    = errors.New("notify: route not found")
	ErrNameConflict     = errors.New("notify: name already in use")
	ErrInvalidCursor    = errors.New("notify: invalid cursor")
	ErrVaultUnavailable = errors.New("notify: secrets vault not configured")
)

// SMTPConfig is the non-secret part of a SMTP channel.
type SMTPConfig struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Username string   `json:"username,omitempty"`
	From     string   `json:"from"`
	To       []string `json:"to"`
	StartTLS bool     `json:"starttls,omitempty"`
}

// WebhookConfig is the non-secret part of a generic webhook channel.
type WebhookConfig struct {
	URL       string `json:"url"`
	Payload   string `json:"payload"` // ids|summary
	TimeoutMS int    `json:"timeout_ms,omitempty"`
}

// SlackConfig is the non-secret part of a Slack channel (the incoming webhook
// URL is the secret).
type SlackConfig struct {
	Channel string `json:"channel,omitempty"`
}

// TeamsConfig has no non-secret fields (the webhook URL is the secret).
type TeamsConfig struct{}

// SMTPSecret / SigningSecret / WebhookURLSecret are the sealed JSON shapes.
type SMTPSecret struct {
	Password string `json:"password"`
}

// SigningSecret is the generic webhook HMAC key.
type SigningSecret struct {
	SigningSecret string `json:"signing_secret"`
}

// WebhookURLSecret carries a Slack/Teams incoming-webhook URL.
type WebhookURLSecret struct {
	WebhookURL string `json:"webhook_url"`
}

// Channel is one notification_channels row. Envelope is populated only by
// delivery/test paths (list/get never read secret material); SecretSet is the
// metadata projection ("a sealed secret exists").
type Channel struct {
	ID        uuid.UUID
	OrgID     uuid.UUID
	Kind      string
	Name      string
	Enabled   bool
	Config    []byte // raw JSON as stored
	Envelope  *secrets.Envelope
	SecretSet bool
	CreatedBy *uuid.UUID
	CreatedAt time.Time
	UpdatedAt time.Time
}

// HasSecret reports whether the channel carries a sealed secret.
func (c Channel) HasSecret() bool { return c.Envelope != nil || c.SecretSet }

// RouteMatch is the parsed notification_routes.match JSON.
type RouteMatch struct {
	Severities []string // empty = all severities
	Scope      RouteScope
}

// RouteScope narrows which alerts a route matches.
type RouteScope struct {
	Sites       []uuid.UUID
	DeviceIDs   []uuid.UUID
	DeviceKinds []string
}

// IsEmpty reports whether the scope matches every device.
func (s RouteScope) IsEmpty() bool {
	return len(s.Sites) == 0 && len(s.DeviceIDs) == 0 && len(s.DeviceKinds) == 0
}

// Route is one notification_routes row.
type Route struct {
	ID                uuid.UUID
	OrgID             uuid.UUID
	Name              string
	Match             RouteMatch
	MatchJSON         []byte
	ChannelIDs        []uuid.UUID
	TemplateOverrides []byte
	Enabled           bool
	CreatedBy         *uuid.UUID
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// Delivery is one notification_deliveries row (secret-free projection used by
// the API; the engine works with the same shape plus channel snapshots).
type Delivery struct {
	ID              uuid.UUID
	OrgID           uuid.UUID
	AlertID         *uuid.UUID
	EventID         *uuid.UUID
	EventKind       string
	Severity        string
	RouteID         *uuid.UUID
	ChannelID       uuid.UUID
	Status          string
	Attempts        int
	NextAttemptAt   *time.Time
	ResponseCode    *int
	ResponseExcerpt string
	DedupKey        string
	Subject         string
	Body            string
	Payload         []byte
	CreatedAt       time.Time
	UpdatedAt       time.Time
	DeliveredAt     *time.Time
}

// DeliveryClaim is a claimed due delivery plus the channel snapshot needed to
// send it (engine-internal; never leaves the process).
type DeliveryClaim struct {
	Delivery Delivery
	Subject  string
	Body     string
	Payload  []byte
	// Channel snapshot.
	Channel Channel
}

// DeliveryFilter narrows ListDeliveries.
type DeliveryFilter struct {
	ChannelID *uuid.UUID
	Status    *string
	AlertID   *uuid.UUID
}

// ChannelPage / RoutePage / DeliveryPage are cursor pages.
type ChannelPage struct {
	Channels   []Channel
	NextCursor string
	HasMore    bool
}

// RoutePage is one cursor page of routes.
type RoutePage struct {
	Routes     []Route
	NextCursor string
	HasMore    bool
}

// DeliveryPage is one cursor page of the delivery log.
type DeliveryPage struct {
	Deliveries []Delivery
	NextCursor string
	HasMore    bool
}

// Actor identifies the operator for created_by.
type Actor struct {
	UserID uuid.UUID
}

// ChannelCreateInput is the validated POST body (secrets stay []byte JSON and
// are sealed immediately).
type ChannelCreateInput struct {
	Kind   string
	Name   string
	Config []byte
	Secret []byte // optional sealed JSON; nil means no secret
}

// ChannelPatchInput is PATCH: omitted fields keep their value.
type ChannelPatchInput struct {
	Name        *string
	Enabled     *bool
	Config      []byte
	Secret      []byte
	ClearSecret bool
}

// RouteCreateInput is the validated POST body.
type RouteCreateInput struct {
	Name              string
	MatchJSON         []byte
	ChannelIDs        []uuid.UUID
	TemplateOverrides []byte
}

// RoutePatchInput is PATCH: omitted fields keep their value.
type RoutePatchInput struct {
	Name              *string
	MatchJSON         []byte
	ChannelIDs        []uuid.UUID
	TemplateOverrides []byte
	Enabled           *bool
}

// TestResult is one synchronous channel test outcome.
type TestResult struct {
	OK          bool
	Kind        string
	StatusCode  int
	Excerpt     string
	AttemptedAt time.Time
}
