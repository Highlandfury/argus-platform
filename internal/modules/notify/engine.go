package notify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/argus-platform/argus/internal/modules/alerts"
	"github.com/argus-platform/argus/internal/platform/database"
	"github.com/argus-platform/argus/internal/platform/secrets"
)

// Engine is the M11-S2 notification engine: it consumes committed alert
// transitions, routes them, renders messages, persists delivery rows and runs
// the retry/breaker worker. The clock is injectable; ProcessDue is the
// deterministic worker entry point tests drive instead of sleeping.
type Engine struct {
	app         *pgxpool.Pool
	auth        *pgxpool.Pool
	vault       secrets.SecretsVault
	now         func() time.Time
	logger      *slog.Logger
	baseURL     string
	workerLimit int

	transports map[string]Transport
	breakers   *breakerSet
	buckets    *bucketSet
}

// EngineOptions configures the engine. Zero values take documented defaults.
type EngineOptions struct {
	Now     func() time.Time
	Logger  *slog.Logger
	BaseURL string
	// Auth lists organizations for the background worker (same auth-role
	// pattern as the alert scheduler). When nil the worker ticks are no-ops;
	// ProcessDue remains usable per org.
	Auth *pgxpool.Pool
	// Transports overrides the channel adapters (tests inject fakes).
	// Missing kinds fall back to the production adapters.
	Transports  map[string]Transport
	WorkerLimit int
}

// NewEngine wires the engine.
func NewEngine(app *pgxpool.Pool, vault secrets.SecretsVault, opts EngineOptions) *Engine {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.WorkerLimit <= 0 {
		opts.WorkerLimit = 100
	}
	e := &Engine{
		app:         app,
		auth:        opts.Auth,
		vault:       vault,
		now:         opts.Now,
		logger:      opts.Logger,
		baseURL:     strings.TrimRight(opts.BaseURL, "/"),
		workerLimit: opts.WorkerLimit,
		transports: map[string]Transport{
			KindSMTP:    SMTPTransport{},
			KindWebhook: DefaultHTTPTransport(),
			KindSlack:   DefaultHTTPTransport(),
			KindTeams:   DefaultHTTPTransport(),
		},
		breakers: newBreakerSet(),
		buckets:  newBucketSet(),
	}
	for kind, tr := range opts.Transports {
		if tr != nil {
			e.transports[kind] = tr
		}
	}
	return e
}

// Now returns the engine clock instant.
func (e *Engine) Now() time.Time { return e.now().UTC() }

// DedupKey is the at-least-once dedup identity of one (channel, alert,
// event-kind) notification. It is stable across retries and identical
// transitions inside the 5 min suppression window.
func DedupKey(channelID, alertID uuid.UUID, eventKind string) string {
	sum := sha256.Sum256([]byte("v1|" + channelID.String() + "|" + alertID.String() + "|" + eventKind))
	return hex.EncodeToString(sum[:])
}

// Transitioned implements alerts.TransitionSink. It enqueues one pending
// delivery per matching (route, channel); enqueue failures are logged and
// never propagate back into the state machine.
func (e *Engine) Transitioned(ctx context.Context, t alerts.Transition) {
	if !alerts.NotifyKinds[t.Event.Kind] {
		return
	}
	notifyTransitions.WithLabelValues(t.Event.Kind).Inc()
	if _, err := e.enqueue(ctx, t); err != nil && e.logger != nil {
		e.logger.Warn("notify: enqueue failed",
			"component", "notify", "org_id", t.Alert.OrgID, "alert_id", t.Alert.ID,
			"kind", t.Event.Kind, "error", err)
	}
}

// enqueue creates the delivery rows for one transition. Everything happens in
// one tenant transaction so a transition either produces its delivery rows or
// none (the crash window between the alert commit and this call is the
// documented best-effort boundary; see M11_EVIDENCE §S2).
func (e *Engine) enqueue(ctx context.Context, t alerts.Transition) (int, error) {
	now := e.Now()
	alert := t.Alert
	created := 0
	err := database.WithTenant(ctx, e.app, alert.OrgID, func(ctx context.Context, tx pgx.Tx) error {
		ruleName, deviceName, deviceKind, siteName, err := snapshots(ctx, tx, alert)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `
			SELECT id, match, channel_ids, template_overrides
			FROM notification_routes
			WHERE enabled
			ORDER BY created_at, id`)
		if err != nil {
			return err
		}
		type routeRow struct {
			id         uuid.UUID
			match      RouteMatch
			channelIDs []uuid.UUID
			subjectPre string
		}
		var routes []routeRow
		for rows.Next() {
			var (
				id      uuid.UUID
				matchIn []byte
				chIDs   []uuid.UUID
				tplRaw  []byte
			)
			if err := rows.Scan(&id, &matchIn, &chIDs, &tplRaw); err != nil {
				rows.Close()
				return err
			}
			match, _, verrs := ParseRouteMatch(matchIn)
			if len(verrs) > 0 {
				continue // stored match cannot fail validation; skip defensively
			}
			var tpl struct {
				SubjectPrefix string `json:"subject_prefix"`
			}
			_ = json.Unmarshal(tplRaw, &tpl)
			routes = append(routes, routeRow{id: id, match: match, channelIDs: chIDs, subjectPre: tpl.SubjectPrefix})
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()

		for _, rt := range routes {
			if !routeMatches(rt.match, alert, deviceKind) {
				continue
			}
			// Canonical per-route severity token bucket: consumed once per
			// matched (transition, route), never once per channel, and only
			// when at least one non-duplicate channel actually receives the
			// notification. A multi-channel route therefore does not drain the
			// bucket N×, and an all-dedup-suppressed transition spends nothing.
			routeAllowed := false
			routeChecked := false
			for _, channelID := range rt.channelIDs {
				ch, err := scanChannelSecret(tx.QueryRow(ctx,
					`SELECT `+channelEnvelopeColumns+` FROM notification_channels c WHERE c.id = $1`, channelID))
				if errors.Is(err, pgx.ErrNoRows) {
					continue
				}
				if err != nil {
					return err
				}
				if !ch.Enabled {
					continue
				}
				dedupKey := DedupKey(ch.ID, alert.ID, t.Event.Kind)
				deliveryID, err := uuid.NewV7()
				if err != nil {
					return err
				}
				suppressed, err := duplicateSuppressed(ctx, tx, dedupKey, now)
				if err != nil {
					return err
				}
				if suppressed {
					notifySuppressed.WithLabelValues("dedup").Inc()
					if err := insertDelivery(ctx, tx, deliveryID, alert, t, rt.id, ch, dedupKey, now,
						StatusDeadLetter, "suppressed: duplicate content within 5m window", 0, nil, "", "", nil); err != nil {
						return err
					}
					created++
					continue
				}
				if !routeChecked {
					routeAllowed = e.buckets.allow(routeBucketKey(rt.id, alert.Severity), SeverityBucketRate(alert.Severity), now)
					routeChecked = true
				}
				if reason := e.throttleReason(routeAllowed, alert.Severity, ch, now); reason != "" {
					notifySuppressed.WithLabelValues("throttle").Inc()
					if err := insertDelivery(ctx, tx, deliveryID, alert, t, rt.id, ch, dedupKey, now,
						StatusDeadLetter, "throttled: "+reason, 0, nil, "", "", nil); err != nil {
						return err
					}
					created++
					continue
				}
				msg := RenderMessage(e.baseURL, t, ruleName, deviceName, siteName, rt.subjectPre)
				msg.DedupKey = dedupKey
				msg.DeliveryID = deliveryID
				if err := insertDelivery(ctx, tx, deliveryID, alert, t, rt.id, ch, dedupKey, now,
					StatusPending, "", 0, &now, msg.Subject, msg.Body, msg.Payload); err != nil {
					return err
				}
				created++
			}
		}
		return nil
	})
	return created, err
}

func snapshots(ctx context.Context, tx pgx.Tx, alert alerts.Alert) (ruleName, deviceName, deviceKind, siteName string, err error) {
	if err = tx.QueryRow(ctx, `
		SELECT name FROM alert_rules WHERE rule_id = $1 AND version = $2`,
		alert.RuleID, alert.RuleVersion).Scan(&ruleName); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", "", "", "", err
	}
	if err = tx.QueryRow(ctx, `
		SELECT d.name, d.kind, coalesce(s.name, '')
		FROM devices d LEFT JOIN sites s ON s.id = d.site_id AND s.org_id = d.org_id
		WHERE d.id = $1`, alert.ResourceID).Scan(&deviceName, &deviceKind, &siteName); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", "", "", "", err
	}
	return ruleName, deviceName, deviceKind, siteName, nil
}

// routeMatches applies the canonical severity + scope match.
func routeMatches(m RouteMatch, alert alerts.Alert, deviceKind string) bool {
	if len(m.Severities) > 0 {
		ok := false
		for _, s := range m.Severities {
			if s == alert.Severity {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if m.Scope.IsEmpty() {
		return true
	}
	if alert.SiteID != uuid.Nil {
		for _, site := range m.Scope.Sites {
			if site == alert.SiteID {
				return true
			}
		}
	}
	for _, id := range m.Scope.DeviceIDs {
		if id == alert.ResourceID {
			return true
		}
	}
	for _, kind := range m.Scope.DeviceKinds {
		if kind == deviceKind {
			return true
		}
	}
	return false
}

// duplicateSuppressed reports whether the same dedup key already produced a
// delivery inside the canonical 5 min window.
func duplicateSuppressed(ctx context.Context, tx pgx.Tx, dedupKey string, now time.Time) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM notification_deliveries
			WHERE dedup_key = $1 AND created_at > $2
		)`, dedupKey, now.Add(-DedupWindow)).Scan(&exists)
	return exists, err
}

// routeBucketKey is the per-route severity bucket key (canonical docs/10
// §17.7: one token bucket per route, not per channel).
func routeBucketKey(routeID uuid.UUID, severity string) string {
	return "route:" + routeID.String() + ":" + severity
}

// throttleReason consumes one recipient-cap token when `routeAllowed` is true
// and returns a non-empty reason when the route bucket or a recipient cap
// denies. The severity bucket itself is consumed by the caller once per
// matched route.
func (e *Engine) throttleReason(routeAllowed bool, severity string, ch Channel, now time.Time) string {
	rate := SeverityBucketRate(severity)
	if !routeAllowed {
		return fmt.Sprintf("%s severity bucket exhausted (%d/h)", severity, int(rate))
	}
	recipients := []string{""}
	if ch.Kind == KindSMTP {
		var cfg SMTPConfig
		if json.Unmarshal(ch.Config, &cfg) == nil && len(cfg.To) > 0 {
			recipients = cfg.To
		}
	}
	for _, to := range recipients {
		key := "cap:" + ch.ID.String() + "|" + strings.ToLower(strings.TrimSpace(to))
		if !e.buckets.allow(key, RecipientHourlyCap, now) {
			return fmt.Sprintf("per-recipient cap exhausted (%d/h)", RecipientHourlyCap)
		}
	}
	return ""
}

// insertDelivery writes one delivery row. body/payload are the rendered
// snapshot (empty for suppressed/throttled records). The id is minted by the
// caller so the rendered message and the row share the X-Argus-Delivery id.
func insertDelivery(ctx context.Context, tx pgx.Tx, id uuid.UUID, alert alerts.Alert, t alerts.Transition,
	routeID uuid.UUID, ch Channel, dedupKey string, now time.Time, status, excerptText string,
	attempts int, next *time.Time, subject, body string, payload []byte) error {
	var routeRef *uuid.UUID
	if routeID != uuid.Nil {
		routeRef = &routeID
	}
	var alertRef *uuid.UUID
	if alert.ID != uuid.Nil {
		alertRef = &alert.ID
	}
	var eventRef *uuid.UUID
	if t.Event.ID != uuid.Nil {
		eventRef = &t.Event.ID
	}
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO notification_deliveries
			(id, org_id, alert_id, event_id, event_kind, severity, route_id, channel_id, status,
			 attempts, next_attempt_at, response_code, response_excerpt, dedup_key, subject, body, payload,
			 created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NULL, $12, $13, $14, $15, $16::jsonb, $17, $17)`,
		id, alert.OrgID, alertRef, eventRef, t.Event.Kind, alert.Severity, routeRef, ch.ID,
		status, attempts, next, excerptText, dedupKey, subject, body, payload, now)
	return err
}

// claimed is one due delivery plus its channel snapshot.
type claimed struct {
	delivery   Delivery
	channel    Channel
	secretJSON []byte
}

// ProcessDue claims and attempts due deliveries of one organization at `now`.
// It returns the number of claims processed. The injected clock makes retry,
// breaker and lease behavior deterministic in tests.
func (e *Engine) ProcessDue(ctx context.Context, orgID uuid.UUID, now time.Time, limit int) (int, error) {
	if limit <= 0 {
		limit = e.workerLimit
	}
	now = now.UTC()
	claims, err := e.claimDue(ctx, orgID, now, limit)
	if err != nil {
		return 0, err
	}
	for _, c := range claims {
		allowed, openUntil := e.breakers.allow(c.delivery.ChannelID, now)
		if !allowed {
			notifyBreaker.WithLabelValues("denied").Inc()
			next := openUntil
			if next.Before(now) {
				next = now
			}
			// Keep the provider's last response excerpt: the queued message's
			// audit trail should not lose it while the breaker is open.
			excerptText := c.delivery.ResponseExcerpt
			if excerptText == "" {
				excerptText = "circuit breaker open: message queued"
			}
			if err := e.finalize(ctx, orgID, c.delivery, now, StatusFailed, c.delivery.Attempts, &next,
				c.delivery.ResponseCode, excerptText); err != nil {
				return 0, err
			}
			continue
		}
		if _, err := e.attempt(ctx, orgID, c, now); err != nil {
			return 0, err
		}
	}
	if len(claims) > 0 {
		notifyWorkerRuns.Inc()
	}
	return len(claims), nil
}

// claimDue loads due deliveries with a row lock and lease so a second worker
// (Phase-2 HA) cannot double-claim them. Channel snapshots come from the same
// transaction.
func (e *Engine) claimDue(ctx context.Context, orgID uuid.UUID, now time.Time, limit int) ([]claimed, error) {
	var out []claimed
	leaseUntil := now.Add(LeaseDuration)
	err := database.WithTenant(ctx, e.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT d.id, d.org_id, d.alert_id, d.event_id, d.event_kind, d.severity,
			       d.route_id, d.channel_id, d.status, d.attempts, d.next_attempt_at,
			       d.response_code, d.response_excerpt, d.dedup_key, d.subject, d.body,
			       d.payload, d.created_at, d.updated_at, d.delivered_at,
			       c.id, c.kind, c.name, c.enabled, c.config,
			       c.secret_enc, c.kms_key_id, c.key_version, c.encryption_context
			FROM notification_deliveries d
			JOIN notification_channels c ON c.id = d.channel_id
			WHERE d.status IN ('pending', 'failed')
			  AND d.next_attempt_at IS NOT NULL
			  AND d.next_attempt_at <= $1
			ORDER BY d.next_attempt_at, d.id
			LIMIT $2
			FOR UPDATE OF d SKIP LOCKED`, now, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				c         claimed
				secretEnc []byte
				kmsKeyID  *string
				keyVer    *int
				ctxRaw    []byte
			)
			if err := rows.Scan(
				&c.delivery.ID, &c.delivery.OrgID, &c.delivery.AlertID, &c.delivery.EventID,
				&c.delivery.EventKind, &c.delivery.Severity, &c.delivery.RouteID,
				&c.delivery.ChannelID, &c.delivery.Status, &c.delivery.Attempts,
				&c.delivery.NextAttemptAt, &c.delivery.ResponseCode, &c.delivery.ResponseExcerpt,
				&c.delivery.DedupKey, &c.delivery.Subject, &c.delivery.Body, &c.delivery.Payload,
				&c.delivery.CreatedAt, &c.delivery.UpdatedAt, &c.delivery.DeliveredAt,
				&c.channel.ID, &c.channel.Kind, &c.channel.Name, &c.channel.Enabled, &c.channel.Config,
				&secretEnc, &kmsKeyID, &keyVer, &ctxRaw); err != nil {
				return err
			}
			if len(secretEnc) > 0 {
				env, err := buildEnvelope(secretEnc, kmsKeyID, keyVer, ctxRaw)
				if err != nil {
					return err
				}
				c.channel.Envelope = env
				c.channel.SecretSet = true
			}
			out = append(out, c)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		ids := make([]uuid.UUID, 0, len(out))
		for _, c := range out {
			ids = append(ids, c.delivery.ID)
		}
		if len(ids) > 0 {
			if _, err := tx.Exec(ctx,
				`UPDATE notification_deliveries SET next_attempt_at = $2, updated_at = $3 WHERE id = ANY($1)`,
				ids, leaseUntil, now); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Open secrets after the claim transaction (crypto does not belong in a
	// database transaction).
	for i := range out {
		if out[i].channel.Envelope == nil {
			continue
		}
		if e.vault == nil {
			out[i].secretJSON = nil
			continue
		}
		plain, err := e.vault.Open(*out[i].channel.Envelope)
		if err != nil {
			out[i].secretJSON = nil
			continue
		}
		out[i].secretJSON = plain
	}
	return out, nil
}

// attempt sends one claimed delivery and finalizes it. Returns false when the
// claim was requeued without an attempt (breaker wait handled by caller).
func (e *Engine) attempt(ctx context.Context, orgID uuid.UUID, c claimed, now time.Time) (bool, error) {
	d := c.delivery
	if d.ChannelID == uuid.Nil {
		return false, nil
	}
	if c.channel.Envelope != nil && c.secretJSON == nil {
		// Secret cannot be opened: permanent failure, no retry storm.
		return true, e.finalize(ctx, orgID, d, now, StatusDeadLetter, d.Attempts, nil, nil, "channel secret unavailable")
	}
	msg := Message{
		DeliveryID: d.ID,
		EventKind:  d.EventKind,
		EventType:  EventType(d.EventKind),
		AlertID:    uuid.Nil,
		OrgID:      d.OrgID,
		Severity:   d.Severity,
		DedupKey:   d.DedupKey,
		Subject:    d.Subject,
		Body:       d.Body,
		Payload:    d.Payload,
		OccurredAt: d.CreatedAt,
		StartedAt:  d.CreatedAt,
		SentAt:     now,
	}
	if d.AlertID != nil {
		msg.AlertID = *d.AlertID
	}
	transport := e.transports[c.channel.Kind]
	if transport == nil {
		return true, e.finalize(ctx, orgID, d, now, StatusDeadLetter, d.Attempts, nil, nil, "no transport for channel kind "+c.channel.Kind)
	}
	attemptCtx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	code, ex, sendErr := transport.Send(attemptCtx, c.channel, c.secretJSON, msg)

	attempts := d.Attempts + 1
	if sendErr == nil {
		e.breakers.success(d.ChannelID)
		notifyAttempts.WithLabelValues(c.channel.Kind, "delivered").Inc()
		if err := e.finalize(ctx, orgID, d, now, StatusDelivered, attempts, nil, &code, ex); err != nil {
			return true, err
		}
		if err := e.observeChannelHealth(ctx, orgID, d.ChannelID, now); err != nil && e.logger != nil {
			e.logger.Warn("notify: channel health watch query failed", "component", "notify", "error", err)
		}
		return true, nil
	}
	notifyAttempts.WithLabelValues(c.channel.Kind, "failed").Inc()
	opened := e.breakers.failure(d.ChannelID, now)
	if opened {
		notifyBreaker.WithLabelValues("opened").Inc()
	}
	status := StatusFailed
	var next *time.Time
	if attempts >= MaxAttempts {
		status = StatusDeadLetter
		notifyDeadLetters.Inc()
	} else {
		n := NextRetryAt(d.CreatedAt, now, attempts)
		next = &n
	}
	if err := e.finalize(ctx, orgID, d, now, status, attempts, next, &code, ex); err != nil {
		return true, err
	}
	if err := e.observeChannelHealth(ctx, orgID, d.ChannelID, now); err != nil && e.logger != nil {
		e.logger.Warn("notify: channel health watch query failed", "component", "notify", "error", err)
	}
	return true, nil
}

// finalize writes one attempt outcome. responseCode is nil when no response
// was received.
func (e *Engine) finalize(ctx context.Context, orgID uuid.UUID, d Delivery, now time.Time,
	status string, attempts int, next *time.Time, responseCode *int, responseExcerpt string) error {
	var deliveredAt *time.Time
	if status == StatusDelivered {
		deliveredAt = &now
	}
	return database.WithTenant(ctx, e.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE notification_deliveries SET
				status = $2, attempts = $3, next_attempt_at = $4,
				response_code = $5, response_excerpt = $6, delivered_at = $7, updated_at = $8
			WHERE id = $1`,
			d.ID, status, attempts, next, responseCode, excerpt(responseExcerpt), deliveredAt, now)
		return err
	})
}

// observeChannelHealth emits the platform failure-rate metric when a channel
// exceeds 5 % failures over the last 15 min (minimum 20 finalized attempts).
// Rows that never reached a provider (dedup/throttle suppressions and
// breaker-queued messages keep attempts = 0) are excluded: they are policy
// records, not channel failures. Wiring this to an ops alert is M12
// (docs/10 §17.7).
func (e *Engine) observeChannelHealth(ctx context.Context, orgID, channelID uuid.UUID, now time.Time) error {
	var total, failed int
	err := database.WithTenant(ctx, e.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT count(*),
			       count(*) FILTER (WHERE status IN ('failed', 'dead_letter'))
			FROM notification_deliveries
			WHERE channel_id = $1
			  AND status IN ('delivered', 'failed', 'dead_letter')
			  AND attempts > 0
			  AND created_at > $2`, channelID, now.Add(-15*time.Minute)).Scan(&total, &failed)
	})
	if err != nil {
		return err
	}
	if total >= 20 && float64(failed)/float64(total) > 0.05 {
		notifyChannelFailureWatch.Inc()
		if e.logger != nil {
			e.logger.Warn("notify: channel failure rate above 5% over 15m",
				"component", "notify", "org_id", orgID, "channel_id", channelID,
				"attempts", total, "failed", failed)
		}
	}
	return nil
}

// Run ticks the retry worker until ctx is done. The first tick runs
// immediately.
func (e *Engine) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	tick := func() {
		if e.app == nil || e.auth == nil {
			return
		}
		orgs, err := e.listOrgs(ctx)
		if err != nil {
			if ctx.Err() == nil && e.logger != nil {
				e.logger.Warn("notify worker: list orgs failed", "component", "notify", "error", err)
			}
			return
		}
		now := e.Now()
		for _, orgID := range orgs {
			if _, err := e.ProcessDue(ctx, orgID, now, e.workerLimit); err != nil && ctx.Err() == nil && e.logger != nil {
				e.logger.Warn("notify worker: process due failed",
					"component", "notify", "org_id", orgID, "error", err)
			}
		}
	}
	tick()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tick()
		}
	}
}

func (e *Engine) listOrgs(ctx context.Context) ([]uuid.UUID, error) {
	var out []uuid.UUID
	err := database.WithAuthTx(ctx, e.auth, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM organizations ORDER BY id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out = append(out, id)
		}
		return rows.Err()
	})
	return out, err
}

// TestChannel sends one synchronous test message through the channel's
// adapter. The test does not create a delivery row (it is not an alert
// notification) and returns the provider outcome to the caller.
func (e *Engine) TestChannel(ctx context.Context, orgID, channelID uuid.UUID) (TestResult, error) {
	var ch Channel
	err := database.WithTenant(ctx, e.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		ch, err = scanChannelSecret(tx.QueryRow(ctx,
			`SELECT `+channelEnvelopeColumns+` FROM notification_channels c WHERE c.id = $1`, channelID))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrChannelNotFound
		}
		return err
	})
	if err != nil {
		return TestResult{}, err
	}
	if !ch.Enabled {
		return TestResult{}, ValidationErrors{{Field: "enabled", Code: "invalid", Message: "channel is disabled"}}
	}
	var secretJSON []byte
	if ch.Envelope != nil {
		if e.vault == nil {
			return TestResult{}, ErrVaultUnavailable
		}
		plain, err := e.vault.Open(*ch.Envelope)
		if err != nil {
			return TestResult{}, fmt.Errorf("notify: channel secret unavailable: %w", err)
		}
		secretJSON = plain
	}
	now := e.Now()
	msg := Message{
		DeliveryID:  uuid.New(),
		EventKind:   alerts.EventActivated,
		EventType:   EventFired,
		OrgID:       orgID,
		Severity:    SeverityInfo,
		Summary:     "Argus notification channel test",
		OccurredAt:  now,
		StartedAt:   now,
		SentAt:      now,
		DedupKey:    DedupKey(channelID, uuid.Nil, "test"),
		EvidenceURL: link(e.baseURL, "/healthz"),
		AckURL:      link(e.baseURL, "/healthz"),
	}
	msg.Subject = "[test] Argus notification channel test"
	msg.Body = renderText(msg)
	msg.Payload = renderPayload(msg)
	transport := e.transports[ch.Kind]
	if transport == nil {
		return TestResult{}, errNoTransport
	}
	attemptCtx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	code, ex, sendErr := transport.Send(attemptCtx, ch, secretJSON, msg)
	res := TestResult{
		OK:          sendErr == nil,
		Kind:        ch.Kind,
		StatusCode:  code,
		Excerpt:     excerpt(ex),
		AttemptedAt: now,
	}
	if sendErr != nil && res.Excerpt == "" {
		res.Excerpt = excerpt(sendErr.Error())
	}
	return res, nil
}

// bucketSet is the in-memory token-bucket store (severity buckets and
// per-recipient caps). It is process-local: budgets reset on restart, which
// is documented as an M11-S2 limitation (durable budgets are M12).
type bucketSet struct {
	mu      sync.Mutex
	buckets map[string]*bucketState
}

type bucketState struct {
	tokens float64
	last   time.Time
}

func newBucketSet() *bucketSet { return &bucketSet{buckets: map[string]*bucketState{}} }

func (b *bucketSet) allow(key string, ratePerHour float64, now time.Time) bool {
	if b == nil || ratePerHour <= 0 {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.buckets) > 10000 {
		for k, v := range b.buckets {
			if now.Sub(v.last) > 2*time.Hour {
				delete(b.buckets, k)
			}
		}
	}
	s, ok := b.buckets[key]
	if !ok {
		s = &bucketState{tokens: ratePerHour, last: now}
		b.buckets[key] = s
	}
	if elapsed := now.Sub(s.last).Hours(); elapsed > 0 {
		s.tokens += elapsed * ratePerHour
		if s.tokens > ratePerHour {
			s.tokens = ratePerHour
		}
		s.last = now
	}
	if s.tokens >= 1 {
		s.tokens--
		return true
	}
	return false
}

// breakerSet is the per-channel circuit breaker store. State is process-local
// (restart resets the breaker), matching the message queue's in-process
// scope in Phase 2.
type breakerSet struct {
	mu    sync.Mutex
	state map[uuid.UUID]*breakerState
}

type breakerState struct {
	consecutive int
	openUntil   time.Time
	probing     bool
}

func newBreakerSet() *breakerSet { return &breakerSet{state: map[uuid.UUID]*breakerState{}} }

// allow reports whether an attempt may start. In the half-open state one
// probe is admitted at a time.
func (b *breakerSet) allow(id uuid.UUID, now time.Time) (bool, time.Time) {
	if b == nil {
		return true, time.Time{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.get(id)
	if s.openUntil.IsZero() {
		return true, time.Time{}
	}
	if now.Before(s.openUntil) {
		return false, s.openUntil
	}
	if s.probing {
		return false, s.openUntil
	}
	s.probing = true
	return true, time.Time{}
}

// success closes the breaker and clears the failure streak.
func (b *breakerSet) success(id uuid.UUID) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.get(id)
	s.consecutive = 0
	s.openUntil = time.Time{}
	s.probing = false
}

// failure records one failure; it returns true when the breaker transitioned
// to open (5 consecutive failures).
func (b *breakerSet) failure(id uuid.UUID, now time.Time) bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.get(id)
	wasOpen := !s.openUntil.IsZero()
	s.probing = false
	s.consecutive++
	if s.consecutive >= BreakerThreshold {
		s.openUntil = now.Add(BreakerHalfOpen)
		s.consecutive = BreakerThreshold
		return !wasOpen
	}
	return false
}

func (b *breakerSet) get(id uuid.UUID) *breakerState {
	s, ok := b.state[id]
	if !ok {
		s = &breakerState{}
		b.state[id] = s
	}
	return s
}
