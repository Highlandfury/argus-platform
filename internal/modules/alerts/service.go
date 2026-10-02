package alerts

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/argus-platform/argus/internal/platform/authz"
	"github.com/argus-platform/argus/internal/platform/database"
)

// Authorizer resolves server-side scope bindings (P2-D5). Implemented by
// *authz.Authorizer; an interface keeps this module testable.
type Authorizer interface {
	ScopeFor(ctx context.Context, orgID, userID uuid.UUID) (authz.Scope, error)
}

// Service implements the rules/alerts lifecycle over the database. Every
// method runs inside one database.WithTenant transaction (RLS is the
// isolation floor); scope enforcement is applied on top.
type Service struct {
	app *pgxpool.Pool
	az  Authorizer
	// Now is the clock seam for deterministic tests.
	Now func() time.Time
}

// New wires the service.
func New(app *pgxpool.Pool, az Authorizer) *Service {
	return &Service{app: app, az: az, Now: time.Now}
}

// ScopeFor resolves the caller's bindings (fails closed when the authorizer is
// not configured).
func (s *Service) ScopeFor(ctx context.Context, orgID, userID uuid.UUID) (authz.Scope, error) {
	if s.az == nil {
		return authz.Scope{}, errors.New("alerts: authorizer not configured")
	}
	return s.az.ScopeFor(ctx, orgID, userID)
}

const ruleColumns = `rule_id, version, name, type, severity, condition, scope_selector, enabled, created_by, created_at`

func scanRule(row pgx.Row) (Rule, error) {
	var (
		r             Rule
		conditionJSON []byte
		selectorJSON  []byte
		createdBy     *uuid.UUID
		createdAt     time.Time
	)
	err := row.Scan(&r.RuleID, &r.Version, &r.Name, &r.Type, &r.Severity,
		&conditionJSON, &selectorJSON, &r.Enabled, &createdBy, &createdAt)
	if err != nil {
		return Rule{}, err
	}
	r.CreatedBy = createdBy
	r.CreatedAt = createdAt
	cond, cerrs := ParseConditionJSON(r.Type, conditionJSON)
	if len(cerrs) > 0 {
		return Rule{}, fmt.Errorf("alerts: stored condition invalid: %w", cerrs)
	}
	sel, serrs := ParseSelectorJSON(selectorJSON)
	if len(serrs) > 0 {
		return Rule{}, fmt.Errorf("alerts: stored selector invalid: %w", serrs)
	}
	r.Condition, r.Selector = cond, sel
	r.ConditionJSON, r.SelectorJSON = conditionJSON, selectorJSON
	return r, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// CreateRule validates the input, enforces scope, and inserts version 1 of a
// new rule identity.
func (s *Service) CreateRule(ctx context.Context, orgID uuid.UUID, actor Actor, in RuleCreateInput, sc authz.Scope) (Rule, error) {
	parsed, errs := ParseRule(in.Name, in.Type, in.Severity, in.ConditionJSON, in.SelectorJSON)
	if len(errs) > 0 {
		return Rule{}, errs
	}
	var out Rule
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.requireSelectorInScope(ctx, tx, parsed.Selector, sc); err != nil {
			return err
		}
		ruleID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		var createdBy *uuid.UUID
		if actor.UserID != uuid.Nil {
			uid := actor.UserID
			createdBy = &uid
		}
		row := tx.QueryRow(ctx, `
			INSERT INTO alert_rules AS r
				(org_id, rule_id, version, name, type, severity, condition, scope_selector, enabled, created_by)
			VALUES ($1, $2, 1, $3, $4, $5, $6::jsonb, $7::jsonb, true, $8)
			RETURNING `+ruleColumns,
			orgID, ruleID, parsed.Name, parsed.Type, parsed.Severity, parsed.ConditionJSON, parsed.SelectorJSON, createdBy)
		out, err = scanRule(row)
		return err
	})
	if err != nil {
		return Rule{}, err
	}
	return out, nil
}

// UpdateRule applies a partial patch as a NEW immutable version (docs/10
// §17.2). Omitted fields are copied from the current version. Updating a
// disabled rule is allowed (and re-enables only when the patch says so).
func (s *Service) UpdateRule(ctx context.Context, orgID, ruleID uuid.UUID, actor Actor, patch RulePatchInput, sc authz.Scope) (Rule, error) {
	var out Rule
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		current, err := lockLatestRule(ctx, tx, ruleID)
		if err != nil {
			return err
		}
		// An edit requires the caller to be able to SEE the current rule; the
		// new selector is checked below.
		visible, err := s.ruleVisible(ctx, tx, current, sc)
		if err != nil {
			return err
		}
		if !visible {
			return ErrRuleNotFound
		}
		next := current
		name := current.Name
		if patch.Name != nil {
			name = *patch.Name
		}
		ruleType := current.Type
		if patch.Type != nil {
			ruleType = *patch.Type
		}
		severity := current.Severity
		if patch.Severity != nil {
			severity = *patch.Severity
		}
		conditionJSON := current.ConditionJSON
		if len(patch.ConditionJSON) > 0 {
			conditionJSON = patch.ConditionJSON
		}
		selectorJSON := current.SelectorJSON
		if len(patch.SelectorJSON) > 0 {
			selectorJSON = patch.SelectorJSON
		}
		parsed, errs := ParseRule(name, ruleType, severity, conditionJSON, selectorJSON)
		if len(errs) > 0 {
			return errs
		}
		if err := s.requireSelectorInScope(ctx, tx, parsed.Selector, sc); err != nil {
			return err
		}
		enabled := current.Enabled
		if patch.Enabled != nil {
			enabled = *patch.Enabled
		}
		row := tx.QueryRow(ctx, `
			INSERT INTO alert_rules AS r
				(org_id, rule_id, version, name, type, severity, condition, scope_selector, enabled, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9, $10)
			RETURNING `+ruleColumns,
			orgID, current.RuleID, current.Version+1, parsed.Name, parsed.Type, parsed.Severity,
			parsed.ConditionJSON, parsed.SelectorJSON, enabled, actorRef(actor))
		if err := row.Scan(&next.RuleID, &next.Version, &next.Name, &next.Type, &next.Severity,
			&next.ConditionJSON, &next.SelectorJSON, &next.Enabled, &next.CreatedBy, &next.CreatedAt); err != nil {
			if isUniqueViolation(err) {
				return ErrVersionConflict
			}
			return err
		}
		next.Condition, next.Selector = parsed.Condition, parsed.Selector
		out = next
		return nil
	})
	if err != nil {
		return Rule{}, err
	}
	return out, nil
}

// DisableRule writes a new immutable version with enabled=false (DELETE
// disables; the definition history is preserved). Disabling an already
// disabled rule writes one more disabled version rather than mutating a row
// (the immutable-version rule has no exception). Scope is the caller's
// resolved scope: an out-of-scope rule is a 404, exactly like reads.
func (s *Service) DisableRule(ctx context.Context, orgID, ruleID uuid.UUID, actor Actor, sc authz.Scope) (Rule, error) {
	disabled := false
	return s.UpdateRule(ctx, orgID, ruleID, actor, RulePatchInput{Enabled: &disabled}, sc)
}

// GetRule returns one rule version (latest when version is nil) if it is
// visible to the caller's scope.
func (s *Service) GetRule(ctx context.Context, orgID, ruleID uuid.UUID, version *int, sc authz.Scope) (Rule, error) {
	var out Rule
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		var row pgx.Row
		if version != nil {
			row = tx.QueryRow(ctx, `SELECT `+ruleColumns+` FROM alert_rules WHERE rule_id = $1 AND version = $2`, ruleID, *version)
		} else {
			row = tx.QueryRow(ctx, `SELECT `+ruleColumns+` FROM alert_rules WHERE rule_id = $1 ORDER BY version DESC LIMIT 1`, ruleID)
		}
		r, err := scanRule(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRuleNotFound
		}
		if err != nil {
			return err
		}
		visible, err := s.ruleVisible(ctx, tx, r, sc)
		if err != nil {
			return err
		}
		if !visible {
			return ErrRuleNotFound
		}
		out = r
		return nil
	})
	if err != nil {
		return Rule{}, err
	}
	return out, nil
}

// ListRules returns one cursor page of the latest version per rule, newest
// rule identity first (UUIDv7 ordering), scope-filtered.
func (s *Service) ListRules(ctx context.Context, orgID uuid.UUID, sc authz.Scope, limit int, cursor string) (RulePage, error) {
	if limit <= 0 || limit > MaxRulePageSize {
		limit = 25
	}
	var after *uuid.UUID
	if cursor != "" {
		id, err := uuid.Parse(cursor)
		if err != nil {
			return RulePage{}, ErrInvalidCursor
		}
		after = &id
	}
	var page RulePage
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT rule_id, version, name, type, severity, condition, scope_selector, enabled, created_by, created_at
			FROM (
				SELECT DISTINCT ON (rule_id)
					rule_id, version, name, type, severity, condition, scope_selector, enabled, created_by, created_at
				FROM alert_rules
				WHERE ($1::uuid IS NULL OR rule_id < $1)
				  AND ($2::boolean
				       OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(coalesce(scope_selector->'sites', '[]'::jsonb)) s
				                  WHERE s::uuid = ANY($3::uuid[]))
				       OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(coalesce(scope_selector->'device_ids', '[]'::jsonb)) di
				                  JOIN devices d ON d.id = di::uuid AND d.org_id = alert_rules.org_id
				                  WHERE d.site_id = ANY($3::uuid[])))
				ORDER BY rule_id, version DESC
			) latest
			ORDER BY rule_id DESC
			LIMIT $4`,
			after, sc.Unrestricted, sc.Sites, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanRule(rows)
			if err != nil {
				return err
			}
			page.Rules = append(page.Rules, r)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(page.Rules) > limit {
			page.NextCursor = page.Rules[limit-1].RuleID.String()
			page.HasMore = true
			page.Rules = page.Rules[:limit]
		}
		return nil
	})
	if err != nil {
		return RulePage{}, err
	}
	return page, nil
}

// ListAlerts returns one cursor page of alerts (newest onset first),
// scope-filtered by the resource device's site. The cursor is the opaque
// base64 (started_at, id) keyset.
func (s *Service) ListAlerts(ctx context.Context, orgID uuid.UUID, f AlertFilter, sc authz.Scope, limit int, cursor string) (AlertPage, error) {
	if limit <= 0 || limit > MaxAlertPageSize {
		limit = 25
	}
	var (
		afterTs *time.Time
		afterID *uuid.UUID
	)
	if cursor != "" {
		ts, id, err := decodeAlertCursor(cursor)
		if err != nil {
			return AlertPage{}, ErrInvalidCursor
		}
		afterTs, afterID = &ts, &id
	}
	var page AlertPage
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT `+alertColumns+`, d.site_id
			FROM alerts a
			LEFT JOIN devices d
			  ON a.resource_type = 'device' AND d.id = a.resource_id AND d.org_id = a.org_id
			WHERE ($1::timestamptz IS NULL OR (a.started_at, a.id) < ($1::timestamptz, $2::uuid))
			  AND ($3::text IS NULL OR a.state = $3)
			  AND ($4::text IS NULL OR a.severity = $4)
			  AND ($5::uuid IS NULL OR a.rule_id = $5)
			  AND ($6::uuid IS NULL OR a.resource_id = $6)
			  AND ($7::boolean OR d.site_id = ANY($8::uuid[]))
			ORDER BY a.started_at DESC, a.id DESC
			LIMIT $9`,
			afterTs, afterID, f.State, f.Severity, f.RuleID, f.DeviceID,
			sc.Unrestricted, sc.Sites, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			a, err := scanAlertWithSite(rows)
			if err != nil {
				return err
			}
			page.Alerts = append(page.Alerts, a)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(page.Alerts) > limit {
			last := page.Alerts[limit-1]
			page.NextCursor = encodeAlertCursor(last.StartedAt, last.ID)
			page.HasMore = true
			page.Alerts = page.Alerts[:limit]
		}
		return nil
	})
	if err != nil {
		return AlertPage{}, err
	}
	return page, nil
}

// GetAlert returns one alert plus its recent timeline (newest first).
func (s *Service) GetAlert(ctx context.Context, orgID, alertID uuid.UUID, sc authz.Scope) (Alert, []AlertEvent, error) {
	var (
		out    Alert
		events []AlertEvent
	)
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		a, err := lockAlert(ctx, tx, alertID)
		if err != nil {
			return err
		}
		if err := requireAlertScope(a, sc); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `
			SELECT id, alert_id, kind, actor_id, data, ts
			FROM alert_events WHERE alert_id = $1
			ORDER BY ts DESC, id DESC LIMIT $2`, alertID, MaxEventsInDetail)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e AlertEvent
			if err := rows.Scan(&e.ID, &e.AlertID, &e.Kind, &e.ActorID, &e.Data, &e.Ts); err != nil {
				return err
			}
			events = append(events, e)
		}
		out = a
		return rows.Err()
	})
	if err != nil {
		return Alert{}, nil, err
	}
	return out, events, nil
}

// ResolveDeviceSite resolves a device's site (including soft-deleted devices:
// alert history must stay filterable after a device is retired). Used by the
// HTTP layer for the deterministic out-of-scope 403 on explicit filters.
func (s *Service) ResolveDeviceSite(ctx context.Context, orgID, deviceID uuid.UUID) (uuid.UUID, error) {
	var siteID uuid.UUID
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT site_id FROM devices WHERE id = $1`, deviceID).Scan(&siteID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrAlertNotFound
		}
		return err
	})
	return siteID, err
}

const alertColumns = `a.id, a.org_id, a.rule_id, a.rule_version, a.fingerprint, a.resource_type, a.resource_id,
	a.dimension_subset, a.state, a.severity, a.value, a.started_at, a.last_evaluated_at, a.resolved_at,
	a.ack_by, a.ack_at, a.snooze_until, a.suppression_reason, a.created_at`

func scanAlertWithSite(row pgx.Row) (Alert, error) {
	var (
		a      Alert
		siteID *uuid.UUID
	)
	err := row.Scan(&a.ID, &a.OrgID, &a.RuleID, &a.RuleVersion, &a.Fingerprint, &a.ResourceType, &a.ResourceID,
		&a.DimensionSubset, &a.State, &a.Severity, &a.Value, &a.StartedAt, &a.LastEvaluatedAt, &a.ResolvedAt,
		&a.AckBy, &a.AckAt, &a.SnoozeUntil, &a.SuppressionReason, &a.CreatedAt, &siteID)
	if siteID != nil {
		a.SiteID = *siteID
	}
	return a, err
}

func scanAlert(row pgx.Row) (Alert, error) {
	return scanAlertWithSite(&scanNoSite{row: row})
}

// scanNoSite adapts a plain alert row (no site column) to scanAlertWithSite.
type scanNoSite struct{ row pgx.Row }

func (s *scanNoSite) Scan(dest ...any) error {
	// The site destination is the last one; scan without it.
	return s.row.Scan(dest[:len(dest)-1]...)
}

func lockAlert(ctx context.Context, tx pgx.Tx, alertID uuid.UUID) (Alert, error) {
	row := tx.QueryRow(ctx, `
		SELECT `+alertColumns+`, d.site_id
		FROM alerts a
		LEFT JOIN devices d
		  ON a.resource_type = 'device' AND d.id = a.resource_id AND d.org_id = a.org_id
		WHERE a.id = $1
		FOR UPDATE OF a`, alertID)
	a, err := scanAlertWithSite(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Alert{}, ErrAlertNotFound
	}
	return a, err
}

// AckAlert acknowledges an open alert (capability enforced by the router;
// scope by the handler).
func (s *Service) AckAlert(ctx context.Context, orgID, alertID uuid.UUID, actor Actor, sc authz.Scope) (Alert, error) {
	return s.transitionAlert(ctx, orgID, alertID, sc, func(ctx context.Context, tx pgx.Tx, a Alert) (Alert, error) {
		if a.State != StateActive && a.State != StateAcknowledged && a.State != StateSnoozed && a.State != StateSuppressed {
			return Alert{}, ErrStateConflict
		}
		now := s.Now().UTC()
		row := tx.QueryRow(ctx, `
			UPDATE alerts AS a SET state = 'acknowledged', ack_by = $2, ack_at = $3,
				snooze_until = NULL, last_evaluated_at = $3
			WHERE id = $1
			RETURNING `+alertColumns,
			alertID, actorRef(actor), now)
		out, err := scanAlert(row)
		if err != nil {
			return Alert{}, err
		}
		if err := appendEvent(ctx, tx, orgID, alertID, EventAcknowledged, actorRef(actor), map[string]any{
			"from": a.State, "to": StateAcknowledged,
		}, now); err != nil {
			return Alert{}, err
		}
		return out, nil
	})
}

// SnoozeAlert snoozes an open alert until `until` (bounded by MaxSnooze). The
// evaluator keeps evaluating during the snooze and reactivates when the
// condition is still true at expiry (docs/10 §17.5; P2-AC-30).
func (s *Service) SnoozeAlert(ctx context.Context, orgID, alertID uuid.UUID, actor Actor, until time.Time, reason string, sc authz.Scope) (Alert, error) {
	now := s.Now().UTC()
	until = until.UTC()
	reason = strings.TrimSpace(reason)
	if len(reason) > MaxCommentLen {
		return Alert{}, ValidationErrors{{Field: "reason", Code: "too_long", Message: "reason must be at most 2000 characters"}}
	}
	if !until.After(now) {
		return Alert{}, ValidationErrors{{Field: "until", Code: "range", Message: "snooze expiry must be in the future"}}
	}
	if until.After(now.Add(MaxSnooze)) {
		return Alert{}, ValidationErrors{{Field: "until", Code: "range", Message: "snooze expiry must be within 30 days"}}
	}
	return s.transitionAlert(ctx, orgID, alertID, sc, func(ctx context.Context, tx pgx.Tx, a Alert) (Alert, error) {
		switch a.State {
		case StatePending, StateActive, StateAcknowledged, StateSnoozed, StateSuppressed:
		default:
			return Alert{}, ErrStateConflict
		}
		row := tx.QueryRow(ctx, `
			UPDATE alerts AS a SET state = 'snoozed', snooze_until = $2, last_evaluated_at = $3
			WHERE id = $1
			RETURNING `+alertColumns,
			alertID, until, now)
		out, err := scanAlert(row)
		if err != nil {
			return Alert{}, err
		}
		if err := appendEvent(ctx, tx, orgID, alertID, EventSnoozed, actorRef(actor), map[string]any{
			"from": a.State, "to": StateSnoozed, "snooze_until": until.Format(time.RFC3339), "reason": reason,
		}, now); err != nil {
			return Alert{}, err
		}
		return out, nil
	})
}

// ResolveAlert manually resolves an open alert. The canonical contract
// requires a reason and the alert.ack capability (docs/10 §17.5); a re-fire
// within the documented cooldown reopens the same row.
func (s *Service) ResolveAlert(ctx context.Context, orgID, alertID uuid.UUID, actor Actor, reason string, sc authz.Scope) (Alert, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > MaxCommentLen {
		return Alert{}, ValidationErrors{{Field: "reason", Code: "required", Message: "reason is required (max 2000 characters)"}}
	}
	return s.transitionAlert(ctx, orgID, alertID, sc, func(ctx context.Context, tx pgx.Tx, a Alert) (Alert, error) {
		if a.State == StateResolved {
			return Alert{}, ErrStateConflict
		}
		now := s.Now().UTC()
		row := tx.QueryRow(ctx, `
			UPDATE alerts AS a SET state = 'resolved', resolved_at = $2, snooze_until = NULL, last_evaluated_at = $2
			WHERE id = $1
			RETURNING `+alertColumns,
			alertID, now)
		out, err := scanAlert(row)
		if err != nil {
			return Alert{}, err
		}
		if err := appendEvent(ctx, tx, orgID, alertID, EventManualResolved, actorRef(actor), map[string]any{
			"from": a.State, "to": StateResolved, "reason": reason,
		}, now); err != nil {
			return Alert{}, err
		}
		return out, nil
	})
}

// CommentAlert appends a free-text comment to the alert timeline (any state).
func (s *Service) CommentAlert(ctx context.Context, orgID, alertID uuid.UUID, actor Actor, comment string, sc authz.Scope) (Alert, error) {
	comment = strings.TrimSpace(comment)
	if comment == "" || len(comment) > MaxCommentLen {
		return Alert{}, ValidationErrors{{Field: "comment", Code: "required", Message: "comment is required (max 2000 characters)"}}
	}
	return s.transitionAlert(ctx, orgID, alertID, sc, func(ctx context.Context, tx pgx.Tx, a Alert) (Alert, error) {
		now := s.Now().UTC()
		if err := appendEvent(ctx, tx, orgID, alertID, EventComment, actorRef(actor), map[string]any{
			"comment": comment,
		}, now); err != nil {
			return Alert{}, err
		}
		return a, nil
	})
}

// transitionAlert locks the alert, enforces scope, applies fn, and reloads the
// site projection.
func (s *Service) transitionAlert(ctx context.Context, orgID, alertID uuid.UUID, sc authz.Scope,
	fn func(ctx context.Context, tx pgx.Tx, a Alert) (Alert, error)) (Alert, error) {
	var out Alert
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		a, err := lockAlert(ctx, tx, alertID)
		if err != nil {
			return err
		}
		if err := requireAlertScope(a, sc); err != nil {
			return err
		}
		updated, err := fn(ctx, tx, a)
		if err != nil {
			return err
		}
		// The UPDATE ... RETURNING path omits site_id; carry it forward.
		updated.SiteID = a.SiteID
		out = updated
		return nil
	})
	if err != nil {
		return Alert{}, err
	}
	return out, nil
}

func actorRef(a Actor) *uuid.UUID {
	if a.UserID == uuid.Nil {
		return nil
	}
	uid := a.UserID
	return &uid
}

// appendEvent writes one alert_events row. The generator is the timeline.
func appendEvent(ctx context.Context, tx pgx.Tx, orgID, alertID uuid.UUID, kind string, actor *uuid.UUID, data map[string]any, ts time.Time) error {
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO alert_events (id, org_id, alert_id, kind, actor_id, data, ts)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)`,
		id, orgID, alertID, kind, actor, mustMarshal(data), ts)
	return err
}

// requireAlertScope maps out-of-scope alerts to not-found (enumeration
// resistance). Non-device resources are only visible to unrestricted callers.
func requireAlertScope(a Alert, sc authz.Scope) error {
	if sc.Unrestricted {
		return nil
	}
	if a.ResourceType == "device" && a.SiteID != uuid.Nil && sc.AllowsSite(a.SiteID) {
		return nil
	}
	return ErrAlertNotFound
}

// lockLatestRule loads the newest version of a rule with a row lock.
func lockLatestRule(ctx context.Context, tx pgx.Tx, ruleID uuid.UUID) (Rule, error) {
	r, err := scanRule(tx.QueryRow(ctx, `
		SELECT `+ruleColumns+` FROM alert_rules
		WHERE rule_id = $1 ORDER BY version DESC LIMIT 1 FOR UPDATE`, ruleID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Rule{}, ErrRuleNotFound
	}
	return r, err
}

// requireSelectorInScope enforces the P2-D5 rule: a caller with site/group
// bindings may only create rules whose targets are inside those bindings.
// Org-wide selectors (and kind-only selectors) require org-wide scope.
// Referenced sites/devices must exist in the tenant.
func (s *Service) requireSelectorInScope(ctx context.Context, tx pgx.Tx, sel ScopeSelector, sc authz.Scope) error {
	if !sc.Unrestricted {
		if len(sel.Sites) == 0 && len(sel.DeviceIDs) == 0 {
			return ErrScopeRequired
		}
		for _, siteID := range sel.Sites {
			if !sc.AllowsSite(siteID) {
				return ErrScopeForbidden
			}
		}
	}
	// Existence + scope of explicit site references (RLS hides foreign rows).
	if len(sel.Sites) > 0 {
		var found int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM sites WHERE id = ANY($1::uuid[])`, sel.Sites).Scan(&found); err != nil {
			return err
		}
		if found != len(sel.Sites) {
			return ValidationErrors{{Field: "scope_selector.sites", Code: "not_found", Message: "one or more sites do not exist in this organization"}}
		}
	}
	if len(sel.DeviceIDs) > 0 {
		rows, err := tx.Query(ctx, `SELECT id, site_id FROM devices WHERE id = ANY($1::uuid[])`, sel.DeviceIDs)
		if err != nil {
			return err
		}
		defer rows.Close()
		found := map[uuid.UUID]uuid.UUID{}
		for rows.Next() {
			var id, siteID uuid.UUID
			if err := rows.Scan(&id, &siteID); err != nil {
				return err
			}
			found[id] = siteID
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(found) != len(sel.DeviceIDs) {
			return ValidationErrors{{Field: "scope_selector.device_ids", Code: "not_found", Message: "one or more devices do not exist in this organization"}}
		}
		if !sc.Unrestricted {
			for _, siteID := range found {
				if !sc.AllowsSite(siteID) {
					return ErrScopeForbidden
				}
			}
		}
	}
	return nil
}

// ruleVisible reports whether a rule's target selector intersects the
// caller's scope.
func (s *Service) ruleVisible(ctx context.Context, tx pgx.Tx, r Rule, sc authz.Scope) (bool, error) {
	if sc.Unrestricted {
		return true, nil
	}
	for _, siteID := range r.Selector.Sites {
		if sc.AllowsSite(siteID) {
			return true, nil
		}
	}
	if len(r.Selector.DeviceIDs) > 0 {
		rows, err := tx.Query(ctx, `SELECT site_id FROM devices WHERE id = ANY($1::uuid[])`, r.Selector.DeviceIDs)
		if err != nil {
			return false, err
		}
		defer rows.Close()
		for rows.Next() {
			var siteID uuid.UUID
			if err := rows.Scan(&siteID); err != nil {
				return false, err
			}
			if sc.AllowsSite(siteID) {
				return true, nil
			}
		}
		return false, rows.Err()
	}
	return false, nil
}

// encodeAlertCursor is an opaque base64("unix_nano|uuid") keyset cursor.
func encodeAlertCursor(ts time.Time, id uuid.UUID) string {
	raw := strconv.FormatInt(ts.UTC().UnixNano(), 10) + "|" + id.String()
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeAlertCursor(cursor string) (time.Time, uuid.UUID, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, uuid.Nil, err
	}
	parts := strings.SplitN(string(raw), "|", 2)
	if len(parts) != 2 {
		return time.Time{}, uuid.Nil, errors.New("alerts: cursor shape")
	}
	nanos, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return time.Time{}, uuid.Nil, err
	}
	id, err := uuid.Parse(parts[1])
	if err != nil {
		return time.Time{}, uuid.Nil, err
	}
	return time.Unix(0, nanos).UTC(), id, nil
}
