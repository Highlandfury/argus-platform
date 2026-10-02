package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/argus-platform/argus/internal/modules/metrics"
	"github.com/argus-platform/argus/internal/platform/database"
)

// Evaluator is the in-process alert evaluator (PHASE_2_SPEC P2-D3: no NATS,
// no external queue). It is deliberately deterministic:
//
//   - the clock is injectable (`Now`), and EvaluateOnce / EvaluateRule accept
//     the evaluation instant explicitly, so tests never sleep;
//   - trigger/recovery truth is recomputed from stored data over the whole
//     continuity span, so a missed cycle cannot fabricate continuity ("no
//     condition is assumed true/false across gaps": missing data is false);
//   - all state transitions run in one tenant transaction per rule, so a
//     rule's evaluation is atomic.
type Evaluator struct {
	app            *pgxpool.Pool
	now            func() time.Time
	logger         *slog.Logger
	queryTimeout   time.Duration
	stormThreshold int
	stormWindow    time.Duration
	maxTargets     int
	maxGrid        int
	reopenCooldown time.Duration
	// sink consumes committed transitions (M11-S2 notify engine). Nil means
	// notifications are disabled; evaluation semantics are unaffected.
	sink TransitionSink
}

// EvaluatorOptions configures the evaluator. Zero values take the documented
// defaults.
type EvaluatorOptions struct {
	Now            func() time.Time
	Logger         *slog.Logger
	QueryTimeout   time.Duration
	StormThreshold int
	StormWindow    time.Duration
	MaxTargets     int
	MaxGridPoints  int
	ReopenCooldown time.Duration
}

// NewEvaluator wires the evaluator.
func NewEvaluator(app *pgxpool.Pool, opts EvaluatorOptions) *Evaluator {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.QueryTimeout <= 0 {
		opts.QueryTimeout = QueryTimeout
	}
	if opts.StormThreshold <= 0 {
		opts.StormThreshold = DefaultStormThreshold
	}
	if opts.StormWindow <= 0 {
		opts.StormWindow = StormWindow
	}
	if opts.MaxTargets <= 0 {
		opts.MaxTargets = MaxTargetsPerRule
	}
	if opts.MaxGridPoints <= 0 {
		opts.MaxGridPoints = MaxGridPoints
	}
	if opts.ReopenCooldown <= 0 {
		opts.ReopenCooldown = DefaultReopenCooldown
	}
	return &Evaluator{
		app:            app,
		now:            opts.Now,
		logger:         opts.Logger,
		queryTimeout:   opts.QueryTimeout,
		stormThreshold: opts.StormThreshold,
		stormWindow:    opts.StormWindow,
		maxTargets:     opts.MaxTargets,
		maxGrid:        opts.MaxGridPoints,
		reopenCooldown: opts.ReopenCooldown,
	}
}

// Now returns the evaluator's current instant.
func (e *Evaluator) Now() time.Time { return e.now().UTC() }

// SetSink installs the committed-transition consumer (notify engine).
func (e *Evaluator) SetSink(sink TransitionSink) { e.sink = sink }

// Summary is the outcome of one EvaluateOnce call.
type Summary struct {
	Rules       int
	Targets     int
	Transitions int
	Errors      int
}

// RuleSummary is the outcome of one rule evaluation.
type RuleSummary struct {
	Targets     int
	Transitions int
}

// EvaluateOnce evaluates every enabled rule of the organization at `now`.
// It is the exported deterministic entry point tests use instead of sleeping.
func (e *Evaluator) EvaluateOnce(ctx context.Context, orgID uuid.UUID, now time.Time) (Summary, error) {
	rules, err := e.loadEnabledRules(ctx, orgID)
	if err != nil {
		return Summary{}, err
	}
	sum := Summary{Rules: len(rules)}
	for _, r := range rules {
		rs, err := e.EvaluateRule(ctx, orgID, r, now)
		sum.Targets += rs.Targets
		sum.Transitions += rs.Transitions
		if err != nil {
			sum.Errors++
			if e.logger != nil {
				e.logger.Warn("alert rule evaluation failed",
					"component", "alerts", "org_id", orgID, "rule_id", r.RuleID, "error", err)
			}
		}
	}
	return sum, nil
}

// EvaluateRule evaluates one rule's targets at `now` in a single tenant
// transaction. A rule-level failure rolls back the whole rule (atomic).
// Committed notify-worthy transitions are handed to the sink after commit.
func (e *Evaluator) EvaluateRule(ctx context.Context, orgID uuid.UUID, rule Rule, now time.Time) (RuleSummary, error) {
	now = now.UTC()
	var sum RuleSummary
	var transitions []Transition
	rctx, cancel := context.WithTimeout(ctx, e.queryTimeout)
	defer cancel()
	err := database.WithTenant(rctx, e.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		targets, err := e.resolveTargets(ctx, tx, rule)
		if err != nil {
			return err
		}
		sum.Targets = len(targets)
		for _, tg := range targets {
			transition, tr, err := e.evaluateTarget(ctx, tx, orgID, rule, tg, now)
			if err != nil {
				return err
			}
			if transition != "" {
				sum.Transitions++
				alertsTransitions.WithLabelValues(transition).Inc()
			}
			if tr != nil {
				transitions = append(transitions, *tr)
			}
			alertsEvaluations.WithLabelValues("ok").Inc()
		}
		return nil
	})
	if err != nil {
		alertsEvaluations.WithLabelValues("error").Inc()
		return sum, err
	}
	if e.sink != nil {
		for _, tr := range transitions {
			e.sink.Transitioned(ctx, tr)
		}
	}
	return sum, nil
}

// loadEnabledRules loads the latest enabled version of every rule of the org.
func (e *Evaluator) loadEnabledRules(ctx context.Context, orgID uuid.UUID) ([]Rule, error) {
	var out []Rule
	err := database.WithTenant(ctx, e.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT DISTINCT ON (rule_id)
				rule_id, version, name, type, severity, condition, scope_selector, enabled, created_by, created_at
			FROM alert_rules
			WHERE enabled
			ORDER BY rule_id, version DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanRule(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// target is one evaluation target: a resolved (device, series) pair, or a
// bare device for poll-health absence rules.
type target struct {
	DeviceID uuid.UUID
	SiteID   uuid.UUID
	SeriesID *int64
	Dims     []byte // canonical dimension subset (fingerprint input)
}

// resolveTargets resolves the rule's scope selector to concrete series/devices.
// Results are ordered deterministically and bounded by MaxTargetsPerRule.
func (e *Evaluator) resolveTargets(ctx context.Context, tx pgx.Tx, rule Rule) ([]target, error) {
	if rule.Type == TypeAbsence && rule.Condition.Source == SourcePollHealth {
		rows, err := tx.Query(ctx, `
			SELECT d.id, d.site_id
			FROM devices d
			WHERE d.deleted_at IS NULL
			  AND ($1::uuid[] IS NULL OR d.site_id = ANY($1::uuid[]))
			  AND ($2::uuid[] IS NULL OR d.id = ANY($2::uuid[]))
			  AND ($3::text[] IS NULL OR d.kind = ANY($3::text[]))
			ORDER BY d.id
			LIMIT $4`,
			nullUUIDs(rule.Selector.Sites), nullUUIDs(rule.Selector.DeviceIDs), nullStrings(rule.Selector.DeviceKinds), e.maxTargets)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []target
		for rows.Next() {
			var tg target
			if err := rows.Scan(&tg.DeviceID, &tg.SiteID); err != nil {
				return nil, err
			}
			tg.Dims = []byte("{}")
			out = append(out, tg)
		}
		return out, rows.Err()
	}

	dims := json.RawMessage("{}")
	if len(rule.Selector.Dimensions) > 0 {
		dims = sortedDimensions(rule.Selector.Dimensions)
	}
	rows, err := tx.Query(ctx, `
		SELECT ms.id, ms.device_id, d.site_id, ms.dimensions
		FROM metric_series ms
		JOIN devices d ON d.id = ms.device_id AND d.org_id = ms.org_id
		WHERE ms.device_id IS NOT NULL
		  AND ms.retired_at IS NULL
		  AND ms.quarantined_at IS NULL
		  AND ms.metric_key = $1
		  AND ms.dimensions @> $2::jsonb
		  AND ($3::uuid[] IS NULL OR d.site_id = ANY($3::uuid[]))
		  AND ($4::uuid[] IS NULL OR d.id = ANY($4::uuid[]))
		  AND ($5::text[] IS NULL OR d.kind = ANY($5::text[]))
		  AND d.deleted_at IS NULL
		ORDER BY ms.device_id, ms.id
		LIMIT $6`,
		rule.Selector.MetricKey, string(dims),
		nullUUIDs(rule.Selector.Sites), nullUUIDs(rule.Selector.DeviceIDs), nullStrings(rule.Selector.DeviceKinds), e.maxTargets)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []target
	for rows.Next() {
		var (
			tg  target
			raw []byte
			sID int64
		)
		if err := rows.Scan(&sID, &tg.DeviceID, &tg.SiteID, &raw); err != nil {
			return nil, err
		}
		id := sID
		tg.SeriesID = &id
		tg.Dims = canonicalDimensions(raw)
		out = append(out, tg)
	}
	return out, rows.Err()
}

func nullUUIDs(ids []uuid.UUID) any {
	if len(ids) == 0 {
		return nil
	}
	return ids
}

func nullStrings(vals []string) any {
	if len(vals) == 0 {
		return nil
	}
	return vals
}

// canonicalDimensions normalizes a stored dimensions JSON object into the
// sorted-key canonical form used by the fingerprint.
func canonicalDimensions(raw []byte) []byte {
	if len(raw) == 0 {
		return []byte("{}")
	}
	var dims map[string]string
	if err := json.Unmarshal(raw, &dims); err != nil {
		return []byte("{}")
	}
	return sortedDimensions(dims)
}

// evaluateTarget runs the state machine for one target and returns the
// transition name ("" when the state is unchanged) for metrics plus the
// notify-worthy transition when one occurred (activated/reactivated/resolved).
func (e *Evaluator) evaluateTarget(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, rule Rule, tg target, now time.Time) (string, *Transition, error) {
	fp := Fingerprint(rule.RuleID, "device", tg.DeviceID, tg.Dims)
	open, found, err := findOpenAlert(ctx, tx, orgID, fp)
	if err != nil {
		return "", nil, err
	}

	trigger, triggerData, err := e.triggerAt(ctx, tx, rule, tg, now)
	if err != nil {
		return "", nil, err
	}

	if !found {
		if !trigger {
			return "", nil, nil
		}
		return e.openAlert(ctx, tx, orgID, rule, tg, fp, now, triggerData)
	}

	if open.State == StatePending {
		if !trigger {
			if _, err := tx.Exec(ctx, `DELETE FROM alerts WHERE id = $1`, open.ID); err != nil {
				return "", nil, err
			}
			return "reset", nil, nil
		}
		activate := rule.Condition.ForDuration <= 0
		if !activate && !now.Before(open.StartedAt.Add(rule.Condition.ForDuration)) {
			// The for_duration span is complete: continuity must hold at
			// every instant. A revealed false instant is the canonical
			// Pending -> Inactive reset (the pending row is removed; a later
			// true evaluation starts a fresh Pending onset).
			cont, err := e.continuousTrigger(ctx, tx, rule, tg, open.StartedAt, now)
			if err != nil {
				return "", nil, err
			}
			if !cont {
				if _, err := tx.Exec(ctx, `DELETE FROM alerts WHERE id = $1`, open.ID); err != nil {
					return "", nil, err
				}
				return "reset", nil, nil
			}
			activate = true
		}
		if !activate {
			_, err := tx.Exec(ctx, `
				UPDATE alerts SET value = $2::jsonb, last_evaluated_at = $3 WHERE id = $1`,
				open.ID, mustMarshal(triggerData), now)
			if err != nil {
				return "", nil, err
			}
			return "", nil, nil
		}
		_, err := tx.Exec(ctx, `
			UPDATE alerts SET state = 'active', value = $2::jsonb, last_evaluated_at = $3 WHERE id = $1`,
			open.ID, mustMarshal(triggerData), now)
		if err != nil {
			return "", nil, err
		}
		ev, err := appendEvent(ctx, tx, orgID, open.ID, EventActivated, nil, map[string]any{
			"from": StatePending, "to": StateActive, "value": triggerData,
		}, now)
		if err != nil {
			return "", nil, err
		}
		activated := open
		activated.State = StateActive
		activated.SiteID = tg.SiteID
		activated.Value = mustMarshal(triggerData)
		activated.LastEvaluatedAt = now
		return StateActive, &Transition{Alert: activated, Event: ev}, nil
	}

	// Open, past-pending states: active | acknowledged | snoozed | suppressed.
	state := open.State
	var reactivation *Transition
	if state == StateSnoozed && open.SnoozeUntil != nil && !now.Before(*open.SnoozeUntil) {
		if trigger {
			state = StateActive
			if _, err := tx.Exec(ctx, `UPDATE alerts SET state = 'active', snooze_until = NULL WHERE id = $1`, open.ID); err != nil {
				return "", nil, err
			}
			ev, err := appendEvent(ctx, tx, orgID, open.ID, EventReactivated, nil, map[string]any{
				"from": StateSnoozed, "to": StateActive, "value": triggerData,
			}, now)
			if err != nil {
				return "", nil, err
			}
			reactivated := open
			reactivated.State = StateActive
			reactivated.SiteID = tg.SiteID
			reactivated.SnoozeUntil = nil
			reactivated.Value = mustMarshal(triggerData)
			reactivated.LastEvaluatedAt = now
			reactivation = &Transition{Alert: reactivated, Event: ev}
		} else {
			state = StateActive
			if _, err := tx.Exec(ctx, `UPDATE alerts SET state = 'active', snooze_until = NULL WHERE id = $1`, open.ID); err != nil {
				return "", nil, err
			}
			if _, err := appendEvent(ctx, tx, orgID, open.ID, EventUnsnoozed, nil, map[string]any{
				"from": StateSnoozed, "to": StateActive, "reason": "snooze expired; condition no longer true",
			}, now); err != nil {
				return "", nil, err
			}
		}
	}

	if trigger {
		// Dedup (docs/10 §17.4): the repeat updates value/last_evaluated_at
		// and appends an event; the row is never duplicated.
		if _, err := tx.Exec(ctx, `
			UPDATE alerts SET value = $2::jsonb, last_evaluated_at = $3 WHERE id = $1`,
			open.ID, mustMarshal(triggerData), now); err != nil {
			return "", nil, err
		}
		if _, err := appendEvent(ctx, tx, orgID, open.ID, EventUpdated, nil, map[string]any{
			"value": triggerData,
		}, now); err != nil {
			return "", nil, err
		}
		if reactivation != nil {
			return StateActive, reactivation, nil
		}
		return "", nil, nil
	}

	// Recovery path: the logical inverse must hold continuously for the
	// recovery for_duration (default: 2x the trigger duration, at least the
	// window; docs/10 §17.5).
	recovered, recData, err := e.recoveryMet(ctx, tx, rule, tg, now)
	if err != nil {
		return "", nil, err
	}
	if !recovered {
		if _, err := tx.Exec(ctx, `
			UPDATE alerts SET value = $2::jsonb, last_evaluated_at = $3 WHERE id = $1`,
			open.ID, mustMarshal(triggerData), now); err != nil {
			return "", nil, err
		}
		return "", nil, nil
	}
	_, err = tx.Exec(ctx, `
		UPDATE alerts SET state = 'resolved', resolved_at = $2, snooze_until = NULL, last_evaluated_at = $2, value = $3::jsonb
		WHERE id = $1`,
		open.ID, now, mustMarshal(recData))
	if err != nil {
		return "", nil, err
	}
	ev, err := appendEvent(ctx, tx, orgID, open.ID, EventResolved, nil, map[string]any{
		"from": state, "to": StateResolved, "recovery": recData,
	}, now)
	if err != nil {
		return "", nil, err
	}
	resolved := open
	resolved.State = StateResolved
	resolved.SiteID = tg.SiteID
	resolved.ResolvedAt = &now
	resolved.SnoozeUntil = nil
	resolved.Value = mustMarshal(recData)
	resolved.LastEvaluatedAt = now
	return StateResolved, &Transition{Alert: resolved, Event: ev}, nil
}

// openAlert inserts a new alert row (Pending, or Active when for_duration is
// zero, or Suppressed(storm) when the device is over the storm threshold) and
// its onset events. It returns the transition name for metrics plus the
// notify-worthy transition when the alert opens Active.
func (e *Evaluator) openAlert(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, rule Rule, tg target, fp string, now time.Time, value map[string]any) (string, *Transition, error) {
	// Manual-resolve cooldown: a re-fire within the cooldown reopens the same
	// row (canonical docs/10 §17.5: no duplicate).
	reopened, reopenedTr, err := e.tryReopen(ctx, tx, orgID, rule, tg, fp, now, value)
	if err != nil {
		return "", nil, err
	}
	if reopened {
		return EventReopened, reopenedTr, nil
	}

	storm, count, err := e.stormExceeds(ctx, tx, orgID, tg.DeviceID, now)
	if err != nil {
		return "", nil, err
	}
	state := StatePending
	suppression := ""
	switch {
	case storm:
		state = StateSuppressed
		suppression = SuppressionStorm
		alertsStormSuppressed.Inc()
	case rule.Condition.ForDuration <= 0:
		state = StateActive
	}

	id, err := uuid.NewV7()
	if err != nil {
		return "", nil, err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO alerts
			(id, org_id, rule_id, rule_version, fingerprint, resource_type, resource_id,
			 dimension_subset, state, severity, value, started_at, last_evaluated_at,
			 suppression_reason, created_at)
		VALUES ($1, $2, $3, $4, $5, 'device', $6, $7::jsonb, $8, $9, $10::jsonb, $11, $11, $12, $11)`,
		id, orgID, rule.RuleID, rule.Version, fp, tg.DeviceID, string(tg.Dims),
		state, rule.Severity, mustMarshal(value), now, suppression)
	if err != nil {
		return "", nil, err
	}
	alert := Alert{
		ID: id, OrgID: orgID, RuleID: rule.RuleID, RuleVersion: rule.Version,
		Fingerprint: fp, ResourceType: "device", ResourceID: tg.DeviceID,
		DimensionSubset: tg.Dims, State: state, Severity: rule.Severity,
		Value: mustMarshal(value), StartedAt: now, LastEvaluatedAt: now,
		SuppressionReason: suppression, CreatedAt: now, SiteID: tg.SiteID,
	}
	if _, err := appendEvent(ctx, tx, orgID, id, EventPending, nil, map[string]any{
		"value": value, "for_duration": rule.Condition.ForDuration.String(),
	}, now); err != nil {
		return "", nil, err
	}
	switch state {
	case StateActive:
		ev, err := appendEvent(ctx, tx, orgID, id, EventActivated, nil, map[string]any{
			"from": StatePending, "to": StateActive, "value": value,
		}, now)
		if err != nil {
			return "", nil, err
		}
		return StateActive, &Transition{Alert: alert, Event: ev}, nil
	case StateSuppressed:
		if _, err := appendEvent(ctx, tx, orgID, id, EventSuppressed, nil, map[string]any{
			"from": StatePending, "to": StateSuppressed,
			"reason": SuppressionStorm, "recent_device_alerts": count,
		}, now); err != nil {
			return "", nil, err
		}
	}
	return state, nil, nil
}

// tryReopen reopens a manually resolved alert when the condition re-fires
// inside the reopen cooldown. Returns true when the same row was reopened and
// the notify-worthy activated transition when for_duration is zero.
func (e *Evaluator) tryReopen(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, rule Rule, tg target, fp string, now time.Time, value map[string]any) (bool, *Transition, error) {
	var (
		alertID uuid.UUID
		from    time.Time
	)
	err := tx.QueryRow(ctx, `
		SELECT a.id, last_event.ts
		FROM alerts a
		JOIN LATERAL (
			SELECT kind, ts FROM alert_events ev
			WHERE ev.alert_id = a.id ORDER BY ev.ts DESC, ev.id DESC LIMIT 1
		) last_event ON true
		WHERE a.org_id = $1 AND a.fingerprint = $2 AND a.state = 'resolved'
		  AND last_event.kind = 'manual_resolved'
		  AND last_event.ts > $3
		ORDER BY a.resolved_at DESC
		LIMIT 1
		FOR UPDATE OF a`,
		orgID, fp, now.Add(-e.reopenCooldown)).Scan(&alertID, &from)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	state := StateActive
	if rule.Condition.ForDuration > 0 {
		state = StatePending
	}
	_, err = tx.Exec(ctx, `
		UPDATE alerts
		SET state = $2, started_at = $3, resolved_at = NULL, ack_by = NULL, ack_at = NULL,
		    snooze_until = NULL, suppression_reason = '', value = $4::jsonb, last_evaluated_at = $3
		WHERE id = $1`,
		alertID, state, now, mustMarshal(value))
	if err != nil {
		return false, nil, err
	}
	if _, err := appendEvent(ctx, tx, orgID, alertID, EventReopened, nil, map[string]any{
		"manual_resolved_at": from.Format(time.RFC3339),
		"value":              value,
	}, now); err != nil {
		return false, nil, err
	}
	alert := Alert{
		ID: alertID, OrgID: orgID, RuleID: rule.RuleID, RuleVersion: rule.Version,
		Fingerprint: fp, ResourceType: "device", ResourceID: tg.DeviceID,
		DimensionSubset: tg.Dims, State: state, Severity: rule.Severity,
		Value: mustMarshal(value), StartedAt: now, LastEvaluatedAt: now, CreatedAt: now,
		SiteID: tg.SiteID,
	}
	tr, err := e.activateIfInstant(ctx, tx, orgID, alert, value, now, state)
	return true, tr, err
}

// activateIfInstant activates a reopened Pending alert when for_duration is
// zero (keeps the Inactive -> Pending -> Active event shape consistent).
func (e *Evaluator) activateIfInstant(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, alert Alert, value map[string]any, now time.Time, state string) (*Transition, error) {
	if state != StateActive {
		return nil, nil
	}
	ev, err := appendEvent(ctx, tx, orgID, alert.ID, EventActivated, nil, map[string]any{
		"from": StatePending, "to": StateActive, "value": value,
	}, now)
	if err != nil {
		return nil, err
	}
	return &Transition{Alert: alert, Event: ev}, nil
}

// findOpenAlert loads the fingerprint's open alert with a row lock.
func findOpenAlert(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, fingerprint string) (Alert, bool, error) {
	row := tx.QueryRow(ctx, `
		SELECT `+alertColumns+`
		FROM alerts a
		WHERE a.org_id = $1 AND a.fingerprint = $2 AND a.state <> 'resolved'
		ORDER BY a.created_at DESC
		LIMIT 1
		FOR UPDATE OF a`, orgID, fingerprint)
	a, err := scanAlert(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Alert{}, false, nil
	}
	if err != nil {
		return Alert{}, false, err
	}
	return a, true, nil
}

// stormExceeds counts this device's alerts created inside the storm window.
func (e *Evaluator) stormExceeds(ctx context.Context, tx pgx.Tx, orgID, deviceID uuid.UUID, now time.Time) (bool, int, error) {
	var n int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM alerts
		WHERE org_id = $1 AND resource_type = 'device' AND resource_id = $2
		  AND created_at > $3`,
		orgID, deviceID, now.Add(-e.stormWindow)).Scan(&n); err != nil {
		return false, 0, err
	}
	return n >= e.stormThreshold, n, nil
}

// continuousTrigger checks the trigger condition at every continuity grid
// instant over [from, now] (docs/10 §17.3 "continuously true ... no two lucky
// samples").
func (e *Evaluator) continuousTrigger(ctx context.Context, tx pgx.Tx, rule Rule, tg target, from, now time.Time) (bool, error) {
	cadence := RuleCadence(rule)
	return Continuous(from, now, cadence, e.maxGrid, func(t time.Time) (bool, error) {
		ok, _, err := e.triggerAt(ctx, tx, rule, tg, t)
		return ok, err
	})
}

// recoveryMet checks the recovery condition for the recovery for_duration.
func (e *Evaluator) recoveryMet(ctx context.Context, tx pgx.Tx, rule Rule, tg target, now time.Time) (bool, map[string]any, error) {
	rec := rule.Condition.Recovery
	if rec == nil {
		rec = defaultRecovery(rule.Type, rule.Condition)
	}
	if rec.ForDuration <= 0 {
		ok, data, err := e.recoveryAt(ctx, tx, rule, tg, now)
		return ok, data, err
	}
	cadence := RuleCadence(rule)
	var last map[string]any
	ok, err := Continuous(now.Add(-rec.ForDuration), now, cadence, e.maxGrid, func(t time.Time) (bool, error) {
		good, data, err := e.recoveryAt(ctx, tx, rule, tg, t)
		if err != nil {
			return false, err
		}
		if good {
			last = data
		}
		return good, nil
	})
	if err != nil {
		return false, nil, err
	}
	if last == nil {
		last = map[string]any{"checked_at": now.Format(time.RFC3339)}
	}
	return ok, last, nil
}

// triggerAt computes the trigger condition truth at instant `at`.
func (e *Evaluator) triggerAt(ctx context.Context, tx pgx.Tx, rule Rule, tg target, at time.Time) (bool, map[string]any, error) {
	switch rule.Type {
	case TypeThreshold:
		val, meta, err := e.aggregateAt(ctx, tx, rule, tg, at)
		if err != nil || val == nil {
			return false, meta, err
		}
		meta["value"] = *val
		meta["op"] = rule.Condition.Op
		meta["threshold"] = *rule.Condition.Value
		meta["phase"] = "trigger"
		return ApplyOp(rule.Condition.Op, *val, *rule.Condition.Value), meta, nil
	case TypeRateOfChange:
		curr, meta, err := e.aggregateAt(ctx, tx, rule, tg, at)
		if err != nil {
			return false, nil, err
		}
		if curr == nil {
			return false, map[string]any{"phase": "trigger", "missing": true}, nil
		}
		prev, _, err := e.aggregateAt(ctx, tx, rule, tg, at.Add(-rule.Condition.Window))
		if err != nil {
			return false, nil, err
		}
		if prev == nil {
			return false, map[string]any{"phase": "trigger", "missing": true}, nil
		}
		rate := (*curr - *prev) / rule.Condition.Window.Seconds()
		meta["value"] = rate
		meta["current"] = *curr
		meta["previous"] = *prev
		meta["op"] = rule.Condition.Op
		meta["threshold"] = *rule.Condition.Value
		meta["phase"] = "trigger"
		return ApplyOp(rule.Condition.Op, rate, *rule.Condition.Value), meta, nil
	case TypeAbsence:
		if rule.Condition.Source == SourcePollHealth {
			fails, data, err := e.pollConsecutiveAt(ctx, tx, tg.DeviceID, at)
			if err != nil {
				return false, nil, err
			}
			return fails >= rule.Condition.ConsecutiveFailures, data, nil
		}
		last, err := lastSampleTS(ctx, tx, tg, at)
		if err != nil {
			return false, nil, err
		}
		if last == nil {
			// Never seen: absence cannot be established from nothing.
			return false, map[string]any{"phase": "trigger", "missing": true}, nil
		}
		age := at.Sub(*last)
		return age > rule.Condition.Window, map[string]any{
			"phase":          "trigger",
			"last_sample_at": last.Format(time.RFC3339),
			"age_seconds":    age.Seconds(),
			"window":         rule.Condition.Window.String(),
		}, nil
	default:
		return false, nil, fmt.Errorf("alerts: unsupported rule type %q", rule.Type)
	}
}

// recoveryAt computes the recovery condition truth at instant `at`.
func (e *Evaluator) recoveryAt(ctx context.Context, tx pgx.Tx, rule Rule, tg target, at time.Time) (bool, map[string]any, error) {
	rec := rule.Condition.Recovery
	if rec == nil {
		rec = defaultRecovery(rule.Type, rule.Condition)
	}
	switch rule.Type {
	case TypeThreshold:
		val, meta, err := e.aggregateAt(ctx, tx, rule, tg, at)
		if err != nil || val == nil {
			return false, meta, err
		}
		meta["value"] = *val
		meta["op"] = rec.Op
		meta["threshold"] = *rec.Value
		meta["phase"] = "recovery"
		return ApplyOp(rec.Op, *val, *rec.Value), meta, nil
	case TypeRateOfChange:
		curr, meta, err := e.aggregateAt(ctx, tx, rule, tg, at)
		if err != nil || curr == nil {
			return false, meta, err
		}
		prev, _, err := e.aggregateAt(ctx, tx, rule, tg, at.Add(-rule.Condition.Window))
		if err != nil || prev == nil {
			return false, map[string]any{"phase": "recovery", "missing": true}, err
		}
		rate := (*curr - *prev) / rule.Condition.Window.Seconds()
		meta["value"] = rate
		meta["op"] = rec.Op
		meta["threshold"] = *rec.Value
		meta["phase"] = "recovery"
		return ApplyOp(rec.Op, rate, *rec.Value), meta, nil
	case TypeAbsence:
		if rule.Condition.Source == SourcePollHealth {
			_, data, err := e.pollConsecutiveAt(ctx, tx, tg.DeviceID, at)
			if err != nil {
				return false, nil, err
			}
			successes, _ := data["consecutive_successes"].(int)
			data["phase"] = "recovery"
			return successes >= rule.Condition.RecoverySuccesses, data, nil
		}
		last, err := lastSampleTS(ctx, tx, tg, at)
		if err != nil {
			return false, nil, err
		}
		window := rec.Window
		if window <= 0 {
			window = rule.Condition.Window
		}
		if last == nil {
			return false, map[string]any{"phase": "recovery", "missing": true}, nil
		}
		age := at.Sub(*last)
		return age <= window, map[string]any{
			"phase":          "recovery",
			"last_sample_at": last.Format(time.RFC3339),
			"age_seconds":    age.Seconds(),
			"window":         window.String(),
		}, nil
	default:
		return false, nil, fmt.Errorf("alerts: unsupported rule type %q", rule.Type)
	}
}

// pollConsecutiveAt counts the consecutive failure/success tail of the
// device's scheduled poll_health at instant `at`. Only scheduled polls count
// (on-demand checks never flip a device-down state, M10-S1; M10-S0 marks
// origin).
func (e *Evaluator) pollConsecutiveAt(ctx context.Context, tx pgx.Tx, deviceID uuid.UUID, at time.Time) (int, map[string]any, error) {
	const limit = 100
	rows, err := tx.Query(ctx, `
		SELECT outcome, consecutive_failures, ts
		FROM poll_health
		WHERE device_id = $1 AND origin = 'scheduled' AND ts <= $2
		ORDER BY ts DESC, id DESC
		LIMIT $3`,
		deviceID, at, limit)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	var (
		fails, successes  int
		countingFails     = true
		countingSuccesses = true
		lastOutcome       string
		lastFailures      int
		lastTS            *time.Time
		seen              int
	)
	for rows.Next() {
		var (
			outcome     string
			consecutive int
			ts          time.Time
		)
		if err := rows.Scan(&outcome, &consecutive, &ts); err != nil {
			return 0, nil, err
		}
		if seen == 0 {
			lastOutcome, lastFailures, lastTS = outcome, consecutive, &ts
		}
		seen++
		if countingFails {
			if outcome == "failure" {
				fails++
			} else {
				countingFails = false
			}
		}
		if countingSuccesses {
			if outcome == "success" {
				successes++
			} else {
				countingSuccesses = false
			}
		}
		if !countingFails && !countingSuccesses {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return 0, nil, err
	}
	data := map[string]any{
		"consecutive_failures":  fails,
		"consecutive_successes": successes,
		"last_outcome":          lastOutcome,
		"last_consecutive":      lastFailures,
	}
	if lastTS != nil {
		data["last_checked_at"] = lastTS.Format(time.RFC3339)
	}
	return fails, data, nil
}

// lastSampleTS returns the newest sample timestamp at or before `at`.
func lastSampleTS(ctx context.Context, tx pgx.Tx, tg target, at time.Time) (*time.Time, error) {
	if tg.SeriesID == nil {
		return nil, nil
	}
	var ts *time.Time
	if err := tx.QueryRow(ctx, `
		SELECT max(ts) FROM metric_samples
		WHERE org_id = (SELECT org_id FROM metric_series WHERE id = $1)
		  AND series_id = $1 AND ts <= $2`, *tg.SeriesID, at).Scan(&ts); err != nil {
		return nil, err
	}
	return ts, nil
}

// aggTotals accumulates the raw/CAGG aggregate shape.
type aggTotals struct {
	n   int64
	sum float64
	max float64
	min float64
}

func (t *aggTotals) value(agg string) *float64 {
	if t.n == 0 {
		return nil
	}
	var v float64
	switch agg {
	case AggAvg:
		v = t.sum / float64(t.n)
	case AggMax:
		v = t.max
	case AggMin:
		v = t.min
	default:
		v = t.sum
	}
	return &v
}

// aggregateAt computes agg(series.window) ending at `at`. Windows >= 5 m read
// the continuous aggregates with a raw fallback for the materialization tail;
// smaller windows read raw samples. The newest incomplete rollup bucket is
// excluded unless allow_partial (canonical docs/10 §17.3).
func (e *Evaluator) aggregateAt(ctx context.Context, tx pgx.Tx, rule Rule, tg target, at time.Time) (*float64, map[string]any, error) {
	if tg.SeriesID == nil {
		return nil, map[string]any{"phase": "value", "missing": true}, nil
	}
	win := rule.Condition.Window
	meta := map[string]any{"phase": "value", "window": win.String(), "agg": rule.Condition.Agg}
	totals := &aggTotals{}
	from := at.Add(-win)

	step := metrics.PickStep(from, at)
	useCAGG := win >= 5*time.Minute && metrics.IsRollupStep(step)
	if !useCAGG {
		if err := e.rawAggregate(ctx, tx, tg, from, at, totals); err != nil {
			return nil, nil, err
		}
		meta["resolution"] = "raw"
		return totals.value(rule.Condition.Agg), meta, nil
	}

	pol, ok := metricsPolicy(step)
	if !ok {
		if err := e.rawAggregate(ctx, tx, tg, from, at, totals); err != nil {
			return nil, nil, err
		}
		meta["resolution"] = "raw"
		return totals.value(rule.Condition.Agg), meta, nil
	}
	// Conservative materialization boundary: one full refresh schedule behind
	// the CAGG watermark (same rule the M8 query engine uses).
	boundary := at.Add(-(pol.EndOffset + pol.Schedule)).Truncate(step.Interval())
	caggEnd := boundary
	if rule.Condition.AllowPartial {
		caggEnd = at
	}
	if from.Before(boundary) {
		if err := e.caggAggregate(ctx, tx, pol, tg, from, boundary, totals); err != nil {
			return nil, nil, err
		}
	}
	if rule.Condition.AllowPartial && caggEnd.After(boundary) {
		// Partial tail computed from raw so the evaluation sees the newest
		// (possibly incomplete) materialization span.
		if err := e.rawAggregate(ctx, tx, tg, boundary, caggEnd, totals); err != nil {
			return nil, nil, err
		}
		meta["partial"] = true
	}
	if totals.n == 0 && from.Before(boundary) {
		// Nothing materialized yet (fresh install/backfill): recompute the
		// older span from raw so the answer stays truthful (M8 rollup_missing
		// rule).
		if err := e.rawAggregate(ctx, tx, tg, from, boundary, totals); err != nil {
			return nil, nil, err
		}
		meta["rollup_missing"] = true
	}
	meta["resolution"] = metrics.ResolutionName(step)
	return totals.value(rule.Condition.Agg), meta, nil
}

// metricsPolicy resolves the rollup policy for a step from the shared M8
// policy table.
func metricsPolicy(step metrics.Step) (metrics.RollupPolicy, bool) {
	for _, p := range metrics.RollupPolicies() {
		if p.Step == step {
			return p, true
		}
	}
	return metrics.RollupPolicy{}, false
}

func (e *Evaluator) rawAggregate(ctx context.Context, tx pgx.Tx, tg target, from, to time.Time, totals *aggTotals) error {
	var (
		n               int64
		sum, maxV, minV float64
	)
	err := tx.QueryRow(ctx, `
		SELECT count(*)::bigint, coalesce(sum(value), 0)::float8,
		       coalesce(max(value), 0)::float8, coalesce(min(value), 0)::float8
		FROM metric_samples
		WHERE series_id = $1 AND ts > $2 AND ts <= $3`,
		*tg.SeriesID, from, to).Scan(&n, &sum, &maxV, &minV)
	if err != nil {
		return err
	}
	mergeTotals(totals, n, sum, maxV, minV)
	return nil
}

// mergeTotals folds one aggregate result into the running totals; empty
// results never influence max/min.
func mergeTotals(t *aggTotals, n int64, sum, maxV, minV float64) {
	if n <= 0 {
		return
	}
	if t.n == 0 {
		t.max, t.min = maxV, minV
	} else {
		if maxV > t.max {
			t.max = maxV
		}
		if minV < t.min {
			t.min = minV
		}
	}
	t.n += n
	t.sum += sum
}

func (e *Evaluator) caggAggregate(ctx context.Context, tx pgx.Tx, pol metrics.RollupPolicy, tg target, from, to time.Time, totals *aggTotals) error {
	view := pol.TenantView // from the fixed policy table; never user input
	var (
		n               int64
		sum, maxV, minV float64
	)
	err := tx.QueryRow(ctx, fmt.Sprintf(`
		SELECT coalesce(sum(n), 0)::bigint, coalesce(sum("sum"), 0)::float8,
		       coalesce(max(max), 0)::float8, coalesce(min(min), 0)::float8
		FROM %s
		WHERE series_id = $1 AND bucket >= $2 AND bucket < $3`, view), //nolint:gosec // view name from the fixed M8 policy table
		*tg.SeriesID, from, to).Scan(&n, &sum, &maxV, &minV)
	if err != nil {
		return err
	}
	mergeTotals(totals, n, sum, maxV, minV)
	return nil
}
