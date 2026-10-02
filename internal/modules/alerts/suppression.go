package alerts

// M11-S3a suppression objects: maintenance windows and operator silences
// (docs/10 §17.6; docs/12 §22.9). A matching active window or silence makes an
// alert `Suppressed (maintenance|silence)`: still recorded, still evaluated,
// never notified; the reason (and object id) are recorded on the alert and its
// timeline, and disappear when the suppression stops applying.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/argus-platform/argus/internal/platform/authz"
	"github.com/argus-platform/argus/internal/platform/database"
)

// Suppression object constants.
const (
	// MaxWindowPageSize / MaxSilencePageSize bound cursor pages.
	MaxWindowPageSize  = 100
	MaxSilencePageSize = 100
	// MaxFingerprintLen matches alerts.fingerprint (sha256 hex).
	MaxFingerprintLen = 64
)

// TargetScope is the site/device/kind targeting vocabulary shared by windows
// and silences (and mirroring alert_rules.scope_selector). The zero value is
// an empty (org-wide) scope. Matching is OR across the present lists.
type TargetScope struct {
	Sites       []uuid.UUID
	DeviceIDs   []uuid.UUID
	DeviceKinds []string
}

// IsEmpty reports whether the scope targets everything in the org.
func (s TargetScope) IsEmpty() bool {
	return len(s.Sites) == 0 && len(s.DeviceIDs) == 0 && len(s.DeviceKinds) == 0
}

// Matches reports whether a device resource is covered: site, device id, or
// kind membership. An empty scope matches every device.
func (s TargetScope) Matches(siteID, deviceID uuid.UUID, deviceKind string) bool {
	if s.IsEmpty() {
		return true
	}
	if siteID != uuid.Nil && containsUUID(s.Sites, siteID) {
		return true
	}
	if deviceID != uuid.Nil && containsUUID(s.DeviceIDs, deviceID) {
		return true
	}
	for _, kind := range s.DeviceKinds {
		if deviceKind != "" && kind == deviceKind {
			return true
		}
	}
	return false
}

func containsUUID(ids []uuid.UUID, want uuid.UUID) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// canonicalJSON stores the normalized scope (present lists only, sorted kinds).
func (s TargetScope) canonicalJSON() []byte {
	obj := map[string]any{}
	if len(s.Sites) > 0 {
		obj["sites"] = uuidStrings(s.Sites)
	}
	if len(s.DeviceIDs) > 0 {
		obj["device_ids"] = uuidStrings(s.DeviceIDs)
	}
	if len(s.DeviceKinds) > 0 {
		kinds := append([]string{}, s.DeviceKinds...)
		sort.Strings(kinds)
		obj["device_kinds"] = kinds
	}
	return mustMarshal(obj)
}

// ParseTargetScopeJSON parses the {sites, device_ids, device_kinds} scope
// object used by windows and silences. Any other key is rejected.
func ParseTargetScopeJSON(field string, raw []byte) (TargetScope, ValidationErrors) {
	if len(raw) == 0 {
		return TargetScope{}, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return TargetScope{}, ValidationErrors{{Field: field, Code: "invalid", Message: "must be a JSON object"}}
	}
	var errs ValidationErrors
	var scope TargetScope
	for key := range obj {
		switch key {
		case "sites", "device_ids", "device_kinds":
		default:
			errs = append(errs, ValidationError{Field: field + "." + key, Code: "unknown", Message: "unknown scope field"})
		}
	}
	if rawSites, ok := obj["sites"]; ok {
		ids, err := parseUUIDArray(rawSites)
		if err != nil {
			errs = append(errs, ValidationError{Field: field + ".sites", Code: "invalid", Message: err.Error()})
		} else {
			scope.Sites = ids
		}
	}
	if rawDevices, ok := obj["device_ids"]; ok {
		ids, err := parseUUIDArray(rawDevices)
		if err != nil {
			errs = append(errs, ValidationError{Field: field + ".device_ids", Code: "invalid", Message: err.Error()})
		} else {
			scope.DeviceIDs = ids
		}
	}
	if rawKinds, ok := obj["device_kinds"]; ok {
		var kinds []string
		if err := json.Unmarshal(rawKinds, &kinds); err != nil {
			errs = append(errs, ValidationError{Field: field + ".device_kinds", Code: "invalid", Message: "must be an array of strings"})
		} else {
			for i, k := range kinds {
				k = strings.TrimSpace(k)
				if k == "" || len(k) > 100 {
					errs = append(errs, ValidationError{Field: fmt.Sprintf("%s.device_kinds[%d]", field, i), Code: "invalid", Message: "kind must be 1..100 characters"})
				}
			}
			scope.DeviceKinds = kinds
		}
	}
	if len(errs) > 0 {
		return TargetScope{}, errs
	}
	return scope, nil
}

// ParseSilenceMatchJSON parses the silences.match JSON. Fields:
//
//	alert_id    uuid  — matches exactly one alert
//	fingerprint text  — matches the alert dedup fingerprint (64 hex)
//	scope       obj   — {sites, device_ids, device_kinds}
//
// Multiple matchers are combined with AND (all present matchers must match);
// at least one matcher is required. A bare scope is treated as a scope
// matcher; top-level sites/device_ids/device_kinds are also accepted as a
// convenience alias for scope.
func ParseSilenceMatchJSON(raw []byte) (SilenceMatch, ValidationErrors) {
	if len(raw) == 0 {
		return SilenceMatch{}, ValidationErrors{{Field: "match", Code: "required", Message: "match is required"}}
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return SilenceMatch{}, ValidationErrors{{Field: "match", Code: "invalid", Message: "must be a JSON object"}}
	}
	var (
		errs  ValidationErrors
		match SilenceMatch
	)
	for key := range obj {
		switch key {
		case "alert_id", "fingerprint", "scope", "sites", "device_ids", "device_kinds":
		default:
			errs = append(errs, ValidationError{Field: "match." + key, Code: "unknown", Message: "unknown match field"})
		}
	}
	if rawID, ok := obj["alert_id"]; ok {
		var idStr string
		if err := json.Unmarshal(rawID, &idStr); err != nil {
			errs = append(errs, ValidationError{Field: "match.alert_id", Code: "invalid", Message: "must be a UUID string"})
		} else if id, err := uuid.Parse(idStr); err != nil {
			errs = append(errs, ValidationError{Field: "match.alert_id", Code: "invalid", Message: "must be a UUID"})
		} else {
			match.AlertID = &id
		}
	}
	if rawFP, ok := obj["fingerprint"]; ok {
		var fp string
		if err := json.Unmarshal(rawFP, &fp); err != nil {
			errs = append(errs, ValidationError{Field: "match.fingerprint", Code: "invalid", Message: "must be a string"})
		} else {
			fp = strings.TrimSpace(fp)
			switch {
			case fp == "":
				errs = append(errs, ValidationError{Field: "match.fingerprint", Code: "required", Message: "fingerprint must not be empty"})
			case len(fp) != MaxFingerprintLen:
				errs = append(errs, ValidationError{Field: "match.fingerprint", Code: "invalid", Message: "fingerprint must be 64 hex characters"})
			case !isHex(fp):
				errs = append(errs, ValidationError{Field: "match.fingerprint", Code: "invalid", Message: "fingerprint must be 64 hex characters"})
			default:
				match.Fingerprint = fp
			}
		}
	}
	// scope may be nested under "scope" or supplied inline.
	if rawScope, ok := obj["scope"]; ok {
		scope, serrs := ParseTargetScopeJSON("match.scope", rawScope)
		if len(serrs) > 0 {
			errs = append(errs, serrs...)
		} else {
			match.Scope = scope
		}
	}
	inline := map[string]json.RawMessage{}
	for _, key := range []string{"sites", "device_ids", "device_kinds"} {
		if rawVal, ok := obj[key]; ok {
			inline[key] = rawVal
		}
	}
	if _, hasScope := obj["scope"]; hasScope && len(inline) > 0 {
		errs = append(errs, ValidationError{Field: "match", Code: "conflict", Message: "scope and top-level scope fields cannot be combined"})
	} else if len(inline) > 0 {
		inlineJSON, _ := json.Marshal(inline)
		scope, serrs := ParseTargetScopeJSON("match", inlineJSON)
		if len(serrs) > 0 {
			errs = append(errs, serrs...)
		} else {
			match.Scope = scope
		}
	}
	if len(errs) > 0 {
		return SilenceMatch{}, errs
	}
	if !match.Any() {
		return SilenceMatch{}, ValidationErrors{{Field: "match", Code: "required", Message: "at least one of alert_id, fingerprint or scope is required"}}
	}
	return match, nil
}

func (m SilenceMatch) canonicalJSON() []byte {
	obj := map[string]any{}
	if m.AlertID != nil {
		obj["alert_id"] = m.AlertID.String()
	}
	if m.Fingerprint != "" {
		obj["fingerprint"] = m.Fingerprint
	}
	if !m.Scope.IsEmpty() {
		var scope map[string]any
		_ = json.Unmarshal(m.Scope.canonicalJSON(), &scope)
		obj["scope"] = scope
	}
	return mustMarshal(obj)
}

// Matches reports whether the silence covers one alert: every present matcher
// must match (AND). fingerprint is the target alert's dedup fingerprint.
func (m SilenceMatch) Matches(alertID *uuid.UUID, fingerprint string, siteID, deviceID uuid.UUID, deviceKind string) bool {
	if m.AlertID != nil {
		if alertID == nil || *m.AlertID != *alertID {
			return false
		}
	}
	if m.Fingerprint != "" && !strings.EqualFold(m.Fingerprint, fingerprint) {
		return false
	}
	if !m.Scope.IsEmpty() && !m.Scope.Matches(siteID, deviceID, deviceKind) {
		return false
	}
	return true
}

func isHex(s string) bool {
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// suppressionPlan is the effective suppression for one target at one instant.
type suppressionPlan struct {
	Reason string // '' | maintenance | silence
	Ref    *uuid.UUID
}

func (p suppressionPlan) active() bool { return p.Reason != "" }

// activeSuppression resolves the effective suppression at `now`: silences take
// precedence over maintenance windows (the more specific operator action),
// and within one kind the oldest object wins deterministically.
func (e *Evaluator) activeSuppression(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, tg target, alertID *uuid.UUID, fingerprint string, now time.Time) (suppressionPlan, error) {
	// Silences.
	rows, err := tx.Query(ctx, `
		SELECT id, match FROM silences
		WHERE org_id = $1 AND starts_at <= $2 AND ends_at > $2
		ORDER BY starts_at, created_at, id`, orgID, now)
	if err != nil {
		return suppressionPlan{}, err
	}
	for rows.Next() {
		var (
			id  uuid.UUID
			raw []byte
		)
		if err := rows.Scan(&id, &raw); err != nil {
			rows.Close()
			return suppressionPlan{}, err
		}
		match, verrs := ParseSilenceMatchJSON(raw)
		if len(verrs) > 0 {
			continue // stored match cannot fail validation; skip defensively
		}
		if match.Matches(alertID, fingerprint, tg.SiteID, tg.DeviceID, tg.DeviceKind) {
			rows.Close()
			ref := id
			return suppressionPlan{Reason: SuppressionSilence, Ref: &ref}, nil
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return suppressionPlan{}, err
	}
	rows.Close()

	// Maintenance windows: enabled and [starts_at, ends_at) containing now.
	rows, err = tx.Query(ctx, `
		SELECT id, scope FROM maintenance_windows
		WHERE org_id = $1 AND enabled AND starts_at <= $2 AND ends_at > $2
		ORDER BY starts_at, created_at, id`, orgID, now)
	if err != nil {
		return suppressionPlan{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id  uuid.UUID
			raw []byte
		)
		if err := rows.Scan(&id, &raw); err != nil {
			return suppressionPlan{}, err
		}
		scope, verrs := ParseTargetScopeJSON("scope", raw)
		if len(verrs) > 0 {
			continue
		}
		if scope.Matches(tg.SiteID, tg.DeviceID, tg.DeviceKind) {
			ref := id
			return suppressionPlan{Reason: SuppressionMaintenance, Ref: &ref}, nil
		}
	}
	return suppressionPlan{}, rows.Err()
}

// hasActivationEvent reports whether the alert ever activated (i.e. ever
// became visible as firing). Suppression-created alerts never do until a
// window/silence clears; a resolution of such an alert must not notify.
func hasActivationEvent(ctx context.Context, tx pgx.Tx, alertID uuid.UUID) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM alert_events
			WHERE alert_id = $1 AND kind IN ('activated', 'reactivated', 'reopened')
		)`, alertID).Scan(&exists)
	return exists, err
}

// ---------------------------------------------------------------------------
// Maintenance window service methods
// ---------------------------------------------------------------------------

const windowColumns = `id, org_id, name, scope, enabled, starts_at, ends_at, created_by, created_at, updated_at`

func scanWindow(row pgx.Row) (MaintenanceWindow, error) {
	var (
		w         MaintenanceWindow
		scopeJSON []byte
		createdBy *uuid.UUID
		createdAt time.Time
		updatedAt time.Time
	)
	err := row.Scan(&w.ID, &w.OrgID, &w.Name, &scopeJSON, &w.Enabled, &w.StartsAt, &w.EndsAt, &createdBy, &createdAt, &updatedAt)
	if err != nil {
		return MaintenanceWindow{}, err
	}
	scope, verrs := ParseTargetScopeJSON("scope", scopeJSON)
	if len(verrs) > 0 {
		return MaintenanceWindow{}, fmt.Errorf("alerts: stored window scope invalid: %w", verrs)
	}
	w.Scope, w.ScopeJSON = scope, scopeJSON
	w.CreatedBy, w.CreatedAt, w.UpdatedAt = createdBy, createdAt, updatedAt
	return w, nil
}

// validateWindowInput normalizes and validates a window create/patch body.
func validateWindowInput(name string, startsAt, endsAt time.Time) ValidationErrors {
	var errs ValidationErrors
	name = strings.TrimSpace(name)
	if name == "" {
		errs = append(errs, ValidationError{Field: "name", Code: "required", Message: "name is required"})
	} else if len(name) > MaxNameLen {
		errs = append(errs, ValidationError{Field: "name", Code: "too_long", Message: "name must be at most 200 characters"})
	}
	if startsAt.IsZero() {
		errs = append(errs, ValidationError{Field: "starts_at", Code: "required", Message: "starts_at is required"})
	}
	if endsAt.IsZero() {
		errs = append(errs, ValidationError{Field: "ends_at", Code: "required", Message: "ends_at is required"})
	}
	if !startsAt.IsZero() && !endsAt.IsZero() {
		if !endsAt.After(startsAt) {
			errs = append(errs, ValidationError{Field: "ends_at", Code: "range", Message: "ends_at must be after starts_at"})
		} else if endsAt.Sub(startsAt) > MaxMaintenanceWindow {
			errs = append(errs, ValidationError{Field: "ends_at", Code: "range", Message: "window duration must be at most 365 days"})
		}
	}
	return errs
}

// validateWindowScope enforces the P2-D5 scope-binding rule: a restricted
// caller may only create windows whose targets are inside its bindings;
// org-wide/kind-only scopes require org-wide scope. Referenced sites/devices
// must exist in the tenant.
func (s *Service) validateWindowScope(ctx context.Context, tx pgx.Tx, scope TargetScope, sc authz.Scope) error {
	return s.requireTargetScopeInScope(ctx, tx, scope, sc, "scope")
}

// requireTargetScopeInScope is the shared target-scope enforcement for windows
// and silences (mirrors requireSelectorInScope for rules).
func (s *Service) requireTargetScopeInScope(ctx context.Context, tx pgx.Tx, scope TargetScope, sc authz.Scope, field string) error {
	if !sc.Unrestricted {
		if len(scope.Sites) == 0 && len(scope.DeviceIDs) == 0 {
			return ErrScopeRequired
		}
		for _, siteID := range scope.Sites {
			if !sc.AllowsSite(siteID) {
				return ErrScopeForbidden
			}
		}
	}
	if len(scope.Sites) > 0 {
		var found int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM sites WHERE id = ANY($1::uuid[])`, scope.Sites).Scan(&found); err != nil {
			return err
		}
		if found != len(scope.Sites) {
			return ValidationErrors{{Field: field + ".sites", Code: "not_found", Message: "one or more sites do not exist in this organization"}}
		}
	}
	if len(scope.DeviceIDs) > 0 {
		rows, err := tx.Query(ctx, `SELECT id, site_id FROM devices WHERE id = ANY($1::uuid[])`, scope.DeviceIDs)
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
		if len(found) != len(scope.DeviceIDs) {
			return ValidationErrors{{Field: field + ".device_ids", Code: "not_found", Message: "one or more devices do not exist in this organization"}}
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

// CreateWindow validates and inserts a maintenance window.
func (s *Service) CreateWindow(ctx context.Context, orgID uuid.UUID, actor Actor, in WindowCreateInput, sc authz.Scope) (MaintenanceWindow, error) {
	scope, verrs := ParseTargetScopeJSON("scope", in.ScopeJSON)
	if len(verrs) > 0 {
		return MaintenanceWindow{}, verrs
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	if errs := validateWindowInput(in.Name, in.StartsAt, in.EndsAt); len(errs) > 0 {
		return MaintenanceWindow{}, errs
	}
	var out MaintenanceWindow
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.validateWindowScope(ctx, tx, scope, sc); err != nil {
			return err
		}
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		row := tx.QueryRow(ctx, `
			INSERT INTO maintenance_windows AS m
				(id, org_id, name, scope, enabled, starts_at, ends_at, created_by)
			VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8)
			RETURNING `+windowColumns,
			id, orgID, strings.TrimSpace(in.Name), scope.canonicalJSON(), enabled, in.StartsAt.UTC(), in.EndsAt.UTC(), actorRef(actor))
		out, err = scanWindow(row)
		return err
	})
	if err != nil {
		return MaintenanceWindow{}, err
	}
	return out, nil
}

// UpdateWindow applies a partial patch (omitted fields keep their value).
func (s *Service) UpdateWindow(ctx context.Context, orgID, windowID uuid.UUID, _ Actor, patch WindowPatchInput, sc authz.Scope) (MaintenanceWindow, error) {
	var out MaintenanceWindow
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+windowColumns+` FROM maintenance_windows WHERE id = $1 FOR UPDATE`, windowID)
		current, err := scanWindow(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrWindowNotFound
		}
		if err != nil {
			return err
		}
		visible, err := s.windowVisible(ctx, tx, current, sc)
		if err != nil {
			return err
		}
		if !visible {
			return ErrWindowNotFound
		}
		name := current.Name
		if patch.Name != nil {
			name = *patch.Name
		}
		scope := current.Scope
		if len(patch.ScopeJSON) > 0 {
			parsed, verrs := ParseTargetScopeJSON("scope", patch.ScopeJSON)
			if len(verrs) > 0 {
				return verrs
			}
			scope = parsed
		}
		enabled := current.Enabled
		if patch.Enabled != nil {
			enabled = *patch.Enabled
		}
		startsAt, endsAt := current.StartsAt, current.EndsAt
		if patch.StartsAt != nil {
			startsAt = patch.StartsAt.UTC()
		}
		if patch.EndsAt != nil {
			endsAt = patch.EndsAt.UTC()
		}
		if errs := validateWindowInput(name, startsAt, endsAt); len(errs) > 0 {
			return errs
		}
		if err := s.validateWindowScope(ctx, tx, scope, sc); err != nil {
			return err
		}
		row = tx.QueryRow(ctx, `
			UPDATE maintenance_windows AS m
			SET name = $2, scope = $3::jsonb, enabled = $4, starts_at = $5, ends_at = $6,
			    updated_at = now()
			WHERE id = $1
			RETURNING `+windowColumns,
			windowID, strings.TrimSpace(name), scope.canonicalJSON(), enabled, startsAt, endsAt)
		out, err = scanWindow(row)
		return err
	})
	if err != nil {
		return MaintenanceWindow{}, err
	}
	return out, nil
}

// GetWindow returns one window when it is visible to the caller's scope.
func (s *Service) GetWindow(ctx context.Context, orgID, windowID uuid.UUID, sc authz.Scope) (MaintenanceWindow, error) {
	var out MaintenanceWindow
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		w, err := scanWindow(tx.QueryRow(ctx, `SELECT `+windowColumns+` FROM maintenance_windows WHERE id = $1`, windowID))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrWindowNotFound
		}
		if err != nil {
			return err
		}
		visible, err := s.windowVisible(ctx, tx, w, sc)
		if err != nil {
			return err
		}
		if !visible {
			return ErrWindowNotFound
		}
		out = w
		return nil
	})
	if err != nil {
		return MaintenanceWindow{}, err
	}
	return out, nil
}

// ListWindows returns one cursor page of windows (newest id first),
// scope-filtered: a restricted caller sees only windows whose targets
// intersect its bindings.
func (s *Service) ListWindows(ctx context.Context, orgID uuid.UUID, sc authz.Scope, limit int, cursor string) (WindowPage, error) {
	if limit <= 0 || limit > MaxWindowPageSize {
		limit = 25
	}
	var after *uuid.UUID
	if cursor != "" {
		id, err := uuid.Parse(cursor)
		if err != nil {
			return WindowPage{}, ErrInvalidCursor
		}
		after = &id
	}
	var page WindowPage
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT `+windowColumns+`
			FROM maintenance_windows m
			WHERE ($1::uuid IS NULL OR id < $1)
			  AND ($2::boolean
			       OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(coalesce(scope->'sites', '[]'::jsonb)) s
			                  WHERE s::uuid = ANY($3::uuid[]))
			       OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(coalesce(scope->'device_ids', '[]'::jsonb)) di
			                  JOIN devices d ON d.id = di::uuid AND d.org_id = m.org_id
			                  WHERE d.site_id = ANY($3::uuid[])))
			ORDER BY id DESC
			LIMIT $4`,
			after, sc.Unrestricted, sc.Sites, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			w, err := scanWindow(rows)
			if err != nil {
				return err
			}
			page.Windows = append(page.Windows, w)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(page.Windows) > limit {
			page.NextCursor = page.Windows[limit-1].ID.String()
			page.HasMore = true
			page.Windows = page.Windows[:limit]
		}
		return nil
	})
	if err != nil {
		return WindowPage{}, err
	}
	return page, nil
}

// DeleteWindow removes a window (hard delete; the suppression audit lives on
// the affected alerts). Out-of-scope is a deterministic 404.
func (s *Service) DeleteWindow(ctx context.Context, orgID, windowID uuid.UUID, sc authz.Scope) error {
	return database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		w, err := scanWindow(tx.QueryRow(ctx, `SELECT `+windowColumns+` FROM maintenance_windows WHERE id = $1 FOR UPDATE`, windowID))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrWindowNotFound
		}
		if err != nil {
			return err
		}
		visible, err := s.windowVisible(ctx, tx, w, sc)
		if err != nil {
			return err
		}
		if !visible {
			return ErrWindowNotFound
		}
		_, err = tx.Exec(ctx, `DELETE FROM maintenance_windows WHERE id = $1`, windowID)
		return err
	})
}

// windowVisible reports whether a window's target scope intersects the
// caller's bindings. Org-wide windows are only visible to org-wide callers.
func (s *Service) windowVisible(ctx context.Context, tx pgx.Tx, w MaintenanceWindow, sc authz.Scope) (bool, error) {
	if sc.Unrestricted {
		return true, nil
	}
	for _, siteID := range w.Scope.Sites {
		if sc.AllowsSite(siteID) {
			return true, nil
		}
	}
	if len(w.Scope.DeviceIDs) > 0 {
		rows, err := tx.Query(ctx, `SELECT site_id FROM devices WHERE id = ANY($1::uuid[])`, w.Scope.DeviceIDs)
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

// ---------------------------------------------------------------------------
// Silence service methods
// ---------------------------------------------------------------------------

const silenceColumns = `id, org_id, match, reason, starts_at, ends_at, created_by, created_at, updated_at`

func scanSilence(row pgx.Row) (Silence, error) {
	var (
		s         Silence
		matchJSON []byte
		createdBy *uuid.UUID
		createdAt time.Time
		updatedAt time.Time
	)
	err := row.Scan(&s.ID, &s.OrgID, &matchJSON, &s.Reason, &s.StartsAt, &s.EndsAt, &createdBy, &createdAt, &updatedAt)
	if err != nil {
		return Silence{}, err
	}
	match, verrs := ParseSilenceMatchJSON(matchJSON)
	if len(verrs) > 0 {
		return Silence{}, fmt.Errorf("alerts: stored silence match invalid: %w", verrs)
	}
	s.Match, s.MatchJSON = match, matchJSON
	s.CreatedBy, s.CreatedAt, s.UpdatedAt = createdBy, createdAt, updatedAt
	return s, nil
}

// validateSilenceInput normalizes and validates a silence create body.
func validateSilenceInput(reason string, startsAt, endsAt time.Time) ValidationErrors {
	var errs ValidationErrors
	reason = strings.TrimSpace(reason)
	if reason == "" {
		errs = append(errs, ValidationError{Field: "reason", Code: "required", Message: "reason is required"})
	} else if len(reason) > MaxCommentLen {
		errs = append(errs, ValidationError{Field: "reason", Code: "too_long", Message: "reason must be at most 2000 characters"})
	}
	if startsAt.IsZero() {
		errs = append(errs, ValidationError{Field: "starts_at", Code: "required", Message: "starts_at is required"})
	}
	if endsAt.IsZero() {
		errs = append(errs, ValidationError{Field: "ends_at", Code: "required", Message: "ends_at is required"})
	}
	if !startsAt.IsZero() && !endsAt.IsZero() {
		if !endsAt.After(startsAt) {
			errs = append(errs, ValidationError{Field: "ends_at", Code: "range", Message: "ends_at must be after starts_at"})
		} else if endsAt.Sub(startsAt) > MaxSilence {
			errs = append(errs, ValidationError{Field: "ends_at", Code: "range", Message: "silence expiry must be within 30 days"})
		}
	}
	return errs
}

// validateSilenceMatchScope enforces scope bindings for a silence's matchers:
// a scope target must be inside the caller's bindings; an alert_id target must
// resolve to an in-scope alert; a fingerprint-only target is only allowed for
// org-wide callers (its resource cannot be verified server-side).
func (s *Service) validateSilenceMatchScope(ctx context.Context, tx pgx.Tx, match SilenceMatch, sc authz.Scope) error {
	if sc.Unrestricted {
		return nil
	}
	if match.Fingerprint != "" {
		return ErrScopeRequired
	}
	if match.AlertID != nil {
		var siteID uuid.UUID
		err := tx.QueryRow(ctx, `
			SELECT coalesce(d.site_id, '00000000-0000-0000-0000-000000000000'::uuid)
			FROM alerts a
			LEFT JOIN devices d ON a.resource_type = 'device' AND d.id = a.resource_id AND d.org_id = a.org_id
			WHERE a.id = $1`, *match.AlertID).Scan(&siteID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ValidationErrors{{Field: "match.alert_id", Code: "not_found", Message: "alert does not exist in this organization"}}
		}
		if err != nil {
			return err
		}
		if siteID == uuid.Nil || !sc.AllowsSite(siteID) {
			return ErrScopeForbidden
		}
	}
	if err := s.requireTargetScopeInScope(ctx, tx, match.Scope, sc, "match.scope"); err != nil {
		return err
	}
	return nil
}

// CreateSilence validates and inserts an operator silence.
func (s *Service) CreateSilence(ctx context.Context, orgID uuid.UUID, actor Actor, in SilenceCreateInput, sc authz.Scope) (Silence, error) {
	match, verrs := ParseSilenceMatchJSON(in.MatchJSON)
	if len(verrs) > 0 {
		return Silence{}, verrs
	}
	if errs := validateSilenceInput(in.Reason, in.StartsAt, in.EndsAt); len(errs) > 0 {
		return Silence{}, errs
	}
	var out Silence
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.validateSilenceMatchScope(ctx, tx, match, sc); err != nil {
			return err
		}
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		row := tx.QueryRow(ctx, `
			INSERT INTO silences AS s
				(id, org_id, match, reason, starts_at, ends_at, created_by)
			VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7)
			RETURNING `+silenceColumns,
			id, orgID, match.canonicalJSON(), strings.TrimSpace(in.Reason), in.StartsAt.UTC(), in.EndsAt.UTC(), actorRef(actor))
		out, err = scanSilence(row)
		return err
	})
	if err != nil {
		return Silence{}, err
	}
	return out, nil
}

// ListSilences returns one cursor page of silences (newest id first),
// scope-filtered. alert_id silences are visible when the alert is in scope;
// fingerprint-only silences are only visible to org-wide callers.
func (s *Service) ListSilences(ctx context.Context, orgID uuid.UUID, sc authz.Scope, limit int, cursor string) (SilencePage, error) {
	if limit <= 0 || limit > MaxSilencePageSize {
		limit = 25
	}
	var after *uuid.UUID
	if cursor != "" {
		id, err := uuid.Parse(cursor)
		if err != nil {
			return SilencePage{}, ErrInvalidCursor
		}
		after = &id
	}
	var page SilencePage
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT `+silenceColumns+`
			FROM silences s
			WHERE ($1::uuid IS NULL OR id < $1)
			  AND ($2::boolean
			       OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(coalesce(match->'scope'->'sites', '[]'::jsonb)) sx
			                  WHERE sx::uuid = ANY($3::uuid[]))
			       OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(coalesce(match->'scope'->'device_ids', '[]'::jsonb)) di
			                  JOIN devices d ON d.id = di::uuid AND d.org_id = s.org_id
			                  WHERE d.site_id = ANY($3::uuid[]))
			       OR EXISTS (SELECT 1 FROM alerts a
			                  JOIN devices d ON a.resource_type = 'device' AND d.id = a.resource_id AND d.org_id = a.org_id
			                  WHERE a.id = nullif(match->>'alert_id', '')::uuid
			                    AND d.site_id = ANY($3::uuid[])))
			ORDER BY id DESC
			LIMIT $4`,
			after, sc.Unrestricted, sc.Sites, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			sil, err := scanSilence(rows)
			if err != nil {
				return err
			}
			page.Silences = append(page.Silences, sil)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(page.Silences) > limit {
			page.NextCursor = page.Silences[limit-1].ID.String()
			page.HasMore = true
			page.Silences = page.Silences[:limit]
		}
		return nil
	})
	if err != nil {
		return SilencePage{}, err
	}
	return page, nil
}

// DeleteSilence removes a silence (hard delete: "silences expire cleanly").
func (s *Service) DeleteSilence(ctx context.Context, orgID, silenceID uuid.UUID, sc authz.Scope) error {
	return database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		sil, err := scanSilence(tx.QueryRow(ctx, `SELECT `+silenceColumns+` FROM silences WHERE id = $1 FOR UPDATE`, silenceID))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSilenceNotFound
		}
		if err != nil {
			return err
		}
		visible, err := s.silenceVisible(ctx, tx, sil, sc)
		if err != nil {
			return err
		}
		if !visible {
			return ErrSilenceNotFound
		}
		_, err = tx.Exec(ctx, `DELETE FROM silences WHERE id = $1`, silenceID)
		return err
	})
}

// silenceVisible reports whether a silence is visible to the caller's scope.
func (s *Service) silenceVisible(ctx context.Context, tx pgx.Tx, sil Silence, sc authz.Scope) (bool, error) {
	if sc.Unrestricted {
		return true, nil
	}
	if sil.Match.Fingerprint != "" {
		return false, nil
	}
	if sil.Match.AlertID != nil {
		var siteID uuid.UUID
		err := tx.QueryRow(ctx, `
			SELECT coalesce(d.site_id, '00000000-0000-0000-0000-000000000000'::uuid)
			FROM alerts a
			LEFT JOIN devices d ON a.resource_type = 'device' AND d.id = a.resource_id AND d.org_id = a.org_id
			WHERE a.id = $1`, *sil.Match.AlertID).Scan(&siteID)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if siteID != uuid.Nil && sc.AllowsSite(siteID) {
			return true, nil
		}
	}
	for _, siteID := range sil.Match.Scope.Sites {
		if sc.AllowsSite(siteID) {
			return true, nil
		}
	}
	if len(sil.Match.Scope.DeviceIDs) > 0 {
		rows, err := tx.Query(ctx, `SELECT site_id FROM devices WHERE id = ANY($1::uuid[])`, sil.Match.Scope.DeviceIDs)
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
