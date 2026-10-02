package alerts

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/platform/authz"
	"github.com/argus-platform/argus/internal/platform/httpx"
)

// HTTP exposes the M11-S1 rules/alerts surface. Session + CSRF + capability
// are enforced by the router; scope is enforced here against server-side
// bindings (P2-D5), exactly like the inventory/check surfaces. Stream is the
// M11-S3a SSE hub (nil when the stream is not configured).
type HTTP struct {
	Svc    *Service
	Stream *StreamHub
}

type createRuleRequest struct {
	Name          string          `json:"name"`
	Type          string          `json:"type"`
	Severity      string          `json:"severity"`
	Condition     json.RawMessage `json:"condition"`
	ScopeSelector json.RawMessage `json:"scope_selector"`
}

type updateRuleRequest struct {
	Name          *string         `json:"name"`
	Type          *string         `json:"type"`
	Severity      *string         `json:"severity"`
	Condition     json.RawMessage `json:"condition"`
	ScopeSelector json.RawMessage `json:"scope_selector"`
	Enabled       *bool           `json:"enabled"`
}

type snoozeRequest struct {
	Until           string `json:"until"`
	DurationSeconds *int   `json:"duration_seconds"`
	Reason          string `json:"reason"`
}

type resolveRequest struct {
	Reason string `json:"reason"`
}

type commentRequest struct {
	Comment string `json:"comment"`
}

// principalOrg extracts the authenticated principal (the router already
// enforced the session; this is a defensive guard).
func (h *HTTP) principalOrg(w http.ResponseWriter, r *http.Request) (httpx.Principal, bool) {
	p, ok := httpx.PrincipalFrom(r.Context())
	if !ok {
		httpx.WriteProblem(w, r, http.StatusUnauthorized, "auth.unauthenticated", "authentication required")
		return httpx.Principal{}, false
	}
	return p, true
}

// scopeFor resolves the caller's scope bindings (fail closed).
func (h *HTTP) scopeFor(w http.ResponseWriter, r *http.Request, p httpx.Principal) (authz.Scope, bool) {
	sc, err := h.Svc.ScopeFor(r.Context(), p.OrgID, p.UserID)
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "authorization scope lookup failed")
		return authz.Scope{}, false
	}
	return sc, true
}

// writeRuleError maps the service errors to deterministic problem+json.
func writeRuleError(w http.ResponseWriter, r *http.Request, err error) {
	var verrs ValidationErrors
	switch {
	case errors.As(err, &verrs):
		writeValidation(w, r, verrs)
	case errors.Is(err, ErrRuleNotFound):
		httpx.WriteProblem(w, r, http.StatusNotFound, "alert_rule.not_found", "alert rule not found")
	case errors.Is(err, ErrScopeRequired):
		httpx.WriteProblem(w, r, http.StatusForbidden, "auth.forbidden", "org-wide rules require org-wide scope")
	case errors.Is(err, ErrScopeForbidden):
		httpx.WriteProblem(w, r, http.StatusForbidden, "auth.forbidden", "rule target is outside the caller's scope")
	case errors.Is(err, ErrVersionConflict):
		httpx.WriteProblem(w, r, http.StatusConflict, "alert_rule.version_conflict", "the rule was edited concurrently; reload and retry")
	default:
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "alert rule operation failed")
	}
}

func writeAlertError(w http.ResponseWriter, r *http.Request, err error) {
	var verrs ValidationErrors
	switch {
	case errors.As(err, &verrs):
		writeValidation(w, r, verrs)
	case errors.Is(err, ErrAlertNotFound):
		httpx.WriteProblem(w, r, http.StatusNotFound, "alert.not_found", "alert not found")
	case errors.Is(err, ErrStateConflict):
		httpx.WriteProblem(w, r, http.StatusConflict, "alert.state_conflict", "operation is not allowed in the alert's current state")
	case errors.Is(err, ErrInvalidCursor):
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid cursor")
	default:
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "alert operation failed")
	}
}

func writeValidation(w http.ResponseWriter, r *http.Request, errs ValidationErrors) {
	fields := make([]httpx.FieldError, 0, len(errs))
	for _, e := range errs {
		fields = append(fields, httpx.FieldError{Field: e.Field, Code: e.Code, Message: e.Message})
	}
	httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "validation failed", fields...)
}

// decodeBody decodes a strict JSON body (unknown fields rejected).
func decodeBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "request body must be a JSON object with known fields")
		return false
	}
	return true
}

// CreateRule handles POST /v1/alert-rules (alertrule.write; scope here).
func (h *HTTP) CreateRule(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	var req createRuleRequest
	if !decodeBody(w, r, &req) {
		return
	}
	rule, err := h.Svc.CreateRule(r.Context(), p.OrgID, Actor{UserID: p.UserID}, RuleCreateInput{
		Name: req.Name, Type: req.Type, Severity: req.Severity,
		ConditionJSON: req.Condition, SelectorJSON: req.ScopeSelector,
	}, sc)
	if err != nil {
		writeRuleError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, rulePayload(rule))
}

// ListRules handles GET /v1/alert-rules (alertrule.read).
func (h *HTTP) ListRules(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	limit, ok := parseLimit(w, r, MaxRulePageSize)
	if !ok {
		return
	}
	page, err := h.Svc.ListRules(r.Context(), p.OrgID, sc, limit, r.URL.Query().Get("cursor"))
	if err != nil {
		writeRuleError(w, r, err)
		return
	}
	data := make([]map[string]any, 0, len(page.Rules))
	for _, rule := range page.Rules {
		data = append(data, rulePayload(rule))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"data":        data,
		"next_cursor": cursorOrNil(page.NextCursor),
		"has_more":    page.HasMore,
	})
}

// GetRule handles GET /v1/alert-rules/{id} (alertrule.read), optionally
// pinned to ?version=N.
func (h *HTTP) GetRule(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	ruleID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "alert_rule.not_found", "alert rule not found")
		return
	}
	var version *int
	if raw := r.URL.Query().Get("version"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "version must be a positive integer")
			return
		}
		version = &n
	}
	rule, err := h.Svc.GetRule(r.Context(), p.OrgID, ruleID, version, sc)
	if err != nil {
		writeRuleError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, rulePayload(rule))
}

// UpdateRule handles PATCH /v1/alert-rules/{id}: omitted fields keep the
// current value; a new immutable version is written (alertrule.write).
func (h *HTTP) UpdateRule(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	ruleID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "alert_rule.not_found", "alert rule not found")
		return
	}
	var req updateRuleRequest
	if !decodeBody(w, r, &req) {
		return
	}
	rule, err := h.Svc.UpdateRule(r.Context(), p.OrgID, ruleID, Actor{UserID: p.UserID}, RulePatchInput{
		Name: req.Name, Type: req.Type, Severity: req.Severity,
		ConditionJSON: req.Condition, SelectorJSON: req.ScopeSelector, Enabled: req.Enabled,
	}, sc)
	if err != nil {
		writeRuleError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, rulePayload(rule))
}

// DeleteRule handles DELETE /v1/alert-rules/{id}: disables the rule by writing
// a new immutable version with enabled=false (definition history preserved).
func (h *HTTP) DeleteRule(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	ruleID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "alert_rule.not_found", "alert rule not found")
		return
	}
	rule, err := h.Svc.DisableRule(r.Context(), p.OrgID, ruleID, Actor{UserID: p.UserID}, sc)
	if err != nil {
		writeRuleError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, rulePayload(rule))
}

// ValidateRule handles POST /v1/alert-rules:validate: a pure dry-run of the
// condition/selector/rule shape with no persistence.
func (h *HTTP) ValidateRule(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.principalOrg(w, r); !ok {
		return
	}
	var req createRuleRequest
	if !decodeBody(w, r, &req) {
		return
	}
	_, errs := ParseRule(req.Name, req.Type, req.Severity, req.Condition, req.ScopeSelector)
	if len(errs) > 0 {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"valid": false, "errors": fieldErrors(errs)})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"valid": true})
}

// InstallDefaults handles POST /v1/alert-rules:install-defaults: installs the
// curated P2-AC-32 pack for the org. Idempotent per rule key (already-present
// keys are skipped), so a retry never duplicates or rewrites rules.
func (h *HTTP) InstallDefaults(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	res, err := h.Svc.InstallDefaults(r.Context(), p.OrgID, Actor{UserID: p.UserID}, sc)
	if err != nil {
		writeRuleError(w, r, err)
		return
	}
	data := make([]map[string]any, 0, len(res.Rules))
	for _, rule := range res.Rules {
		data = append(data, rulePayload(rule))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"installed": res.Installed,
		"skipped":   res.Skipped,
		"data":      data,
	})
}

// ListAlerts handles GET /v1/alerts (alert.read) with state/severity/rule_id/
// device_id filters and a keyset cursor.
func (h *HTTP) ListAlerts(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	query := r.URL.Query()
	limit, ok := parseLimit(w, r, MaxAlertPageSize)
	if !ok {
		return
	}
	var filter AlertFilter
	if raw := query.Get("filter[state]"); raw != "" {
		switch raw {
		case StatePending, StateActive, StateAcknowledged, StateSnoozed, StateSuppressed, StateResolved:
			filter.State = &raw
		default:
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid state filter",
				httpx.FieldError{Field: "filter[state]", Code: "invalid", Message: "allowed: pending, active, acknowledged, snoozed, suppressed, resolved"})
			return
		}
	}
	if raw := query.Get("filter[severity]"); raw != "" {
		if !ValidSeverity(raw) {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid severity filter",
				httpx.FieldError{Field: "filter[severity]", Code: "invalid", Message: "allowed: info, warning, critical"})
			return
		}
		filter.Severity = &raw
	}
	if raw := query.Get("filter[rule_id]"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid rule_id filter",
				httpx.FieldError{Field: "filter[rule_id]", Code: "invalid", Message: "must be a UUID"})
			return
		}
		filter.RuleID = &id
	}
	if raw := query.Get("filter[device_id]"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid device_id filter",
				httpx.FieldError{Field: "filter[device_id]", Code: "invalid", Message: "must be a UUID"})
			return
		}
		if !sc.Unrestricted {
			// Deterministic 403 for out-of-scope explicit device filters
			// (mirrors the M7 device-list / M10 checks rule).
			siteID, err := h.Svc.ResolveDeviceSite(r.Context(), p.OrgID, id)
			if err != nil {
				httpx.WriteProblem(w, r, http.StatusForbidden, "auth.forbidden", "device filter is outside the caller's scope")
				return
			}
			if !sc.AllowsSite(siteID) {
				httpx.WriteProblem(w, r, http.StatusForbidden, "auth.forbidden", "device filter is outside the caller's scope")
				return
			}
		}
		filter.DeviceID = &id
	}
	page, err := h.Svc.ListAlerts(r.Context(), p.OrgID, filter, sc, limit, query.Get("cursor"))
	if err != nil {
		writeAlertError(w, r, err)
		return
	}
	data := make([]map[string]any, 0, len(page.Alerts))
	for _, a := range page.Alerts {
		data = append(data, alertPayload(a))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"data":        data,
		"next_cursor": cursorOrNil(page.NextCursor),
		"has_more":    page.HasMore,
	})
}

// GetAlert handles GET /v1/alerts/{id}: detail plus the recent timeline.
func (h *HTTP) GetAlert(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	alertID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "alert.not_found", "alert not found")
		return
	}
	alert, events, err := h.Svc.GetAlert(r.Context(), p.OrgID, alertID, sc)
	if err != nil {
		writeAlertError(w, r, err)
		return
	}
	payload := alertPayload(alert)
	payload["events"] = eventPayloads(events)
	httpx.WriteJSON(w, http.StatusOK, payload)
}

// AckAlert handles POST /v1/alerts/{id}/ack (alert.ack).
func (h *HTTP) AckAlert(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	alertID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "alert.not_found", "alert not found")
		return
	}
	alert, err := h.Svc.AckAlert(r.Context(), p.OrgID, alertID, Actor{UserID: p.UserID}, sc)
	if err != nil {
		writeAlertError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, alertPayload(alert))
}

// SnoozeAlert handles POST /v1/alerts/{id}/snooze (alert.snooze). Exactly one
// of until/duration_seconds is required, bounded to 30 days.
func (h *HTTP) SnoozeAlert(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	alertID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "alert.not_found", "alert not found")
		return
	}
	var req snoozeRequest
	if !decodeBody(w, r, &req) {
		return
	}
	now := h.Svc.Now().UTC()
	var until time.Time
	switch {
	case req.Until != "" && req.DurationSeconds != nil:
		writeValidation(w, r, ValidationErrors{{Field: "until", Code: "conflict", Message: "provide either until or duration_seconds, not both"}})
		return
	case req.Until != "":
		parsed, err := time.Parse(time.RFC3339, req.Until)
		if err != nil {
			writeValidation(w, r, ValidationErrors{{Field: "until", Code: "invalid", Message: "must be RFC 3339"}})
			return
		}
		until = parsed
	case req.DurationSeconds != nil:
		secs := *req.DurationSeconds
		if secs < 1 || secs > int(MaxSnooze.Seconds()) {
			writeValidation(w, r, ValidationErrors{{Field: "duration_seconds", Code: "range", Message: "must be between 1 and 2592000 (30 days)"}})
			return
		}
		until = now.Add(time.Duration(secs) * time.Second)
	default:
		writeValidation(w, r, ValidationErrors{{Field: "until", Code: "required", Message: "provide until or duration_seconds"}})
		return
	}
	alert, err := h.Svc.SnoozeAlert(r.Context(), p.OrgID, alertID, Actor{UserID: p.UserID}, until, strings.TrimSpace(req.Reason), sc)
	if err != nil {
		writeAlertError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, alertPayload(alert))
}

// ResolveAlert handles POST /v1/alerts/{id}/resolve (alert.ack; canonical
// manual resolve requires a reason).
func (h *HTTP) ResolveAlert(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	alertID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "alert.not_found", "alert not found")
		return
	}
	var req resolveRequest
	if !decodeBody(w, r, &req) {
		return
	}
	alert, err := h.Svc.ResolveAlert(r.Context(), p.OrgID, alertID, Actor{UserID: p.UserID}, req.Reason, sc)
	if err != nil {
		writeAlertError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, alertPayload(alert))
}

// CommentAlert handles POST /v1/alerts/{id}/comment (alert.ack; the canonical
// catalog has no alert.comment capability, so commenting audits under the
// acknowledgment capability).
func (h *HTTP) CommentAlert(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	alertID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "alert.not_found", "alert not found")
		return
	}
	var req commentRequest
	if !decodeBody(w, r, &req) {
		return
	}
	alert, err := h.Svc.CommentAlert(r.Context(), p.OrgID, alertID, Actor{UserID: p.UserID}, req.Comment, sc)
	if err != nil {
		writeAlertError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, alertPayload(alert))
}

// parseLimit parses ?limit with the collection's maximum.
func parseLimit(w http.ResponseWriter, r *http.Request, maxLimit int) (int, bool) {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return 25, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > maxLimit {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed",
			"limit must be an integer between 1 and "+strconv.Itoa(maxLimit))
		return 0, false
	}
	return n, true
}

func cursorOrNil(cursor string) any {
	if cursor == "" {
		return nil
	}
	return cursor
}

func rulePayload(r Rule) map[string]any {
	payload := map[string]any{
		"rule_id":        r.RuleID.String(),
		"version":        r.Version,
		"name":           r.Name,
		"type":           r.Type,
		"severity":       r.Severity,
		"scope_selector": json.RawMessage(r.SelectorJSON),
		"condition":      json.RawMessage(r.ConditionJSON),
		"enabled":        r.Enabled,
		"created_by":     nil,
		"created_at":     r.CreatedAt.UTC().Format(time.RFC3339),
	}
	if r.CreatedBy != nil {
		payload["created_by"] = r.CreatedBy.String()
	}
	return payload
}

func alertPayload(a Alert) map[string]any {
	payload := map[string]any{
		"id":                 a.ID.String(),
		"rule_id":            a.RuleID.String(),
		"rule_version":       a.RuleVersion,
		"fingerprint":        a.Fingerprint,
		"resource_type":      a.ResourceType,
		"resource_id":        a.ResourceID.String(),
		"dimension_subset":   json.RawMessage(a.DimensionSubset),
		"state":              a.State,
		"severity":           a.Severity,
		"value":              json.RawMessage(a.Value),
		"started_at":         a.StartedAt.UTC().Format(time.RFC3339),
		"last_evaluated_at":  a.LastEvaluatedAt.UTC().Format(time.RFC3339),
		"resolved_at":        nil,
		"ack_by":             nil,
		"ack_at":             nil,
		"snooze_until":       nil,
		"suppression_reason": a.SuppressionReason,
		"suppression_ref":    nil,
		"created_at":         a.CreatedAt.UTC().Format(time.RFC3339),
	}
	if a.SuppressionRef != nil {
		payload["suppression_ref"] = a.SuppressionRef.String()
	}
	if a.ResolvedAt != nil {
		payload["resolved_at"] = a.ResolvedAt.UTC().Format(time.RFC3339)
	}
	if a.AckBy != nil {
		payload["ack_by"] = a.AckBy.String()
	}
	if a.AckAt != nil {
		payload["ack_at"] = a.AckAt.UTC().Format(time.RFC3339)
	}
	if a.SnoozeUntil != nil {
		payload["snooze_until"] = a.SnoozeUntil.UTC().Format(time.RFC3339)
	}
	if a.SiteID != uuid.Nil {
		payload["site_id"] = a.SiteID.String()
	}
	return payload
}

func eventPayloads(events []AlertEvent) []map[string]any {
	out := make([]map[string]any, 0, len(events))
	for _, e := range events {
		p := map[string]any{
			"id":       e.ID.String(),
			"alert_id": e.AlertID.String(),
			"kind":     e.Kind,
			"actor_id": nil,
			"data":     json.RawMessage(e.Data),
			"ts":       e.Ts.UTC().Format(time.RFC3339),
		}
		if e.ActorID != nil {
			p["actor_id"] = e.ActorID.String()
		}
		out = append(out, p)
	}
	return out
}

func fieldErrors(errs ValidationErrors) []map[string]string {
	out := make([]map[string]string, 0, len(errs))
	for _, e := range errs {
		out = append(out, map[string]string{"field": e.Field, "code": e.Code, "message": e.Message})
	}
	return out
}
