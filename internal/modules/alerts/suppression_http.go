package alerts

// M11-S3a suppression + stream HTTP surface. Canonical capability for both
// /v1/silences and /v1/maintenance-windows is `alert.silence` (docs/12 §22.9);
// the routes are org-scoped with the same server-side binding enforcement as
// alert rules (a restricted caller may only target in-scope resources).
// GET /v1/streams/events is a collection read under `alert.read` with site
// scope (docs/12 §22.16).

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/platform/httpx"
)

type windowCreateRequest struct {
	Name     string          `json:"name"`
	Scope    json.RawMessage `json:"scope"`
	Enabled  *bool           `json:"enabled"`
	StartsAt string          `json:"starts_at"`
	EndsAt   string          `json:"ends_at"`
}

type windowUpdateRequest struct {
	Name     *string         `json:"name"`
	Scope    json.RawMessage `json:"scope"`
	Enabled  *bool           `json:"enabled"`
	StartsAt *string         `json:"starts_at"`
	EndsAt   *string         `json:"ends_at"`
}

type silenceCreateRequest struct {
	Match           json.RawMessage `json:"match"`
	Reason          string          `json:"reason"`
	StartsAt        string          `json:"starts_at"`
	EndsAt          string          `json:"ends_at"`
	DurationSeconds *int            `json:"duration_seconds"`
}

// writeSuppressionError maps suppression-object errors to deterministic
// problem+json (out-of-scope item access is a 404, enumeration resistance).
func writeSuppressionError(w http.ResponseWriter, r *http.Request, err error) {
	var verrs ValidationErrors
	switch {
	case errors.As(err, &verrs):
		writeValidation(w, r, verrs)
	case errors.Is(err, ErrWindowNotFound):
		httpx.WriteProblem(w, r, http.StatusNotFound, "maintenance_window.not_found", "maintenance window not found")
	case errors.Is(err, ErrSilenceNotFound):
		httpx.WriteProblem(w, r, http.StatusNotFound, "alert_silence.not_found", "silence not found")
	case errors.Is(err, ErrScopeRequired):
		httpx.WriteProblem(w, r, http.StatusForbidden, "auth.forbidden", "org-wide scopes require org-wide scope")
	case errors.Is(err, ErrScopeForbidden):
		httpx.WriteProblem(w, r, http.StatusForbidden, "auth.forbidden", "suppression target is outside the caller's scope")
	case errors.Is(err, ErrInvalidCursor):
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid cursor")
	default:
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "suppression operation failed")
	}
}

// parseRFC3339 parses one required timestamp field.
func parseRFC3339(w http.ResponseWriter, r *http.Request, field, value string) (time.Time, bool) {
	ts, err := time.Parse(time.RFC3339, value)
	if err != nil {
		writeValidation(w, r, ValidationErrors{{Field: field, Code: "invalid", Message: "must be RFC 3339"}})
		return time.Time{}, false
	}
	return ts.UTC(), true
}

// CreateWindow handles POST /v1/maintenance-windows (alert.silence).
func (h *HTTP) CreateWindow(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	var req windowCreateRequest
	if !decodeBody(w, r, &req) {
		return
	}
	startsAt, ok := parseRFC3339(w, r, "starts_at", req.StartsAt)
	if !ok {
		return
	}
	endsAt, ok := parseRFC3339(w, r, "ends_at", req.EndsAt)
	if !ok {
		return
	}
	window, err := h.Svc.CreateWindow(r.Context(), p.OrgID, Actor{UserID: p.UserID}, WindowCreateInput{
		Name: req.Name, ScopeJSON: req.Scope, Enabled: req.Enabled,
		StartsAt: startsAt, EndsAt: endsAt,
	}, sc)
	if err != nil {
		writeSuppressionError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, windowPayload(window, h.Svc.Now().UTC()))
}

// ListWindows handles GET /v1/maintenance-windows (alert.silence).
func (h *HTTP) ListWindows(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	limit, ok := parseLimit(w, r, MaxWindowPageSize)
	if !ok {
		return
	}
	page, err := h.Svc.ListWindows(r.Context(), p.OrgID, sc, limit, r.URL.Query().Get("cursor"))
	if err != nil {
		writeSuppressionError(w, r, err)
		return
	}
	now := h.Svc.Now().UTC()
	data := make([]map[string]any, 0, len(page.Windows))
	for _, window := range page.Windows {
		data = append(data, windowPayload(window, now))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"data":        data,
		"next_cursor": cursorOrNil(page.NextCursor),
		"has_more":    page.HasMore,
	})
}

// GetWindow handles GET /v1/maintenance-windows/{id} (alert.silence).
func (h *HTTP) GetWindow(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	windowID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "maintenance_window.not_found", "maintenance window not found")
		return
	}
	window, err := h.Svc.GetWindow(r.Context(), p.OrgID, windowID, sc)
	if err != nil {
		writeSuppressionError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, windowPayload(window, h.Svc.Now().UTC()))
}

// UpdateWindow handles PATCH /v1/maintenance-windows/{id} (alert.silence).
func (h *HTTP) UpdateWindow(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	windowID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "maintenance_window.not_found", "maintenance window not found")
		return
	}
	var req windowUpdateRequest
	if !decodeBody(w, r, &req) {
		return
	}
	patch := WindowPatchInput{Name: req.Name, ScopeJSON: req.Scope, Enabled: req.Enabled}
	if req.StartsAt != nil {
		ts, ok := parseRFC3339(w, r, "starts_at", *req.StartsAt)
		if !ok {
			return
		}
		patch.StartsAt = &ts
	}
	if req.EndsAt != nil {
		ts, ok := parseRFC3339(w, r, "ends_at", *req.EndsAt)
		if !ok {
			return
		}
		patch.EndsAt = &ts
	}
	window, err := h.Svc.UpdateWindow(r.Context(), p.OrgID, windowID, Actor{UserID: p.UserID}, patch, sc)
	if err != nil {
		writeSuppressionError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, windowPayload(window, h.Svc.Now().UTC()))
}

// DeleteWindow handles DELETE /v1/maintenance-windows/{id} (alert.silence).
func (h *HTTP) DeleteWindow(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	windowID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "maintenance_window.not_found", "maintenance window not found")
		return
	}
	if err := h.Svc.DeleteWindow(r.Context(), p.OrgID, windowID, sc); err != nil {
		writeSuppressionError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// CreateSilence handles POST /v1/silences (alert.silence). Exactly one of
// ends_at/duration_seconds is required: the canonical expiry is mandatory and
// bounded to 30 days.
func (h *HTTP) CreateSilence(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	var req silenceCreateRequest
	if !decodeBody(w, r, &req) {
		return
	}
	now := h.Svc.Now().UTC()
	startsAt := now
	if req.StartsAt != "" {
		ts, ok := parseRFC3339(w, r, "starts_at", req.StartsAt)
		if !ok {
			return
		}
		startsAt = ts
	}
	var endsAt time.Time
	switch {
	case req.EndsAt != "" && req.DurationSeconds != nil:
		writeValidation(w, r, ValidationErrors{{Field: "ends_at", Code: "conflict", Message: "provide either ends_at or duration_seconds, not both"}})
		return
	case req.EndsAt != "":
		ts, ok := parseRFC3339(w, r, "ends_at", req.EndsAt)
		if !ok {
			return
		}
		endsAt = ts
	case req.DurationSeconds != nil:
		secs := *req.DurationSeconds
		if secs < 1 || secs > int(MaxSilence.Seconds()) {
			writeValidation(w, r, ValidationErrors{{Field: "duration_seconds", Code: "range", Message: "must be between 1 and 2592000 (30 days)"}})
			return
		}
		endsAt = startsAt.Add(time.Duration(secs) * time.Second)
	default:
		writeValidation(w, r, ValidationErrors{{Field: "ends_at", Code: "required", Message: "provide ends_at or duration_seconds"}})
		return
	}
	silence, err := h.Svc.CreateSilence(r.Context(), p.OrgID, Actor{UserID: p.UserID}, SilenceCreateInput{
		MatchJSON: req.Match, Reason: req.Reason, StartsAt: startsAt, EndsAt: endsAt,
	}, sc)
	if err != nil {
		writeSuppressionError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, silencePayload(silence, now))
}

// ListSilences handles GET /v1/silences (alert.silence).
func (h *HTTP) ListSilences(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	limit, ok := parseLimit(w, r, MaxSilencePageSize)
	if !ok {
		return
	}
	page, err := h.Svc.ListSilences(r.Context(), p.OrgID, sc, limit, r.URL.Query().Get("cursor"))
	if err != nil {
		writeSuppressionError(w, r, err)
		return
	}
	now := h.Svc.Now().UTC()
	data := make([]map[string]any, 0, len(page.Silences))
	for _, silence := range page.Silences {
		data = append(data, silencePayload(silence, now))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"data":        data,
		"next_cursor": cursorOrNil(page.NextCursor),
		"has_more":    page.HasMore,
	})
}

// DeleteSilence handles DELETE /v1/silences/{id} (alert.silence).
func (h *HTTP) DeleteSilence(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	silenceID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "alert_silence.not_found", "silence not found")
		return
	}
	if err := h.Svc.DeleteSilence(r.Context(), p.OrgID, silenceID, sc); err != nil {
		writeSuppressionError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func windowPayload(window MaintenanceWindow, now time.Time) map[string]any {
	payload := map[string]any{
		"id":         window.ID.String(),
		"name":       window.Name,
		"scope":      json.RawMessage(window.ScopeJSON),
		"enabled":    window.Enabled,
		"starts_at":  window.StartsAt.UTC().Format(time.RFC3339),
		"ends_at":    window.EndsAt.UTC().Format(time.RFC3339),
		"active":     window.Enabled && !now.Before(window.StartsAt) && now.Before(window.EndsAt),
		"created_by": nil,
		"created_at": window.CreatedAt.UTC().Format(time.RFC3339),
		"updated_at": window.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if window.CreatedBy != nil {
		payload["created_by"] = window.CreatedBy.String()
	}
	return payload
}

func silencePayload(silence Silence, now time.Time) map[string]any {
	payload := map[string]any{
		"id":         silence.ID.String(),
		"match":      json.RawMessage(silence.MatchJSON),
		"reason":     silence.Reason,
		"starts_at":  silence.StartsAt.UTC().Format(time.RFC3339),
		"ends_at":    silence.EndsAt.UTC().Format(time.RFC3339),
		"active":     !now.Before(silence.StartsAt) && now.Before(silence.EndsAt),
		"created_by": nil,
		"created_at": silence.CreatedAt.UTC().Format(time.RFC3339),
	}
	if silence.CreatedBy != nil {
		payload["created_by"] = silence.CreatedBy.String()
	}
	return payload
}
