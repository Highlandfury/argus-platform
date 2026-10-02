package notify

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/platform/httpx"
)

// HTTP exposes the M11-S2 notification surface. Session + CSRF + capability
// are enforced by the router (integration.write for channels/route writes,
// alertrule.write for routes per docs/12 §22.14, alert.read for deliveries).
type HTTP struct {
	Svc         *Service
	Engine      *Engine
	Idempotency *httpx.IdempotencyCache
}

type channelCreateRequest struct {
	Kind   string          `json:"kind"`
	Name   string          `json:"name"`
	Config json.RawMessage `json:"config"`
	Secret json.RawMessage `json:"secret"`
}

type channelUpdateRequest struct {
	Name    *string         `json:"name"`
	Enabled *bool           `json:"enabled"`
	Config  json.RawMessage `json:"config"`
	Secret  json.RawMessage `json:"secret"`
}

type routeCreateRequest struct {
	Name              string          `json:"name"`
	Match             json.RawMessage `json:"match"`
	ChannelIDs        []uuid.UUID     `json:"channel_ids"`
	TemplateOverrides json.RawMessage `json:"template_overrides"`
}

type routeUpdateRequest struct {
	Name              *string         `json:"name"`
	Match             json.RawMessage `json:"match"`
	ChannelIDs        []uuid.UUID     `json:"channel_ids"`
	TemplateOverrides json.RawMessage `json:"template_overrides"`
	Enabled           *bool           `json:"enabled"`
}

// principalOrg resolves the authenticated caller and enforces the org-wide
// scope every notification route declares (x-argus-scope: org in the OpenAPI
// contract). Channels carry write-only secrets and routes are org-level
// integration config, so a caller with scope bindings is denied
// deterministically (mirrors the credentials requireOrgScope rule from M7).
func (h *HTTP) principalOrg(w http.ResponseWriter, r *http.Request) (httpx.Principal, bool) {
	p, ok := httpx.PrincipalFrom(r.Context())
	if !ok {
		httpx.WriteProblem(w, r, http.StatusUnauthorized, "auth.unauthenticated", "authentication required")
		return httpx.Principal{}, false
	}
	sc, err := h.Svc.ScopeFor(r.Context(), p.OrgID, p.UserID)
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "authorization scope lookup failed")
		return httpx.Principal{}, false
	}
	if !sc.Unrestricted {
		httpx.WriteProblem(w, r, http.StatusForbidden, "auth.forbidden", "notification management requires org-wide scope")
		return httpx.Principal{}, false
	}
	return p, true
}

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

func writeNotifyError(w http.ResponseWriter, r *http.Request, err error) {
	var verrs ValidationErrors
	switch {
	case errors.As(err, &verrs):
		writeValidation(w, r, verrs)
	case errors.Is(err, ErrChannelNotFound):
		httpx.WriteProblem(w, r, http.StatusNotFound, "notification_channel.not_found", "notification channel not found")
	case errors.Is(err, ErrRouteNotFound):
		httpx.WriteProblem(w, r, http.StatusNotFound, "notification_route.not_found", "notification route not found")
	case errors.Is(err, ErrNameConflict):
		httpx.WriteProblem(w, r, http.StatusConflict, "notification.name_conflict", "a channel or route with this name already exists")
	case errors.Is(err, ErrInvalidCursor):
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid cursor")
	case errors.Is(err, ErrVaultUnavailable):
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "integration.vault_unavailable", "secrets vault is not configured")
	default:
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "notification operation failed")
	}
}

func writeValidation(w http.ResponseWriter, r *http.Request, errs ValidationErrors) {
	fields := make([]httpx.FieldError, 0, len(errs))
	for _, e := range errs {
		fields = append(fields, httpx.FieldError{Field: e.Field, Code: e.Code, Message: e.Message})
	}
	httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "validation failed", fields...)
}

// CreateChannel handles POST /v1/notification/channels.
func (h *HTTP) CreateChannel(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	var req channelCreateRequest
	if !decodeBody(w, r, &req) {
		return
	}
	ch, err := h.Svc.CreateChannel(r.Context(), p.OrgID, Actor{UserID: p.UserID}, ChannelCreateInput{
		Kind: req.Kind, Name: req.Name, Config: req.Config, Secret: req.Secret,
	})
	if err != nil {
		writeNotifyError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, channelPayload(ch))
}

// ListChannels handles GET /v1/notification/channels.
func (h *HTTP) ListChannels(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	limit, ok := parseLimit(w, r)
	if !ok {
		return
	}
	page, err := h.Svc.ListChannels(r.Context(), p.OrgID, limit, r.URL.Query().Get("cursor"))
	if err != nil {
		writeNotifyError(w, r, err)
		return
	}
	data := make([]map[string]any, 0, len(page.Channels))
	for _, ch := range page.Channels {
		data = append(data, channelPayload(ch))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"data":        data,
		"next_cursor": cursorOrNil(page.NextCursor),
		"has_more":    page.HasMore,
	})
}

// GetChannel handles GET /v1/notification/channels/{id}.
func (h *HTTP) GetChannel(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "notification_channel.not_found", "notification channel not found")
		return
	}
	ch, err := h.Svc.GetChannel(r.Context(), p.OrgID, id)
	if err != nil {
		writeNotifyError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, channelPayload(ch))
}

// UpdateChannel handles PATCH /v1/notification/channels/{id}: a new secret
// replaces the sealed envelope, `secret: null` clears it, omitted keeps it.
func (h *HTTP) UpdateChannel(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "notification_channel.not_found", "notification channel not found")
		return
	}
	var req channelUpdateRequest
	if !decodeBody(w, r, &req) {
		return
	}
	patch := ChannelPatchInput{Name: req.Name, Enabled: req.Enabled, Config: req.Config}
	if req.Secret != nil {
		if isJSONNull(req.Secret) {
			patch.ClearSecret = true
		} else {
			patch.Secret = req.Secret
		}
	}
	ch, err := h.Svc.UpdateChannel(r.Context(), p.OrgID, id, patch)
	if err != nil {
		writeNotifyError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, channelPayload(ch))
}

// DeleteChannel handles DELETE /v1/notification/channels/{id}: soft disable
// so the delivery log's audit trail survives.
func (h *HTTP) DeleteChannel(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "notification_channel.not_found", "notification channel not found")
		return
	}
	ch, err := h.Svc.DeleteChannel(r.Context(), p.OrgID, id)
	if err != nil {
		writeNotifyError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, channelPayload(ch))
}

// TestChannel handles POST /v1/notification/channels/{id}/test. The optional
// Idempotency-Key header replays the first outcome for transport retries.
// (Canonical docs/12 §22.14 spells this `{id}:test`; the repo route style
// uses `/{id}/test`, documented in M11_EVIDENCE §S2.)
func (h *HTTP) TestChannel(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "notification_channel.not_found", "notification channel not found")
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if status, body, ok := h.Idempotency.Get(key); ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		// #nosec G705 -- cached Argus JSON with an explicit JSON content type, never HTML.
		_, _ = w.Write(body)
		return
	}
	res, err := h.Engine.TestChannel(r.Context(), p.OrgID, id)
	if err != nil {
		writeNotifyError(w, r, err)
		return
	}
	payload := testResultPayload(res)
	raw, _ := json.Marshal(payload)
	status := http.StatusOK
	if !res.OK {
		status = http.StatusBadGateway
	}
	h.Idempotency.Put(key, status, raw)
	httpx.WriteJSON(w, status, payload)
}

// CreateRoute handles POST /v1/notification/routes.
func (h *HTTP) CreateRoute(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	var req routeCreateRequest
	if !decodeBody(w, r, &req) {
		return
	}
	route, err := h.Svc.CreateRoute(r.Context(), p.OrgID, Actor{UserID: p.UserID}, RouteCreateInput{
		Name: req.Name, MatchJSON: req.Match, ChannelIDs: req.ChannelIDs,
		TemplateOverrides: req.TemplateOverrides,
	})
	if err != nil {
		writeNotifyError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, routePayload(route))
}

// ListRoutes handles GET /v1/notification/routes.
func (h *HTTP) ListRoutes(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	limit, ok := parseLimit(w, r)
	if !ok {
		return
	}
	page, err := h.Svc.ListRoutes(r.Context(), p.OrgID, limit, r.URL.Query().Get("cursor"))
	if err != nil {
		writeNotifyError(w, r, err)
		return
	}
	data := make([]map[string]any, 0, len(page.Routes))
	for _, rt := range page.Routes {
		data = append(data, routePayload(rt))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"data":        data,
		"next_cursor": cursorOrNil(page.NextCursor),
		"has_more":    page.HasMore,
	})
}

// GetRoute handles GET /v1/notification/routes/{id}.
func (h *HTTP) GetRoute(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "notification_route.not_found", "notification route not found")
		return
	}
	rt, err := h.Svc.GetRoute(r.Context(), p.OrgID, id)
	if err != nil {
		writeNotifyError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, routePayload(rt))
}

// UpdateRoute handles PATCH /v1/notification/routes/{id}.
func (h *HTTP) UpdateRoute(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "notification_route.not_found", "notification route not found")
		return
	}
	var req routeUpdateRequest
	if !decodeBody(w, r, &req) {
		return
	}
	rt, err := h.Svc.UpdateRoute(r.Context(), p.OrgID, id, RoutePatchInput{
		Name: req.Name, MatchJSON: req.Match, ChannelIDs: req.ChannelIDs,
		TemplateOverrides: req.TemplateOverrides, Enabled: req.Enabled,
	})
	if err != nil {
		writeNotifyError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, routePayload(rt))
}

// DeleteRoute handles DELETE /v1/notification/routes/{id}.
func (h *HTTP) DeleteRoute(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "notification_route.not_found", "notification route not found")
		return
	}
	if err := h.Svc.DeleteRoute(r.Context(), p.OrgID, id); err != nil {
		writeNotifyError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ListDeliveries handles GET /v1/notification/deliveries with
// channel_id/status/alert_id filters and a keyset cursor.
func (h *HTTP) ListDeliveries(w http.ResponseWriter, r *http.Request) {
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	query := r.URL.Query()
	limit, ok := parseLimit(w, r)
	if !ok {
		return
	}
	var filter DeliveryFilter
	if raw := query.Get("filter[channel_id]"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			writeValidation(w, r, ValidationErrors{{Field: "filter[channel_id]", Code: "invalid", Message: "must be a UUID"}})
			return
		}
		filter.ChannelID = &id
	}
	if raw := query.Get("filter[alert_id]"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			writeValidation(w, r, ValidationErrors{{Field: "filter[alert_id]", Code: "invalid", Message: "must be a UUID"}})
			return
		}
		filter.AlertID = &id
	}
	if raw := query.Get("filter[status]"); raw != "" {
		if !ValidStatus(raw) {
			writeValidation(w, r, ValidationErrors{{Field: "filter[status]", Code: "invalid", Message: "allowed: pending, delivered, failed, dead_letter"}})
			return
		}
		filter.Status = &raw
	}
	page, err := h.Svc.ListDeliveries(r.Context(), p.OrgID, filter, limit, query.Get("cursor"))
	if err != nil {
		writeNotifyError(w, r, err)
		return
	}
	data := make([]map[string]any, 0, len(page.Deliveries))
	for _, d := range page.Deliveries {
		data = append(data, deliveryPayload(d))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"data":        data,
		"next_cursor": cursorOrNil(page.NextCursor),
		"has_more":    page.HasMore,
	})
}

func isJSONNull(raw []byte) bool {
	return len(bytes.TrimSpace(raw)) == 4 && string(bytes.TrimSpace(raw)) == "null"
}

func parseLimit(w http.ResponseWriter, r *http.Request) (int, bool) {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return 25, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > MaxPageSize {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed",
			"limit must be an integer between 1 and "+strconv.Itoa(MaxPageSize))
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

func channelPayload(c Channel) map[string]any {
	return map[string]any{
		"id":         c.ID.String(),
		"kind":       c.Kind,
		"name":       c.Name,
		"enabled":    c.Enabled,
		"config":     json.RawMessage(c.Config),
		"has_secret": c.HasSecret(),
		"created_at": c.CreatedAt.UTC().Format(time.RFC3339),
		"updated_at": c.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

func routePayload(r Route) map[string]any {
	channelIDs := make([]string, 0, len(r.ChannelIDs))
	for _, id := range r.ChannelIDs {
		channelIDs = append(channelIDs, id.String())
	}
	return map[string]any{
		"id":                 r.ID.String(),
		"name":               r.Name,
		"match":              json.RawMessage(r.MatchJSON),
		"channel_ids":        channelIDs,
		"template_overrides": json.RawMessage(r.TemplateOverrides),
		"enabled":            r.Enabled,
		"created_at":         r.CreatedAt.UTC().Format(time.RFC3339),
		"updated_at":         r.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

func deliveryPayload(d Delivery) map[string]any {
	payload := map[string]any{
		"id":               d.ID.String(),
		"alert_id":         nil,
		"event_id":         nil,
		"event_kind":       d.EventKind,
		"severity":         d.Severity,
		"route_id":         nil,
		"channel_id":       d.ChannelID.String(),
		"status":           d.Status,
		"attempts":         d.Attempts,
		"next_attempt_at":  nil,
		"response_code":    nil,
		"response_excerpt": d.ResponseExcerpt,
		"dedup_key":        d.DedupKey,
		"subject":          d.Subject,
		"body":             d.Body,
		"payload":          json.RawMessage(d.Payload),
		"created_at":       d.CreatedAt.UTC().Format(time.RFC3339),
		"updated_at":       d.UpdatedAt.UTC().Format(time.RFC3339),
		"delivered_at":     nil,
	}
	if d.AlertID != nil {
		payload["alert_id"] = d.AlertID.String()
	}
	if d.EventID != nil {
		payload["event_id"] = d.EventID.String()
	}
	if d.RouteID != nil {
		payload["route_id"] = d.RouteID.String()
	}
	if d.NextAttemptAt != nil {
		payload["next_attempt_at"] = d.NextAttemptAt.UTC().Format(time.RFC3339)
	}
	if d.ResponseCode != nil {
		payload["response_code"] = *d.ResponseCode
	}
	if d.DeliveredAt != nil {
		payload["delivered_at"] = d.DeliveredAt.UTC().Format(time.RFC3339)
	}
	return payload
}

func testResultPayload(res TestResult) map[string]any {
	return map[string]any{
		"ok":           res.OK,
		"kind":         res.Kind,
		"status_code":  res.StatusCode,
		"excerpt":      res.Excerpt,
		"attempted_at": res.AttemptedAt.UTC().Format(time.RFC3339),
	}
}
