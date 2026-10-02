package pollhealth

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/modules/inventory"
	"github.com/argus-platform/argus/internal/platform/authz"
	"github.com/argus-platform/argus/internal/platform/httpx"
)

// DeviceResolver is the inventory surface the poll-health API resolves device
// scope with (kept as an interface so the module stays independently testable).
type DeviceResolver interface {
	GetDevice(ctx context.Context, orgID, deviceID uuid.UUID, includeDeleted bool) (inventory.Device, error)
	ScopeFor(ctx context.Context, orgID, userID uuid.UUID) (authz.Scope, error)
}

// HTTP exposes GET /v1/devices/{id}/poll-health.
type HTTP struct {
	Svc     *Service
	Devices DeviceResolver
}

// ListDevicePollHealth handles GET /v1/devices/{id}/poll-health (session +
// device.read capability enforced by the router; scope enforced here).
func (h *HTTP) ListDevicePollHealth(w http.ResponseWriter, r *http.Request) {
	p, ok := httpx.PrincipalFrom(r.Context())
	if !ok {
		httpx.WriteProblem(w, r, http.StatusUnauthorized, "auth.unauthenticated", "authentication required")
		return
	}
	deviceID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
		return
	}
	limit := 25
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 100 {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed",
				"limit must be an integer between 1 and 100")
			return
		}
		limit = n
	}

	dev, err := h.Devices.GetDevice(r.Context(), p.OrgID, deviceID, false)
	if err != nil {
		if errors.Is(err, inventory.ErrDeviceNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "device lookup failed")
		return
	}
	sc, err := h.Devices.ScopeFor(r.Context(), p.OrgID, p.UserID)
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "authorization scope lookup failed")
		return
	}
	if !sc.AllowsDevice(dev.SiteID) {
		// Enumeration resistance: foreign and missing devices are identical.
		httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
		return
	}

	page, err := h.Svc.ListDeviceHealth(r.Context(), p.OrgID, deviceID, limit, r.URL.Query().Get("cursor"))
	if err != nil {
		if errors.Is(err, ErrInvalidCursor) {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid cursor")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "poll health lookup failed")
		return
	}
	data := make([]map[string]any, 0, len(page.Records))
	for _, rec := range page.Records {
		data = append(data, recordPayload(rec))
	}
	payload := map[string]any{
		"data":     data,
		"has_more": page.HasMore,
	}
	if page.NextCursor != "" {
		payload["next_cursor"] = page.NextCursor
	} else {
		payload["next_cursor"] = nil
	}
	httpx.WriteJSON(w, http.StatusOK, payload)
}

// Bounds for the bounded recent poll-health feed (M10-S3b-3).
const (
	recentDefaultWindow = time.Hour
	recentMaxWindow     = 24 * time.Hour
	// recentWindowGrace absorbs client/server clock and request-latency skew
	// for a caller that asks for exactly the 24 h maximum (an exact
	// now-24h bound would otherwise be rejected milliseconds later).
	recentWindowGrace  = time.Minute
	recentDefaultLimit = 50
	recentMaxLimit     = 200
)

// ListPollHealth handles GET /v1/poll-health (session + device.read capability
// enforced by the router; scope enforced here). Bounded recent feed: outcome
// (success|failure), poll_type (icmp|snmp), device_id filters, an RFC3339
// `since` (default now-1h, must be within the last 24h plus a 60 s
// clock-skew grace) and limit <=200 (default 50). Ordered ts DESC; there is
// no cursor (documented bounded feed, not a deep-pagination collection).
//
// Scope mirrors the checks list / devices list (join devices on site); an
// explicit out-of-scope device_id is a deterministic 403.
func (h *HTTP) ListPollHealth(w http.ResponseWriter, r *http.Request) {
	p, ok := httpx.PrincipalFrom(r.Context())
	if !ok {
		httpx.WriteProblem(w, r, http.StatusUnauthorized, "auth.unauthenticated", "authentication required")
		return
	}
	sc, err := h.Devices.ScopeFor(r.Context(), p.OrgID, p.UserID)
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "authorization scope lookup failed")
		return
	}
	query := r.URL.Query()
	limit := recentDefaultLimit
	if raw := query.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > recentMaxLimit {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "limit must be an integer between 1 and 200")
			return
		}
		limit = n
	}
	now := time.Now().UTC()
	since := now.Add(-recentDefaultWindow)
	if raw := query.Get("since"); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid since",
				httpx.FieldError{Field: "since", Code: "invalid", Message: "must be RFC3339, e.g. 2026-10-02T09:00:00Z"})
			return
		}
		since = parsed.UTC()
	}
	if since.After(now) {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid since",
			httpx.FieldError{Field: "since", Code: "invalid", Message: "must not be in the future"})
		return
	}
	if since.Before(now.Add(-recentMaxWindow - recentWindowGrace)) {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid since",
			httpx.FieldError{Field: "since", Code: "invalid", Message: "must be within the last 24 hours"})
		return
	}
	filter := RecentFilter{Scope: ScopeFilter{Unrestricted: sc.Unrestricted, SiteIDs: sc.Sites}}
	if raw := query.Get("outcome"); raw != "" {
		switch raw {
		case "success", "failure":
			filter.Outcome = &raw
		default:
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid outcome filter",
				httpx.FieldError{Field: "outcome", Code: "invalid", Message: "allowed: success, failure"})
			return
		}
	}
	if raw := query.Get("poll_type"); raw != "" {
		switch raw {
		case "icmp", "snmp":
			filter.PollType = &raw
		default:
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid poll_type filter",
				httpx.FieldError{Field: "poll_type", Code: "invalid", Message: "allowed: icmp, snmp"})
			return
		}
	}
	if raw := query.Get("device_id"); raw != "" {
		deviceID, err := uuid.Parse(raw)
		if err != nil {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid device_id filter",
				httpx.FieldError{Field: "device_id", Code: "invalid", Message: "must be a UUID"})
			return
		}
		if !sc.Unrestricted {
			dev, err := h.Devices.GetDevice(r.Context(), p.OrgID, deviceID, true)
			if err != nil {
				if errors.Is(err, inventory.ErrDeviceNotFound) {
					writeScopeForbidden(w, r, "device filter is outside the caller's scope")
					return
				}
				httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "device lookup failed")
				return
			}
			if !sc.AllowsDevice(dev.SiteID) {
				writeScopeForbidden(w, r, "device filter is outside the caller's scope")
				return
			}
		}
		filter.DeviceID = &deviceID
	}
	records, err := h.Svc.ListRecent(r.Context(), p.OrgID, filter, since, limit)
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "poll health lookup failed")
		return
	}
	data := make([]map[string]any, 0, len(records))
	for _, rec := range records {
		data = append(data, recordPayload(rec))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"data":  data,
		"since": since.Format(time.RFC3339),
	})
}

// writeScopeForbidden is the deterministic 403 for out-of-scope collection
// filters (mirrors the M7 device-list site filter).
func writeScopeForbidden(w http.ResponseWriter, r *http.Request, detail string) {
	httpx.WriteProblem(w, r, http.StatusForbidden, "auth.forbidden", detail)
}

// GetDeviceStatus handles GET /v1/devices/{id}/status (session + device.read
// capability enforced by the router; scope enforced here). Foreign, missing
// and out-of-scope devices are an identical 404 (M7 enumeration resistance).
func (h *HTTP) GetDeviceStatus(w http.ResponseWriter, r *http.Request) {
	p, ok := httpx.PrincipalFrom(r.Context())
	if !ok {
		httpx.WriteProblem(w, r, http.StatusUnauthorized, "auth.unauthenticated", "authentication required")
		return
	}
	deviceID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
		return
	}
	dev, err := h.Devices.GetDevice(r.Context(), p.OrgID, deviceID, false)
	if err != nil {
		if errors.Is(err, inventory.ErrDeviceNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "device lookup failed")
		return
	}
	sc, err := h.Devices.ScopeFor(r.Context(), p.OrgID, p.UserID)
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "authorization scope lookup failed")
		return
	}
	if !sc.AllowsDevice(dev.SiteID) {
		httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
		return
	}
	statuses, err := h.Svc.DeviceStatuses(r.Context(), p.OrgID, []uuid.UUID{deviceID})
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "device status lookup failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, statuses[deviceID].Payload())
}

func recordPayload(rec Record) map[string]any {
	return map[string]any{
		"id":                   rec.ID.String(),
		"device_id":            rec.DeviceID.String(),
		"collector_id":         rec.CollectorID.String(),
		"poll_type":            rec.PollType,
		"checked_at":           rec.CheckedAt.UTC().Format(time.RFC3339),
		"latency_ms":           rec.LatencyMS,
		"outcome":              rec.Outcome,
		"error_class":          rec.ErrorClass,
		"consecutive_failures": rec.ConsecutiveFailures,
		"origin":               rec.Origin,
	}
}
