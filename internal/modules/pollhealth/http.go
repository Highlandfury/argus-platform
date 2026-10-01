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
