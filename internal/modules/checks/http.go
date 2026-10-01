package checks

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/modules/inventory"
	"github.com/argus-platform/argus/internal/platform/authz"
	"github.com/argus-platform/argus/internal/platform/httpx"
)

// DeviceResolver is the inventory surface the checks API resolves device scope
// with (kept as an interface so the module stays independently testable).
type DeviceResolver interface {
	GetDevice(ctx context.Context, orgID, deviceID uuid.UUID, includeDeleted bool) (inventory.Device, error)
	ScopeFor(ctx context.Context, orgID, userID uuid.UUID) (authz.Scope, error)
}

// HTTP exposes POST /v1/devices/{id}/checks and GET /v1/checks/{id}.
type HTTP struct {
	Svc     *Service
	Devices DeviceResolver
}

type createCheckRequest struct {
	PollType string `json:"poll_type"`
}

// CreateDeviceCheck handles POST /v1/devices/{id}/checks (session + CSRF +
// diagnostic.run capability enforced by the router; scope enforced here).
// Idempotency-Key is required: a replay within the retention window returns
// the original check with Idempotent-Replayed: true (docs/12 §22.1).
func (h *HTTP) CreateDeviceCheck(w http.ResponseWriter, r *http.Request) {
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
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" || len(key) > RequestKeyMaxLen {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed",
			"Idempotency-Key header is required for check creation (max 128 chars)")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var req createCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "request body must be JSON")
		return
	}
	pollType := strings.ToLower(strings.TrimSpace(req.PollType))
	if pollType != PollICMP && pollType != PollSNMP {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid check",
			httpx.FieldError{Field: "poll_type", Code: "invalid", Message: "allowed: icmp, snmp"})
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
		// Enumeration resistance: foreign and missing devices are identical.
		httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
		return
	}

	check, replayed, err := h.Svc.CreateCheck(r.Context(), p.OrgID, deviceID, pollType, key, Actor{UserID: p.UserID})
	if err != nil {
		switch {
		case errors.Is(err, ErrDeviceNotFound):
			httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
		case errors.Is(err, ErrNoMgmtIP):
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid check",
				httpx.FieldError{Field: "mgmt_ip", Code: "missing", Message: "device has no management IP address"})
		case errors.Is(err, ErrNoCollector):
			httpx.WriteProblem(w, r, http.StatusConflict, "check.no_collector", "no collector is registered for the device's site")
		case errors.Is(err, ErrPendingLimit):
			httpx.WriteProblem(w, r, http.StatusConflict, "check.pending_limit", "too many pending checks for this device; wait for them to complete or expire")
		case errors.Is(err, ErrInvalidPollType):
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid check",
				httpx.FieldError{Field: "poll_type", Code: "invalid", Message: "allowed: icmp, snmp"})
		case errors.Is(err, ErrInvalidRequestKey):
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed",
				"Idempotency-Key header is required for check creation (max 128 chars)")
		default:
			httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "check create failed")
		}
		return
	}
	if replayed {
		w.Header().Set("Idempotent-Replayed", "true")
	}
	httpx.WriteJSON(w, http.StatusAccepted, checkPayload(check))
}

// GetCheck handles GET /v1/checks/{id} (session + device.read capability
// enforced by the router; scope enforced here). Unknown, foreign, and
// out-of-scope checks are all 404 (no existence oracle).
func (h *HTTP) GetCheck(w http.ResponseWriter, r *http.Request) {
	p, ok := httpx.PrincipalFrom(r.Context())
	if !ok {
		httpx.WriteProblem(w, r, http.StatusUnauthorized, "auth.unauthenticated", "authentication required")
		return
	}
	checkID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "check.not_found", "check not found")
		return
	}
	check, siteID, err := h.Svc.GetCheck(r.Context(), p.OrgID, checkID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "check.not_found", "check not found")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "check lookup failed")
		return
	}
	sc, err := h.Devices.ScopeFor(r.Context(), p.OrgID, p.UserID)
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "authorization scope lookup failed")
		return
	}
	if !sc.AllowsSite(siteID) {
		httpx.WriteProblem(w, r, http.StatusNotFound, "check.not_found", "check not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, checkPayload(check))
}

func checkPayload(c DeviceCheck) map[string]any {
	payload := map[string]any{
		"check_id":     c.ID.String(),
		"device_id":    c.DeviceID.String(),
		"collector_id": nil,
		"poll_type":    c.PollType,
		"status":       c.Status,
		"outcome":      c.Outcome,
		"error_class":  c.ErrorClass,
		"latency_ms":   nil,
		"created_at":   c.CreatedAt.UTC().Format(time.RFC3339),
		"completed_at": nil,
		"status_url":   "/v1/checks/" + c.ID.String(),
	}
	if c.CollectorID != nil {
		payload["collector_id"] = c.CollectorID.String()
	}
	if c.LatencyMS != nil {
		payload["latency_ms"] = *c.LatencyMS
	}
	if c.CompletedAt != nil {
		payload["completed_at"] = c.CompletedAt.UTC().Format(time.RFC3339)
	}
	return payload
}
