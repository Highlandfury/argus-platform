package checks

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
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

// ListChecks handles GET /v1/checks (session + device.read capability enforced
// by the router; scope enforced here). The collection is org-wide, newest
// first by default (order=asc opts into oldest-first), cursor-paged by check
// id, and narrowed by filter[status], filter[poll_type] and filter[device_id].
//
// Scope mirrors the devices list: rows whose device site is outside the
// caller's bindings are invisible. An explicit filter[device_id] outside the
// caller's scope is a deterministic 403 (the M7 list-filter rule); unknown
// device ids are not an existence oracle for unrestricted callers (200, empty
// page) and are folded into the same 403 for restricted callers, exactly like
// an unknown filter[site_id].
func (h *HTTP) ListChecks(w http.ResponseWriter, r *http.Request) {
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
	limit := 25
	if raw := query.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 100 {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "limit must be an integer between 1 and 100")
			return
		}
		limit = n
	}
	filter := ListFilter{Scope: ScopeFilter{Unrestricted: sc.Unrestricted, SiteIDs: sc.Sites}}
	if raw := query.Get("filter[status]"); raw != "" {
		switch raw {
		case StatusPending, StatusCompleted, StatusFailed:
			filter.Status = &raw
		default:
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid status filter",
				httpx.FieldError{Field: "filter[status]", Code: "invalid", Message: "allowed: pending, completed, failed"})
			return
		}
	}
	if raw := query.Get("filter[poll_type]"); raw != "" {
		switch raw {
		case PollICMP, PollSNMP:
			filter.PollType = &raw
		default:
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid poll_type filter",
				httpx.FieldError{Field: "filter[poll_type]", Code: "invalid", Message: "allowed: icmp, snmp"})
			return
		}
	}
	if raw := query.Get("filter[device_id]"); raw != "" {
		deviceID, err := uuid.Parse(raw)
		if err != nil {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid device_id filter",
				httpx.FieldError{Field: "filter[device_id]", Code: "invalid", Message: "must be a UUID"})
			return
		}
		if !sc.Unrestricted {
			// includeDeleted=true: a soft-deleted in-scope device is a valid
			// filter (the ledger keeps its checks). Everything unresolvable or
			// out of scope is the same deterministic 403.
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
	order := query.Get("order")
	if order != "" && order != "asc" && order != "desc" {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid order",
			httpx.FieldError{Field: "order", Code: "invalid", Message: "allowed: asc, desc"})
		return
	}
	// Default newest first (documented M10-S3b-3 choice): the ledger has no
	// pre-existing consumers, so desc is the collection's default, unlike the
	// devices list whose asc default predates the operator UI.
	page, err := h.Svc.ListChecks(r.Context(), p.OrgID, filter, limit, query.Get("cursor"), order != "asc")
	if err != nil {
		if errors.Is(err, ErrInvalidCursor) {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid cursor")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "checks lookup failed")
		return
	}
	data := make([]map[string]any, 0, len(page.Checks))
	for _, c := range page.Checks {
		data = append(data, checkPayload(c))
	}
	var nextCursor any
	if page.NextCursor != "" {
		nextCursor = page.NextCursor
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"data":        data,
		"next_cursor": nextCursor,
		"has_more":    page.HasMore,
	})
}

// writeScopeForbidden is the deterministic 403 for out-of-scope collection
// filters (mirrors the M7 device-list site filter).
func writeScopeForbidden(w http.ResponseWriter, r *http.Request, detail string) {
	httpx.WriteProblem(w, r, http.StatusForbidden, "auth.forbidden", detail)
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
