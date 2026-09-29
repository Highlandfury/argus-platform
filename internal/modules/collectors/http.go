package collectors

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
	"github.com/argus-platform/argus/internal/platform/httpx"
)

// HTTP exposes the collector registry + enrollment management API. All routes
// sit behind session auth; mutations require the admin role (Phase-1 stand-in
// for the full RBAC-SC model).
type HTTP struct {
	Svc      *Service
	Registry *SessionRegistry
}

func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	p, ok := httpx.PrincipalFrom(r.Context())
	if !ok {
		httpx.WriteProblem(w, r, http.StatusUnauthorized, "auth.unauthenticated", "authentication required")
		return false
	}
	if p.Role != "admin" {
		httpx.WriteProblem(w, r, http.StatusForbidden, "auth.forbidden", "admin role required")
		return false
	}
	return true
}

func principalOrg(w http.ResponseWriter, r *http.Request) (httpx.Principal, bool) {
	p, ok := httpx.PrincipalFrom(r.Context())
	if !ok {
		httpx.WriteProblem(w, r, http.StatusUnauthorized, "auth.unauthenticated", "authentication required")
		return httpx.Principal{}, false
	}
	return p, true
}

func parseLimit(r *http.Request) (int, bool) {
	limit := 25
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 100 {
			return 0, false
		}
		limit = n
	}
	return limit, true
}

func rfc3339Ptr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format(time.RFC3339)
	return &s
}

// collectorPayload is the API projection of a registry row (matches openapi).
func collectorPayload(c CollectorRow, now time.Time) map[string]any {
	out := map[string]any{
		"id":                c.ID.String(),
		"name":              c.Name,
		"site_id":           c.SiteID.String(),
		"status":            EffectiveStatus(c, now),
		"agent_version":     c.AgentVersion,
		"last_heartbeat_at": rfc3339Ptr(c.LastHeartbeatAt),
		"last_stream_at":    rfc3339Ptr(c.LastStreamAt),
		"enrolled_at":       rfc3339Ptr(c.EnrolledAt),
	}
	return out
}

// ListCollectors handles GET /v1/collectors.
func (h *HTTP) ListCollectors(w http.ResponseWriter, r *http.Request) {
	p, ok := principalOrg(w, r)
	if !ok {
		return
	}
	limit, ok := parseLimit(r)
	if !ok {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "limit must be an integer between 1 and 100")
		return
	}
	filter := ListFilter{}
	if raw := r.URL.Query().Get("filter[site_id]"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid site filter")
			return
		}
		filter.SiteID = &id
	}
	if raw := r.URL.Query().Get("filter[status]"); raw != "" {
		switch raw {
		case "pending", "active", "stale", "revoked":
			filter.Status = &raw
		default:
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid status filter")
			return
		}
	}

	page, err := h.Svc.ListCollectors(r.Context(), p.OrgID, filter, limit, r.URL.Query().Get("cursor"))
	if err != nil {
		if errors.Is(err, ErrInvalidCursor) {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid cursor")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "collectors lookup failed")
		return
	}
	now := time.Now()
	data := make([]map[string]any, 0, len(page.Collectors))
	for _, c := range page.Collectors {
		data = append(data, collectorPayload(c, now))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"data": data, "next_cursor": page.NextCursor})
}

// GetCollector handles GET /v1/collectors/{id} including policy + certificate
// detail.
func (h *HTTP) GetCollector(w http.ResponseWriter, r *http.Request) {
	p, ok := principalOrg(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "collector not found")
		return
	}
	row, err := h.Svc.GetCollector(r.Context(), p.OrgID, id)
	if err != nil {
		if errors.Is(err, ErrCollectorNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "collector.not_found", "collector not found")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "collector lookup failed")
		return
	}

	maxVersion := row.PolicyVersion
	if latest, err := h.Svc.LatestPolicy(r.Context(), p.OrgID, id); err == nil && latest != nil {
		maxVersion = latest.Version
	}
	payload := collectorPayload(row, time.Now())
	payload["hostname"] = row.Hostname
	payload["os"] = row.OS
	payload["policy"] = map[string]any{
		"acked_version": row.PolicyVersion,
		"max_version":   maxVersion,
	}
	payload["certificate"] = map[string]any{
		"not_after":  rfc3339Ptr(row.CertNotAfter),
		"revoked_at": rfc3339Ptr(row.CertRevokedAt),
	}
	var stats any
	if len(row.ReportedStats) > 0 {
		_ = json.Unmarshal(row.ReportedStats, &stats)
	}
	payload["reported_stats"] = stats
	payload["connected"] = h.Registry != nil && h.Registry.ActiveCount() > 0 && h.connected(id)

	httpx.WriteJSON(w, http.StatusOK, payload)
}

func (h *HTTP) connected(id uuid.UUID) bool {
	if h.Registry == nil {
		return false
	}
	h.Registry.mu.Lock()
	defer h.Registry.mu.Unlock()
	_, ok := h.Registry.sessions[id]
	return ok
}

type createEnrollmentRequest struct {
	SiteID     string `json:"site_id"`
	TTLSeconds int    `json:"ttl_seconds"`
}

// CreateEnrollment handles POST /v1/enrollments (admin only). The raw token is
// returned exactly once.
func (h *HTTP) CreateEnrollment(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	p, _ := httpx.PrincipalFrom(r.Context())
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var req createEnrollmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "request body must be JSON")
		return
	}
	siteID, err := uuid.Parse(req.SiteID)
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "site_id is required",
			httpx.FieldError{Field: "site_id", Code: "required", Message: "site_id is required (site-bound tokens only in M3)"})
		return
	}
	ttl := 24 * time.Hour
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	creator := p.UserID
	raw, id, expiresAt, err := h.Svc.CreateEnrollmentToken(r.Context(), p.OrgID, siteID, ttl, &creator)
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"id":         id.String(),
		"token":      raw,
		"site_id":    siteID.String(),
		"expires_at": expiresAt.UTC().Format(time.RFC3339),
	})
}

// ListEnrollments handles GET /v1/enrollments (metadata only).
func (h *HTTP) ListEnrollments(w http.ResponseWriter, r *http.Request) {
	p, ok := principalOrg(w, r)
	if !ok {
		return
	}
	limit, ok := parseLimit(r)
	if !ok {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "limit must be an integer between 1 and 100")
		return
	}
	page, err := h.Svc.ListTokens(r.Context(), p.OrgID, limit, r.URL.Query().Get("cursor"))
	if err != nil {
		if errors.Is(err, ErrInvalidCursor) {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid cursor")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "enrollments lookup failed")
		return
	}
	data := make([]map[string]any, 0, len(page.Tokens))
	for _, t := range page.Tokens {
		item := map[string]any{
			"id":         t.ID.String(),
			"expires_at": t.ExpiresAt.UTC().Format(time.RFC3339),
			"created_at": t.CreatedAt.UTC().Format(time.RFC3339),
			"used_at":    rfc3339Ptr(t.UsedAt),
		}
		if t.SiteID != nil {
			item["site_id"] = t.SiteID.String()
		} else {
			item["site_id"] = nil
		}
		data = append(data, item)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"data": data, "next_cursor": page.NextCursor})
}

// RevokeCollector handles POST /v1/collectors/{id}:revoke (admin only).
func (h *HTTP) RevokeCollector(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	p, _ := httpx.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "collector.not_found", "collector not found")
		return
	}
	if _, err := h.Svc.RevokeCollector(r.Context(), p.OrgID, id); err != nil {
		if errors.Is(err, ErrCollectorNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "collector.not_found", "collector not found")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "revoke failed")
		return
	}
	if h.Registry != nil {
		h.Registry.Disconnect(id, DisconnectMsg{Code: collectorv1.Disconnect_CODE_REVOKED, Reason: "collector revoked"})
	}
	row, err := h.Svc.GetCollector(r.Context(), p.OrgID, id)
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "collector lookup failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, collectorPayload(row, time.Now()))
}

// ResyncPolicy handles POST /v1/collectors/{id}/policy:resync (admin only).
func (h *HTTP) ResyncPolicy(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	p, _ := httpx.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "collector.not_found", "collector not found")
		return
	}
	if _, err := h.Svc.GetCollector(r.Context(), p.OrgID, id); err != nil {
		if errors.Is(err, ErrCollectorNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "collector.not_found", "collector not found")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "collector lookup failed")
		return
	}
	version, err := h.Svc.ResyncPolicy(r.Context(), p.OrgID, id)
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "policy resync failed")
		return
	}
	if h.Registry != nil {
		if latest, err := h.Svc.LatestPolicy(r.Context(), p.OrgID, id); err == nil && latest != nil {
			h.Registry.PushPolicy(id, latest)
		}
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"policy_version": version})
}
