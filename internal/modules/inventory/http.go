package inventory

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/platform/authz"
	"github.com/argus-platform/argus/internal/platform/httpx"
)

// HTTP exposes the inventory API. Reads require a session; every mutation
// requires the admin role (the Phase-1 role model; capabilities replace it
// when RBAC-SC lands). Capability enforcement runs in the router (route
// metadata); scope enforcement runs here after the target resource is
// resolved (P2-D5).
type HTTP struct {
	Svc *Service
	// Status decorates device list payloads with the poll-health rollup when
	// `?include=status` is requested (M10-S1 bulk convention). It is nil in
	// configurations without the poll-health service; the include then fails
	// closed with 503.
	Status DeviceStatusProvider
}

// maxBodyBytes bounds inventory request bodies (devices are small documents).
const maxBodyBytes = 64 << 10

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

// scopeFor resolves the caller's server-side scope bindings (P2-D5). Failure
// to resolve is a 500: no access decision is made on an unreadable state.
func (h *HTTP) scopeFor(w http.ResponseWriter, r *http.Request, p httpx.Principal) (authz.Scope, bool) {
	sc, err := h.Svc.ScopeFor(r.Context(), p.OrgID, p.UserID)
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "authorization scope lookup failed")
		return authz.Scope{}, false
	}
	return sc, true
}

// scopeFilter converts the resolved scope into the store-layer list filter.
func scopeFilter(sc authz.Scope) ScopeFilter {
	return ScopeFilter{Unrestricted: sc.Unrestricted, SiteIDs: sc.Sites, GroupIDs: sc.DeviceGroups}
}

// writeScopeForbidden is the deterministic 403 for scope conflicts on
// collection filters and out-of-scope parents. Item access instead returns the
// resource's 404 (enumeration resistance) without disclosing scope state.
func writeScopeForbidden(w http.ResponseWriter, r *http.Request, detail string) {
	httpx.WriteProblem(w, r, http.StatusForbidden, "auth.forbidden", detail)
}

// interfaceInScope resolves an interface's parent device and verifies it is
// within the caller's scope. Denial writes the interface 404 so foreign and
// missing interfaces are indistinguishable.
func (h *HTTP) interfaceInScope(w http.ResponseWriter, r *http.Request, p httpx.Principal, sc authz.Scope, i Interface) bool {
	dev, err := h.Svc.GetDevice(r.Context(), p.OrgID, i.DeviceID, false)
	if err != nil {
		if errors.Is(err, ErrDeviceNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "interface.not_found", "interface not found")
			return false
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "device lookup failed")
		return false
	}
	if !sc.AllowsDevice(dev.SiteID) {
		httpx.WriteProblem(w, r, http.StatusNotFound, "interface.not_found", "interface not found")
		return false
	}
	return true
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

// actorFrom captures the audit context of a mutation request.
func actorFrom(r *http.Request) Actor {
	a := Actor{RequestID: httpx.RequestIDFrom(r.Context())}
	if p, ok := httpx.PrincipalFrom(r.Context()); ok {
		a.UserID = p.UserID
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		a.ClientIP = host
	} else {
		a.ClientIP = r.RemoteAddr
	}
	return a
}

func decodeBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "request body must be JSON")
		return false
	}
	return true
}

func rfc3339Ptr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format(time.RFC3339)
	return &s
}

func uuidPtr(id *uuid.UUID) *string {
	if id == nil {
		return nil
	}
	s := id.String()
	return &s
}

func cursorOrNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func validJSONObject(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return false
	}
	return m != nil
}

func devicePayload(d Device) map[string]any {
	return map[string]any{
		"id":            d.ID.String(),
		"site_id":       d.SiteID.String(),
		"zone_id":       uuidPtr(d.ZoneID),
		"name":          d.Name,
		"kind":          d.Kind,
		"vendor_id":     uuidPtr(d.VendorID),
		"model_id":      uuidPtr(d.ModelID),
		"sys_object_id": d.SysObjectID,
		"serial":        d.Serial,
		"firmware":      d.Firmware,
		"mgmt_ip":       d.MgmtIP,
		"status":        d.Status,
		"poll_profile":  d.PollProfile,
		"critical":      d.Critical,
		"confidence":    d.Confidence,
		"metadata":      d.Metadata,
		"first_seen_at": d.FirstSeenAt.UTC().Format(time.RFC3339),
		"last_seen_at":  rfc3339Ptr(d.LastSeenAt),
		"deleted_at":    rfc3339Ptr(d.DeletedAt),
		"created_at":    d.CreatedAt.UTC().Format(time.RFC3339),
		"updated_at":    d.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

func identityPayload(h IdentityRecord) map[string]any {
	return map[string]any{
		"id":               h.ID.String(),
		"device_id":        h.DeviceID.String(),
		"identifier_type":  h.IdentifierType,
		"identifier_value": h.IdentifierValue,
		"source":           h.Source,
		"first_seen_at":    h.FirstSeenAt.UTC().Format(time.RFC3339),
		"last_seen_at":     rfc3339Ptr(h.LastSeenAt),
		"created_at":       h.CreatedAt.UTC().Format(time.RFC3339),
	}
}

func interfacePayload(i Interface) map[string]any {
	return map[string]any{
		"id":            i.ID.String(),
		"device_id":     i.DeviceID.String(),
		"if_index":      i.IfIndex,
		"if_name":       i.IfName,
		"if_alias":      i.IfAlias,
		"if_type":       i.IfType,
		"admin_status":  i.AdminStatus,
		"oper_status":   i.OperStatus,
		"speed_bps":     i.SpeedBPS,
		"mtu":           i.MTU,
		"mac":           i.MAC,
		"description":   i.Description,
		"role":          i.Role,
		"monitored":     i.Monitored,
		"first_seen_at": i.FirstSeenAt.UTC().Format(time.RFC3339),
		"last_seen_at":  rfc3339Ptr(i.LastSeenAt),
	}
}

func groupPayload(g DeviceGroup) map[string]any {
	return map[string]any{
		"id":         g.ID.String(),
		"name":       g.Name,
		"selector":   g.Selector,
		"created_at": g.CreatedAt.UTC().Format(time.RFC3339),
		"updated_at": g.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

// ListDevices handles GET /v1/devices.
func (h *HTTP) ListDevices(w http.ResponseWriter, r *http.Request) {
	p, ok := principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	limit, ok := parseLimit(r)
	if !ok {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "limit must be an integer between 1 and 100")
		return
	}
	query := r.URL.Query()
	includeStatus, ok := parseDeviceListInclude(w, r, query.Get("include"))
	if !ok {
		return
	}
	filter := DeviceFilter{IncludeDeleted: query.Get("include_deleted") == "true"}
	if raw := query.Get("filter[site_id]"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid site_id filter",
				httpx.FieldError{Field: "filter[site_id]", Code: "invalid", Message: "must be a UUID"})
			return
		}
		if !sc.AllowsSite(id) {
			writeScopeForbidden(w, r, "site filter is outside the caller's scope")
			return
		}
		filter.SiteID = &id
	}
	if raw := query.Get("filter[status]"); raw != "" {
		if !contains(DeviceStatuses, raw) {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid status filter",
				httpx.FieldError{Field: "filter[status]", Code: "invalid", Message: "allowed: " + strings.Join(DeviceStatuses, ", ")})
			return
		}
		filter.Status = &raw
	}
	if raw := query.Get("filter[kind]"); raw != "" {
		filter.Kind = &raw
	}
	filter.Scope = scopeFilter(sc)

	page, err := h.Svc.ListDevices(r.Context(), p.OrgID, filter, limit, query.Get("cursor"))
	if err != nil {
		if errors.Is(err, ErrInvalidCursor) {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid cursor")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "devices lookup failed")
		return
	}
	var statuses map[uuid.UUID]DeviceStatus
	if includeStatus {
		if h.Status == nil {
			httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "service.unavailable", "device status service not configured")
			return
		}
		ids := make([]uuid.UUID, 0, len(page.Devices))
		for _, d := range page.Devices {
			ids = append(ids, d.ID)
		}
		statuses, err = h.Status.DeviceStatuses(r.Context(), p.OrgID, ids)
		if err != nil {
			httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "device status lookup failed")
			return
		}
	}
	data := make([]map[string]any, 0, len(page.Devices))
	for _, d := range page.Devices {
		payload := devicePayload(d)
		if includeStatus {
			// Nested under `poll_status` (not `status`): the device object's
			// `status` field is the M7 inventory lifecycle state and stays
			// backward compatible. The object is identical to
			// GET /v1/devices/{id}/status.
			payload["poll_status"] = statuses[d.ID].Payload()
		}
		data = append(data, payload)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"data":        data,
		"next_cursor": cursorOrNil(page.NextCursor),
		"has_more":    page.HasMore,
	})
}

// parseDeviceListInclude parses the list `include` allowlist. Only `status`
// (the poll-health rollup decoration) is implemented; anything else is a
// validation error, mirroring the canonical unknown-filter rule.
func parseDeviceListInclude(w http.ResponseWriter, r *http.Request, raw string) (includeStatus bool, ok bool) {
	if strings.TrimSpace(raw) == "" {
		return false, true
	}
	for _, part := range strings.Split(raw, ",") {
		switch strings.TrimSpace(part) {
		case "":
			continue
		case "status":
			includeStatus = true
		default:
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid include",
				httpx.FieldError{Field: "include", Code: "invalid", Message: "allowed: status"})
			return false, false
		}
	}
	return includeStatus, true
}

type identityEntry struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type createDeviceRequest struct {
	SiteID      string          `json:"site_id"`
	Name        string          `json:"name"`
	Kind        string          `json:"kind"`
	PollProfile string          `json:"poll_profile"`
	Critical    bool            `json:"critical"`
	SysObjectID *string         `json:"sys_object_id"`
	Serial      *string         `json:"serial"`
	Firmware    *string         `json:"firmware"`
	MgmtIP      *string         `json:"mgmt_ip"`
	Metadata    json.RawMessage `json:"metadata"`
	Identities  []identityEntry `json:"identities"`
}

// CreateDevice handles POST /v1/devices (admin only).
func (h *HTTP) CreateDevice(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	p, _ := httpx.PrincipalFrom(r.Context())
	var req createDeviceRequest
	if !decodeBody(w, r, &req) {
		return
	}
	siteID, err := uuid.Parse(req.SiteID)
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid device",
			httpx.FieldError{Field: "site_id", Code: "required", Message: "site_id is required and must be a UUID"})
		return
	}
	var fieldErrs []httpx.FieldError
	if strings.TrimSpace(req.Name) == "" || len(req.Name) > 200 {
		fieldErrs = append(fieldErrs, httpx.FieldError{Field: "name", Code: "required", Message: "name is required (max 200 chars)"})
	}
	if strings.TrimSpace(req.Kind) == "" {
		fieldErrs = append(fieldErrs, httpx.FieldError{Field: "kind", Code: "required", Message: "kind is required"})
	}
	if req.PollProfile != "" && strings.TrimSpace(req.PollProfile) == "" {
		fieldErrs = append(fieldErrs, httpx.FieldError{Field: "poll_profile", Code: "invalid", Message: "poll_profile must not be blank"})
	}
	if req.MgmtIP != nil && net.ParseIP(*req.MgmtIP) == nil {
		fieldErrs = append(fieldErrs, httpx.FieldError{Field: "mgmt_ip", Code: "invalid", Message: "mgmt_ip must be a valid IP address"})
	}
	if req.Metadata != nil && !validJSONObject(req.Metadata) {
		fieldErrs = append(fieldErrs, httpx.FieldError{Field: "metadata", Code: "invalid", Message: "metadata must be a JSON object"})
	}
	identities := make([]IdentityInput, 0, len(req.Identities))
	for i, e := range req.Identities {
		if !contains(IdentityTypes, e.Type) {
			fieldErrs = append(fieldErrs, httpx.FieldError{
				Field: "identities[" + strconv.Itoa(i) + "].type", Code: "invalid",
				Message: "allowed: " + strings.Join(IdentityTypes, ", "),
			})
			continue
		}
		if strings.TrimSpace(e.Value) == "" {
			fieldErrs = append(fieldErrs, httpx.FieldError{
				Field: "identities[" + strconv.Itoa(i) + "].value", Code: "required", Message: "value is required",
			})
			continue
		}
		identities = append(identities, IdentityInput(e))
	}
	if len(fieldErrs) > 0 {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid device", fieldErrs...)
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	if !sc.AllowsSite(siteID) {
		writeScopeForbidden(w, r, "site is outside the caller's scope")
		return
	}

	created, err := h.Svc.CreateDevice(r.Context(), p.OrgID, CreateDeviceInput{
		SiteID:      siteID,
		Name:        req.Name,
		Kind:        req.Kind,
		PollProfile: req.PollProfile,
		Critical:    req.Critical,
		SysObjectID: req.SysObjectID,
		Serial:      req.Serial,
		Firmware:    req.Firmware,
		MgmtIP:      req.MgmtIP,
		Metadata:    req.Metadata,
		Identities:  identities,
	}, actorFrom(r))
	if err != nil {
		switch {
		case errors.Is(err, ErrSiteNotFound):
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid device",
				httpx.FieldError{Field: "site_id", Code: "invalid", Message: "site_id does not reference a site in this organization"})
		case errors.Is(err, ErrIdentityConflict):
			httpx.WriteProblem(w, r, http.StatusConflict, "device.identity_conflict", "an identity value is already assigned to another live device")
		case errors.Is(err, ErrNameConflict):
			httpx.WriteProblem(w, r, http.StatusConflict, "device.name_conflict", "a device with this name already exists in the site")
		default:
			httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "device create failed")
		}
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, devicePayload(created))
}

// GetDevice handles GET /v1/devices/{id}.
func (h *HTTP) GetDevice(w http.ResponseWriter, r *http.Request) {
	p, ok := principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
		return
	}
	d, err := h.Svc.GetDevice(r.Context(), p.OrgID, id, r.URL.Query().Get("include_deleted") == "true")
	if err != nil {
		if errors.Is(err, ErrDeviceNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "device lookup failed")
		return
	}
	if !sc.AllowsDevice(d.SiteID) {
		httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, devicePayload(d))
}

// devicePatchFields is the PATCH /v1/devices/{id} allowlist.
var devicePatchFields = map[string]bool{
	"name": true, "kind": true, "site_id": true, "status": true, "poll_profile": true, "critical": true,
	"sys_object_id": true, "serial": true, "firmware": true, "mgmt_ip": true, "metadata": true,
}

func patchString(raw map[string]json.RawMessage, field string, errs *[]httpx.FieldError) (string, bool) {
	v, ok := raw[field]
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		*errs = append(*errs, httpx.FieldError{Field: field, Code: "invalid", Message: field + " must be a string"})
		return "", false
	}
	return s, true
}

func patchNullable(raw map[string]json.RawMessage, field string, errs *[]httpx.FieldError) NullableString {
	v, ok := raw[field]
	if !ok {
		return NullableString{}
	}
	if string(v) == "null" {
		return NullableString{Set: true}
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		*errs = append(*errs, httpx.FieldError{Field: field, Code: "invalid", Message: field + " must be a string or null"})
		return NullableString{}
	}
	return NullableString{Set: true, Value: &s}
}

// decodeDevicePatch validates a PATCH body: unknown fields are rejected and
// explicit null clears nullable columns.
func decodeDevicePatch(w http.ResponseWriter, r *http.Request) (DevicePatch, bool) {
	var raw map[string]json.RawMessage
	if !decodeBody(w, r, &raw) {
		return DevicePatch{}, false
	}
	var errs []httpx.FieldError
	for field := range raw {
		if !devicePatchFields[field] {
			errs = append(errs, httpx.FieldError{Field: field, Code: "unknown_field", Message: "field is not updatable"})
		}
	}
	var p DevicePatch
	if name, ok := patchString(raw, "name", &errs); ok {
		if strings.TrimSpace(name) == "" || len(name) > 200 {
			errs = append(errs, httpx.FieldError{Field: "name", Code: "invalid", Message: "name must not be blank (max 200 chars)"})
		} else {
			p.Name, p.HasName = name, true
		}
	}
	if kind, ok := patchString(raw, "kind", &errs); ok {
		if strings.TrimSpace(kind) == "" {
			errs = append(errs, httpx.FieldError{Field: "kind", Code: "invalid", Message: "kind must not be blank"})
		} else {
			p.Kind, p.HasKind = kind, true
		}
	}
	if rawSite, ok := raw["site_id"]; ok {
		var siteID string
		if err := json.Unmarshal(rawSite, &siteID); err != nil {
			errs = append(errs, httpx.FieldError{Field: "site_id", Code: "invalid", Message: "site_id must be a UUID"})
		} else if id, err := uuid.Parse(siteID); err != nil {
			errs = append(errs, httpx.FieldError{Field: "site_id", Code: "invalid", Message: "site_id must be a UUID"})
		} else {
			p.SiteID, p.HasSiteID = id, true
		}
	}
	if status, ok := patchString(raw, "status", &errs); ok {
		if !contains(DeviceStatuses, status) {
			errs = append(errs, httpx.FieldError{Field: "status", Code: "invalid", Message: "allowed: " + strings.Join(DeviceStatuses, ", ")})
		} else {
			p.Status, p.HasStatus = status, true
		}
	}
	if profile, ok := patchString(raw, "poll_profile", &errs); ok {
		if strings.TrimSpace(profile) == "" {
			errs = append(errs, httpx.FieldError{Field: "poll_profile", Code: "invalid", Message: "poll_profile must not be blank"})
		} else {
			p.PollProfile, p.HasPollProfile = profile, true
		}
	}
	if v, ok := raw["critical"]; ok {
		var critical bool
		if err := json.Unmarshal(v, &critical); err != nil {
			errs = append(errs, httpx.FieldError{Field: "critical", Code: "invalid", Message: "critical must be a boolean"})
		} else {
			p.Critical, p.HasCritical = critical, true
		}
	}
	p.SysObjectID = patchNullable(raw, "sys_object_id", &errs)
	p.Serial = patchNullable(raw, "serial", &errs)
	p.Firmware = patchNullable(raw, "firmware", &errs)
	p.MgmtIP = patchNullable(raw, "mgmt_ip", &errs)
	if p.MgmtIP.Set && p.MgmtIP.Value != nil && net.ParseIP(*p.MgmtIP.Value) == nil {
		errs = append(errs, httpx.FieldError{Field: "mgmt_ip", Code: "invalid", Message: "mgmt_ip must be a valid IP address"})
	}
	if v, ok := raw["metadata"]; ok {
		if !validJSONObject(v) {
			errs = append(errs, httpx.FieldError{Field: "metadata", Code: "invalid", Message: "metadata must be a JSON object"})
		} else {
			p.Metadata, p.HasMetadata = v, true
		}
	}
	if len(errs) > 0 {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid device update", errs...)
		return DevicePatch{}, false
	}
	return p, true
}

// UpdateDevice handles PATCH /v1/devices/{id} (admin only).
func (h *HTTP) UpdateDevice(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	p, _ := httpx.PrincipalFrom(r.Context())
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
		return
	}
	patch, ok := decodeDevicePatch(w, r)
	if !ok {
		return
	}
	cur, err := h.Svc.GetDevice(r.Context(), p.OrgID, id, false)
	if err != nil {
		if errors.Is(err, ErrDeviceNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "device lookup failed")
		return
	}
	if !sc.AllowsDevice(cur.SiteID) {
		httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
		return
	}
	// Destination scope (M7-S3 review): a PATCH must not move the device
	// outside the caller's permitted subtree, and a denied move must not
	// mutate anything (the service transaction never starts).
	if patch.HasSiteID && !sc.AllowsSite(patch.SiteID) {
		writeScopeForbidden(w, r, "site is outside the caller's scope")
		return
	}
	updated, err := h.Svc.UpdateDevice(r.Context(), p.OrgID, id, patch, actorFrom(r))
	if err != nil {
		switch {
		case errors.Is(err, ErrDeviceNotFound):
			httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
		case errors.Is(err, ErrSiteNotFound):
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid device update",
				httpx.FieldError{Field: "site_id", Code: "invalid", Message: "site_id does not reference a site in this organization"})
		case errors.Is(err, ErrIdentityConflict):
			httpx.WriteProblem(w, r, http.StatusConflict, "device.identity_conflict", "an identity value is already assigned to another live device")
		case errors.Is(err, ErrNameConflict):
			httpx.WriteProblem(w, r, http.StatusConflict, "device.name_conflict", "a device with this name already exists in the site")
		default:
			httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "device update failed")
		}
		return
	}
	httpx.WriteJSON(w, http.StatusOK, devicePayload(updated))
}

// DeleteDevice handles DELETE /v1/devices/{id} (admin only; soft delete).
func (h *HTTP) DeleteDevice(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	p, _ := httpx.PrincipalFrom(r.Context())
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
		return
	}
	cur, err := h.Svc.GetDevice(r.Context(), p.OrgID, id, false)
	if err != nil {
		if errors.Is(err, ErrDeviceNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "device lookup failed")
		return
	}
	if !sc.AllowsDevice(cur.SiteID) {
		httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
		return
	}
	if err := h.Svc.DeleteDevice(r.Context(), p.OrgID, id, actorFrom(r)); err != nil {
		if errors.Is(err, ErrDeviceNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "device delete failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ListDeviceIdentityHistory handles GET /v1/devices/{id}/identity-history.
func (h *HTTP) ListDeviceIdentityHistory(w http.ResponseWriter, r *http.Request) {
	p, ok := principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
		return
	}
	limit, ok := parseLimit(r)
	if !ok {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "limit must be an integer between 1 and 100")
		return
	}
	d, err := h.Svc.GetDevice(r.Context(), p.OrgID, id, false)
	if err != nil {
		if errors.Is(err, ErrDeviceNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "device lookup failed")
		return
	}
	if !sc.AllowsDevice(d.SiteID) {
		httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
		return
	}
	page, err := h.Svc.ListIdentityHistory(r.Context(), p.OrgID, id, limit, r.URL.Query().Get("cursor"))
	if err != nil {
		switch {
		case errors.Is(err, ErrDeviceNotFound):
			httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
		case errors.Is(err, ErrInvalidCursor):
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid cursor")
		default:
			httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "identity history lookup failed")
		}
		return
	}
	data := make([]map[string]any, 0, len(page.Identities))
	for _, hRow := range page.Identities {
		data = append(data, identityPayload(hRow))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"data":        data,
		"next_cursor": cursorOrNil(page.NextCursor),
		"has_more":    page.HasMore,
	})
}

type mergeRequest struct {
	SourceDeviceIDs []string `json:"source_device_ids"`
	Reason          string   `json:"reason"`
}

// MergeDevice handles POST /v1/devices/{id}/merge (admin only; P2-D7). The
// canonical API spells this /devices/{id}:merge; Go's ServeMux wildcards must
// be complete path segments, so the action is a sub-path.
func (h *HTTP) MergeDevice(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	p, _ := httpx.PrincipalFrom(r.Context())
	targetID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
		return
	}
	var req mergeRequest
	if !decodeBody(w, r, &req) {
		return
	}
	var fieldErrs []httpx.FieldError
	if len(req.SourceDeviceIDs) == 0 {
		fieldErrs = append(fieldErrs, httpx.FieldError{Field: "source_device_ids", Code: "required", Message: "at least one source device is required"})
	}
	sources := make([]uuid.UUID, 0, len(req.SourceDeviceIDs))
	seen := map[uuid.UUID]bool{}
	for i, raw := range req.SourceDeviceIDs {
		id, err := uuid.Parse(raw)
		if err != nil {
			fieldErrs = append(fieldErrs, httpx.FieldError{Field: "source_device_ids[" + strconv.Itoa(i) + "]", Code: "invalid", Message: "must be a UUID"})
			continue
		}
		if id == targetID {
			fieldErrs = append(fieldErrs, httpx.FieldError{Field: "source_device_ids[" + strconv.Itoa(i) + "]", Code: "invalid", Message: "a device cannot be merged into itself"})
			continue
		}
		if seen[id] {
			fieldErrs = append(fieldErrs, httpx.FieldError{Field: "source_device_ids[" + strconv.Itoa(i) + "]", Code: "duplicate", Message: "duplicate source device"})
			continue
		}
		seen[id] = true
		sources = append(sources, id)
	}
	if len(fieldErrs) > 0 {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid merge request", fieldErrs...)
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	// Scope is checked on the target AND every source: a merge must not move
	// out-of-scope devices (foreign ids are uniformly 404, no oracle).
	targetDevice, err := h.Svc.GetDevice(r.Context(), p.OrgID, targetID, false)
	if err != nil {
		if errors.Is(err, ErrDeviceNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "device lookup failed")
		return
	}
	if !sc.AllowsDevice(targetDevice.SiteID) {
		httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
		return
	}
	for _, sourceID := range sources {
		src, err := h.Svc.GetDevice(r.Context(), p.OrgID, sourceID, false)
		if err != nil {
			if errors.Is(err, ErrDeviceNotFound) {
				httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
				return
			}
			httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "device lookup failed")
			return
		}
		if !sc.AllowsDevice(src.SiteID) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
			return
		}
	}
	target, err := h.Svc.MergeDevices(r.Context(), p.OrgID, actorFrom(r), targetID, sources, req.Reason)
	if err != nil {
		switch {
		case errors.Is(err, ErrDeviceNotFound):
			httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
		case errors.Is(err, ErrMergeConflict):
			httpx.WriteProblem(w, r, http.StatusConflict, "device.merge_conflict",
				"merge would collide interfaces with the same if_index; resolve the duplication first")
		case errors.Is(err, ErrIdentityConflict):
			httpx.WriteProblem(w, r, http.StatusConflict, "device.identity_conflict",
				"merge would leave duplicate open identity windows; resolve the conflict first")
		default:
			httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "device merge failed")
		}
		return
	}
	httpx.WriteJSON(w, http.StatusOK, devicePayload(target))
}

type splitRequest struct {
	IdentityHistoryIDs []string `json:"identity_history_ids"`
	Name               string   `json:"name"`
	Kind               string   `json:"kind"`
	SiteID             *string  `json:"site_id"`
	Reason             string   `json:"reason"`
}

// SplitDevice handles POST /v1/devices/{id}/split (admin only; P2-D7).
func (h *HTTP) SplitDevice(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	p, _ := httpx.PrincipalFrom(r.Context())
	sourceID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
		return
	}
	var req splitRequest
	if !decodeBody(w, r, &req) {
		return
	}
	var fieldErrs []httpx.FieldError
	if strings.TrimSpace(req.Name) == "" || len(req.Name) > 200 {
		fieldErrs = append(fieldErrs, httpx.FieldError{Field: "name", Code: "required", Message: "name is required (max 200 chars)"})
	}
	if req.Kind != "" && strings.TrimSpace(req.Kind) == "" {
		fieldErrs = append(fieldErrs, httpx.FieldError{Field: "kind", Code: "invalid", Message: "kind must not be blank"})
	}
	var siteID *uuid.UUID
	if req.SiteID != nil {
		id, err := uuid.Parse(*req.SiteID)
		if err != nil {
			fieldErrs = append(fieldErrs, httpx.FieldError{Field: "site_id", Code: "invalid", Message: "site_id must be a UUID"})
		} else {
			siteID = &id
		}
	}
	if len(req.IdentityHistoryIDs) == 0 {
		fieldErrs = append(fieldErrs, httpx.FieldError{Field: "identity_history_ids", Code: "required", Message: "at least one identity history row is required"})
	}
	identityIDs := make([]uuid.UUID, 0, len(req.IdentityHistoryIDs))
	seen := map[uuid.UUID]bool{}
	for i, raw := range req.IdentityHistoryIDs {
		id, err := uuid.Parse(raw)
		if err != nil {
			fieldErrs = append(fieldErrs, httpx.FieldError{Field: "identity_history_ids[" + strconv.Itoa(i) + "]", Code: "invalid", Message: "must be a UUID"})
			continue
		}
		if seen[id] {
			fieldErrs = append(fieldErrs, httpx.FieldError{Field: "identity_history_ids[" + strconv.Itoa(i) + "]", Code: "duplicate", Message: "duplicate identity history row"})
			continue
		}
		seen[id] = true
		identityIDs = append(identityIDs, id)
	}
	if len(fieldErrs) > 0 {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid split request", fieldErrs...)
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	src, err := h.Svc.GetDevice(r.Context(), p.OrgID, sourceID, false)
	if err != nil {
		if errors.Is(err, ErrDeviceNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "device lookup failed")
		return
	}
	if !sc.AllowsDevice(src.SiteID) {
		httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
		return
	}
	if siteID != nil && !sc.AllowsSite(*siteID) {
		writeScopeForbidden(w, r, "split target site is outside the caller's scope")
		return
	}
	created, err := h.Svc.SplitDevice(r.Context(), p.OrgID, actorFrom(r), sourceID, identityIDs, req.Name, req.Kind, siteID, req.Reason)
	if err != nil {
		switch {
		case errors.Is(err, ErrDeviceNotFound):
			httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
		case errors.Is(err, ErrIdentityNotFound):
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid split request",
				httpx.FieldError{Field: "identity_history_ids", Code: "invalid", Message: "identity history rows must belong to the source device"})
		case errors.Is(err, ErrSiteNotFound):
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid split request",
				httpx.FieldError{Field: "site_id", Code: "invalid", Message: "site_id does not reference a site in this organization"})
		case errors.Is(err, ErrIdentityConflict):
			httpx.WriteProblem(w, r, http.StatusConflict, "device.identity_conflict", "an identity value is already assigned to another live device")
		case errors.Is(err, ErrNameConflict):
			httpx.WriteProblem(w, r, http.StatusConflict, "device.name_conflict", "a device with this name already exists in the site")
		default:
			httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "device split failed")
		}
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, devicePayload(created))
}

type createInterfaceRequest struct {
	IfIndex     int     `json:"if_index"`
	IfName      string  `json:"if_name"`
	IfAlias     *string `json:"if_alias"`
	IfType      *int    `json:"if_type"`
	AdminStatus *string `json:"admin_status"`
	OperStatus  *string `json:"oper_status"`
	SpeedBPS    *int64  `json:"speed_bps"`
	MTU         *int    `json:"mtu"`
	MAC         *string `json:"mac"`
	Description *string `json:"description"`
	Role        string  `json:"role"`
	Monitored   *bool   `json:"monitored"`
}

// ListDeviceInterfaces handles GET /v1/devices/{id}/interfaces.
func (h *HTTP) ListDeviceInterfaces(w http.ResponseWriter, r *http.Request) {
	p, ok := principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	deviceID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
		return
	}
	limit, ok := parseLimit(r)
	if !ok {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "limit must be an integer between 1 and 100")
		return
	}
	d, err := h.Svc.GetDevice(r.Context(), p.OrgID, deviceID, false)
	if err != nil {
		if errors.Is(err, ErrDeviceNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "device lookup failed")
		return
	}
	if !sc.AllowsDevice(d.SiteID) {
		httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
		return
	}
	page, err := h.Svc.ListInterfaces(r.Context(), p.OrgID, deviceID, limit, r.URL.Query().Get("cursor"))
	if err != nil {
		switch {
		case errors.Is(err, ErrDeviceNotFound):
			httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
		case errors.Is(err, ErrInvalidCursor):
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid cursor")
		default:
			httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "interfaces lookup failed")
		}
		return
	}
	data := make([]map[string]any, 0, len(page.Interfaces))
	for _, i := range page.Interfaces {
		data = append(data, interfacePayload(i))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"data":        data,
		"next_cursor": cursorOrNil(page.NextCursor),
		"has_more":    page.HasMore,
	})
}

// CreateDeviceInterface handles POST /v1/devices/{id}/interfaces (admin only).
func (h *HTTP) CreateDeviceInterface(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	p, _ := httpx.PrincipalFrom(r.Context())
	deviceID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
		return
	}
	var req createInterfaceRequest
	if !decodeBody(w, r, &req) {
		return
	}
	var fieldErrs []httpx.FieldError
	if req.IfIndex < 1 {
		fieldErrs = append(fieldErrs, httpx.FieldError{Field: "if_index", Code: "invalid", Message: "if_index must be a positive integer"})
	}
	if strings.TrimSpace(req.IfName) == "" {
		fieldErrs = append(fieldErrs, httpx.FieldError{Field: "if_name", Code: "required", Message: "if_name is required"})
	}
	if req.Role != "" && !contains(InterfaceRoles, req.Role) {
		fieldErrs = append(fieldErrs, httpx.FieldError{Field: "role", Code: "invalid", Message: "allowed: " + strings.Join(InterfaceRoles, ", ")})
	}
	if req.SpeedBPS != nil && *req.SpeedBPS < 0 {
		fieldErrs = append(fieldErrs, httpx.FieldError{Field: "speed_bps", Code: "invalid", Message: "speed_bps must not be negative"})
	}
	if req.MTU != nil && *req.MTU < 0 {
		fieldErrs = append(fieldErrs, httpx.FieldError{Field: "mtu", Code: "invalid", Message: "mtu must not be negative"})
	}
	if req.MAC != nil {
		if _, err := net.ParseMAC(*req.MAC); err != nil {
			fieldErrs = append(fieldErrs, httpx.FieldError{Field: "mac", Code: "invalid", Message: "mac must be a MAC address"})
		}
	}
	if len(fieldErrs) > 0 {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid interface", fieldErrs...)
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	dev, err := h.Svc.GetDevice(r.Context(), p.OrgID, deviceID, false)
	if err != nil {
		if errors.Is(err, ErrDeviceNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "device lookup failed")
		return
	}
	if !sc.AllowsDevice(dev.SiteID) {
		httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
		return
	}
	created, err := h.Svc.CreateInterface(r.Context(), p.OrgID, deviceID, CreateInterfaceInput(req), actorFrom(r))
	if err != nil {
		switch {
		case errors.Is(err, ErrDeviceNotFound):
			httpx.WriteProblem(w, r, http.StatusNotFound, "device.not_found", "device not found")
		case errors.Is(err, ErrIFIndexConflict):
			httpx.WriteProblem(w, r, http.StatusConflict, "interface.if_index_conflict", "an interface with this if_index already exists on the device")
		default:
			httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "interface create failed")
		}
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, interfacePayload(created))
}

// GetInterface handles GET /v1/interfaces/{id}.
func (h *HTTP) GetInterface(w http.ResponseWriter, r *http.Request) {
	p, ok := principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "interface.not_found", "interface not found")
		return
	}
	i, err := h.Svc.GetInterface(r.Context(), p.OrgID, id)
	if err != nil {
		if errors.Is(err, ErrInterfaceNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "interface.not_found", "interface not found")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "interface lookup failed")
		return
	}
	if !h.interfaceInScope(w, r, p, sc, i) {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, interfacePayload(i))
}

// interfacePatchFields is the PATCH /v1/interfaces/{id} allowlist (editable
// metadata; if_index is the immutable SNMP identity key).
var interfacePatchFields = map[string]bool{
	"if_name": true, "if_alias": true, "if_type": true, "admin_status": true, "oper_status": true,
	"speed_bps": true, "mtu": true, "mac": true, "description": true, "role": true, "monitored": true,
}

func patchInt(raw map[string]json.RawMessage, field string, errs *[]httpx.FieldError) (int, bool) {
	v, ok := raw[field]
	if !ok {
		return 0, false
	}
	var n int
	if err := json.Unmarshal(v, &n); err != nil {
		*errs = append(*errs, httpx.FieldError{Field: field, Code: "invalid", Message: field + " must be an integer"})
		return 0, false
	}
	return n, true
}

func patchBool(raw map[string]json.RawMessage, field string, errs *[]httpx.FieldError) (bool, bool) {
	v, ok := raw[field]
	if !ok {
		return false, false
	}
	var b bool
	if err := json.Unmarshal(v, &b); err != nil {
		*errs = append(*errs, httpx.FieldError{Field: field, Code: "invalid", Message: field + " must be a boolean"})
		return false, false
	}
	return b, true
}

func decodeInterfacePatch(w http.ResponseWriter, r *http.Request) (InterfacePatch, bool) {
	var raw map[string]json.RawMessage
	if !decodeBody(w, r, &raw) {
		return InterfacePatch{}, false
	}
	var errs []httpx.FieldError
	for field := range raw {
		if !interfacePatchFields[field] {
			errs = append(errs, httpx.FieldError{Field: field, Code: "unknown_field", Message: "field is not updatable"})
		}
	}
	var p InterfacePatch
	if name, ok := patchString(raw, "if_name", &errs); ok {
		if strings.TrimSpace(name) == "" {
			errs = append(errs, httpx.FieldError{Field: "if_name", Code: "invalid", Message: "if_name must not be blank"})
		} else {
			p.IfName = &name
		}
	}
	p.IfAlias = patchNullable(raw, "if_alias", &errs)
	if n, ok := patchInt(raw, "if_type", &errs); ok {
		if n < 0 {
			errs = append(errs, httpx.FieldError{Field: "if_type", Code: "invalid", Message: "if_type must not be negative"})
		} else {
			p.IfType = &n
		}
	}
	p.AdminStatus = patchNullable(raw, "admin_status", &errs)
	p.OperStatus = patchNullable(raw, "oper_status", &errs)
	if v, ok := raw["speed_bps"]; ok {
		var n int64
		if err := json.Unmarshal(v, &n); err != nil || n < 0 {
			errs = append(errs, httpx.FieldError{Field: "speed_bps", Code: "invalid", Message: "speed_bps must be a non-negative integer"})
		} else {
			p.SpeedBPS = &n
		}
	}
	if n, ok := patchInt(raw, "mtu", &errs); ok {
		if n < 0 {
			errs = append(errs, httpx.FieldError{Field: "mtu", Code: "invalid", Message: "mtu must not be negative"})
		} else {
			p.MTU = &n
		}
	}
	p.MAC = patchNullable(raw, "mac", &errs)
	if p.MAC.Set && p.MAC.Value != nil {
		if _, err := net.ParseMAC(*p.MAC.Value); err != nil {
			errs = append(errs, httpx.FieldError{Field: "mac", Code: "invalid", Message: "mac must be a MAC address"})
		}
	}
	p.Description = patchNullable(raw, "description", &errs)
	if role, ok := patchString(raw, "role", &errs); ok {
		if !contains(InterfaceRoles, role) {
			errs = append(errs, httpx.FieldError{Field: "role", Code: "invalid", Message: "allowed: " + strings.Join(InterfaceRoles, ", ")})
		} else {
			p.Role = &role
		}
	}
	if monitored, ok := patchBool(raw, "monitored", &errs); ok {
		p.Monitored = &monitored
	}
	if len(errs) > 0 {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid interface update", errs...)
		return InterfacePatch{}, false
	}
	return p, true
}

// UpdateInterface handles PATCH /v1/interfaces/{id} (admin only).
func (h *HTTP) UpdateInterface(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	p, _ := httpx.PrincipalFrom(r.Context())
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "interface.not_found", "interface not found")
		return
	}
	patch, ok := decodeInterfacePatch(w, r)
	if !ok {
		return
	}
	cur, err := h.Svc.GetInterface(r.Context(), p.OrgID, id)
	if err != nil {
		if errors.Is(err, ErrInterfaceNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "interface.not_found", "interface not found")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "interface lookup failed")
		return
	}
	if !h.interfaceInScope(w, r, p, sc, cur) {
		return
	}
	updated, err := h.Svc.UpdateInterface(r.Context(), p.OrgID, id, patch, actorFrom(r))
	if err != nil {
		if errors.Is(err, ErrInterfaceNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "interface.not_found", "interface not found")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "interface update failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, interfacePayload(updated))
}

// DeleteInterface handles DELETE /v1/interfaces/{id} (admin only; hard delete,
// the 000008 shape has no deleted_at column).
func (h *HTTP) DeleteInterface(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	p, _ := httpx.PrincipalFrom(r.Context())
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "interface.not_found", "interface not found")
		return
	}
	cur, err := h.Svc.GetInterface(r.Context(), p.OrgID, id)
	if err != nil {
		if errors.Is(err, ErrInterfaceNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "interface.not_found", "interface not found")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "interface lookup failed")
		return
	}
	if !h.interfaceInScope(w, r, p, sc, cur) {
		return
	}
	if err := h.Svc.DeleteInterface(r.Context(), p.OrgID, id, actorFrom(r)); err != nil {
		if errors.Is(err, ErrInterfaceNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "interface.not_found", "interface not found")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "interface delete failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type createGroupRequest struct {
	Name     string          `json:"name"`
	Selector json.RawMessage `json:"selector"`
}

// ListDeviceGroups handles GET /v1/device-groups.
func (h *HTTP) ListDeviceGroups(w http.ResponseWriter, r *http.Request) {
	p, ok := principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	limit, ok := parseLimit(r)
	if !ok {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "limit must be an integer between 1 and 100")
		return
	}
	page, err := h.Svc.ListGroups(r.Context(), p.OrgID, scopeFilter(sc), limit, r.URL.Query().Get("cursor"))
	if err != nil {
		if errors.Is(err, ErrInvalidCursor) {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid cursor")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "device groups lookup failed")
		return
	}
	data := make([]map[string]any, 0, len(page.Groups))
	for _, g := range page.Groups {
		data = append(data, groupPayload(g))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"data":        data,
		"next_cursor": cursorOrNil(page.NextCursor),
		"has_more":    page.HasMore,
	})
}

// CreateDeviceGroup handles POST /v1/device-groups (admin only).
func (h *HTTP) CreateDeviceGroup(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	p, _ := httpx.PrincipalFrom(r.Context())
	var req createGroupRequest
	if !decodeBody(w, r, &req) {
		return
	}
	var fieldErrs []httpx.FieldError
	if strings.TrimSpace(req.Name) == "" || len(req.Name) > 200 {
		fieldErrs = append(fieldErrs, httpx.FieldError{Field: "name", Code: "required", Message: "name is required (max 200 chars)"})
	}
	if req.Selector != nil && !validJSONObject(req.Selector) {
		fieldErrs = append(fieldErrs, httpx.FieldError{Field: "selector", Code: "invalid", Message: "selector must be a JSON object"})
	}
	if len(fieldErrs) > 0 {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid device group", fieldErrs...)
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	if !sc.Unrestricted {
		writeScopeForbidden(w, r, "creating a device group requires org-wide scope")
		return
	}
	created, err := h.Svc.CreateGroup(r.Context(), p.OrgID, CreateGroupInput(req), actorFrom(r))
	if err != nil {
		if errors.Is(err, ErrNameConflict) {
			httpx.WriteProblem(w, r, http.StatusConflict, "device_group.name_conflict", "a device group with this name already exists")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "device group create failed")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, groupPayload(created))
}

// GetDeviceGroup handles GET /v1/device-groups/{id}.
func (h *HTTP) GetDeviceGroup(w http.ResponseWriter, r *http.Request) {
	p, ok := principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "device_group.not_found", "device group not found")
		return
	}
	g, err := h.Svc.GetGroup(r.Context(), p.OrgID, id)
	if err != nil {
		if errors.Is(err, ErrGroupNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "device_group.not_found", "device group not found")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "device group lookup failed")
		return
	}
	if !sc.AllowsDeviceGroup(g.ID) {
		httpx.WriteProblem(w, r, http.StatusNotFound, "device_group.not_found", "device group not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, groupPayload(g))
}

// groupPatchFields is the PATCH /v1/device-groups/{id} allowlist.
var groupPatchFields = map[string]bool{"name": true, "selector": true}

// UpdateDeviceGroup handles PATCH /v1/device-groups/{id} (admin only).
func (h *HTTP) UpdateDeviceGroup(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	p, _ := httpx.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "device_group.not_found", "device group not found")
		return
	}
	var raw map[string]json.RawMessage
	if !decodeBody(w, r, &raw) {
		return
	}
	var errs []httpx.FieldError
	for field := range raw {
		if !groupPatchFields[field] {
			errs = append(errs, httpx.FieldError{Field: field, Code: "unknown_field", Message: "field is not updatable"})
		}
	}
	var patch GroupPatch
	if name, ok := patchString(raw, "name", &errs); ok {
		if strings.TrimSpace(name) == "" || len(name) > 200 {
			errs = append(errs, httpx.FieldError{Field: "name", Code: "invalid", Message: "name must not be blank (max 200 chars)"})
		} else {
			patch.Name = &name
		}
	}
	if v, ok := raw["selector"]; ok {
		if !validJSONObject(v) {
			errs = append(errs, httpx.FieldError{Field: "selector", Code: "invalid", Message: "selector must be a JSON object"})
		} else {
			patch.Selector, patch.HasSelector = v, true
		}
	}
	if len(errs) > 0 {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid device group update", errs...)
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	cur, err := h.Svc.GetGroup(r.Context(), p.OrgID, id)
	if err != nil {
		if errors.Is(err, ErrGroupNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "device_group.not_found", "device group not found")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "device group lookup failed")
		return
	}
	if !sc.AllowsDeviceGroup(cur.ID) {
		httpx.WriteProblem(w, r, http.StatusNotFound, "device_group.not_found", "device group not found")
		return
	}
	updated, err := h.Svc.UpdateGroup(r.Context(), p.OrgID, id, patch, actorFrom(r))
	if err != nil {
		switch {
		case errors.Is(err, ErrGroupNotFound):
			httpx.WriteProblem(w, r, http.StatusNotFound, "device_group.not_found", "device group not found")
		case errors.Is(err, ErrNameConflict):
			httpx.WriteProblem(w, r, http.StatusConflict, "device_group.name_conflict", "a device group with this name already exists")
		default:
			httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "device group update failed")
		}
		return
	}
	httpx.WriteJSON(w, http.StatusOK, groupPayload(updated))
}

// DeleteDeviceGroup handles DELETE /v1/device-groups/{id} (admin only).
func (h *HTTP) DeleteDeviceGroup(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	p, _ := httpx.PrincipalFrom(r.Context())
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "device_group.not_found", "device group not found")
		return
	}
	cur, err := h.Svc.GetGroup(r.Context(), p.OrgID, id)
	if err != nil {
		if errors.Is(err, ErrGroupNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "device_group.not_found", "device group not found")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "device group lookup failed")
		return
	}
	if !sc.AllowsDeviceGroup(cur.ID) {
		httpx.WriteProblem(w, r, http.StatusNotFound, "device_group.not_found", "device group not found")
		return
	}
	if err := h.Svc.DeleteGroup(r.Context(), p.OrgID, id, actorFrom(r)); err != nil {
		if errors.Is(err, ErrGroupNotFound) {
			httpx.WriteProblem(w, r, http.StatusNotFound, "device_group.not_found", "device group not found")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "device group delete failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
