package credentials

import (
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/platform/authz"
	"github.com/argus-platform/argus/internal/platform/httpx"
)

// HTTP exposes the credential API. Reads require a session; mutations require
// the admin role, CSRF, and the enforced capability. Capability enforcement
// runs in the router (route metadata); scope enforcement runs here after the
// caller's server-side scope bindings are resolved.
//
// The surface is write-only by construction: no handler, response type, or
// query reads secret material back. The only secret field in the entire API is
// the request-side `secret` on create/rotate; it is sealed before any response
// is written.
type HTTP struct {
	Svc *Service
}

// maxBodyBytes bounds credential request bodies; secret values are small
// (SNMP communities, SSH passwords, v3 auth keys).
const maxBodyBytes = 64 << 10

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

// requireOrgScope gates the credential surface: credential profiles are
// org-level objects (device_credentials has no site column) whose bindings may
// target any scope, so managing them requires an org-wide caller. A caller
// with scope bindings is denied deterministically (mirrors the device-group
// create rule from M7-S3).
func requireOrgScope(w http.ResponseWriter, r *http.Request, sc authz.Scope) bool {
	if !sc.Unrestricted {
		httpx.WriteProblem(w, r, http.StatusForbidden, "auth.forbidden", "credential management requires org-wide scope")
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

func cursorOrNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// writeServiceError maps module sentinels to deterministic problem+json. The
// detail strings never include request values (no secret material can reach an
// error message).
func writeServiceError(w http.ResponseWriter, r *http.Request, err error, fallback string) {
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.WriteProblem(w, r, http.StatusNotFound, "credential.not_found", "credential not found")
	case errors.Is(err, ErrBindingNotFound):
		httpx.WriteProblem(w, r, http.StatusNotFound, "credential.binding_not_found", "binding not found")
	case errors.Is(err, ErrTargetNotFound):
		httpx.WriteProblem(w, r, http.StatusNotFound, "credential.target_not_found", "binding target not found")
	case errors.Is(err, ErrNameConflict):
		httpx.WriteProblem(w, r, http.StatusConflict, "credential.name_conflict", "a credential with this name already exists")
	case errors.Is(err, ErrBindingConflict):
		httpx.WriteProblem(w, r, http.StatusConflict, "credential.binding_conflict", "this credential is already bound to the scope target")
	case errors.Is(err, ErrInvalidScope):
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid scope type",
			httpx.FieldError{Field: "scope_type", Code: "invalid", Message: "allowed: " + strings.Join(ScopeTypes, ", ")})
	case errors.Is(err, ErrValidation):
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid credential request")
	case errors.Is(err, ErrInvalidCursor):
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid cursor")
	case errors.Is(err, ErrVaultUnavailable):
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "service.unavailable", "secrets vault not configured")
	default:
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", fallback)
	}
}

// ListCredentials handles GET /v1/credentials (metadata only).
func (h *HTTP) ListCredentials(w http.ResponseWriter, r *http.Request) {
	p, ok := principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	if !requireOrgScope(w, r, sc) {
		return
	}
	limit, ok := parseLimit(r)
	if !ok {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "limit must be an integer between 1 and 100")
		return
	}
	order := r.URL.Query().Get("order")
	if order != "" && order != "asc" && order != "desc" {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid order",
			httpx.FieldError{Field: "order", Code: "invalid", Message: "allowed: asc, desc"})
		return
	}
	items, nextCursor, hasMore, err := h.Svc.List(r.Context(), p.OrgID, limit, r.URL.Query().Get("cursor"), order == "desc")
	if err != nil {
		writeServiceError(w, r, err, "credentials lookup failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"data":        items,
		"next_cursor": cursorOrNil(nextCursor),
		"has_more":    hasMore,
	})
}

type createRequest struct {
	Name     string          `json:"name"`
	Kind     string          `json:"kind"`
	Secret   string          `json:"secret"`
	Metadata json.RawMessage `json:"metadata"`
}

// validateCreateRequest validates a create body (the secret is required and
// must never be echoed back in an error).
func validateCreateRequest(req createRequest) []httpx.FieldError {
	var fieldErrs []httpx.FieldError
	if strings.TrimSpace(req.Name) == "" || len(req.Name) > 200 {
		fieldErrs = append(fieldErrs, httpx.FieldError{Field: "name", Code: "required", Message: "name is required (max 200 chars)"})
	}
	if strings.TrimSpace(req.Kind) == "" {
		fieldErrs = append(fieldErrs, httpx.FieldError{Field: "kind", Code: "required", Message: "kind is required"})
	}
	if req.Secret == "" {
		fieldErrs = append(fieldErrs, httpx.FieldError{Field: "secret", Code: "required", Message: "secret is required and is never returned"})
	}
	if req.Metadata != nil && !validJSONObject(req.Metadata) {
		fieldErrs = append(fieldErrs, httpx.FieldError{Field: "metadata", Code: "invalid", Message: "metadata must be a JSON object"})
	}
	return fieldErrs
}

// CreateCredential handles POST /v1/credentials. The secret is sealed by the
// vault; the response carries metadata only.
func (h *HTTP) CreateCredential(w http.ResponseWriter, r *http.Request) {
	p, ok := principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	if !requireOrgScope(w, r, sc) {
		return
	}
	var req createRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if fieldErrs := validateCreateRequest(req); len(fieldErrs) > 0 {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid credential", fieldErrs...)
		return
	}
	created, err := h.Svc.Create(r.Context(), p.OrgID, CreateInput{
		Name:     req.Name,
		Kind:     req.Kind,
		Secret:   []byte(req.Secret),
		Metadata: req.Metadata,
	}, actorFrom(r))
	if err != nil {
		writeServiceError(w, r, err, "credential create failed")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, created)
}

// GetCredential handles GET /v1/credentials/{id} (metadata only).
func (h *HTTP) GetCredential(w http.ResponseWriter, r *http.Request) {
	p, ok := principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	if !requireOrgScope(w, r, sc) {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "credential.not_found", "credential not found")
		return
	}
	meta, err := h.Svc.Get(r.Context(), p.OrgID, id)
	if err != nil {
		writeServiceError(w, r, err, "credential lookup failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, meta)
}

type rotateRequest struct {
	Secret string `json:"secret"`
}

// RotateCredential handles POST /v1/credentials/{id}/rotate: the stored
// envelope is replaced atomically; the response is metadata only.
func (h *HTTP) RotateCredential(w http.ResponseWriter, r *http.Request) {
	p, ok := principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	if !requireOrgScope(w, r, sc) {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "credential.not_found", "credential not found")
		return
	}
	var req rotateRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Secret == "" {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid credential rotation",
			httpx.FieldError{Field: "secret", Code: "required", Message: "secret is required and is never returned"})
		return
	}
	updated, err := h.Svc.Rotate(r.Context(), p.OrgID, id, []byte(req.Secret), actorFrom(r))
	if err != nil {
		writeServiceError(w, r, err, "credential rotation failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, updated)
}

type bindRequest struct {
	ScopeType string `json:"scope_type"`
	ScopeID   string `json:"scope_id"`
	Priority  *int   `json:"priority"`
}

// BindCredential handles POST /v1/credentials/{id}/bind. The target is
// resolved server-side; foreign/unknown targets are uniformly 404 with no
// existence oracle.
func (h *HTTP) BindCredential(w http.ResponseWriter, r *http.Request) {
	p, ok := principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	if !requireOrgScope(w, r, sc) {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "credential.not_found", "credential not found")
		return
	}
	var req bindRequest
	if !decodeBody(w, r, &req) {
		return
	}
	scopeID, ok := validateBindingRequest(w, r, req.ScopeType, req.ScopeID, req.Priority, "bind")
	if !ok {
		return
	}
	binding, err := h.Svc.Bind(r.Context(), p.OrgID, id, req.ScopeType, scopeID, priorityOrZero(req.Priority), actorFrom(r))
	if err != nil {
		writeServiceError(w, r, err, "credential bind failed")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, ProjectBinding(binding))
}

type unbindRequest struct {
	ScopeType string `json:"scope_type"`
	ScopeID   string `json:"scope_id"`
}

// UnbindCredential handles POST /v1/credentials/{id}/unbind (204 on success).
func (h *HTTP) UnbindCredential(w http.ResponseWriter, r *http.Request) {
	p, ok := principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}
	if !requireOrgScope(w, r, sc) {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "credential.not_found", "credential not found")
		return
	}
	var req unbindRequest
	if !decodeBody(w, r, &req) {
		return
	}
	scopeID, ok := validateBindingRequest(w, r, req.ScopeType, req.ScopeID, nil, "unbind")
	if !ok {
		return
	}
	if err := h.Svc.Unbind(r.Context(), p.OrgID, id, req.ScopeType, scopeID, actorFrom(r)); err != nil {
		writeServiceError(w, r, err, "credential unbind failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// validateBindingRequest validates a bind/unbind body. The anonymous priority
// (nil on unbind) is validated only when present; int32 bounds mirror the
// credential_bindings column type.
func validateBindingRequest(w http.ResponseWriter, r *http.Request, scopeType, scopeID string, priority *int, action string) (uuid.UUID, bool) {
	var fieldErrs []httpx.FieldError
	if !IsScopeType(scopeType) {
		fieldErrs = append(fieldErrs, httpx.FieldError{Field: "scope_type", Code: "invalid", Message: "allowed: " + strings.Join(ScopeTypes, ", ")})
	}
	id, err := uuid.Parse(scopeID)
	if err != nil {
		fieldErrs = append(fieldErrs, httpx.FieldError{Field: "scope_id", Code: "invalid", Message: "scope_id must be a UUID"})
	}
	if priority != nil && (*priority > math.MaxInt32 || *priority < math.MinInt32) {
		fieldErrs = append(fieldErrs, httpx.FieldError{Field: "priority", Code: "invalid", Message: "priority must be a 32-bit integer"})
	}
	if len(fieldErrs) > 0 {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid credential "+action+" request", fieldErrs...)
		return uuid.Nil, false
	}
	return id, true
}

func priorityOrZero(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}
