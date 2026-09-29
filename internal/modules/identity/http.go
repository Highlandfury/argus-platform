package identity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/platform/httpx"
)

// HTTP exposes login/logout/me handlers. The api package guarantees a
// principal on logout/me (session middleware) and wires OrgLookup.
type HTTP struct {
	Svc           *Service
	SecureCookies bool
	OrgLookup     func(ctx context.Context, orgID uuid.UUID) (httpx.PublicOrg, error)
}

type loginRequest struct {
	OrgSlug  string `json:"org_slug"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Login handles POST /v1/auth/login.
func (h *HTTP) Login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "request body must be JSON")
		return
	}
	var fieldErrs []httpx.FieldError
	if req.OrgSlug == "" {
		fieldErrs = append(fieldErrs, httpx.FieldError{Field: "org_slug", Code: "required", Message: "organization slug is required"})
	}
	if req.Email == "" {
		fieldErrs = append(fieldErrs, httpx.FieldError{Field: "email", Code: "required", Message: "email is required"})
	}
	if req.Password == "" {
		fieldErrs = append(fieldErrs, httpx.FieldError{Field: "password", Code: "required", Message: "password is required"})
	}
	if len(fieldErrs) > 0 {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "missing fields", fieldErrs...)
		return
	}

	res, err := h.Svc.Login(r.Context(), req.OrgSlug, req.Email, req.Password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			httpx.WriteProblem(w, r, http.StatusUnauthorized, "auth.invalid_credentials", "email or password is incorrect")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "login failed")
		return
	}

	httpx.SetSessionCookies(w, res.RawToken, res.RawCSRF, res.ExpiresAt, h.SecureCookies)
	httpx.WriteJSON(w, http.StatusOK, httpx.MePayload{
		User: httpx.PublicUser{ID: res.User.ID.String(), Email: res.User.Email, Role: res.User.Role},
		Org:  httpx.PublicOrg(res.Org),
	})
}

// Logout handles POST /v1/auth/logout (session + CSRF enforced upstream).
func (h *HTTP) Logout(w http.ResponseWriter, r *http.Request) {
	p, ok := httpx.PrincipalFrom(r.Context())
	if !ok {
		httpx.WriteProblem(w, r, http.StatusUnauthorized, "auth.unauthenticated", "authentication required")
		return
	}
	if err := h.Svc.Logout(r.Context(), p.SessionID); err != nil {
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "logout failed")
		return
	}
	httpx.ClearSessionCookies(w, h.SecureCookies)
	w.WriteHeader(http.StatusNoContent)
}

// Me handles GET /v1/me via the authenticated principal. The organization
// lookup runs through the tenant-scoped path (app role + RLS).
func (h *HTTP) Me(w http.ResponseWriter, r *http.Request) {
	p, ok := httpx.PrincipalFrom(r.Context())
	if !ok {
		httpx.WriteProblem(w, r, http.StatusUnauthorized, "auth.unauthenticated", "authentication required")
		return
	}
	if h.OrgLookup == nil {
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "service.unavailable", "tenancy service not configured")
		return
	}
	org, err := h.OrgLookup(r.Context(), p.OrgID)
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "organization lookup failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.MePayload{
		User: httpx.PublicUser{ID: p.UserID.String(), Email: p.Email, Role: p.Role},
		Org:  org,
	})
}
