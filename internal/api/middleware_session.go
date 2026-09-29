package api

import (
	"net/http"

	"github.com/argus-platform/argus/internal/platform/httpx"
	"github.com/argus-platform/argus/internal/platform/security"
)

// requireSession resolves the session cookie into a principal. Invalid,
// expired, or revoked sessions are uniformly 401 (no detail leakage).
func (h *handlers) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.o.Identity == nil {
			serviceUnavailable(w, r, "identity service not configured")
			return
		}
		auth, err := h.o.Identity.Authenticate(r.Context(), httpx.SessionCookie(r))
		if err != nil {
			httpx.WriteProblem(w, r, http.StatusUnauthorized, "auth.unauthenticated", "authentication required")
			return
		}
		p := httpx.Principal{
			UserID:    auth.User.ID,
			OrgID:     auth.User.OrgID,
			SessionID: auth.Session.ID,
			Email:     auth.User.Email,
			Role:      auth.User.Role,
			CSRFHash:  auth.Session.CSRFHash,
		}
		next.ServeHTTP(w, r.WithContext(httpx.WithPrincipal(r.Context(), p)))
	})
}

// requireCSRF validates the double-submit pair against the session's stored
// fingerprint. Must run AFTER requireSession (needs the principal).
func (h *handlers) requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := httpx.PrincipalFrom(r.Context())
		if !ok {
			httpx.WriteProblem(w, r, http.StatusUnauthorized, "auth.unauthenticated", "authentication required")
			return
		}
		if !security.VerifyCSRF(httpx.CSRFCookie(r), r.Header.Get(httpx.CSRFHeaderName), p.CSRFHash) {
			httpx.WriteProblem(w, r, http.StatusForbidden, "auth.csrf", "CSRF token missing or invalid")
			return
		}
		next.ServeHTTP(w, r)
	})
}
