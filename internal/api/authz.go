package api

import (
	"net/http"

	"github.com/argus-platform/argus/internal/platform/authz"
	"github.com/argus-platform/argus/internal/platform/httpx"
)

// requireCapability enforces the route's declared capability (P2-D5) using the
// Phase-1 role model (admin: all inventory capabilities; viewer: reads only).
// It runs INSIDE the session middleware and, for mutations, inside CSRF
// verification, so capabilities are strictly in addition to the existing
// session/CSRF/admin protections. Denials are deterministic 403 problem+json.
func (h *handlers) requireCapability(capability string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := httpx.PrincipalFrom(r.Context())
		if !ok {
			httpx.WriteProblem(w, r, http.StatusUnauthorized, "auth.unauthenticated", "authentication required")
			return
		}
		if !authz.Allowed(p.Role, capability) {
			httpx.WriteProblem(w, r, http.StatusForbidden, "auth.forbidden", "insufficient capability: "+capability)
			return
		}
		next.ServeHTTP(w, r)
	})
}
