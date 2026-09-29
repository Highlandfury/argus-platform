package tenancy

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/argus-platform/argus/internal/platform/httpx"
)

// HTTP exposes tenancy read handlers. All routes sit behind session auth.
type HTTP struct {
	Svc *Service
}

// ListSites handles GET /v1/sites with limit/cursor pagination.
func (h *HTTP) ListSites(w http.ResponseWriter, r *http.Request) {
	p, ok := httpx.PrincipalFrom(r.Context())
	if !ok {
		httpx.WriteProblem(w, r, http.StatusUnauthorized, "auth.unauthenticated", "authentication required")
		return
	}

	limit := 25
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 100 {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "limit must be an integer between 1 and 100")
			return
		}
		limit = n
	}

	page, err := h.Svc.ListSitesPage(r.Context(), p.OrgID, limit, r.URL.Query().Get("cursor"))
	if err != nil {
		if errors.Is(err, ErrInvalidCursor) {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "invalid cursor")
			return
		}
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "sites lookup failed")
		return
	}

	data := make([]map[string]string, 0, len(page.Sites))
	for _, s := range page.Sites {
		data = append(data, map[string]string{"id": s.ID, "name": s.Name})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"data":        data,
		"next_cursor": page.NextCursor,
	})
}
