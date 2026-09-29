// Package api wires HTTP routes for the public API and the ops surface.
package api

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/modules/collectors"
	"github.com/argus-platform/argus/internal/modules/identity"
	"github.com/argus-platform/argus/internal/modules/tenancy"
	"github.com/argus-platform/argus/internal/platform/httpx"
	"github.com/argus-platform/argus/internal/platform/telemetry"
)

// Check is one readiness probe. Readiness returns 503 while any check fails.
type Check struct {
	Name string
	Fn   func(ctx context.Context) error
}

// Options configures the routers. Services may be nil in degraded
// configurations (routes then answer 503 instead of panicking).
type Options struct {
	Logger            *slog.Logger
	Telemetry         *telemetry.Registry
	Version           string
	Commit            string
	Readiness         []Check
	SecureCookies     bool
	Identity          *identity.Service
	Tenancy           *tenancy.Service
	Collectors        *collectors.Service
	CollectorSessions *collectors.SessionRegistry
}

type handlers struct {
	o              Options
	limiter        *loginLimiter
	identityHTTP   *identity.HTTP
	tenancyHTTP    *tenancy.HTTP
	collectorsHTTP *collectors.HTTP
}

func newHandlers(o Options) *handlers {
	h := &handlers{o: o, limiter: newLoginLimiter()}
	if o.Identity != nil {
		h.identityHTTP = &identity.HTTP{
			Svc:           o.Identity,
			SecureCookies: o.SecureCookies,
			OrgLookup: func(ctx context.Context, orgID uuid.UUID) (httpx.PublicOrg, error) {
				if o.Tenancy == nil {
					return httpx.PublicOrg{}, errors.New("tenancy service not configured")
				}
				org, err := o.Tenancy.GetOrg(ctx, orgID)
				if err != nil {
					return httpx.PublicOrg{}, err
				}
				return httpx.PublicOrg{ID: org.ID, Slug: org.Slug, Name: org.Name}, nil
			},
		}
	}
	if o.Tenancy != nil {
		h.tenancyHTTP = &tenancy.HTTP{Svc: o.Tenancy}
	}
	if o.Collectors != nil {
		h.collectorsHTTP = &collectors.HTTP{Svc: o.Collectors, Registry: o.CollectorSessions}
	}
	return h
}

// NewRouter returns the public API router.
func NewRouter(o Options) http.Handler {
	h := newHandlers(o)
	mux := http.NewServeMux()
	for _, rt := range routeTable {
		handler := h.handlerFor(rt)
		if rt.Protected {
			if rt.CSRF {
				handler = h.requireCSRF(handler)
			}
			handler = h.requireSession(handler)
		}
		mux.Handle(rt.Method+" "+rt.Path, handler)
	}
	return httpx.RequestID(httpx.AccessLog(o.Logger, mux))
}

// NewOpsRouter returns the ops router (metrics + health). Intended for a
// private listener.
func NewOpsRouter(o Options) http.Handler {
	h := newHandlers(o)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.health)
	mux.HandleFunc("GET /readyz", h.ready)
	mux.Handle("GET /metrics", o.Telemetry.Handler())
	return httpx.RequestID(httpx.AccessLog(o.Logger, mux))
}

func (h *handlers) handlerFor(rt Route) http.Handler {
	switch rt.Path {
	case "/v1/auth/login":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.identityHTTP == nil {
				serviceUnavailable(w, r, "identity service not configured")
				return
			}
			if ok, retry := h.limiter.allow(clientIP(r)); !ok {
				w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
				httpx.WriteProblem(w, r, http.StatusTooManyRequests, "rate_limited", "too many login attempts; retry later")
				return
			}
			h.identityHTTP.Login(w, r)
		})
	case "/v1/auth/logout":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.identityHTTP == nil {
				serviceUnavailable(w, r, "identity service not configured")
				return
			}
			h.identityHTTP.Logout(w, r)
		})
	case "/v1/me":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.identityHTTP == nil {
				serviceUnavailable(w, r, "identity service not configured")
				return
			}
			h.identityHTTP.Me(w, r)
		})
	case "/v1/sites":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.tenancyHTTP == nil {
				serviceUnavailable(w, r, "tenancy service not configured")
				return
			}
			h.tenancyHTTP.ListSites(w, r)
		})
	case "/v1/enrollments":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.collectorsHTTP == nil {
				serviceUnavailable(w, r, "collectors service not configured")
				return
			}
			if r.Method == http.MethodPost {
				h.collectorsHTTP.CreateEnrollment(w, r)
				return
			}
			h.collectorsHTTP.ListEnrollments(w, r)
		})
	case "/v1/collectors":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.collectorsHTTP == nil {
				serviceUnavailable(w, r, "collectors service not configured")
				return
			}
			h.collectorsHTTP.ListCollectors(w, r)
		})
	case "/v1/collectors/{id}":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.collectorsHTTP == nil {
				serviceUnavailable(w, r, "collectors service not configured")
				return
			}
			h.collectorsHTTP.GetCollector(w, r)
		})
	case "/v1/collectors/{id}/revoke":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.collectorsHTTP == nil {
				serviceUnavailable(w, r, "collectors service not configured")
				return
			}
			h.collectorsHTTP.RevokeCollector(w, r)
		})
	case "/v1/collectors/{id}/policy:resync":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.collectorsHTTP == nil {
				serviceUnavailable(w, r, "collectors service not configured")
				return
			}
			h.collectorsHTTP.ResyncPolicy(w, r)
		})
	case "/v1/healthz":
		return http.HandlerFunc(h.health)
	case "/v1/readyz":
		return http.HandlerFunc(h.ready)
	default:
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serviceUnavailable(w, r, "route not wired")
		})
	}
}

func (h handlers) health(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"version": h.o.Version,
		"commit":  h.o.Commit,
	})
}

func (h handlers) ready(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{}
	failed := false
	for _, c := range h.o.Readiness {
		if err := c.Fn(r.Context()); err != nil {
			checks[c.Name] = err.Error()
			failed = true
		} else {
			checks[c.Name] = "ok"
		}
	}
	status := http.StatusOK
	state := "ok"
	if failed {
		status = http.StatusServiceUnavailable
		state = "unavailable"
	}
	httpx.WriteJSON(w, status, map[string]any{
		"status":  state,
		"version": h.o.Version,
		"commit":  h.o.Commit,
		"checks":  checks,
	})
}

// clientIP is the direct peer address. X-Forwarded-For is deliberately NOT
// trusted until a known-proxy boundary is configured (it would allow limiter
// bypass by spoofing).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func serviceUnavailable(w http.ResponseWriter, r *http.Request, detail string) {
	httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "service.unavailable", detail)
}
