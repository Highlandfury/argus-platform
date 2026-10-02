// Package api wires HTTP routes for the public API and the ops surface.
package api

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/modules/alerts"
	"github.com/argus-platform/argus/internal/modules/checks"
	"github.com/argus-platform/argus/internal/modules/collectors"
	"github.com/argus-platform/argus/internal/modules/credentials"
	"github.com/argus-platform/argus/internal/modules/identity"
	"github.com/argus-platform/argus/internal/modules/inventory"
	"github.com/argus-platform/argus/internal/modules/metrics"
	"github.com/argus-platform/argus/internal/modules/notify"
	"github.com/argus-platform/argus/internal/modules/pollhealth"
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
	Argus             *telemetry.Argus
	Version           string
	Commit            string
	Readiness         []Check
	SecureCookies     bool
	Identity          *identity.Service
	Tenancy           *tenancy.Service
	Collectors        *collectors.Service
	CollectorSessions *collectors.SessionRegistry
	MetricsQuery      *metrics.QueryService
	Inventory         *inventory.Service
	Credentials       *credentials.Service
	PollHealth        *pollhealth.Service
	Checks            *checks.Service
	Alerts            *alerts.Service
	// M11-S2 notification pipeline. Engines stay nil in degraded configs;
	// channel test answers 503 then.
	Notify       *notify.Service
	NotifyEngine *notify.Engine
}

type handlers struct {
	o               Options
	limiter         *loginLimiter
	identityHTTP    *identity.HTTP
	tenancyHTTP     *tenancy.HTTP
	collectorsHTTP  *collectors.HTTP
	metricsHTTP     *metrics.HTTP
	inventoryHTTP   *inventory.HTTP
	credentialsHTTP *credentials.HTTP
	pollHealthHTTP  *pollhealth.HTTP
	checksHTTP      *checks.HTTP
	alertsHTTP      *alerts.HTTP
	notifyHTTP      *notify.HTTP
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
		h.collectorsHTTP = &collectors.HTTP{
			Svc:         o.Collectors,
			Registry:    o.CollectorSessions,
			Idempotency: httpx.NewIdempotencyCache(24*time.Hour, 4096),
		}
	}
	if o.MetricsQuery != nil {
		h.metricsHTTP = &metrics.HTTP{
			Svc:   o.MetricsQuery,
			Cache: metrics.NewMatrixCache(metrics.MatrixCacheTTL, metrics.MatrixCacheMaxEntries),
		}
		if o.Inventory != nil {
			// Scope binding resolution for the M10-S1 multi-series API; nil
			// fails closed in the handler.
			h.metricsHTTP.Scope = o.Inventory
		}
	}
	if o.Inventory != nil {
		h.inventoryHTTP = &inventory.HTTP{Svc: o.Inventory}
		if o.PollHealth != nil {
			h.inventoryHTTP.Status = o.PollHealth
		}
	}
	if o.Credentials != nil {
		h.credentialsHTTP = &credentials.HTTP{Svc: o.Credentials}
	}
	if o.PollHealth != nil && o.Inventory != nil {
		h.pollHealthHTTP = &pollhealth.HTTP{Svc: o.PollHealth, Devices: o.Inventory}
	}
	if o.Checks != nil && o.Inventory != nil {
		h.checksHTTP = &checks.HTTP{Svc: o.Checks, Devices: o.Inventory}
	}
	if o.Alerts != nil {
		h.alertsHTTP = &alerts.HTTP{Svc: o.Alerts}
	}
	if o.Notify != nil {
		h.notifyHTTP = &notify.HTTP{
			Svc:         o.Notify,
			Engine:      o.NotifyEngine,
			Idempotency: httpx.NewIdempotencyCache(24*time.Hour, 4096),
		}
	}
	return h
}

// NewRouter returns the public API router.
func NewRouter(o Options) http.Handler {
	h := newHandlers(o)
	mux := http.NewServeMux()
	for _, rt := range routeTable {
		handler := h.handlerFor(rt)
		if rt.Capability != "" {
			handler = h.requireCapability(rt.Capability, handler)
		}
		if rt.Protected {
			if rt.CSRF {
				handler = h.requireCSRF(handler)
			}
			handler = h.requireSession(handler)
		}
		mux.Handle(rt.Method+" "+rt.Path, handler)
	}
	var handler http.Handler = mux
	if o.Argus != nil {
		// §15 HTTP metrics: bounded route label (matched pattern), method,
		// status class.
		handler = o.Argus.HTTPMiddleware(handler)
	}
	return httpx.RequestID(httpx.AccessLog(o.Logger, handler))
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
	case "/v1/collectors/{id}/metrics":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.metricsHTTP == nil {
				serviceUnavailable(w, r, "metrics query service not configured")
				return
			}
			h.metricsHTTP.QueryCollectorMetric(w, r)
		})
	case "/v1/metrics/query":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.metricsHTTP == nil {
				serviceUnavailable(w, r, "metrics query service not configured")
				return
			}
			if r.Method == http.MethodPost {
				h.metricsHTTP.QueryMetrics(w, r)
				return
			}
			h.metricsHTTP.QueryMetricsGet(w, r)
		})
	case "/v1/devices":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.inventoryHTTP == nil {
				serviceUnavailable(w, r, "inventory service not configured")
				return
			}
			if r.Method == http.MethodPost {
				h.inventoryHTTP.CreateDevice(w, r)
				return
			}
			h.inventoryHTTP.ListDevices(w, r)
		})
	case "/v1/devices/{id}":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.inventoryHTTP == nil {
				serviceUnavailable(w, r, "inventory service not configured")
				return
			}
			switch r.Method {
			case http.MethodPatch:
				h.inventoryHTTP.UpdateDevice(w, r)
			case http.MethodDelete:
				h.inventoryHTTP.DeleteDevice(w, r)
			default:
				h.inventoryHTTP.GetDevice(w, r)
			}
		})
	case "/v1/devices/{id}/identity-history":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.inventoryHTTP == nil {
				serviceUnavailable(w, r, "inventory service not configured")
				return
			}
			h.inventoryHTTP.ListDeviceIdentityHistory(w, r)
		})
	case "/v1/devices/{id}/identities":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.inventoryHTTP == nil {
				serviceUnavailable(w, r, "inventory service not configured")
				return
			}
			h.inventoryHTTP.AddDeviceIdentity(w, r)
		})
	case "/v1/devices/{id}/identities/{historyId}/close":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.inventoryHTTP == nil {
				serviceUnavailable(w, r, "inventory service not configured")
				return
			}
			h.inventoryHTTP.CloseDeviceIdentity(w, r)
		})
	case "/v1/devices/{id}/poll-health":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.pollHealthHTTP == nil {
				serviceUnavailable(w, r, "poll health service not configured")
				return
			}
			h.pollHealthHTTP.ListDevicePollHealth(w, r)
		})
	case "/v1/devices/{id}/status":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.pollHealthHTTP == nil {
				serviceUnavailable(w, r, "poll health service not configured")
				return
			}
			h.pollHealthHTTP.GetDeviceStatus(w, r)
		})
	case "/v1/devices/{id}/checks":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.checksHTTP == nil {
				serviceUnavailable(w, r, "checks service not configured")
				return
			}
			h.checksHTTP.CreateDeviceCheck(w, r)
		})
	case "/v1/checks":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.checksHTTP == nil {
				serviceUnavailable(w, r, "checks service not configured")
				return
			}
			h.checksHTTP.ListChecks(w, r)
		})
	case "/v1/poll-health":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.pollHealthHTTP == nil {
				serviceUnavailable(w, r, "poll health service not configured")
				return
			}
			h.pollHealthHTTP.ListPollHealth(w, r)
		})
	case "/v1/checks/{id}":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.checksHTTP == nil {
				serviceUnavailable(w, r, "checks service not configured")
				return
			}
			h.checksHTTP.GetCheck(w, r)
		})
	case "/v1/devices/{id}/merge":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.inventoryHTTP == nil {
				serviceUnavailable(w, r, "inventory service not configured")
				return
			}
			h.inventoryHTTP.MergeDevice(w, r)
		})
	case "/v1/devices/{id}/split":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.inventoryHTTP == nil {
				serviceUnavailable(w, r, "inventory service not configured")
				return
			}
			h.inventoryHTTP.SplitDevice(w, r)
		})
	case "/v1/devices/{id}/interfaces":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.inventoryHTTP == nil {
				serviceUnavailable(w, r, "inventory service not configured")
				return
			}
			if r.Method == http.MethodPost {
				h.inventoryHTTP.CreateDeviceInterface(w, r)
				return
			}
			h.inventoryHTTP.ListDeviceInterfaces(w, r)
		})
	case "/v1/interfaces/{id}":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.inventoryHTTP == nil {
				serviceUnavailable(w, r, "inventory service not configured")
				return
			}
			switch r.Method {
			case http.MethodPatch:
				h.inventoryHTTP.UpdateInterface(w, r)
			case http.MethodDelete:
				h.inventoryHTTP.DeleteInterface(w, r)
			default:
				h.inventoryHTTP.GetInterface(w, r)
			}
		})
	case "/v1/device-groups":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.inventoryHTTP == nil {
				serviceUnavailable(w, r, "inventory service not configured")
				return
			}
			if r.Method == http.MethodPost {
				h.inventoryHTTP.CreateDeviceGroup(w, r)
				return
			}
			h.inventoryHTTP.ListDeviceGroups(w, r)
		})
	case "/v1/device-groups/{id}":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.inventoryHTTP == nil {
				serviceUnavailable(w, r, "inventory service not configured")
				return
			}
			switch r.Method {
			case http.MethodPatch:
				h.inventoryHTTP.UpdateDeviceGroup(w, r)
			case http.MethodDelete:
				h.inventoryHTTP.DeleteDeviceGroup(w, r)
			default:
				h.inventoryHTTP.GetDeviceGroup(w, r)
			}
		})
	case "/v1/alert-rules":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.alertsHTTP == nil {
				serviceUnavailable(w, r, "alerts service not configured")
				return
			}
			if r.Method == http.MethodPost {
				h.alertsHTTP.CreateRule(w, r)
				return
			}
			h.alertsHTTP.ListRules(w, r)
		})
	case "/v1/alert-rules:validate":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.alertsHTTP == nil {
				serviceUnavailable(w, r, "alerts service not configured")
				return
			}
			h.alertsHTTP.ValidateRule(w, r)
		})
	case "/v1/alert-rules:install-defaults":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.alertsHTTP == nil {
				serviceUnavailable(w, r, "alerts service not configured")
				return
			}
			h.alertsHTTP.InstallDefaults(w, r)
		})
	case "/v1/notification/channels":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.notifyHTTP == nil {
				serviceUnavailable(w, r, "notification service not configured")
				return
			}
			if r.Method == http.MethodPost {
				h.notifyHTTP.CreateChannel(w, r)
				return
			}
			h.notifyHTTP.ListChannels(w, r)
		})
	case "/v1/notification/channels/{id}":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.notifyHTTP == nil {
				serviceUnavailable(w, r, "notification service not configured")
				return
			}
			switch r.Method {
			case http.MethodPatch:
				h.notifyHTTP.UpdateChannel(w, r)
			case http.MethodDelete:
				h.notifyHTTP.DeleteChannel(w, r)
			default:
				h.notifyHTTP.GetChannel(w, r)
			}
		})
	case "/v1/notification/channels/{id}/test":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.notifyHTTP == nil || h.notifyHTTP.Engine == nil {
				serviceUnavailable(w, r, "notification engine not configured")
				return
			}
			h.notifyHTTP.TestChannel(w, r)
		})
	case "/v1/notification/routes":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.notifyHTTP == nil {
				serviceUnavailable(w, r, "notification service not configured")
				return
			}
			if r.Method == http.MethodPost {
				h.notifyHTTP.CreateRoute(w, r)
				return
			}
			h.notifyHTTP.ListRoutes(w, r)
		})
	case "/v1/notification/routes/{id}":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.notifyHTTP == nil {
				serviceUnavailable(w, r, "notification service not configured")
				return
			}
			switch r.Method {
			case http.MethodPatch:
				h.notifyHTTP.UpdateRoute(w, r)
			case http.MethodDelete:
				h.notifyHTTP.DeleteRoute(w, r)
			default:
				h.notifyHTTP.GetRoute(w, r)
			}
		})
	case "/v1/notification/deliveries":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.notifyHTTP == nil {
				serviceUnavailable(w, r, "notification service not configured")
				return
			}
			h.notifyHTTP.ListDeliveries(w, r)
		})
	case "/v1/alert-rules/{id}":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.alertsHTTP == nil {
				serviceUnavailable(w, r, "alerts service not configured")
				return
			}
			switch r.Method {
			case http.MethodPatch:
				h.alertsHTTP.UpdateRule(w, r)
			case http.MethodDelete:
				h.alertsHTTP.DeleteRule(w, r)
			default:
				h.alertsHTTP.GetRule(w, r)
			}
		})
	case "/v1/alerts":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.alertsHTTP == nil {
				serviceUnavailable(w, r, "alerts service not configured")
				return
			}
			h.alertsHTTP.ListAlerts(w, r)
		})
	case "/v1/alerts/{id}":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.alertsHTTP == nil {
				serviceUnavailable(w, r, "alerts service not configured")
				return
			}
			h.alertsHTTP.GetAlert(w, r)
		})
	case "/v1/alerts/{id}/ack":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.alertsHTTP == nil {
				serviceUnavailable(w, r, "alerts service not configured")
				return
			}
			h.alertsHTTP.AckAlert(w, r)
		})
	case "/v1/alerts/{id}/snooze":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.alertsHTTP == nil {
				serviceUnavailable(w, r, "alerts service not configured")
				return
			}
			h.alertsHTTP.SnoozeAlert(w, r)
		})
	case "/v1/alerts/{id}/resolve":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.alertsHTTP == nil {
				serviceUnavailable(w, r, "alerts service not configured")
				return
			}
			h.alertsHTTP.ResolveAlert(w, r)
		})
	case "/v1/alerts/{id}/comment":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.alertsHTTP == nil {
				serviceUnavailable(w, r, "alerts service not configured")
				return
			}
			h.alertsHTTP.CommentAlert(w, r)
		})
	case "/v1/credentials":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.credentialsHTTP == nil {
				serviceUnavailable(w, r, "credentials service not configured")
				return
			}
			if r.Method == http.MethodPost {
				h.credentialsHTTP.CreateCredential(w, r)
				return
			}
			h.credentialsHTTP.ListCredentials(w, r)
		})
	case "/v1/credentials/{id}":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.credentialsHTTP == nil {
				serviceUnavailable(w, r, "credentials service not configured")
				return
			}
			h.credentialsHTTP.GetCredential(w, r)
		})
	case "/v1/credentials/{id}/rotate":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.credentialsHTTP == nil {
				serviceUnavailable(w, r, "credentials service not configured")
				return
			}
			h.credentialsHTTP.RotateCredential(w, r)
		})
	case "/v1/credentials/{id}/bind":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.credentialsHTTP == nil {
				serviceUnavailable(w, r, "credentials service not configured")
				return
			}
			h.credentialsHTTP.BindCredential(w, r)
		})
	case "/v1/credentials/{id}/unbind":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.credentialsHTTP == nil {
				serviceUnavailable(w, r, "credentials service not configured")
				return
			}
			h.credentialsHTTP.UnbindCredential(w, r)
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
