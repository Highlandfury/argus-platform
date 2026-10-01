package api

import "github.com/argus-platform/argus/internal/platform/authz"

// Route describes one public API endpoint. The registry is the single source
// of truth for mux construction and for the OpenAPI contract test.
type Route struct {
	Method    string
	Path      string
	Protected bool // requires a valid session
	CSRF      bool // requires CSRF verification (implies Protected)
	// Capability is the RBAC-SC capability enforced before the handler runs
	// (P2-D5). Empty means the endpoint is not capability-enforced yet.
	Capability string
	// Scope is the resource scope type the operation resolves against
	// (org|site|device_group|device). Together with server-side scope bindings
	// (migration 000010) it drives scope enforcement in the handlers. Empty
	// means no scope metadata.
	Scope string
}

var routeTable = []Route{
	{Method: "POST", Path: "/v1/auth/login"},
	{Method: "POST", Path: "/v1/auth/logout", Protected: true, CSRF: true},
	{Method: "GET", Path: "/v1/me", Protected: true},
	{Method: "GET", Path: "/v1/sites", Protected: true},
	{Method: "POST", Path: "/v1/enrollments", Protected: true, CSRF: true},
	{Method: "GET", Path: "/v1/enrollments", Protected: true},
	{Method: "GET", Path: "/v1/collectors", Protected: true},
	{Method: "GET", Path: "/v1/collectors/{id}", Protected: true},
	{Method: "POST", Path: "/v1/collectors/{id}/revoke", Protected: true, CSRF: true},
	{Method: "POST", Path: "/v1/collectors/{id}/policy:resync", Protected: true, CSRF: true},
	{Method: "GET", Path: "/v1/collectors/{id}/metrics", Protected: true},
	{Method: "GET", Path: "/v1/devices", Protected: true, Capability: authz.CapDeviceRead, Scope: authz.ScopeSite},
	{Method: "POST", Path: "/v1/devices", Protected: true, CSRF: true, Capability: authz.CapDeviceWrite, Scope: authz.ScopeSite},
	{Method: "GET", Path: "/v1/devices/{id}", Protected: true, Capability: authz.CapDeviceRead, Scope: authz.ScopeDevice},
	{Method: "PATCH", Path: "/v1/devices/{id}", Protected: true, CSRF: true, Capability: authz.CapDeviceWrite, Scope: authz.ScopeDevice},
	{Method: "DELETE", Path: "/v1/devices/{id}", Protected: true, CSRF: true, Capability: authz.CapDeviceWrite, Scope: authz.ScopeDevice},
	{Method: "GET", Path: "/v1/devices/{id}/identity-history", Protected: true, Capability: authz.CapDeviceIdentityRead, Scope: authz.ScopeDevice},
	{Method: "GET", Path: "/v1/devices/{id}/poll-health", Protected: true, Capability: authz.CapDeviceRead, Scope: authz.ScopeDevice},
	{Method: "POST", Path: "/v1/devices/{id}/checks", Protected: true, CSRF: true, Capability: authz.CapDiagnosticRun, Scope: authz.ScopeDevice},
	{Method: "GET", Path: "/v1/checks/{id}", Protected: true, Capability: authz.CapDeviceRead, Scope: authz.ScopeDevice},
	{Method: "POST", Path: "/v1/devices/{id}/merge", Protected: true, CSRF: true, Capability: authz.CapDeviceMerge, Scope: authz.ScopeDevice},
	{Method: "POST", Path: "/v1/devices/{id}/split", Protected: true, CSRF: true, Capability: authz.CapDeviceSplit, Scope: authz.ScopeDevice},
	{Method: "GET", Path: "/v1/devices/{id}/interfaces", Protected: true, Capability: authz.CapInterfaceRead, Scope: authz.ScopeDevice},
	{Method: "POST", Path: "/v1/devices/{id}/interfaces", Protected: true, CSRF: true, Capability: authz.CapInterfaceWrite, Scope: authz.ScopeDevice},
	{Method: "GET", Path: "/v1/interfaces/{id}", Protected: true, Capability: authz.CapInterfaceRead, Scope: authz.ScopeDevice},
	{Method: "PATCH", Path: "/v1/interfaces/{id}", Protected: true, CSRF: true, Capability: authz.CapInterfaceWrite, Scope: authz.ScopeDevice},
	{Method: "DELETE", Path: "/v1/interfaces/{id}", Protected: true, CSRF: true, Capability: authz.CapInterfaceWrite, Scope: authz.ScopeDevice},
	{Method: "GET", Path: "/v1/device-groups", Protected: true, Capability: authz.CapDeviceGroupRead, Scope: authz.ScopeDeviceGroup},
	{Method: "POST", Path: "/v1/device-groups", Protected: true, CSRF: true, Capability: authz.CapDeviceGroupWrite, Scope: authz.ScopeOrg},
	{Method: "GET", Path: "/v1/device-groups/{id}", Protected: true, Capability: authz.CapDeviceGroupRead, Scope: authz.ScopeDeviceGroup},
	{Method: "PATCH", Path: "/v1/device-groups/{id}", Protected: true, CSRF: true, Capability: authz.CapDeviceGroupWrite, Scope: authz.ScopeDeviceGroup},
	{Method: "DELETE", Path: "/v1/device-groups/{id}", Protected: true, CSRF: true, Capability: authz.CapDeviceGroupWrite, Scope: authz.ScopeDeviceGroup},
	{Method: "GET", Path: "/v1/credentials", Protected: true, Capability: authz.CapCredentialReadMetadata, Scope: authz.ScopeOrg},
	{Method: "POST", Path: "/v1/credentials", Protected: true, CSRF: true, Capability: authz.CapCredentialWrite, Scope: authz.ScopeOrg},
	{Method: "GET", Path: "/v1/credentials/{id}", Protected: true, Capability: authz.CapCredentialReadMetadata, Scope: authz.ScopeOrg},
	{Method: "POST", Path: "/v1/credentials/{id}/rotate", Protected: true, CSRF: true, Capability: authz.CapCredentialRotate, Scope: authz.ScopeOrg},
	{Method: "POST", Path: "/v1/credentials/{id}/bind", Protected: true, CSRF: true, Capability: authz.CapCredentialWrite, Scope: authz.ScopeOrg},
	{Method: "POST", Path: "/v1/credentials/{id}/unbind", Protected: true, CSRF: true, Capability: authz.CapCredentialWrite, Scope: authz.ScopeOrg},
	{Method: "GET", Path: "/v1/healthz"},
	{Method: "GET", Path: "/v1/readyz"},
}

// Routes returns a copy of the public API route registry.
func Routes() []Route {
	out := make([]Route, len(routeTable))
	copy(out, routeTable)
	return out
}
