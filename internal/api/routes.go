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
	// M10-S1 multi-series query: canonical metrics reads use device.read
	// (docs/12 §22.8; docs/04 §6.5 defines no metrics-specific capability).
	// The query is a scope-filtered collection read, so its declared scope is
	// site (like the device list).
	{Method: "POST", Path: "/v1/metrics/query", Protected: true, Capability: authz.CapDeviceRead, Scope: authz.ScopeSite},
	{Method: "GET", Path: "/v1/metrics/query", Protected: true, Capability: authz.CapDeviceRead, Scope: authz.ScopeSite},
	{Method: "GET", Path: "/v1/devices", Protected: true, Capability: authz.CapDeviceRead, Scope: authz.ScopeSite},
	{Method: "POST", Path: "/v1/devices", Protected: true, CSRF: true, Capability: authz.CapDeviceWrite, Scope: authz.ScopeSite},
	{Method: "GET", Path: "/v1/devices/{id}", Protected: true, Capability: authz.CapDeviceRead, Scope: authz.ScopeDevice},
	{Method: "PATCH", Path: "/v1/devices/{id}", Protected: true, CSRF: true, Capability: authz.CapDeviceWrite, Scope: authz.ScopeDevice},
	{Method: "DELETE", Path: "/v1/devices/{id}", Protected: true, CSRF: true, Capability: authz.CapDeviceWrite, Scope: authz.ScopeDevice},
	{Method: "GET", Path: "/v1/devices/{id}/identity-history", Protected: true, Capability: authz.CapDeviceIdentityRead, Scope: authz.ScopeDevice},
	{Method: "POST", Path: "/v1/devices/{id}/identities", Protected: true, CSRF: true, Capability: authz.CapDeviceWrite, Scope: authz.ScopeDevice},
	{Method: "POST", Path: "/v1/devices/{id}/identities/{historyId}/close", Protected: true, CSRF: true, Capability: authz.CapDeviceWrite, Scope: authz.ScopeDevice},
	{Method: "GET", Path: "/v1/devices/{id}/poll-health", Protected: true, Capability: authz.CapDeviceRead, Scope: authz.ScopeDevice},
	{Method: "GET", Path: "/v1/devices/{id}/status", Protected: true, Capability: authz.CapDeviceRead, Scope: authz.ScopeDevice},
	{Method: "POST", Path: "/v1/devices/{id}/checks", Protected: true, CSRF: true, Capability: authz.CapDiagnosticRun, Scope: authz.ScopeDevice},
	// M10-S3b-3 operator ledger: org-wide collection reads are scope-filtered
	// site reads (same metadata shape as GET /v1/devices).
	{Method: "GET", Path: "/v1/checks", Protected: true, Capability: authz.CapDeviceRead, Scope: authz.ScopeSite},
	{Method: "GET", Path: "/v1/poll-health", Protected: true, Capability: authz.CapDeviceRead, Scope: authz.ScopeSite},
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
	// M11-S1 alert engine. Rules are org-scoped objects (the scope_selector
	// narrows targets; restricted callers may only reference in-scope targets
	// and org-wide selectors require org-wide scope). Alerts are resource
	// scoped: the collection read is a site-scoped read (site filter like the
	// device list), item/lifecycle operations resolve the alert's resource
	// device scope. Canonical capability names from docs/04 §6.5.
	{Method: "POST", Path: "/v1/alert-rules", Protected: true, CSRF: true, Capability: authz.CapAlertRuleWrite, Scope: authz.ScopeOrg},
	{Method: "GET", Path: "/v1/alert-rules", Protected: true, Capability: authz.CapAlertRuleRead, Scope: authz.ScopeOrg},
	{Method: "POST", Path: "/v1/alert-rules:validate", Protected: true, CSRF: true, Capability: authz.CapAlertRuleWrite, Scope: authz.ScopeOrg},
	// P2-AC-32 curated default pack (M11-S2): installs the embedded rules for
	// the org, idempotent per rule key. Rule-write capability, org scope.
	{Method: "POST", Path: "/v1/alert-rules:install-defaults", Protected: true, CSRF: true, Capability: authz.CapAlertRuleWrite, Scope: authz.ScopeOrg},
	{Method: "GET", Path: "/v1/alert-rules/{id}", Protected: true, Capability: authz.CapAlertRuleRead, Scope: authz.ScopeOrg},
	{Method: "PATCH", Path: "/v1/alert-rules/{id}", Protected: true, CSRF: true, Capability: authz.CapAlertRuleWrite, Scope: authz.ScopeOrg},
	{Method: "DELETE", Path: "/v1/alert-rules/{id}", Protected: true, CSRF: true, Capability: authz.CapAlertRuleWrite, Scope: authz.ScopeOrg},
	{Method: "GET", Path: "/v1/alerts", Protected: true, Capability: authz.CapAlertRead, Scope: authz.ScopeSite},
	{Method: "GET", Path: "/v1/alerts/{id}", Protected: true, Capability: authz.CapAlertRead, Scope: authz.ScopeDevice},
	{Method: "POST", Path: "/v1/alerts/{id}/ack", Protected: true, CSRF: true, Capability: authz.CapAlertAck, Scope: authz.ScopeDevice},
	{Method: "POST", Path: "/v1/alerts/{id}/snooze", Protected: true, CSRF: true, Capability: authz.CapAlertSnooze, Scope: authz.ScopeDevice},
	{Method: "POST", Path: "/v1/alerts/{id}/resolve", Protected: true, CSRF: true, Capability: authz.CapAlertAck, Scope: authz.ScopeDevice},
	{Method: "POST", Path: "/v1/alerts/{id}/comment", Protected: true, CSRF: true, Capability: authz.CapAlertAck, Scope: authz.ScopeDevice},
	// M11-S3a suppression objects and the SSE alert stream. Canonical
	// docs/12 §22.9 places CRUD /silences and /maintenance-windows under
	// alert.silence, org-scoped like alert rules (restricted callers may only
	// target in-scope resources). The stream is a collection read under
	// alert.read with site scope (docs/12 §22.16; P2-AC-33).
	{Method: "POST", Path: "/v1/maintenance-windows", Protected: true, CSRF: true, Capability: authz.CapAlertSilence, Scope: authz.ScopeOrg},
	{Method: "GET", Path: "/v1/maintenance-windows", Protected: true, Capability: authz.CapAlertSilence, Scope: authz.ScopeOrg},
	{Method: "GET", Path: "/v1/maintenance-windows/{id}", Protected: true, Capability: authz.CapAlertSilence, Scope: authz.ScopeOrg},
	{Method: "PATCH", Path: "/v1/maintenance-windows/{id}", Protected: true, CSRF: true, Capability: authz.CapAlertSilence, Scope: authz.ScopeOrg},
	{Method: "DELETE", Path: "/v1/maintenance-windows/{id}", Protected: true, CSRF: true, Capability: authz.CapAlertSilence, Scope: authz.ScopeOrg},
	{Method: "POST", Path: "/v1/silences", Protected: true, CSRF: true, Capability: authz.CapAlertSilence, Scope: authz.ScopeOrg},
	{Method: "GET", Path: "/v1/silences", Protected: true, Capability: authz.CapAlertSilence, Scope: authz.ScopeOrg},
	{Method: "DELETE", Path: "/v1/silences/{id}", Protected: true, CSRF: true, Capability: authz.CapAlertSilence, Scope: authz.ScopeOrg},
	{Method: "GET", Path: "/v1/streams/events", Protected: true, Capability: authz.CapAlertRead, Scope: authz.ScopeSite},
	// M11-S2 notification pipeline. Canonical docs/12 §22.14: channels are
	// enforced under integration.write (CRUD, including reads — the channel
	// payload is integration configuration, and secrets are write-only);
	// routes under alertrule.write; the delivery log under alert.read
	// (docs/17 §35.1). All three surfaces are org-scoped.
	{Method: "POST", Path: "/v1/notification/channels", Protected: true, CSRF: true, Capability: authz.CapIntegrationWrite, Scope: authz.ScopeOrg},
	{Method: "GET", Path: "/v1/notification/channels", Protected: true, Capability: authz.CapIntegrationWrite, Scope: authz.ScopeOrg},
	{Method: "GET", Path: "/v1/notification/channels/{id}", Protected: true, Capability: authz.CapIntegrationWrite, Scope: authz.ScopeOrg},
	{Method: "PATCH", Path: "/v1/notification/channels/{id}", Protected: true, CSRF: true, Capability: authz.CapIntegrationWrite, Scope: authz.ScopeOrg},
	{Method: "DELETE", Path: "/v1/notification/channels/{id}", Protected: true, CSRF: true, Capability: authz.CapIntegrationWrite, Scope: authz.ScopeOrg},
	{Method: "POST", Path: "/v1/notification/channels/{id}/test", Protected: true, CSRF: true, Capability: authz.CapIntegrationWrite, Scope: authz.ScopeOrg},
	{Method: "POST", Path: "/v1/notification/routes", Protected: true, CSRF: true, Capability: authz.CapAlertRuleWrite, Scope: authz.ScopeOrg},
	{Method: "GET", Path: "/v1/notification/routes", Protected: true, Capability: authz.CapAlertRuleWrite, Scope: authz.ScopeOrg},
	{Method: "GET", Path: "/v1/notification/routes/{id}", Protected: true, Capability: authz.CapAlertRuleWrite, Scope: authz.ScopeOrg},
	{Method: "PATCH", Path: "/v1/notification/routes/{id}", Protected: true, CSRF: true, Capability: authz.CapAlertRuleWrite, Scope: authz.ScopeOrg},
	{Method: "DELETE", Path: "/v1/notification/routes/{id}", Protected: true, CSRF: true, Capability: authz.CapAlertRuleWrite, Scope: authz.ScopeOrg},
	{Method: "GET", Path: "/v1/notification/deliveries", Protected: true, Capability: authz.CapAlertRead, Scope: authz.ScopeOrg},
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
