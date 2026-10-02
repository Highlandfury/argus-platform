package api

import (
	"strings"
	"testing"

	"github.com/argus-platform/argus/internal/platform/authz"
)

func checkRoute(path string) bool {
	return strings.HasPrefix(path, "/v1/checks") || strings.HasSuffix(path, "/checks")
}

func inventoryRoute(path string) bool {
	if checkRoute(path) {
		return false
	}
	return strings.HasPrefix(path, "/v1/devices") ||
		strings.HasPrefix(path, "/v1/interfaces") ||
		strings.HasPrefix(path, "/v1/device-groups")
}

func credentialRoute(path string) bool {
	return strings.HasPrefix(path, "/v1/credentials")
}

// TestInventoryRoutesDeclareCapabilityAndScope pins the M7-S3 route metadata:
// all inventory routes declare a capability from the vocabulary and a scope
// from {org,site,device_group,device}, and every mutation keeps CSRF.
func TestInventoryRoutesDeclareCapabilityAndScope(t *testing.T) {
	inventory := 0
	for _, rt := range Routes() {
		if !inventoryRoute(rt.Path) {
			continue
		}
		inventory++
		if rt.Capability == "" {
			t.Errorf("%s %s: missing capability metadata", rt.Method, rt.Path)
		} else if !authz.IsInventoryCapability(rt.Capability) {
			t.Errorf("%s %s: capability %q outside the inventory vocabulary", rt.Method, rt.Path, rt.Capability)
		}
		if rt.Scope == "" {
			t.Errorf("%s %s: missing scope metadata", rt.Method, rt.Path)
		} else if !authz.IsScope(rt.Scope) {
			t.Errorf("%s %s: scope %q outside {org,site,device_group,device}", rt.Method, rt.Path, rt.Scope)
		}
		if !rt.Protected {
			t.Errorf("%s %s: inventory route must require a session", rt.Method, rt.Path)
		}
		switch rt.Method {
		case "POST", "PATCH", "DELETE":
			if !rt.CSRF {
				t.Errorf("%s %s: inventory mutation must require CSRF", rt.Method, rt.Path)
			}
		}
	}
	if inventory != 22 {
		t.Fatalf("inventory routes = %d, want the 18 M7-S3 routes + 1 M9-S1 poll-health route + 1 M10-S1 device-status route + 2 M10-S3b-1 identity routes", inventory)
	}
}

// TestMetricsQueryRoutesDeclareCapabilityAndScope pins the M10-S1 metrics
// query surface: both POST and GET are session-protected reads on the
// canonical device.read capability (docs/04 §6.5 defines no metrics
// capability) with site scope metadata (scope-filtered collection reads).
func TestMetricsQueryRoutesDeclareCapabilityAndScope(t *testing.T) {
	count := 0
	for _, rt := range Routes() {
		if rt.Path != "/v1/metrics/query" {
			continue
		}
		count++
		if !rt.Protected {
			t.Errorf("%s %s: metrics query must require a session", rt.Method, rt.Path)
		}
		if rt.Capability != authz.CapDeviceRead {
			t.Errorf("%s %s: capability %q, want %q", rt.Method, rt.Path, rt.Capability, authz.CapDeviceRead)
		}
		if rt.Scope != authz.ScopeSite {
			t.Errorf("%s %s: scope %q, want site", rt.Method, rt.Path, rt.Scope)
		}
		if rt.CSRF {
			t.Errorf("%s %s: reads must not require CSRF", rt.Method, rt.Path)
		}
	}
	if count != 2 {
		t.Fatalf("metrics query routes = %d, want the M10-S1 POST + GET pair", count)
	}
}

// TestCheckRoutesDeclareCapabilityAndScope pins the M10-S0 on-demand check
// surface: creation is an unsafe POST (CSRF + canonical diagnostic.run
// capability, scope device); the read is a device.read GET. The viewer
// derivation holds no diagnostic capability (docs/04 §6.4).
func TestCheckRoutesDeclareCapabilityAndScope(t *testing.T) {
	count := 0
	for _, rt := range Routes() {
		if !checkRoute(rt.Path) {
			continue
		}
		count++
		if !rt.Protected {
			t.Errorf("%s %s: check route must require a session", rt.Method, rt.Path)
		}
		if rt.Scope != authz.ScopeDevice {
			t.Errorf("%s %s: scope %q, want device", rt.Method, rt.Path, rt.Scope)
		}
		switch rt.Method {
		case "POST":
			if rt.Capability != authz.CapDiagnosticRun {
				t.Errorf("%s %s: capability %q, want %q", rt.Method, rt.Path, rt.Capability, authz.CapDiagnosticRun)
			}
			if !rt.CSRF {
				t.Errorf("%s %s: check creation must require CSRF", rt.Method, rt.Path)
			}
		case "GET":
			if rt.Capability != authz.CapDeviceRead {
				t.Errorf("%s %s: capability %q, want %q", rt.Method, rt.Path, rt.Capability, authz.CapDeviceRead)
			}
		}
	}
	if count != 2 {
		t.Fatalf("check routes = %d, want the 2 M10-S0 routes", count)
	}
	if authz.Allowed("viewer", authz.CapDiagnosticRun) {
		t.Error("viewer derives diagnostic.run; read-only principals must not trigger diagnostics")
	}
}

// TestInventoryWriteRoutesDeniedToViewerDerivation is a guard against
// accidentally granting a write-class capability to the viewer derivation.
func TestInventoryWriteRoutesDeniedToViewerDerivation(t *testing.T) {
	for _, rt := range Routes() {
		if !inventoryRoute(rt.Path) || rt.Capability == "" {
			continue
		}
		switch rt.Method {
		case "POST", "PATCH", "DELETE":
			if authz.Allowed("viewer", rt.Capability) {
				t.Errorf("viewer derives capability %q for %s %s; viewer must be read-only", rt.Capability, rt.Method, rt.Path)
			}
		}
	}
}

// TestCredentialRoutesDeclareCapabilityAndScope pins the M7-S4 route metadata:
// all six credential routes declare a credential-vocabulary capability and an
// org scope, every mutation keeps CSRF, and the viewer derivation holds none of
// the credential capabilities (docs/04 §6.4: the canonical matrix grants
// credential access to admin-tier roles only).
func TestCredentialRoutesDeclareCapabilityAndScope(t *testing.T) {
	count := 0
	for _, rt := range Routes() {
		if !credentialRoute(rt.Path) {
			continue
		}
		count++
		if rt.Capability == "" {
			t.Errorf("%s %s: missing capability metadata", rt.Method, rt.Path)
		} else if !authz.IsCredentialCapability(rt.Capability) {
			t.Errorf("%s %s: capability %q outside the credential vocabulary", rt.Method, rt.Path, rt.Capability)
		}
		if rt.Scope == "" {
			t.Errorf("%s %s: missing scope metadata", rt.Method, rt.Path)
		} else if !authz.IsScope(rt.Scope) {
			t.Errorf("%s %s: scope %q outside {org,site,device_group,device}", rt.Method, rt.Path, rt.Scope)
		}
		if !rt.Protected {
			t.Errorf("%s %s: credential route must require a session", rt.Method, rt.Path)
		}
		switch rt.Method {
		case "POST", "PATCH", "DELETE":
			if !rt.CSRF {
				t.Errorf("%s %s: credential mutation must require CSRF", rt.Method, rt.Path)
			}
		}
		for _, cap := range []string{
			authz.CapCredentialReadMetadata, authz.CapCredentialWrite,
			authz.CapCredentialRotate, authz.CapCredentialUse,
		} {
			if authz.Allowed("viewer", cap) {
				t.Errorf("viewer derives credential capability %q; viewer must hold none", cap)
			}
		}
	}
	if count != 6 {
		t.Fatalf("credential routes = %d, want the 6 M7-S4 routes", count)
	}
}
