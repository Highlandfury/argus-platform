package api

import (
	"strings"
	"testing"

	"github.com/argus-platform/argus/internal/platform/authz"
)

func inventoryRoute(path string) bool {
	return strings.HasPrefix(path, "/v1/devices") ||
		strings.HasPrefix(path, "/v1/interfaces") ||
		strings.HasPrefix(path, "/v1/device-groups")
}

func credentialRoute(path string) bool {
	return strings.HasPrefix(path, "/v1/credentials")
}

// TestInventoryRoutesDeclareCapabilityAndScope pins the M7-S3 route metadata:
// all 18 inventory routes declare a capability from the vocabulary and a scope
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
	if inventory != 18 {
		t.Fatalf("inventory routes = %d, want the 18 M7-S3 routes", inventory)
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
