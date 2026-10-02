// Authorization metadata contract (P2-D5, docs/12 §22.19): every implemented
// inventory (M7-S3) and credential (M7-S4) route must declare and enforce a
// capability + scope, and the OpenAPI document must advertise exactly the same
// metadata. This is the CI gate that fails when enforcement metadata drifts
// from the spec.
package contract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pb33f/libopenapi"

	"github.com/argus-platform/argus/internal/api"
	"github.com/argus-platform/argus/internal/platform/authz"
)

// isCheckPath reports whether a path belongs to the on-demand check surface
// (/v1/devices/{id}/checks and the M10-S3b-3 org-wide list/extent
// /v1/checks, /v1/checks/{id}).
func isCheckPath(path string) bool {
	return strings.HasPrefix(path, "/v1/checks") || strings.HasSuffix(path, "/checks")
}

// isPollHealthPath reports whether a path belongs to the M10-S3b-3 bounded
// recent poll-health feed (/v1/poll-health). The per-device M9-S1 route lives
// under /v1/devices and is covered by the inventory surface.
func isPollHealthPath(path string) bool {
	return path == "/v1/poll-health"
}

// isInventoryPath reports whether a path belongs to the M7-S3 inventory
// surface (/v1/devices, /v1/interfaces, /v1/device-groups). The M10-S0 check
// surface shares the /v1/devices prefix but has its own capability vocabulary
// (diagnostic.run on the creation POST) and is treated separately.
func isInventoryPath(path string) bool {
	if isCheckPath(path) {
		return false
	}
	return strings.HasPrefix(path, "/v1/devices") ||
		strings.HasPrefix(path, "/v1/interfaces") ||
		strings.HasPrefix(path, "/v1/device-groups")
}

// isCredentialPath reports whether a path belongs to the M7-S4 credential
// surface (/v1/credentials).
func isCredentialPath(path string) bool {
	return strings.HasPrefix(path, "/v1/credentials")
}

// isAlertRulePath reports whether a path belongs to the M11-S1 alert-rule
// surface (/v1/alert-rules and /v1/alert-rules:validate).
func isAlertRulePath(path string) bool {
	return strings.HasPrefix(path, "/v1/alert-rules")
}

// isAlertPath reports whether a path belongs to the M11-S1 alert lifecycle
// surface (/v1/alerts...). Checked after isAlertRulePath because the
// /v1/alert-rules prefix must not be captured by /v1/alerts.
func isAlertPath(path string) bool {
	return strings.HasPrefix(path, "/v1/alerts")
}

// M11-S3a suppression + stream surfaces: /v1/silences,
// /v1/maintenance-windows (both alert.silence) and /v1/streams/events
// (alert.read).
func isSilencePath(path string) bool {
	return strings.HasPrefix(path, "/v1/silences")
}

func isMaintenanceWindowPath(path string) bool {
	return strings.HasPrefix(path, "/v1/maintenance-windows")
}

func isAlertStreamPath(path string) bool {
	return strings.HasPrefix(path, "/v1/streams")
}

func isSuppressionPath(path string) bool {
	return isSilencePath(path) || isMaintenanceWindowPath(path) || isAlertStreamPath(path)
}

// M11-S2 notification surface: channels (integration.write), routes
// (alertrule.write) and the delivery log (alert.read) per docs/12 §22.14.
func isNotificationChannelPath(path string) bool {
	return strings.HasPrefix(path, "/v1/notification/channels")
}

func isNotificationRoutePath(path string) bool {
	return strings.HasPrefix(path, "/v1/notification/routes")
}

func isNotificationDeliveryPath(path string) bool {
	return strings.HasPrefix(path, "/v1/notification/deliveries")
}

func isNotificationPath(path string) bool {
	return isNotificationChannelPath(path) || isNotificationRoutePath(path) || isNotificationDeliveryPath(path)
}

type authzMeta struct {
	Capability string
	Scope      string
}

// capabilityInVocabulary reports whether capability belongs to the vocabulary
// enforced for the given surface. Check routes mix vocabularies: creation uses
// diagnostic.run, reads use device.read.
func capabilityInVocabulary(path, capability string) bool {
	if isCheckPath(path) {
		return authz.IsDiagnosticCapability(capability) || authz.IsInventoryCapability(capability)
	}
	if isCredentialPath(path) {
		return authz.IsCredentialCapability(capability)
	}
	if isAlertRulePath(path) {
		return authz.IsAlertRuleCapability(capability)
	}
	if isAlertPath(path) {
		return authz.IsAlertCapability(capability)
	}
	if isSuppressionPath(path) {
		return authz.IsAlertCapability(capability)
	}
	if isNotificationChannelPath(path) {
		return authz.IsIntegrationCapability(capability)
	}
	if isNotificationRoutePath(path) {
		return authz.IsAlertRuleCapability(capability)
	}
	if isNotificationDeliveryPath(path) {
		return authz.IsAlertCapability(capability)
	}
	return authz.IsInventoryCapability(capability)
}

// TestInventoryAuthzMetadataMatchesRoutes compares the route registry's
// enforced capability/scope metadata against the OpenAPI vendor extensions for
// the inventory, credential AND on-demand check surfaces:
//
//   - an implemented route without capability/scope metadata fails;
//   - an operation without x-argus-capability or x-argus-scope fails;
//   - a route and operation that disagree on method/path or metadata fail;
//   - an OpenAPI operation declaring metadata the registry does not enforce
//     fails;
//   - a capability outside the surface's pinned vocabulary fails.
func TestInventoryAuthzMetadataMatchesRoutes(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "openapi", "argus.v1.yaml"))
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	doc, err := libopenapi.NewDocument(raw)
	if err != nil {
		t.Fatalf("parse spec: %v", err)
	}
	model, err := doc.BuildV3Model()
	if err != nil {
		t.Fatalf("spec build errors: %v", err)
	}

	// Enforced metadata from the route registry.
	enforced := map[routeKey]authzMeta{}
	inventoryCount, credentialCount, checkCount, pollHealthCount := 0, 0, 0, 0
	alertRuleCount, alertCount := 0, 0
	channelCount, routeCount, deliveryCount := 0, 0, 0
	silenceCount, windowCount, streamCount := 0, 0, 0
	for _, rt := range api.Routes() {
		if !isInventoryPath(rt.Path) && !isCredentialPath(rt.Path) && !isCheckPath(rt.Path) &&
			!isPollHealthPath(rt.Path) && !isAlertRulePath(rt.Path) && !isAlertPath(rt.Path) &&
			!isNotificationPath(rt.Path) && !isSuppressionPath(rt.Path) {
			continue
		}
		switch {
		case isCheckPath(rt.Path):
			checkCount++
		case isPollHealthPath(rt.Path):
			pollHealthCount++
		case isCredentialPath(rt.Path):
			credentialCount++
		case isNotificationChannelPath(rt.Path):
			channelCount++
		case isNotificationRoutePath(rt.Path):
			routeCount++
		case isNotificationDeliveryPath(rt.Path):
			deliveryCount++
		case isSilencePath(rt.Path):
			silenceCount++
		case isMaintenanceWindowPath(rt.Path):
			windowCount++
		case isAlertStreamPath(rt.Path):
			streamCount++
		case isAlertRulePath(rt.Path):
			alertRuleCount++
		case isAlertPath(rt.Path):
			alertCount++
		default:
			inventoryCount++
		}
		enforced[routeKey{rt.Method, rt.Path}] = authzMeta{Capability: rt.Capability, Scope: rt.Scope}
	}
	if inventoryCount != 22 {
		t.Fatalf("inventory routes in registry = %d, want the 18 M7-S3 routes + 1 M9-S1 poll-health route + 1 M10-S1 device-status route + 2 M10-S3b-1 identity routes", inventoryCount)
	}
	if credentialCount != 6 {
		t.Fatalf("credential routes in registry = %d, want the 6 M7-S4 routes", credentialCount)
	}
	if checkCount != 3 {
		t.Fatalf("check routes in registry = %d, want the 2 M10-S0 routes + the M10-S3b-3 org-wide collection read (GET /v1/checks)", checkCount)
	}
	if pollHealthCount != 1 {
		t.Fatalf("poll-health list routes in registry = %d, want 1 (GET /v1/poll-health)", pollHealthCount)
	}
	if alertRuleCount != 7 {
		t.Fatalf("alert-rule routes in registry = %d, want the 6 M11-S1 routes + the M11-S2 install-defaults route", alertRuleCount)
	}
	if alertCount != 6 {
		t.Fatalf("alert routes in registry = %d, want the 6 M11-S1 routes", alertCount)
	}
	if channelCount != 6 {
		t.Fatalf("notification channel routes in registry = %d, want the 6 M11-S2 routes", channelCount)
	}
	if routeCount != 5 {
		t.Fatalf("notification route routes in registry = %d, want the 5 M11-S2 routes", routeCount)
	}
	if deliveryCount != 1 {
		t.Fatalf("notification delivery routes in registry = %d, want 1 (GET /v1/notification/deliveries)", deliveryCount)
	}
	if silenceCount != 3 {
		t.Fatalf("silence routes in registry = %d, want the 3 M11-S3a routes (POST/GET /v1/silences, DELETE /v1/silences/{id})", silenceCount)
	}
	if windowCount != 5 {
		t.Fatalf("maintenance-window routes in registry = %d, want the 5 M11-S3a CRUD routes", windowCount)
	}
	if streamCount != 1 {
		t.Fatalf("stream routes in registry = %d, want 1 (GET /v1/streams/events)", streamCount)
	}
	for key, meta := range enforced {
		if meta.Capability == "" {
			t.Errorf("route %s %s: missing enforced capability metadata", key.method, key.path)
			continue
		}
		if meta.Scope == "" {
			t.Errorf("route %s %s: missing enforced scope metadata", key.method, key.path)
			continue
		}
		if !capabilityInVocabulary(key.path, meta.Capability) {
			t.Errorf("route %s %s: capability %q not in the %s vocabulary", key.method, key.path, meta.Capability, vocabularyName(key.path))
		}
		if !authz.IsScope(meta.Scope) {
			t.Errorf("route %s %s: scope %q not in {org,site,device_group,device}", key.method, key.path, meta.Scope)
		}
	}

	// Documented metadata from the OpenAPI operations.
	documented := map[routeKey]authzMeta{}
	for pair := model.Model.Paths.PathItems.First(); pair != nil; pair = pair.Next() {
		path := pair.Key()
		if !isInventoryPath(path) && !isCredentialPath(path) && !isCheckPath(path) &&
			!isPollHealthPath(path) && !isAlertRulePath(path) && !isAlertPath(path) &&
			!isNotificationPath(path) && !isSuppressionPath(path) {
			continue
		}
		item := pair.Value()
		if item == nil {
			continue
		}
		for opPair := item.GetOperations().First(); opPair != nil; opPair = opPair.Next() {
			method := strings.ToUpper(opPair.Key())
			op := opPair.Value()
			if op == nil {
				continue
			}
			key := routeKey{method, path}
			var meta authzMeta
			hasCap := false
			hasScope := false
			if op.Extensions != nil {
				if node, ok := op.Extensions.Get("x-argus-capability"); ok && node != nil {
					meta.Capability = node.Value
					hasCap = true
				}
				if node, ok := op.Extensions.Get("x-argus-scope"); ok && node != nil {
					meta.Scope = node.Value
					hasScope = true
				}
			}
			switch {
			case !hasCap && !hasScope:
				t.Errorf("OpenAPI operation %s %s: missing x-argus-capability and x-argus-scope", method, path)
				continue
			case !hasCap:
				t.Errorf("OpenAPI operation %s %s: missing x-argus-capability", method, path)
				continue
			case !hasScope:
				t.Errorf("OpenAPI operation %s %s: missing x-argus-scope (scope mapping)", method, path)
				continue
			}
			if meta.Capability == "" || meta.Scope == "" {
				t.Errorf("OpenAPI operation %s %s: empty capability/scope metadata", method, path)
				continue
			}
			if !capabilityInVocabulary(path, meta.Capability) {
				t.Errorf("OpenAPI operation %s %s: capability %q not in the %s vocabulary", method, path, meta.Capability, vocabularyName(path))
				continue
			}
			if !authz.IsScope(meta.Scope) {
				t.Errorf("OpenAPI operation %s %s: scope %q not in {org,site,device_group,device}", method, path, meta.Scope)
				continue
			}
			documented[key] = meta
		}
	}

	// Route registry -> spec: every enforced route must be documented with the
	// same metadata (this also catches method/path disagreements).
	for key, meta := range enforced {
		documentedMeta, ok := documented[key]
		if !ok {
			t.Errorf("implemented route %s %s is missing OpenAPI capability/scope metadata", key.method, key.path)
			continue
		}
		if documentedMeta.Capability != meta.Capability {
			t.Errorf("%s %s: OpenAPI capability %q but route enforces %q", key.method, key.path, documentedMeta.Capability, meta.Capability)
		}
		if documentedMeta.Scope != meta.Scope {
			t.Errorf("%s %s: OpenAPI scope %q but route enforces %q", key.method, key.path, documentedMeta.Scope, meta.Scope)
		}
	}

	// Spec -> route registry: no documented metadata without enforcement.
	for key := range documented {
		if _, ok := enforced[key]; !ok {
			t.Errorf("OpenAPI operation %s %s declares x-argus metadata but the route registry does not enforce it", key.method, key.path)
		}
	}
}

func vocabularyName(path string) string {
	switch {
	case isCheckPath(path):
		return "check"
	case isPollHealthPath(path):
		return "poll-health"
	case isCredentialPath(path):
		return "credential"
	case isNotificationChannelPath(path):
		return "notification-channel"
	case isNotificationRoutePath(path):
		return "notification-route"
	case isNotificationDeliveryPath(path):
		return "notification-delivery"
	case isAlertRulePath(path):
		return "alert-rule"
	case isAlertPath(path):
		return "alert"
	case isSuppressionPath(path):
		return "alert-suppression"
	default:
		return "inventory"
	}
}
