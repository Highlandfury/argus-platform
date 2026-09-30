// Inventory authorization metadata contract (P2-D5, docs/12 §22.19): every
// implemented inventory route must declare and enforce a capability + scope,
// and the OpenAPI document must advertise exactly the same metadata. This is
// the CI gate that fails when enforcement metadata drifts from the spec.
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

// isInventoryPath reports whether a path belongs to the M7-S3 inventory
// surface (/v1/devices, /v1/interfaces, /v1/device-groups).
func isInventoryPath(path string) bool {
	return strings.HasPrefix(path, "/v1/devices") ||
		strings.HasPrefix(path, "/v1/interfaces") ||
		strings.HasPrefix(path, "/v1/device-groups")
}

type authzMeta struct {
	Capability string
	Scope      string
}

// TestInventoryAuthzMetadataMatchesRoutes compares the route registry's
// enforced capability/scope metadata against the OpenAPI vendor extensions:
//
//   - an implemented inventory route without capability/scope metadata fails;
//   - an inventory operation without x-argus-capability or x-argus-scope fails;
//   - a route and operation that disagree on method/path or metadata fail;
//   - an OpenAPI operation declaring metadata the registry does not enforce
//     fails.
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
	for _, rt := range api.Routes() {
		if !isInventoryPath(rt.Path) {
			continue
		}
		enforced[routeKey{rt.Method, rt.Path}] = authzMeta{Capability: rt.Capability, Scope: rt.Scope}
	}
	if len(enforced) != 18 {
		t.Fatalf("inventory routes in registry = %d, want the 18 M7-S3 routes", len(enforced))
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
		if !authz.IsInventoryCapability(meta.Capability) {
			t.Errorf("route %s %s: capability %q not in the inventory vocabulary", key.method, key.path, meta.Capability)
		}
		if !authz.IsScope(meta.Scope) {
			t.Errorf("route %s %s: scope %q not in {org,site,device_group,device}", key.method, key.path, meta.Scope)
		}
	}

	// Documented metadata from the OpenAPI operations.
	documented := map[routeKey]authzMeta{}
	for pair := model.Model.Paths.PathItems.First(); pair != nil; pair = pair.Next() {
		path := pair.Key()
		if !isInventoryPath(path) {
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
			documented[key] = meta
		}
	}

	// Route registry -> spec: every enforced route must be documented with the
	// same metadata (this also catches method/path disagreements).
	for key, meta := range enforced {
		documentedMeta, ok := documented[key]
		if !ok {
			t.Errorf("implemented inventory route %s %s is missing OpenAPI capability/scope metadata", key.method, key.path)
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
