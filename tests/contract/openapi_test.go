// Package contract validates openapi/argus.v1.yaml against the implemented
// route registry. CI runs it as the contract gate (SPEC §16, stage 6).
package contract

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/pb33f/libopenapi"

	"github.com/argus-platform/argus/internal/api"
)

type routeKey struct{ method, path string }

// pending lists endpoints that are specified but scheduled for later
// milestones. Every entry must still exist in the spec, so the allowlist
// cannot rot silently.
var pending = map[string]string{
	"POST /v1/enrollments":                   "M3 collectors/enrollment",
	"GET /v1/enrollments":                    "M3 collectors/enrollment",
	"GET /v1/collectors":                     "M3 collectors",
	"GET /v1/collectors/{id}":                "M3 collectors",
	"POST /v1/collectors/{id}:revoke":        "M3 collectors",
	"POST /v1/collectors/{id}/policy:resync": "M3 collectors",
	"GET /v1/collectors/{id}/metrics":        "M4 metrics query",
}

func TestOpenAPISpecMatchesRoutes(t *testing.T) {
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
	info := doc.GetSpecInfo()
	if info == nil || info.Version != "3.1.0" {
		t.Fatalf("expected OpenAPI 3.1.0 spec, got info: %+v", info)
	}

	spec := map[routeKey]bool{}
	for pair := model.Model.Paths.PathItems.First(); pair != nil; pair = pair.Next() {
		path := pair.Key()
		item := pair.Value()
		if item == nil {
			continue
		}
		for opPair := item.GetOperations().First(); opPair != nil; opPair = opPair.Next() {
			spec[routeKey{strings.ToUpper(opPair.Key()), path}] = true
		}
	}
	if len(spec) == 0 {
		t.Fatal("no operations found in the spec")
	}

	implemented := map[routeKey]bool{}
	for _, rt := range api.Routes() {
		implemented[routeKey{rt.Method, rt.Path}] = true
	}

	var missing []string
	for k := range spec {
		if implemented[k] {
			continue
		}
		if _, ok := pending[k.method+" "+k.path]; ok {
			continue
		}
		missing = append(missing, k.method+" "+k.path)
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("spec endpoints not implemented and not marked pending:\n  %s", strings.Join(missing, "\n  "))
	}

	var undocumented []string
	for k := range implemented {
		if strings.HasPrefix(k.path, "/v1/") && !spec[k] {
			undocumented = append(undocumented, k.method+" "+k.path)
		}
	}
	sort.Strings(undocumented)
	if len(undocumented) > 0 {
		t.Errorf("implemented routes missing from the OpenAPI spec:\n  %s", strings.Join(undocumented, "\n  "))
	}

	for key := range pending {
		parts := strings.SplitN(key, " ", 2)
		if len(parts) != 2 || !spec[routeKey{parts[0], parts[1]}] {
			t.Errorf("stale pending entry (not present in spec): %s", key)
		}
	}
}
