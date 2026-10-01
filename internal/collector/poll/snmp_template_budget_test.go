package poll

import (
	"strings"
	"testing"
	"testing/fstest"
)

// TestM9S4TemplateSeriesBudgetGate is the P2-AC-11 compile-time CI gate: every
// embedded template compiles and its worst-case per-device series estimate
// stays within the canonical per-device budget (default 250, docs/08 §13.3);
// the per-kind totals over the selected pack set must fit too.
func TestM9S4TemplateSeriesBudgetGate(t *testing.T) {
	set, err := CoreTemplateSet()
	if err != nil {
		t.Fatalf("CoreTemplateSet: %v", err)
	}
	for _, p := range set.Packs() {
		est, budget := p.EstimatedSeries(), p.SeriesBudgetOrDefault()
		if est > budget {
			t.Fatalf("%s estimates %d series/device over budget %d", p.Name, est, budget)
		}
		if budget != DefaultSeriesBudget {
			t.Fatalf("%s budget = %d, want the canonical default %d", p.Name, budget, DefaultSeriesBudget)
		}
	}

	// Per-kind totals over every pack the device kind selects.
	for _, kind := range []string{"switch", "router", "firewall", "ap", "gateway", "load_balancer", "host", "server", "printer", ""} {
		if got := set.EstimateForKind(kind); got > DefaultSeriesBudget {
			t.Fatalf("kind %q selects %d estimated series/device, over the %d cap", kind, got, DefaultSeriesBudget)
		}
	}
	// Pin the core-pack estimates so a silent template change is caught.
	est := map[string]int{}
	for _, p := range set.Packs() {
		est[p.Name] = p.EstimatedSeries()
	}
	want := map[string]int{
		"core/system":         1,
		"core/if-mib":         7 * 25, // 7 emitting columns × canonical 25 interfaces
		"core/host-resources": 64,     // one series per documented CPU ceiling
	}
	for name, w := range want {
		if est[name] != w {
			t.Fatalf("%s estimate = %d, want %d", name, est[name], w)
		}
	}
	if got := set.EstimateForKind("switch"); got != 1+7*25 {
		t.Fatalf("switch estimate = %d, want %d", got, 1+7*25)
	}
}

func TestTemplateOverBudgetRejectedLoudly(t *testing.T) {
	over := `
name: over
version: 1
columns:
  - oid: "1.2.3.4"
    key: over.a
    unit: percent
    type: gauge
  - oid: "1.2.3.5"
    key: over.b
    unit: percent
    type: gauge
tables:
  - name: t
    walk: "1.2.3"
    max_rows: 200
`
	fsys := fstest.MapFS{"templates/x.yaml": &fstest.MapFile{Data: []byte(over)}}
	_, err := LoadSNMPTemplates(fsys, "templates")
	if err == nil {
		t.Fatal("over-budget template must be rejected")
	}
	if !strings.Contains(err.Error(), "series budget") {
		t.Fatalf("error = %v, want a series-budget rejection", err)
	}

	// The same template compiles with an explicit operator override.
	override := strings.Replace(over, "version: 1", "version: 1\nseries_budget: 400", 1)
	fsys = fstest.MapFS{"templates/x.yaml": &fstest.MapFile{Data: []byte(override)}}
	if _, err := LoadSNMPTemplates(fsys, "templates"); err != nil {
		t.Fatalf("explicit series_budget override rejected: %v", err)
	}
}

func TestTemplateMaxRowsRequiredForEmittingTables(t *testing.T) {
	missing := `
name: no-rows
version: 1
columns:
  - oid: "1.2.3.4"
    key: no.rows
    unit: percent
    type: gauge
tables:
  - name: t
    walk: "1.2.3"
`
	fsys := fstest.MapFS{"templates/x.yaml": &fstest.MapFile{Data: []byte(missing)}}
	if _, err := LoadSNMPTemplates(fsys, "templates"); err == nil {
		t.Fatal("emitting table without max_rows must be rejected")
	}

	// A table with only string columns needs no row bound (no series).
	stringsOnly := `
name: identity-only
version: 1
columns:
  - oid: "1.2.3.4"
    key: id.name
    type: string
tables:
  - name: t
    walk: "1.2.3"
`
	fsys = fstest.MapFS{"templates/x.yaml": &fstest.MapFile{Data: []byte(stringsOnly)}}
	if _, err := LoadSNMPTemplates(fsys, "templates"); err != nil {
		t.Fatalf("string-only table rejected: %v", err)
	}
}
