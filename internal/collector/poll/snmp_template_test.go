package poll

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestCoreTemplateSetLoads(t *testing.T) {
	set, err := CoreTemplateSet()
	if err != nil {
		t.Fatalf("CoreTemplateSet: %v", err)
	}
	names := make([]string, 0, len(set.Packs()))
	for _, p := range set.Packs() {
		names = append(names, p.Name)
	}
	for _, want := range []string{"core/system", "core/if-mib", "core/host-resources"} {
		found := false
		for _, n := range names {
			if n == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("core pack %s missing from %v", want, names)
		}
	}
}

func TestCoreTemplateSelectionByKind(t *testing.T) {
	set, err := CoreTemplateSet()
	if err != nil {
		t.Fatalf("CoreTemplateSet: %v", err)
	}
	names := func(kind string) map[string]bool {
		out := map[string]bool{}
		for _, p := range set.Select(kind) {
			out[p.Name] = true
		}
		return out
	}
	sw := names("switch")
	if !sw["core/system"] || !sw["core/if-mib"] || sw["core/host-resources"] {
		t.Fatalf("switch selection = %v", sw)
	}
	host := names("host")
	if !host["core/system"] || !host["core/host-resources"] || host["core/if-mib"] {
		t.Fatalf("host selection = %v", host)
	}
	unknown := names("printer")
	if !unknown["core/system"] || len(unknown) != 1 {
		t.Fatalf("unknown-kind selection = %v, want system only", unknown)
	}
}

func TestCoreTemplateCounterDeclarations(t *testing.T) {
	set, err := CoreTemplateSet()
	if err != nil {
		t.Fatalf("CoreTemplateSet: %v", err)
	}
	var ifMIB *SNMPTemplate
	for i := range set.Packs() {
		if set.Packs()[i].Name == "core/if-mib" {
			ifMIB = &set.Packs()[i]
		}
	}
	if ifMIB == nil {
		t.Fatal("core/if-mib missing")
	}
	byKey := map[string]SNMPColumn{}
	for _, c := range ifMIB.Columns {
		byKey[c.Key] = c
	}
	for _, key := range []string{"net.if.in_octets", "net.if.out_octets"} {
		col, ok := byKey[key]
		if !ok {
			t.Fatalf("%s missing", key)
		}
		if col.Type != SNMPMetricCounter || col.Width != CounterWidth64 {
			t.Fatalf("%s = type %s width %d, want counter/64", key, col.Type, col.Width)
		}
		if col.MaxRate <= 0 {
			t.Fatalf("%s needs a false-spike ceiling", key)
		}
	}
	for _, key := range []string{"net.if.in_errors", "net.if.out_errors", "net.if.in_discards", "net.if.out_discards"} {
		if col, ok := byKey[key]; !ok || col.Width != CounterWidth32 {
			t.Fatalf("%s = %+v, want 32-bit counter", key, col)
		}
	}
	// Identity chains must include ifName first and ifDescr fallback; ifIndex
	// must never appear as an identity dimension.
	var sawName, sawDescr bool
	for _, id := range ifMIB.Identity {
		if id.Dim == "if_index" {
			t.Fatal("ifIndex must never be the identity")
		}
		for _, oid := range id.OIDs {
			if oid == "1.3.6.1.2.1.31.1.1.1.1" {
				sawName = true
			}
			if oid == "1.3.6.1.2.1.2.2.1.2" {
				sawDescr = true
			}
		}
	}
	if !sawName || !sawDescr {
		t.Fatal("ifName (primary) and ifDescr (fallback) identity OIDs required")
	}
}

func TestTemplateValidationRejectsBadPacks(t *testing.T) {
	cases := map[string]string{
		"unknown type": `
name: bad
version: 1
columns:
  - oid: "1.2.3.4"
    key: bad.key
    unit: percent
    type: magic
tables:
  - name: t
    walk: "1.2.3"
    max_rows: 1
`,
		"counter width": `
name: bad
version: 1
columns:
  - oid: "1.2.3.4"
    key: bad.key
    unit: count/s
    type: counter
    width: 48
tables:
  - name: t
    walk: "1.2.3"
    max_rows: 1
`,
		"missing unit": `
name: bad
version: 1
columns:
  - oid: "1.2.3.4"
    key: bad.key
    type: gauge
tables:
  - name: t
    walk: "1.2.3"
    max_rows: 1
`,
		"unknown field": `
name: bad
version: 1
select:
  kinds: [switch]
bogus: true
`,
	}
	for label, yaml := range cases {
		fsys := fstest.MapFS{"templates/x.yaml": &fstest.MapFile{Data: []byte(yaml)}}
		if _, err := LoadSNMPTemplates(fsys, "templates"); err == nil {
			t.Errorf("%s: expected rejection", label)
		}
	}
}

func TestTemplateDuplicateMetricKeyAcrossPacksRejected(t *testing.T) {
	yaml := `
name: dup
version: 1
columns:
  - oid: "1.2.3.4"
    key: same.key
    unit: percent
    type: gauge
tables:
  - name: t
    walk: "1.2.3"
    max_rows: 1
`
	fsys := fstest.MapFS{
		"templates/a.yaml": &fstest.MapFile{Data: []byte(yaml)},
		"templates/b.yaml": &fstest.MapFile{Data: []byte(strings.ReplaceAll(yaml, "dup", "dup2"))},
	}
	if _, err := LoadSNMPTemplates(fsys, "templates"); err == nil {
		t.Fatal("duplicate metric keys across packs must be rejected")
	}
}
