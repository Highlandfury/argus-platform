package alerts

// P2-AC-32 curated default pack unit tests: the embedded YAML must parse,
// every rule must pass the exact same ParseRule path as operator input, and
// the curated key set is pinned (a duplicate/typo key fails here instead of at
// install time).

import (
	"testing"
)

func TestDefaultPackParsesAndValidates(t *testing.T) {
	pack, err := DefaultPack()
	if err != nil {
		t.Fatalf("DefaultPack: %v", err)
	}
	if len(pack) != 5 {
		t.Fatalf("default pack size = %d, want 5", len(pack))
	}
	wantKeys := map[string]bool{
		"device-unreachable-icmp":    false,
		"poll-failures":              false,
		"interface-down":             false,
		"cpu-high":                   false,
		"interface-utilization-high": false,
	}
	for _, dr := range pack {
		if _, ok := wantKeys[dr.Key]; !ok {
			t.Fatalf("unexpected default rule key %q", dr.Key)
		}
		if wantKeys[dr.Key] {
			t.Fatalf("duplicate default rule key %q", dr.Key)
		}
		wantKeys[dr.Key] = true
		if dr.Name == "" || dr.Input.Name != dr.Name {
			t.Fatalf("rule %q name mismatch: %q", dr.Key, dr.Name)
		}
		if _, errs := ParseRule(dr.Input.Name, dr.Input.Type, dr.Input.Severity, dr.Input.ConditionJSON, dr.Input.SelectorJSON); len(errs) > 0 {
			t.Fatalf("rule %q does not re-validate: %v", dr.Key, errs)
		}
		switch dr.Input.Type {
		case TypeThreshold, TypeAbsence:
		default:
			t.Fatalf("rule %q has non-v1 type %q", dr.Key, dr.Input.Type)
		}
		switch dr.Input.Severity {
		case SeverityInfo, SeverityWarning, SeverityCritical:
		default:
			t.Fatalf("rule %q has invalid severity %q", dr.Key, dr.Input.Severity)
		}
	}
	for key, seen := range wantKeys {
		if !seen {
			t.Fatalf("default pack is missing key %q", key)
		}
	}
}
