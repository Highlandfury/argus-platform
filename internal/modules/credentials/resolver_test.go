package credentials

import (
	"testing"

	"github.com/google/uuid"
)

func candidateFor(name, scopeType string, priority int, credentialID uuid.UUID) candidate {
	return candidate{
		Credential: Credential{ID: credentialID, Name: name, Kind: "snmp_v2c"},
		Binding:    Binding{CredentialID: credentialID, ScopeType: scopeType, Priority: priority},
	}
}

var (
	olderID = uuid.MustParse("01111111-1111-7111-8111-111111111111")
	newerID = uuid.MustParse("02111111-1111-7111-8111-111111111111")
	otherID = uuid.MustParse("03111111-1111-7111-8111-111111111111")
)

// TestSelectEffectivePrecedence pins the canonical dispatch precedence:
// device > device_group > site > org regardless of priority.
func TestSelectEffectivePrecedence(t *testing.T) {
	cases := []struct {
		name       string
		candidates []candidate
		want       uuid.UUID
		wantScope  string
	}{
		{
			"device beats everything",
			[]candidate{
				candidateFor("org", "org", 999, otherID),
				candidateFor("site", "site", 999, otherID),
				candidateFor("group", "device_group", 999, otherID),
				candidateFor("device", "device", 0, olderID),
			},
			olderID, "device",
		},
		{
			"group beats site and org",
			[]candidate{
				candidateFor("org", "org", 50, otherID),
				candidateFor("site", "site", 10, otherID),
				candidateFor("group", "device_group", -5, olderID),
			},
			olderID, "device_group",
		},
		{
			"site beats org",
			[]candidate{
				candidateFor("org", "org", 100, otherID),
				candidateFor("site", "site", -100, olderID),
			},
			olderID, "site",
		},
		{
			"org alone",
			[]candidate{candidateFor("org", "org", 0, olderID)},
			olderID, "org",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := selectEffective(tc.candidates)
			if !ok {
				t.Fatal("no effective credential selected")
			}
			if got.CredentialID != tc.want || got.ScopeType != tc.wantScope {
				t.Fatalf("effective = %s/%s, want %s/%s", got.CredentialID, got.ScopeType, tc.want, tc.wantScope)
			}
		})
	}
}

// TestSelectEffectivePriorityAndTieBreak pins the within-level rules: higher
// priority wins; equal priority is broken by the lowest (oldest) credential id
// deterministically.
func TestSelectEffectivePriorityAndTieBreak(t *testing.T) {
	got, ok := selectEffective([]candidate{
		candidateFor("site-low", "site", 1, olderID),
		candidateFor("site-high", "site", 10, newerID),
	})
	if !ok || got.CredentialID != newerID || got.Priority != 10 {
		t.Fatalf("priority selection = %+v", got)
	}

	got, ok = selectEffective([]candidate{
		candidateFor("newer", "site", 5, newerID),
		candidateFor("older", "site", 5, olderID),
		candidateFor("other", "site", 5, otherID),
	})
	if !ok || got.CredentialID != olderID || got.Name != "older" {
		t.Fatalf("tie-break selection = %+v", got)
	}

	// Determinism under permutation.
	perm := []candidate{
		candidateFor("other", "site", 5, otherID),
		candidateFor("newer", "site", 5, newerID),
		candidateFor("older", "site", 5, olderID),
	}
	for i := 0; i < 5; i++ {
		if got2, _ := selectEffective(append([]candidate(nil), perm...)); got2.CredentialID != olderID {
			t.Fatalf("permuted tie-break = %s, want %s", got2.CredentialID, olderID)
		}
	}
}

// TestSelectEffectiveFailClosed: no candidates, and candidates with an unknown
// scope type, resolve to nothing.
func TestSelectEffectiveFailClosed(t *testing.T) {
	if _, ok := selectEffective(nil); ok {
		t.Fatal("empty candidate set must not resolve")
	}
	if _, ok := selectEffective([]candidate{candidateFor("bogus", "bogus", 100, olderID)}); ok {
		t.Fatal("unknown scope type must not resolve")
	}
}

// TestScopeTypesAndRank pins the vocabulary and the precedence tiers.
func TestScopeTypesAndRank(t *testing.T) {
	want := map[string]int{"device": 1, "device_group": 2, "site": 3, "org": 4}
	for _, st := range ScopeTypes {
		rank, ok := want[st]
		if !ok {
			t.Fatalf("unexpected scope type %q", st)
		}
		if scopeRank(st) != rank {
			t.Fatalf("scopeRank(%q) = %d, want %d", st, scopeRank(st), rank)
		}
		if !IsScopeType(st) {
			t.Fatalf("IsScopeType(%q) = false", st)
		}
	}
	if IsScopeType("building") || scopeRank("building") != 5 {
		t.Fatal("unknown scope types must not be accepted or win")
	}
}
