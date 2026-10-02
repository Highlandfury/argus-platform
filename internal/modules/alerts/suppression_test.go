package alerts

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func TestParseTargetScopeJSON(t *testing.T) {
	site := uuid.MustParse("01890000-0000-7000-8000-000000000001")
	dev := uuid.MustParse("01890000-0000-7000-8000-000000000002")
	raw := `{"sites":["` + site.String() + `"],"device_ids":["` + dev.String() + `"],"device_kinds":["switch","ap"]}`
	scope, errs := ParseTargetScopeJSON("scope", []byte(raw))
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	if len(scope.Sites) != 1 || scope.Sites[0] != site {
		t.Fatalf("sites = %v", scope.Sites)
	}
	if len(scope.DeviceIDs) != 1 || scope.DeviceIDs[0] != dev {
		t.Fatalf("device_ids = %v", scope.DeviceIDs)
	}
	// canonical JSON sorts kinds.
	var canonical map[string]any
	if err := json.Unmarshal(scope.canonicalJSON(), &canonical); err != nil {
		t.Fatalf("canonical: %v", err)
	}
	kinds, _ := canonical["device_kinds"].([]any)
	if len(kinds) != 2 || kinds[0] != "ap" || kinds[1] != "switch" {
		t.Fatalf("canonical kinds = %v, want sorted [ap switch]", canonical["device_kinds"])
	}

	for name, input := range map[string]string{
		"unknown field": `{"metric_key":"x"}`,
		"bad uuid":      `{"sites":["nope"]}`,
		"not an object": `[]`,
	} {
		if _, errs := ParseTargetScopeJSON("scope", []byte(input)); len(errs) == 0 {
			t.Errorf("%s: expected validation error", name)
		}
	}
	if scope, errs := ParseTargetScopeJSON("scope", nil); len(errs) > 0 || !scope.IsEmpty() {
		t.Fatalf("empty scope: %v %v", scope, errs)
	}
}

func TestTargetScopeMatches(t *testing.T) {
	siteA := uuid.MustParse("01890000-0000-7000-8000-00000000000a")
	siteB := uuid.MustParse("01890000-0000-7000-8000-00000000000b")
	devA := uuid.MustParse("01890000-0000-7000-8000-00000000000c")

	empty := TargetScope{}
	if !empty.Matches(uuid.Nil, uuid.Nil, "") {
		t.Fatal("empty scope must match every device (org-wide)")
	}
	bySite := TargetScope{Sites: []uuid.UUID{siteA}}
	if !bySite.Matches(siteA, devA, "switch") || bySite.Matches(siteB, devA, "switch") {
		t.Fatal("site match wrong")
	}
	byDevice := TargetScope{DeviceIDs: []uuid.UUID{devA}}
	if !byDevice.Matches(siteB, devA, "switch") || byDevice.Matches(siteB, uuid.Nil, "switch") {
		t.Fatal("device match wrong")
	}
	byKind := TargetScope{DeviceKinds: []string{"ap"}}
	if !byKind.Matches(siteB, devA, "ap") || byKind.Matches(siteB, devA, "switch") {
		t.Fatal("kind match wrong")
	}
}

func TestParseSilenceMatchJSON(t *testing.T) {
	alertID := uuid.MustParse("01890000-0000-7000-8000-0000000000aa")
	site := uuid.MustParse("01890000-0000-7000-8000-0000000000bb")
	fp := "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12"

	m, errs := ParseSilenceMatchJSON([]byte(`{"alert_id":"` + alertID.String() + `"}`))
	if len(errs) > 0 || m.AlertID == nil || *m.AlertID != alertID {
		t.Fatalf("alert_id match: %+v %v", m, errs)
	}
	m, errs = ParseSilenceMatchJSON([]byte(`{"fingerprint":"` + fp + `"}`))
	if len(errs) > 0 || m.Fingerprint != fp {
		t.Fatalf("fingerprint match: %+v %v", m, errs)
	}
	m, errs = ParseSilenceMatchJSON([]byte(`{"scope":{"sites":["` + site.String() + `"]}}`))
	if len(errs) > 0 || len(m.Scope.Sites) != 1 {
		t.Fatalf("scope match: %+v %v", m, errs)
	}
	// Inline scope fields are accepted as an alias.
	m, errs = ParseSilenceMatchJSON([]byte(`{"sites":["` + site.String() + `"]}`))
	if len(errs) > 0 || len(m.Scope.Sites) != 1 {
		t.Fatalf("inline scope: %+v %v", m, errs)
	}

	for name, input := range map[string]string{
		"empty":        `{}`,
		"unknown":      `{"rule_id":"x"}`,
		"bad uuid":     `{"alert_id":"nope"}`,
		"short fp":     `{"fingerprint":"abc"}`,
		"non-hex fp":   `{"fingerprint":"zz12zz12zz12zz12zz12zz12zz12zz12zz12zz12zz12zz12zz12zz12zz12zz12"}`,
		"scope+inline": `{"scope":{},"sites":["` + site.String() + `"]}`,
	} {
		if _, errs := ParseSilenceMatchJSON([]byte(input)); len(errs) == 0 {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

func TestSilenceMatchMatchesAndSemantics(t *testing.T) {
	alertID := uuid.MustParse("01890000-0000-7000-8000-0000000000aa")
	otherID := uuid.MustParse("01890000-0000-7000-8000-0000000000ab")
	site := uuid.MustParse("01890000-0000-7000-8000-0000000000bb")
	dev := uuid.MustParse("01890000-0000-7000-8000-0000000000cc")
	fp := "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12"

	byID := SilenceMatch{AlertID: &alertID}
	if !byID.Matches(&alertID, fp, site, dev, "switch") || byID.Matches(&otherID, fp, site, dev, "switch") {
		t.Fatal("alert_id matcher wrong")
	}
	if byID.Matches(nil, fp, site, dev, "switch") {
		t.Fatal("alert_id matcher must not match a new alert")
	}
	byFP := SilenceMatch{Fingerprint: fp}
	if !byFP.Matches(nil, fp, site, dev, "switch") || byFP.Matches(nil, "different", site, dev, "switch") {
		t.Fatal("fingerprint matcher wrong")
	}
	// Multiple matchers combine with AND.
	combined := SilenceMatch{AlertID: &alertID, Fingerprint: fp}
	if !combined.Matches(&alertID, fp, site, dev, "switch") {
		t.Fatal("AND matcher should match when both match")
	}
	if combined.Matches(&alertID, "different", site, dev, "switch") {
		t.Fatal("AND matcher must fail when one matcher fails")
	}
}

func TestStreamNameMapping(t *testing.T) {
	cases := map[string]string{
		EventActivated:      StreamEventFired,
		EventReactivated:    StreamEventFired,
		EventReopened:       StreamEventFired,
		EventResolved:       StreamEventResolved,
		EventManualResolved: StreamEventResolved,
		EventPending:        StreamEventUpdated,
		EventUpdated:        StreamEventUpdated,
		EventAcknowledged:   StreamEventUpdated,
		EventSnoozed:        StreamEventUpdated,
		EventUnsnoozed:      StreamEventUpdated,
		EventSuppressed:     StreamEventUpdated,
		EventUnsuppressed:   StreamEventUpdated,
		EventComment:        StreamEventUpdated,
	}
	for kind, want := range cases {
		if got := StreamName(kind); got != want {
			t.Errorf("StreamName(%q) = %q, want %q", kind, got, want)
		}
	}
}
