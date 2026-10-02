package notify

// M11-S2 rendering unit tests: every message carries severity, scope, summary,
// start time, evidence link and ack link; the payload is the canonical
// versioned envelope; resolved notifications use the resolved vocabulary.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/modules/alerts"
)

func testTransition(kind string) alerts.Transition {
	started := time.Date(2026, 10, 2, 11, 0, 0, 0, time.UTC)
	resolved := time.Date(2026, 10, 2, 12, 30, 0, 0, time.UTC)
	alert := alerts.Alert{
		ID:              uuid.New(),
		OrgID:           uuid.New(),
		RuleID:          uuid.New(),
		RuleVersion:     3,
		Fingerprint:     strings.Repeat("f", 64),
		ResourceType:    "device",
		ResourceID:      uuid.New(),
		State:           alerts.StateActive,
		Severity:        alerts.SeverityCritical,
		Value:           []byte(`{"agg":"avg","value":95,"op":"gt","threshold":90,"window":"5m0s"}`),
		StartedAt:       started,
		LastEvaluatedAt: resolved,
		CreatedAt:       started,
		SiteID:          uuid.New(),
	}
	if kind == alerts.EventResolved {
		alert.State = alerts.StateResolved
		alert.ResolvedAt = &resolved
	}
	return alerts.Transition{
		Alert: alert,
		Event: alerts.AlertEvent{
			ID:      uuid.New(),
			AlertID: alert.ID,
			Kind:    kind,
			Data:    []byte(`{}`),
			Ts:      resolved,
		},
	}
}

func TestRenderMessageRequiredFields(t *testing.T) {
	tr := testTransition(alerts.EventActivated)
	tr.Alert.Value = []byte(`{"agg":"avg","value":95,"op":"gt","threshold":90}`)
	msg := RenderMessage("https://argus.example/", tr, "CPU high", "sw-1", "HQ", "[OPS]")

	if msg.Subject != "[OPS] [CRITICAL] CPU high — value 95 gt 90" {
		t.Fatalf("subject = %q", msg.Subject)
	}
	if msg.EventType != EventFired || msg.EventKind != alerts.EventActivated {
		t.Fatalf("event mapping = %s/%s", msg.EventKind, msg.EventType)
	}
	if msg.AlertID != tr.Alert.ID || msg.OrgID != tr.Alert.OrgID || msg.DeviceID != tr.Alert.ResourceID || msg.SiteID != tr.Alert.SiteID {
		t.Fatal("message identity does not mirror the transition")
	}
	evidence := "https://argus.example/alerts/" + tr.Alert.ID.String()
	ack := evidence + "#ack"
	if msg.EvidenceURL != evidence || msg.AckURL != ack {
		t.Fatalf("links = %q %q", msg.EvidenceURL, msg.AckURL)
	}
	for _, want := range []string{
		"Event: alert.fired",
		"Severity: critical",
		"Scope: HQ / sw-1",
		"Summary: CPU high — value 95 gt 90",
		"Started: " + tr.Alert.StartedAt.Format(time.RFC3339),
		"Evidence: " + evidence,
		"Ack: " + ack,
		"Delivery: " + msg.DeliveryID.String(),
	} {
		if !strings.Contains(msg.Body, want) {
			t.Fatalf("body missing %q:\n%s", want, msg.Body)
		}
	}
	if msg.ResolvedAt != nil {
		t.Fatalf("fired message must not carry resolved_at: %v", msg.ResolvedAt)
	}
}

func TestRenderMessageResolved(t *testing.T) {
	tr := testTransition(alerts.EventResolved)
	msg := RenderMessage("", tr, "", "", "", "")
	if msg.EventType != EventResolved || !strings.HasPrefix(msg.Summary, "Resolved: ") {
		t.Fatalf("resolved message = %q / %q", msg.Subject, msg.Summary)
	}
	if msg.ResolvedAt == nil || !strings.Contains(msg.Body, "Resolved: "+tr.Alert.ResolvedAt.Format(time.RFC3339)) {
		t.Fatalf("resolved body = %q", msg.Body)
	}
	if !strings.Contains(msg.Body, "Scope: org-wide") {
		t.Fatalf("missing scope fallback: %q", msg.Body)
	}
	if msg.EvidenceURL != "/alerts/"+tr.Alert.ID.String() {
		t.Fatalf("relative link = %q", msg.EvidenceURL)
	}
}

func TestRenderPayloadEnvelope(t *testing.T) {
	tr := testTransition(alerts.EventActivated)
	tr.Alert.Value = []byte(`{"value":12.5,"op":"gte","threshold":10}`)
	msg := RenderMessage("https://argus.example", tr, "WAN loss", "rtr-1", "DC1", "")

	var payload map[string]any
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		t.Fatalf("payload JSON: %v", err)
	}
	if payload["spec_version"] != "1" || payload["event"] != EventFired {
		t.Fatalf("envelope = %v", payload)
	}
	if payload["org_id"] != tr.Alert.OrgID.String() {
		t.Fatalf("org_id = %v", payload["org_id"])
	}
	if payload["occurred_at"] != tr.Event.Ts.Format(time.RFC3339) {
		t.Fatalf("occurred_at = %v", payload["occurred_at"])
	}
	data, _ := payload["data"].(map[string]any)
	if data["alert_id"] != tr.Alert.ID.String() ||
		data["severity"] != SeverityCritical ||
		data["state"] != alerts.StateActive ||
		data["evidence_ref"] != msg.EvidenceURL ||
		data["ack_url"] != msg.AckURL {
		t.Fatalf("payload data = %v", data)
	}
	if data["summary"] != "WAN loss — value 12.5 gte 10" {
		t.Fatalf("payload summary = %v", data["summary"])
	}
	resource, _ := data["resource"].(map[string]any)
	if resource["type"] != "device" || resource["id"] != tr.Alert.ResourceID.String() {
		t.Fatalf("payload resource = %v", resource)
	}
}

func TestPayloadResolvedState(t *testing.T) {
	tr := testTransition(alerts.EventResolved)
	msg := RenderMessage("", tr, "WAN loss", "rtr-1", "DC1", "")
	var payload map[string]any
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		t.Fatalf("payload JSON: %v", err)
	}
	data, _ := payload["data"].(map[string]any)
	if payload["event"] != EventResolved || data["state"] != alerts.StateResolved || data["resolved_at"] == nil {
		t.Fatalf("resolved payload = %v", payload)
	}
}

func TestEventTypeMapping(t *testing.T) {
	cases := map[string]string{
		alerts.EventActivated:      EventFired,
		alerts.EventReactivated:    EventFired,
		alerts.EventResolved:       EventResolved,
		alerts.EventManualResolved: EventResolved,
	}
	for kind, want := range cases {
		if got := EventType(kind); got != want {
			t.Fatalf("EventType(%q) = %q, want %q", kind, got, want)
		}
	}
}

func TestStateForEventKind(t *testing.T) {
	if stateFor(alerts.EventResolved) != alerts.StateResolved ||
		stateFor(alerts.EventManualResolved) != alerts.StateResolved ||
		stateFor(alerts.EventReactivated) != alerts.StateActive ||
		stateFor(alerts.EventActivated) != alerts.StateActive {
		t.Fatal("state mapping drifted")
	}
}

func TestEvidenceDetailVariants(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"threshold", `{"value":95,"op":"gt","threshold":90}`, "value 95 gt 90"},
		{"fraction", `{"value":12.5,"op":"gte","threshold":10}`, "value 12.5 gte 10"},
		{"sample age", `{"age_seconds":125}`, "no data for 125s"},
		{"poll failures", `{"consecutive_failures":2}`, "2 consecutive scheduled poll failures"},
		{"unknown object", `{"custom":"x"}`, `{"custom":"x"}`},
		{"empty", ``, ""},
		{"invalid json", `{`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := evidenceDetail([]byte(tc.raw)); got != tc.want {
				t.Fatalf("evidenceDetail(%s) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestIDsOnlyPayloadDropsDetails(t *testing.T) {
	tr := testTransition(alerts.EventActivated)
	msg := RenderMessage("", tr, "WAN loss", "rtr-1", "DC1", "")
	raw := idsOnlyPayload(msg)
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("ids payload JSON: %v", err)
	}
	data, _ := payload["data"].(map[string]any)
	if data["alert_id"] != tr.Alert.ID.String() || data["evidence_ref"] == nil {
		t.Fatalf("ids payload = %v", payload)
	}
	for _, forbidden := range []string{"summary", "severity", "state", "started_at", "ack_url"} {
		if _, ok := data[forbidden]; ok {
			t.Fatalf("ids payload leaks %q: %v", forbidden, data)
		}
	}
}

func TestBuildSummaryFallbacks(t *testing.T) {
	a := alerts.Alert{Value: []byte(`{}`)}
	if got := buildSummary("", a, alerts.EventActivated); got != "Alert" {
		t.Fatalf("unnamed summary = %q", got)
	}
	if got := buildSummary("Rule", a, alerts.EventResolved); got != "Resolved: Rule" {
		t.Fatalf("resolved unnamed summary = %q", got)
	}
}
