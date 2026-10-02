package notify

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/modules/alerts"
)

// Message is one rendered notification attempt. Subject/Body are the
// plain-text fallback every channel can use; Payload is the canonical
// versioned webhook envelope (docs/12 §22.17).
type Message struct {
	DeliveryID  uuid.UUID
	EventKind   string
	EventType   string
	AlertID     uuid.UUID
	OrgID       uuid.UUID
	DeviceID    uuid.UUID
	SiteID      uuid.UUID
	Fingerprint string
	Severity    string
	Summary     string
	RuleName    string
	DeviceName  string
	SiteName    string
	OccurredAt  time.Time
	StartedAt   time.Time
	ResolvedAt  *time.Time
	EvidenceURL string
	AckURL      string
	Subject     string
	Body        string
	Payload     []byte
	// DedupKey is the at-least-once dedup header value (stable per
	// channel/alert/event); SentAt is stamped per attempt (webhook signature
	// timestamp).
	DedupKey string
	SentAt   time.Time
}

// EventType maps an alert transition kind to the canonical event vocabulary.
func EventType(kind string) string {
	switch kind {
	case alerts.EventResolved, alerts.EventManualResolved:
		return EventResolved
	default:
		return EventFired
	}
}

// RenderMessage builds the rendered message for one committed transition.
// Grouping/collapse (one message per group with N items) is documented as a
// V2 next step in M11_EVIDENCE §S2; this slice renders one message per
// (transition, route, channel).
func RenderMessage(baseURL string, t alerts.Transition, ruleName, deviceName, siteName, subjectPrefix string) Message {
	a := t.Alert
	eventType := EventType(t.Event.Kind)
	summary := buildSummary(ruleName, a, t.Event.Kind)
	subject := fmt.Sprintf("[%s] %s", strings.ToUpper(a.Severity), summary)
	if subjectPrefix != "" {
		subject = subjectPrefix + " " + subject
	}
	evidence := link(baseURL, "/alerts/"+a.ID.String())
	ack := link(baseURL, "/alerts/"+a.ID.String()+"#ack")
	msg := Message{
		AlertID:     a.ID,
		OrgID:       a.OrgID,
		DeviceID:    a.ResourceID,
		SiteID:      a.SiteID,
		Fingerprint: a.Fingerprint,
		Severity:    a.Severity,
		Summary:     summary,
		RuleName:    ruleName,
		DeviceName:  deviceName,
		SiteName:    siteName,
		OccurredAt:  t.Event.Ts.UTC(),
		StartedAt:   a.StartedAt.UTC(),
		ResolvedAt:  a.ResolvedAt,
		EvidenceURL: evidence,
		AckURL:      ack,
		EventKind:   t.Event.Kind,
		EventType:   eventType,
		Subject:     subject,
	}
	msg.Body = renderText(msg)
	msg.Payload = renderPayload(msg)
	return msg
}

func link(baseURL, path string) string {
	if baseURL == "" {
		return path
	}
	return strings.TrimRight(baseURL, "/") + path
}

// buildSummary turns the rule name plus the alert's evidence into one line.
func buildSummary(ruleName string, a alerts.Alert, eventKind string) string {
	name := ruleName
	if name == "" {
		name = "Alert"
	}
	detail := evidenceDetail(a.Value)
	summary := name
	if detail != "" {
		summary = name + " — " + detail
	}
	if eventKind == alerts.EventResolved || eventKind == alerts.EventManualResolved {
		summary = "Resolved: " + summary
	}
	return summary
}

// evidenceDetail renders the deterministic value projection used in message
// summaries (threshold: value/op/threshold; absence: age or failure count).
func evidenceDetail(raw []byte) string {
	var v map[string]any
	if len(raw) == 0 || json.Unmarshal(raw, &v) != nil {
		return ""
	}
	if val, ok := numString(v["value"]); ok {
		if op, ok := v["op"].(string); ok {
			if thr, ok := numString(v["threshold"]); ok {
				return fmt.Sprintf("value %s %s %s", val, op, thr)
			}
		}
	}
	if age, ok := numString(v["age_seconds"]); ok {
		return "no data for " + age + "s"
	}
	if fails, ok := numString(v["consecutive_failures"]); ok {
		return fails + " consecutive scheduled poll failures"
	}
	if len(v) > 0 {
		if b, err := json.Marshal(v); err == nil {
			return string(b)
		}
	}
	return ""
}

func numString(v any) (string, bool) {
	switch n := v.(type) {
	case float64:
		if n == float64(int64(n)) {
			return fmt.Sprintf("%d", int64(n)), true
		}
		return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.3f", n), "0"), "."), true
	case string:
		return n, true
	default:
		return "", false
	}
}

// renderText is the plain-text fallback body; it carries the canonical
// required fields: severity, scope, summary, start time, evidence and ack
// links (docs/10 §17.7).
func renderText(m Message) string {
	scope := m.SiteName
	if m.DeviceName != "" {
		if scope != "" {
			scope += " / "
		}
		scope += m.DeviceName
	}
	if scope == "" {
		scope = "org-wide"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Argus alert notification\n")
	fmt.Fprintf(&b, "Event: %s\n", m.EventType)
	fmt.Fprintf(&b, "Severity: %s\n", m.Severity)
	fmt.Fprintf(&b, "Scope: %s\n", scope)
	fmt.Fprintf(&b, "Summary: %s\n", m.Summary)
	fmt.Fprintf(&b, "Started: %s\n", m.StartedAt.Format(time.RFC3339))
	if m.ResolvedAt != nil {
		fmt.Fprintf(&b, "Resolved: %s\n", m.ResolvedAt.UTC().Format(time.RFC3339))
	}
	fmt.Fprintf(&b, "Evidence: %s\n", m.EvidenceURL)
	fmt.Fprintf(&b, "Ack: %s\n", m.AckURL)
	fmt.Fprintf(&b, "Delivery: %s\n", m.DeliveryID)
	return b.String()
}

// renderPayload is the canonical versioned envelope with the summary data.
func renderPayload(m Message) []byte {
	data := map[string]any{
		"alert_id":     m.AlertID.String(),
		"fingerprint":  m.Fingerprint,
		"severity":     m.Severity,
		"summary":      m.Summary,
		"resource":     map[string]any{"type": "device", "id": m.DeviceID.String()},
		"state":        stateFor(m.EventKind),
		"started_at":   m.StartedAt.Format(time.RFC3339),
		"evidence_ref": m.EvidenceURL,
		"ack_url":      m.AckURL,
	}
	if m.SiteID != uuid.Nil {
		data["site_id"] = m.SiteID.String()
	}
	if m.ResolvedAt != nil {
		data["resolved_at"] = m.ResolvedAt.UTC().Format(time.RFC3339)
	}
	payload := map[string]any{
		"spec_version": "1",
		"event":        m.EventType,
		"occurred_at":  m.OccurredAt.Format(time.RFC3339),
		"org_id":       m.OrgID.String(),
		"data":         data,
	}
	out, _ := json.Marshal(payload)
	return out
}

func stateFor(eventKind string) string {
	switch eventKind {
	case alerts.EventResolved, alerts.EventManualResolved:
		return alerts.StateResolved
	case alerts.EventReactivated:
		return alerts.StateActive
	default:
		return alerts.StateActive
	}
}

// idsOnlyPayload builds the canonical IDs-only envelope (webhook
// config.payload = "ids"): receivers fetch details with their own
// credentials.
func idsOnlyPayload(m Message) []byte {
	payload := map[string]any{
		"spec_version": "1",
		"event":        m.EventType,
		"occurred_at":  m.OccurredAt.Format(time.RFC3339),
		"org_id":       m.OrgID.String(),
		"data": map[string]any{
			"alert_id":     m.AlertID.String(),
			"fingerprint":  m.Fingerprint,
			"resource":     map[string]any{"type": "device", "id": m.DeviceID.String()},
			"evidence_ref": m.EvidenceURL,
		},
	}
	out, _ := json.Marshal(payload)
	return out
}
