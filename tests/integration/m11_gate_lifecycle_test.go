package integration

// M11 gate (P2-AC-34): the canonical lifecycle end to end - an unreachable
// device becomes Active, exactly one notification reaches the test sink,
// recovery resolves it, and the delivery log proves one message per
// fingerprint per transition with stable dedup identities.

import (
	"testing"
	"time"

	"github.com/argus-platform/argus/internal/modules/notify"
)

func TestM11GateUnreachableLifecycleExactlyOnce(t *testing.T) {
	env := newM11S2Env(t, m11s2Slug("m11-gate-life"))
	orgID := env.org()
	base := time.Now().UTC().Truncate(time.Second)

	receiver, hits := newWebhookReceiver(t, m11s2WebhookMarker)
	channelID := env.createWebhookChannel(t, "gate-webhook", receiver.URL, m11s2WebhookMarker)
	env.createRoute(t, "gate-route", `{}`, channelID)

	collector := m11Collector(t, orgID, env.site(), "gate-col")
	dev := m11Device(t, orgID, env.site(), "gate-down", "switch")
	rule := env.m11CreateRule(t, "gate device down", "absence", "critical",
		`{"source":"poll_health","consecutive_failures":2,"recovery_successes":2}`,
		`{"device_ids":["`+dev.String()+`"]}`)

	// One failure is not enough; two consecutive scheduled failures activate.
	m11PollHealth(t, orgID, collector, dev, base.Add(-2*time.Minute), "failure", 1)
	env.evaluate(t, base)
	if rows := m11CountAlerts(t, orgID, rule.RuleID); len(rows) != 0 {
		t.Fatalf("one failure must not fire: %v", rows)
	}
	m11PollHealth(t, orgID, collector, dev, base.Add(-time.Minute), "failure", 2)
	env.evaluate(t, base)
	rows := m11CountAlerts(t, orgID, rule.RuleID)
	if len(rows) != 1 || rows[0]["state"] != "active" {
		t.Fatalf("two consecutive failures = %v, want one active alert", rows)
	}
	alertID := rows[0]["id"].(interface{ String() string }).String()

	// Exactly one fired notification reaches the sink.
	if n := env.processDue(t, env.engine, base); n < 1 {
		t.Fatalf("process due after activation = %d", n)
	}
	got := hits()
	if len(got) != 1 || got[0].verifyErr != nil || got[0].event != notify.EventFired {
		t.Fatalf("fired hits = %d (%+v), want exactly one valid %s", len(got), got, notify.EventFired)
	}

	// Two consecutive successful polls resolve; exactly one resolved message.
	m11PollHealth(t, orgID, collector, dev, base.Add(30*time.Second), "success", 0)
	m11PollHealth(t, orgID, collector, dev, base.Add(40*time.Second), "success", 0)
	env.evaluate(t, base.Add(40*time.Second))
	rows = m11CountAlerts(t, orgID, rule.RuleID)
	if len(rows) != 1 || rows[0]["state"] != "resolved" {
		t.Fatalf("two consecutive successes = %v, want resolved", rows)
	}
	if n := env.processDue(t, env.engine, base.Add(40*time.Second)); n < 1 {
		t.Fatalf("process due after recovery = %d", n)
	}
	got = hits()
	if len(got) != 2 || got[1].verifyErr != nil || got[1].event != notify.EventResolved {
		t.Fatalf("hits after resolve = %d (%+v), want fired then resolved", len(got), got)
	}

	// The delivery log proves exactly one message per transition kind, each
	// with its own stable dedup identity (no duplicate sends).
	deliveries := env.deliveries(t, "filter[alert_id]="+alertID)
	if len(deliveries) != 2 {
		t.Fatalf("alert deliveries = %d, want exactly 2 (fired + resolved)", len(deliveries))
	}
	kinds := map[string]int{}
	dedup := map[string]bool{}
	for _, d := range deliveries {
		kinds[d["event_kind"].(string)]++
		if d["status"] != "delivered" || d["attempts"].(float64) != 1 {
			t.Fatalf("delivery row = %v, want delivered attempt 1", d)
		}
		dedup[d["dedup_key"].(string)] = true
	}
	if kinds["activated"] != 1 || kinds["resolved"] != 1 || len(dedup) != 2 {
		t.Fatalf("delivery kinds = %v dedup = %d, want activated/resolved once each", kinds, len(dedup))
	}
}
