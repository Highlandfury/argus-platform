package integration

// M11-S3c (P2-AC-28, docs/10 §17.5): samples-absence alerts have a 24 h
// no-data max lifetime and auto-resolve with reason "unknown state"; a fresh
// sample inside the window keeps the alert alive, and a stream silent for the
// whole window never re-fires from the monitoring gap alone.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/modules/notify"
)

func TestM11S3cNoDataMaxLifetimeAutoResolve(t *testing.T) {
	env := newM11S2Env(t, m11s2Slug("m11s3c"))
	orgID := env.org()
	base := time.Now().UTC().Truncate(time.Second)

	// A scripted transport keeps the test deterministic past the webhook
	// replay window (the sweep evaluation instant jumps 25 h ahead).
	scripted := &scriptedTransport{}
	engine := env.installEngine(t, map[string]notify.Transport{notify.KindWebhook: scripted})
	channelID := env.createWebhookChannel(t, "nodata-webhook", "https://receiver.invalid/nodata", m11s2WebhookMarker)
	env.createRoute(t, "nodata-route", `{}`, channelID)

	// The stream stops 2 h before `base`: long past the 1 m absence window but
	// inside the 24 h max lifetime, so the alarm fires normally.
	dev := m11Device(t, orgID, env.site(), "nodata-dev", "switch")
	series := m11Series(t, orgID, dev, "m11.nodata", map[string]string{"probe": "stale"}, "count")
	m11WriteSamples(t, orgID, series, []time.Time{base.Add(-2 * time.Hour)}, []float64{1})
	rule := env.m11CreateRule(t, "nodata", "absence", "critical",
		`{"window":"1m"}`, `{"metric_key":"m11.nodata"}`)
	env.evaluate(t, base)
	rows := m11CountAlerts(t, orgID, rule.RuleID)
	if len(rows) != 1 || rows[0]["state"] != "active" {
		t.Fatalf("absence alert = %v, want one active", rows)
	}
	alertID, ok := rows[0]["id"].(uuid.UUID)
	if !ok {
		t.Fatalf("alert row without uuid id: %v", rows[0])
	}
	if n := env.processDue(t, engine, base); n < 1 {
		t.Fatalf("process due after activation = %d", n)
	}
	if scripted.sendCount() != 1 {
		t.Fatalf("fired sends = %d, want 1", scripted.sendCount())
	}

	// 25 h of silence: the sweep (through the normal evaluator entry point)
	// auto-resolves the aged alarm with the canonical reason.
	env.evaluate(t, base.Add(25*time.Hour))
	rows = m11CountAlerts(t, orgID, rule.RuleID)
	if len(rows) != 1 || rows[0]["state"] != "resolved" {
		t.Fatalf("stale alarm = %v, want resolved by the 24h no-data policy", rows)
	}
	var reason string
	must(t, ownerPool.QueryRow(context.Background(), `
		SELECT data->>'reason' FROM alert_events
		WHERE alert_id = $1 AND kind = 'resolved' ORDER BY ts DESC, id DESC LIMIT 1`,
		alertID).Scan(&reason))
	if reason != "unknown state" {
		t.Fatalf("resolve reason = %q, want unknown state", reason)
	}
	// The resolve is a normal transition: a second dispatched message.
	if n := env.processDue(t, engine, base.Add(25*time.Hour)); n < 1 {
		t.Fatalf("process due after auto-resolve = %d", n)
	}
	if scripted.sendCount() != 2 {
		t.Fatalf("sends after auto-resolve = %d, want 2", scripted.sendCount())
	}
	deliveries := env.deliveries(t, "filter[alert_id]="+alertID.String())
	if len(deliveries) != 2 {
		t.Fatalf("alert deliveries = %d, want exactly 2 (fired + resolved)", len(deliveries))
	}
	kinds := map[string]int{}
	for _, d := range deliveries {
		kinds[d["event_kind"].(string)]++
		if d["status"] != "delivered" || d["attempts"].(float64) != 1 {
			t.Fatalf("delivery row = %v, want delivered attempt 1", d)
		}
	}
	if kinds["activated"] != 1 || kinds["resolved"] != 1 {
		t.Fatalf("delivery kinds = %v, want activated/resolved once each", kinds)
	}
	// Idempotent, and a stream silent for the whole max lifetime must not
	// re-fire a new alarm from the monitoring gap.
	if n, err := env.eval.SweepNoDataAlerts(context.Background(), orgID, base.Add(25*time.Hour+time.Minute)); err != nil || n != 0 {
		t.Fatalf("second sweep = %d err=%v, want 0", n, err)
	}
	env.evaluate(t, base.Add(26*time.Hour))
	rows = m11CountAlerts(t, orgID, rule.RuleID)
	if len(rows) != 1 || rows[0]["state"] != "resolved" {
		t.Fatalf("monitoring gap must not re-fire: %v", rows)
	}

	// A fresh sample inside the last 24 h keeps an aged alert alive: the fresh
	// rule fires at `base` (its stream stopped 2 h earlier), data resumes 2 h
	// after that, and the sweep 25 h later must leave it active.
	freshDev := m11Device(t, orgID, env.site(), "nodata-fresh", "switch")
	freshSeries := m11Series(t, orgID, freshDev, "m11.nodata2", map[string]string{"probe": "fresh"}, "count")
	m11WriteSamples(t, orgID, freshSeries, []time.Time{base.Add(-2 * time.Hour)}, []float64{1})
	freshRule := env.m11CreateRule(t, "nodata fresh", "absence", "warning",
		`{"window":"1m"}`, `{"metric_key":"m11.nodata2"}`)
	env.evaluate(t, base)
	rows = m11CountAlerts(t, orgID, freshRule.RuleID)
	if len(rows) != 1 || rows[0]["state"] != "active" {
		t.Fatalf("fresh absence alert = %v, want one active", rows)
	}
	freshID, ok := rows[0]["id"].(uuid.UUID)
	if !ok {
		t.Fatalf("fresh alert row without uuid id: %v", rows[0])
	}
	m11WriteSamples(t, orgID, freshSeries, []time.Time{base.Add(2 * time.Hour)}, []float64{1})
	// The sweep may resolve other stale alarms; the fresh one must survive.
	if _, err := env.eval.SweepNoDataAlerts(context.Background(), orgID, base.Add(25*time.Hour)); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	rows = m11CountAlerts(t, orgID, freshRule.RuleID)
	if len(rows) != 1 || rows[0]["state"] != "active" {
		t.Fatalf("fresh data must keep the alert active: %v", rows)
	}
	var freshReason string
	var freshState string
	must(t, ownerPool.QueryRow(context.Background(),
		`SELECT state, coalesce((SELECT data->>'reason' FROM alert_events e WHERE e.alert_id = a.id AND e.kind = 'resolved' ORDER BY e.ts DESC, e.id DESC LIMIT 1), '')
		 FROM alerts a WHERE a.id = $1`, freshID).Scan(&freshState, &freshReason))
	if freshState != "active" || freshReason != "" {
		t.Fatalf("fresh alert was auto-resolved: state=%s reason=%s", freshState, freshReason)
	}
}
