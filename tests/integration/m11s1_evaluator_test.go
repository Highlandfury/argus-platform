package integration

// M11-S1 evaluator acceptance (P2-AC-27/28/29): threshold continuity
// ("no two lucky samples"), for_duration boundaries, recovery + dedup +
// manual-resolve reopen, absence (samples and poll-health), rate_of_change,
// CAGG/partial-bucket semantics, and storm control. Everything is
// deterministic: the evaluator clock is injected and EvaluateOnce takes the
// evaluation instant, so no test sleeps.

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestM11S1ThresholdContinuityAndDedup proves the canonical continuous-true
// semantics: a single false evaluation inside the for_duration span prevents
// activation even though the first and last evaluations are true.
func TestM11S1ThresholdContinuityAndDedup(t *testing.T) {
	env := newM11Env(t, "m11-cont-"+newUUID()[:8])
	orgID := env.org()
	base := time.Now().UTC().Truncate(time.Second)

	// Clean series: value 6 continuously.
	devOK := m11Device(t, orgID, env.site(), "m11-ok", "switch")
	okSeries := m11Series(t, orgID, devOK, "m11.gauge", map[string]string{"probe": "ok"}, "count")
	var okTS []time.Time
	var okVals []float64
	for i := -24; i <= 24; i++ {
		okTS = append(okTS, base.Add(time.Duration(i)*10*time.Second))
		okVals = append(okVals, 6)
	}
	m11WriteSamples(t, orgID, okSeries, okTS, okVals)

	// Dip series: one -100 sample inside the span.
	devDip := m11Device(t, orgID, env.site(), "m11-dip", "switch")
	dipSeries := m11Series(t, orgID, devDip, "m11.gauge", map[string]string{"probe": "dip"}, "count")
	var dipTS []time.Time
	var dipVals []float64
	for i := -24; i <= 24; i++ {
		dipTS = append(dipTS, base.Add(time.Duration(i)*10*time.Second))
		v := 6.0
		if i == 6 { // base + 1m: a mid-span dip
			v = -100
		}
		dipVals = append(dipVals, v)
	}
	m11WriteSamples(t, orgID, dipSeries, dipTS, dipVals)

	cond := `{"agg":"avg","op":"gt","value":5,"window":"30s","for_duration":"2m"}`
	sel := `{"metric_key":"m11.gauge"}`
	rule := env.m11CreateRule(t, "continuity", "threshold", "critical", cond, sel)

	// First evaluation: condition true -> Pending (started_at = now).
	env.evaluate(t, base)
	okFP := alertsFingerprint(t, env, rule, devOK, `{"probe":"ok"}`)
	dipFP := alertsFingerprint(t, env, rule, devDip, `{"probe":"dip"}`)
	alert, ok := m11OpenAlert(t, orgID, okFP)
	if !ok || alert["state"] != "pending" {
		t.Fatalf("first evaluation: alert = %v ok=%v, want pending", alert, ok)
	}
	dipFirst, ok := m11OpenAlert(t, orgID, dipFP)
	if !ok {
		t.Fatal("dip series must open a pending alert on the first true evaluation")
	}

	// 1 minute in: the clean series is still pending (for_duration 2m not
	// reached); the dip series' trigger window now contains the -100 sample,
	// so the pending alert resets (Pending -> Inactive, canonical).
	env.evaluate(t, base.Add(time.Minute))
	alert, _ = m11OpenAlert(t, orgID, okFP)
	if alert["state"] != "pending" {
		t.Fatalf("after 1m: state = %v, want pending", alert["state"])
	}
	if dipAlert, ok := m11OpenAlert(t, orgID, dipFP); ok {
		t.Fatalf("the false evaluation must reset the pending alert: %v", dipAlert)
	}

	// 2 minutes in: the clean series activates. The dip series re-fires as a
	// FRESH pending onset (new row, started now), not the disproved one.
	env.evaluate(t, base.Add(2*time.Minute))
	alert, _ = m11OpenAlert(t, orgID, okFP)
	if alert["state"] != "active" {
		t.Fatalf("clean series after for_duration: state = %v, want active", alert["state"])
	}
	dipAlert, ok := m11OpenAlert(t, orgID, dipFP)
	if !ok || dipAlert["state"] != "pending" {
		t.Fatalf("dip series must start a fresh pending onset: %v ok=%v", dipAlert, ok)
	}
	if dipAlert["id"] == dipFirst["id"] {
		t.Fatal("the reset pending row must not be reused")
	}

	// Dedup: another true evaluation updates the row, never duplicates it.
	// (The dip series starts a fresh Pending onset once its data is clean.)
	env.evaluate(t, base.Add(150*time.Second))
	rows := m11CountAlerts(t, orgID, rule.RuleID)
	if len(rows) != 2 {
		t.Fatalf("alert rows = %d, want exactly 2 (one per series)", len(rows))
	}
	kinds := m11EventKinds(t, orgID, alert["id"].(uuid.UUID))
	if !m11Contains(kinds, "pending") || !m11Contains(kinds, "activated") || !m11Contains(kinds, "updated") {
		t.Fatalf("clean-series timeline = %v, want pending+activated+updated", kinds)
	}
}

// TestM11S1RecoveryDedupAndManualReopen covers the recovery inverse with a
// longer for_duration, dedup across evaluations, manual resolve, and the
// reopen-within-cooldown behavior (same row, no duplicate).
func TestM11S1RecoveryDedupAndManualReopen(t *testing.T) {
	env := newM11Env(t, "m11-rec-"+newUUID()[:8])
	orgID := env.org()
	base := time.Now().UTC().Truncate(time.Second)

	dev := m11Device(t, orgID, env.site(), "m11-rec", "switch")
	series := m11Series(t, orgID, dev, "m11.gauge", nil, "count")

	// High samples up to base+3m, low samples base+3m..base+5m, high again
	// base+5m..base+8m.
	write := func(from, to time.Time, value float64) {
		var ts []time.Time
		var vals []float64
		for cur := from; !cur.After(to); cur = cur.Add(10 * time.Second) {
			ts = append(ts, cur)
			vals = append(vals, value)
		}
		m11WriteSamples(t, orgID, series, ts, vals)
	}
	write(base.Add(-2*time.Minute), base.Add(2*time.Minute+50*time.Second), 9)
	write(base.Add(3*time.Minute), base.Add(4*time.Minute+50*time.Second), 1)
	write(base.Add(5*time.Minute), base.Add(8*time.Minute), 9)

	cond := `{"agg":"avg","op":"gt","value":5,"window":"30s","for_duration":"0s","recovery":{"for_duration":"1m"}}`
	rule := env.m11CreateRule(t, "recovery", "threshold", "warning", cond, `{"metric_key":"m11.gauge"}`)
	fp := alertsFingerprint(t, env, rule, dev, `{}`)

	env.evaluate(t, base)
	alert, ok := m11OpenAlert(t, orgID, fp)
	if !ok || alert["state"] != "active" {
		t.Fatalf("zero for_duration must activate immediately: %v ok=%v", alert, ok)
	}
	firstID, _ := alert["id"].(uuid.UUID)

	env.evaluate(t, base.Add(30*time.Second))
	alert, _ = m11OpenAlert(t, orgID, fp)
	if alert["state"] != "active" || len(m11CountAlerts(t, orgID, rule.RuleID)) != 1 {
		t.Fatalf("repeat must keep one active row: %v rows=%d", alert, len(m11CountAlerts(t, orgID, rule.RuleID)))
	}

	// Recovery needs the inverse continuously for 1m: by base+4m30s the
	// window [base+3m30s, base+4m30s] is all low -> resolved.
	env.evaluate(t, base.Add(4*time.Minute+30*time.Second))
	alert, _ = m11OpenAlert(t, orgID, fp)
	if alert != nil {
		t.Fatalf("recovered alert must not remain open: %v", alert)
	}
	kinds := m11EventKinds(t, orgID, firstID)
	if !m11Contains(kinds, "resolved") {
		t.Fatalf("timeline missing resolved: %v", kinds)
	}

	// Re-fire after recovery -> a new row.
	env.evaluate(t, base.Add(5*time.Minute+30*time.Second))
	alert, ok = m11OpenAlert(t, orgID, fp)
	if !ok || alert["state"] != "active" {
		t.Fatalf("re-fire must open a new alert: %v ok=%v", alert, ok)
	}
	secondID, _ := alert["id"].(uuid.UUID)
	if secondID == firstID {
		t.Fatal("re-fire must not reuse the auto-resolved row")
	}

	// Manual resolve then immediate re-fire: same row reopened (cooldown).
	_, err := env.svc.ResolveAlert(context.Background(), orgID, secondID, env.actor(), "operator cleaned up", m11Unrestricted())
	must(t, err)
	env.evaluate(t, base.Add(6*time.Minute))
	alert, ok = m11OpenAlert(t, orgID, fp)
	if !ok || alert["state"] != "active" {
		t.Fatalf("manual-resolve re-fire must reopen: %v ok=%v", alert, ok)
	}
	if alert["id"] != secondID {
		t.Fatalf("reopen must reuse the resolved row: got %v want %v", alert["id"], secondID)
	}
	if rows := m11CountAlerts(t, orgID, rule.RuleID); len(rows) != 2 {
		t.Fatalf("rows after reopen = %d, want 2 (no duplicates)", len(rows))
	}
	kinds = m11EventKinds(t, orgID, secondID)
	if !m11Contains(kinds, "manual_resolved") || !m11Contains(kinds, "reopened") {
		t.Fatalf("timeline = %v, want manual_resolved+reopened", kinds)
	}
}

// TestM11S1AbsenceRateAndPollHealth covers the absence rules (metric samples
// and scheduled poll health, including the 2-consecutive-success device-down
// recovery) and rate_of_change.
func TestM11S1AbsenceRateAndPollHealth(t *testing.T) {
	env := newM11Env(t, "m11-abs-"+newUUID()[:8])
	orgID := env.org()
	base := time.Now().UTC().Truncate(time.Second)

	// Metric absence: one silent series (last sample 5m ago) and one never
	// seen. Only the silent one may fire.
	dev := m11Device(t, orgID, env.site(), "m11-abs", "ap")
	silent := m11Series(t, orgID, dev, "m11.liveness", map[string]string{"probe": "silent"}, "state")
	_ = m11Series(t, orgID, dev, "m11.liveness", map[string]string{"probe": "never"}, "state")
	m11WriteSamples(t, orgID, silent, []time.Time{base.Add(-5 * time.Minute)}, []float64{1})

	absRule := env.m11CreateRule(t, "metric silence", "absence", "warning",
		`{"window":"1m"}`, `{"metric_key":"m11.liveness"}`)
	env.evaluate(t, base)
	rows := m11CountAlerts(t, orgID, absRule.RuleID)
	if len(rows) != 1 || rows[0]["state"] != "active" {
		t.Fatalf("absence alerts = %v, want exactly the silent series active", rows)
	}
	alertID := rows[0]["id"].(uuid.UUID)

	// Data resumes -> recovery (presence) resolves.
	m11WriteSamples(t, orgID, silent, []time.Time{base.Add(10 * time.Second)}, []float64{2})
	env.evaluate(t, base.Add(10*time.Second))
	if rows := m11CountAlerts(t, orgID, absRule.RuleID); len(rows) != 1 || rows[0]["state"] != "resolved" {
		t.Fatalf("absence recovery rows = %v, want resolved", rows)
	}
	if kinds := m11EventKinds(t, orgID, alertID); !m11Contains(kinds, "resolved") {
		t.Fatalf("absence timeline = %v, want resolved", kinds)
	}

	// Poll-health absence: 2 consecutive scheduled failures activate; 2
	// consecutive successes resolve (P2-AC-28).
	collector := m11Collector(t, orgID, env.site(), "m11-col")
	devDown := m11Device(t, orgID, env.site(), "m11-down", "switch")
	phRule := env.m11CreateRule(t, "device down", "absence", "critical",
		`{"source":"poll_health","consecutive_failures":2,"recovery_successes":2}`,
		`{"device_ids":["`+devDown.String()+`"]}`)
	m11PollHealth(t, orgID, collector, devDown, base.Add(-2*time.Minute), "failure", 1)
	env.evaluate(t, base)
	if rows := m11CountAlerts(t, orgID, phRule.RuleID); len(rows) != 0 {
		t.Fatalf("one failure must not fire: %v", rows)
	}
	m11PollHealth(t, orgID, collector, devDown, base.Add(-time.Minute), "failure", 2)
	env.evaluate(t, base)
	phRows := m11CountAlerts(t, orgID, phRule.RuleID)
	if len(phRows) != 1 || phRows[0]["state"] != "active" {
		t.Fatalf("two consecutive failures = %v, want active", phRows)
	}
	m11PollHealth(t, orgID, collector, devDown, base.Add(30*time.Second), "success", 0)
	m11PollHealth(t, orgID, collector, devDown, base.Add(40*time.Second), "success", 0)
	env.evaluate(t, base.Add(40*time.Second))
	if rows := m11CountAlerts(t, orgID, phRule.RuleID); len(rows) != 1 || rows[0]["state"] != "resolved" {
		t.Fatalf("two consecutive successes = %v, want resolved", rows)
	}

	// rate_of_change: rising series crosses +0.05/s; falling stays quiet.
	riseDev := m11Device(t, orgID, env.site(), "m11-rise", "ap")
	riseSeries := m11Series(t, orgID, riseDev, "m11.clients", map[string]string{"dir": "up"}, "count")
	fallDev := m11Device(t, orgID, env.site(), "m11-fall", "ap")
	fallSeries := m11Series(t, orgID, fallDev, "m11.clients", map[string]string{"dir": "down"}, "count")
	var riseTS, fallTS []time.Time
	var riseVals, fallVals []float64
	for i := 0; i < 12; i++ {
		ts := base.Add(time.Duration(i-6) * 10 * time.Second)
		riseTS = append(riseTS, ts)
		riseVals = append(riseVals, float64(i))
		fallTS = append(fallTS, ts)
		fallVals = append(fallVals, float64(12-i))
	}
	m11WriteSamples(t, orgID, riseSeries, riseTS, riseVals)
	m11WriteSamples(t, orgID, fallSeries, fallTS, fallVals)
	rateRule := env.m11CreateRule(t, "clients rising", "rate_of_change", "info",
		`{"agg":"avg","op":"gt","value":0.05,"window":"30s","for_duration":"0s"}`,
		`{"metric_key":"m11.clients"}`)
	env.evaluate(t, base)
	rateRows := m11CountAlerts(t, orgID, rateRule.RuleID)
	if len(rateRows) != 1 || rateRows[0]["state"] != "active" {
		t.Fatalf("rate rule rows = %v, want exactly the rising series active", rateRows)
	}
	rateValue := string(m11OpenAlertValue(t, orgID, rateRows[0]["fingerprint"].(string)))
	var rateDecoded map[string]any
	must(t, json.Unmarshal([]byte(rateValue), &rateDecoded))
	if rateDecoded["phase"] != "trigger" || rateDecoded["resolution"] != "raw" {
		t.Fatalf("rate alert value lacks trigger evidence: %s", rateValue)
	}
}

// TestM11S1PartialBucketAndCAGGSemantics proves a >= 5m window reads the
// rollup path, that the newest incomplete bucket is excluded unless
// allow_partial, and that a missing materialization falls back to raw.
func TestM11S1PartialBucketAndCAGGSemantics(t *testing.T) {
	env := newM11Env(t, "m11-cagg-"+newUUID()[:8])
	orgID := env.org()
	base := time.Now().UTC().Truncate(time.Second)

	device := func(name string) uuid.UUID { return m11Device(t, orgID, env.site(), name, "ap") }
	seedFresh := func(dev uuid.UUID, name string) {
		series := m11Series(t, orgID, dev, "m11.cagg", map[string]string{"probe": name}, "count")
		m11ConstantSamples(t, orgID, series, base, 10*time.Second, 4, 6)
	}
	devStrict := device("m11-cagg-strict")
	seedFresh(devStrict, "strict")
	devPartial := device("m11-cagg-partial")
	seedFresh(devPartial, "partial")
	// A series with data older than the materialization boundary proves the
	// raw fallback when the CAGG has no rows.
	devOld := device("m11-cagg-old")
	oldSeries := m11Series(t, orgID, devOld, "m11.cagg", map[string]string{"probe": "old"}, "count")
	m11ConstantSamples(t, orgID, oldSeries, base.Add(-4*time.Minute), 10*time.Second, 12, 6)

	strictRule := env.m11CreateRule(t, "strict 6m", "threshold", "critical",
		`{"agg":"max","op":"gt","value":5,"window":"6m","for_duration":"0s"}`,
		`{"metric_key":"m11.cagg","device_ids":["`+devStrict.String()+`"]}`)
	partialRule := env.m11CreateRule(t, "partial 6m", "threshold", "critical",
		`{"agg":"max","op":"gt","value":5,"window":"6m","for_duration":"0s","allow_partial":true}`,
		`{"metric_key":"m11.cagg","device_ids":["`+devPartial.String()+`"]}`)
	oldRule := env.m11CreateRule(t, "old 6m", "threshold", "critical",
		`{"agg":"max","op":"gt","value":5,"window":"6m","for_duration":"0s"}`,
		`{"metric_key":"m11.cagg","device_ids":["`+devOld.String()+`"]}`)

	env.evaluate(t, base)
	if rows := m11CountAlerts(t, orgID, strictRule.RuleID); len(rows) != 0 {
		t.Fatalf("strict rule must ignore the incomplete bucket: %v", rows)
	}
	partialRows := m11CountAlerts(t, orgID, partialRule.RuleID)
	if len(partialRows) != 1 || partialRows[0]["state"] != "active" {
		t.Fatalf("allow_partial rule = %v, want active from the raw tail", partialRows)
	}
	value := string(m11OpenAlertValue(t, orgID, partialRows[0]["fingerprint"].(string)))
	var decoded map[string]any
	must(t, json.Unmarshal([]byte(value), &decoded))
	if decoded["resolution"] != "rollup_1m" || decoded["partial"] != true {
		t.Fatalf("partial rule evidence = %s, want rollup_1m + partial", value)
	}

	// The old series has data in the older span: the strict rule activates on
	// the materialization-missing series via the raw fallback.
	oldRows := m11CountAlerts(t, orgID, oldRule.RuleID)
	if len(oldRows) != 1 || oldRows[0]["state"] != "active" {
		t.Fatalf("fallback rule must fire for the materialization-missing series: %v", oldRows)
	}
	value = string(m11OpenAlertValue(t, orgID, oldRows[0]["fingerprint"].(string)))
	must(t, json.Unmarshal([]byte(value), &decoded))
	if decoded["rollup_missing"] != true || decoded["resolution"] != "rollup_1m" {
		t.Fatalf("fallback evidence = %s, want rollup_missing rollup_1m", value)
	}
}

// TestM11S1StormControl proves > 20 new alerts/5 min from one device are
// created Suppressed(storm), retained, and never dropped.
func TestM11S1StormControl(t *testing.T) {
	env := newM11Env(t, "m11-storm-"+newUUID()[:8])
	orgID := env.org()
	base := time.Now().UTC().Truncate(time.Second)

	dev := m11Device(t, orgID, env.site(), "m11-storm", "switch")
	for i := 0; i < 21; i++ {
		dims := map[string]string{"i": pad2(i)}
		series := m11Series(t, orgID, dev, "m11.burst", dims, "count")
		m11ConstantSamples(t, orgID, series, base, 10*time.Second, 4, 6)
	}
	rule := env.m11CreateRule(t, "burst", "threshold", "warning",
		`{"agg":"max","op":"gt","value":5,"window":"30s","for_duration":"0s"}`,
		`{"metric_key":"m11.burst"}`)

	env.evaluate(t, base)
	rows := m11CountAlerts(t, orgID, rule.RuleID)
	if len(rows) != 21 {
		t.Fatalf("storm burst rows = %d, want 21 retained alerts", len(rows))
	}
	suppressed := 0
	for _, row := range rows {
		if row["state"] == "suppressed" {
			suppressed++
			if row["suppression_reason"] != "storm" {
				t.Fatalf("suppressed row reason = %v, want storm", row["suppression_reason"])
			}
			kinds := m11EventKinds(t, orgID, row["id"].(uuid.UUID))
			if !m11Contains(kinds, "suppressed") {
				t.Fatalf("storm timeline = %v, want suppressed", kinds)
			}
		}
	}
	if suppressed != 1 {
		t.Fatalf("suppressed alerts = %d, want exactly 1 (the 21st, threshold 20)", suppressed)
	}
}

// m11OpenAlertValue loads the open alert's value JSON for a fingerprint.
func m11OpenAlertValue(t *testing.T, orgID uuid.UUID, fingerprint string) []byte {
	t.Helper()
	alert, ok := m11OpenAlert(t, orgID, fingerprint)
	if !ok {
		t.Fatalf("open alert %s not found", fingerprint)
	}
	return alert["value"].([]byte)
}

func pad2(i int) string { return fmt.Sprintf("%02d", i) }
