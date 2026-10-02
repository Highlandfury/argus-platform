package integration

// M11-S3a suppression semantics end to end: a matching active maintenance
// window or silence holds a firing alert in the canonical Suppressed state,
// records the reason and object ref, and the M11-S2 notify engine never
// creates a delivery row for a suppressed transition. When the suppression
// ends while the condition still holds the alert reactivates and re-notifies;
// a recovery during the suppression resolves the alert without a resolve
// notification. docs/10 §17.6; P2-AC-30.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/modules/alerts"
	"github.com/argus-platform/argus/internal/modules/notify"
)

func TestM11S3aMaintenanceWindowLifecycle(t *testing.T) {
	env := newM11S3aEnv(t, "m11s3a-maint-"+newUUID()[:8])
	orgID := env.org()
	base := time.Now().UTC().Truncate(time.Second)

	ch := env.createWebhookChannel(t, "maint-wh", "http://127.0.0.1:1/hook", "s3a-secret")
	env.createRoute(t, "maint-route", `{}`, ch)
	engine := env.installEngine(t, map[string]notify.Transport{notify.KindWebhook: &scriptedTransport{}})

	dev, series := m11s3aDeviceAndSeries(t, orgID, env.site(), "maint-dev", "m11.s3a.maint")
	rule := env.m11CreateRule(t, "maint-rule", "threshold", "critical",
		`{"agg":"max","op":"gt","value":5,"window":"30s","for_duration":"0s","recovery":{"for_duration":"0s"}}`,
		`{"metric_key":"m11.s3a.maint"}`)

	// The window starts before the test instant and ends at +2 min.
	windowID := env.createWindow(t, "rack maintenance", `{"sites":["`+env.siteID+`"]}`, base.Add(-time.Minute), base.Add(2*time.Minute))

	// 1) Trigger during the window: the alert exists, suppressed(maintenance),
	// with the window ref recorded, and no notification row is enqueued.
	m11WriteSamples(t, orgID, series, []time.Time{base}, []float64{10})
	sum := env.evaluate(t, base)
	if sum.Errors != 0 {
		t.Fatalf("evaluation errors = %d; logs: %s", sum.Errors, env.logs.String())
	}
	fp := alertsFingerprint(t, env.m11Env, rule, dev, `{}`)
	open, ok := m11OpenAlert(t, orgID, fp)
	if !ok {
		t.Fatalf("alert missing after a firing evaluation inside the window; logs: %s", env.logs.String())
	}
	alertID := open["id"].(uuid.UUID)
	row := m11s3aAlert(t, orgID, alertID)
	if row["state"] != alerts.StateSuppressed || row["suppression_reason"] != alerts.SuppressionMaintenance {
		t.Fatalf("alert = %v, want suppressed/maintenance", row)
	}
	if ref, _ := row["suppression_ref"].(*uuid.UUID); ref == nil || ref.String() != windowID {
		t.Fatalf("suppression_ref = %v, want window %s", row["suppression_ref"], windowID)
	}
	if n := m11s3aDeliveryCount(t, orgID, alertID, alerts.EventActivated); n != 0 {
		t.Fatalf("activated deliveries = %d, want 0 (suppressed)", n)
	}

	// The API payload exposes the suppression reason and ref.
	res := env.do(t, http.MethodGet, "/v1/alerts/"+alertID.String(), "")
	if res.Status != http.StatusOK {
		t.Fatalf("get alert: %d %v", res.Status, res.Body)
	}
	if res.Body["state"] != alerts.StateSuppressed || res.Body["suppression_reason"] != alerts.SuppressionMaintenance {
		t.Fatalf("alert payload = %v", res.Body)
	}
	if res.Body["suppression_ref"] != windowID {
		t.Fatalf("payload suppression_ref = %v, want %s", res.Body["suppression_ref"], windowID)
	}

	// The window is listed as active with its canonical scope.
	res = env.do(t, http.MethodGet, "/v1/maintenance-windows", "")
	if res.Status != http.StatusOK || len(dataList(t, res.Body)) != 1 {
		t.Fatalf("list windows: %d %v", res.Status, res.Body)
	}
	if res.Body["data"].([]any)[0].(map[string]any)["active"] != true {
		t.Fatalf("window not marked active: %v", res.Body)
	}

	// 2) Still firing inside the window: stays suppressed, still no delivery.
	m11WriteSamples(t, orgID, series, []time.Time{base.Add(30 * time.Second)}, []float64{10})
	env.evaluate(t, base.Add(30*time.Second))
	row = m11s3aAlert(t, orgID, alertID)
	if row["state"] != alerts.StateSuppressed {
		t.Fatalf("state inside window = %v, want suppressed", row["state"])
	}
	if n := m11s3aDeliveryCount(t, orgID, alertID, alerts.EventActivated); n != 0 {
		t.Fatalf("activated deliveries inside window = %d, want 0", n)
	}

	// 3) Window ends while the condition is still true: reactivated and
	// re-notified (canonical Suppressed -> Active on suppression end).
	m11WriteSamples(t, orgID, series, []time.Time{base.Add(3 * time.Minute)}, []float64{10})
	env.evaluate(t, base.Add(3*time.Minute))
	row = m11s3aAlert(t, orgID, alertID)
	ref, _ := row["suppression_ref"].(*uuid.UUID)
	if row["state"] != alerts.StateActive || row["suppression_reason"] != "" || ref != nil {
		t.Fatalf("after window end = %v, want active with cleared suppression", row)
	}
	if n := m11s3aDeliveryCount(t, orgID, alertID, alerts.EventReactivated); n != 1 {
		t.Fatalf("reactivated deliveries = %d, want 1", n)
	}

	// The worker can deliver the reactivation through the channel.
	if n := env.processDue(t, engine, base.Add(3*time.Minute)); n != 1 {
		t.Fatalf("processDue after reactivation = %d, want 1", n)
	}

	// 4) Recovery after the window: resolved and notified normally.
	m11WriteSamples(t, orgID, series, []time.Time{base.Add(4 * time.Minute)}, []float64{1})
	env.evaluate(t, base.Add(4*time.Minute))
	row = m11s3aAlert(t, orgID, alertID)
	if row["state"] != alerts.StateResolved {
		t.Fatalf("state after recovery = %v, want resolved", row["state"])
	}
	if n := m11s3aDeliveryCount(t, orgID, alertID, alerts.EventResolved); n != 1 {
		t.Fatalf("resolved deliveries = %d, want 1", n)
	}
}

func TestM11S3aSilenceByAlertID(t *testing.T) {
	env := newM11S3aEnv(t, "m11s3a-sil-"+newUUID()[:8])
	orgID := env.org()
	base := time.Now().UTC().Truncate(time.Second)

	ch := env.createWebhookChannel(t, "sil-wh", "http://127.0.0.1:1/hook", "s3a-secret")
	env.createRoute(t, "sil-route", `{}`, ch)

	dev, series := m11s3aDeviceAndSeries(t, orgID, env.site(), "sil-dev", "m11.s3a.sil")
	rule := env.m11CreateRule(t, "sil-rule", "threshold", "critical",
		`{"agg":"max","op":"gt","value":5,"window":"30s","for_duration":"0s","recovery":{"for_duration":"0s"}}`,
		`{"metric_key":"m11.s3a.sil"}`)

	// Alert fires normally first: one activated delivery.
	m11WriteSamples(t, orgID, series, []time.Time{base}, []float64{10})
	env.evaluate(t, base)
	fp := alertsFingerprint(t, env.m11Env, rule, dev, `{}`)
	open, ok := m11OpenAlert(t, orgID, fp)
	if !ok || open["state"] != alerts.StateActive {
		t.Fatalf("alert = %v ok=%v, want active", open, ok)
	}
	alertID := open["id"].(uuid.UUID)
	if n := m11s3aDeliveryCount(t, orgID, alertID, alerts.EventActivated); n != 1 {
		t.Fatalf("activated deliveries = %d, want 1", n)
	}

	// Silence by alert id; the next firing evaluation enters suppressed.
	silenceID := env.createSilence(t, `{"alert_id":"`+alertID.String()+`"}`, "operator investigation", time.Minute)
	m11WriteSamples(t, orgID, series, []time.Time{base.Add(10 * time.Second)}, []float64{10})
	env.evaluate(t, base.Add(10*time.Second))
	row := m11s3aAlert(t, orgID, alertID)
	if row["state"] != alerts.StateSuppressed || row["suppression_reason"] != alerts.SuppressionSilence {
		t.Fatalf("alert after silence = %v, want suppressed/silence", row)
	}
	if ref, _ := row["suppression_ref"].(*uuid.UUID); ref == nil || ref.String() != silenceID {
		t.Fatalf("suppression_ref = %v, want silence %s", row["suppression_ref"], silenceID)
	}
	if n := m11s3aDeliveryCount(t, orgID, alertID, alerts.EventReactivated); n != 0 {
		t.Fatalf("reactivated deliveries while silent = %d, want 0", n)
	}

	// Recovery while the silence is still active: resolves, no resolve
	// notification, and the reason stays on the row as the audit answer.
	m11WriteSamples(t, orgID, series, []time.Time{base.Add(45 * time.Second)}, []float64{1})
	env.evaluate(t, base.Add(45*time.Second))
	row = m11s3aAlert(t, orgID, alertID)
	if row["state"] != alerts.StateResolved {
		t.Fatalf("state after recovery during silence = %v, want resolved", row["state"])
	}
	if row["suppression_reason"] != alerts.SuppressionSilence {
		t.Fatalf("resolved row lost the suppression reason: %v", row)
	}
	if n := m11s3aDeliveryCount(t, orgID, alertID, alerts.EventResolved); n != 0 {
		t.Fatalf("resolved deliveries during silence = %d, want 0", n)
	}
}

func TestM11S3aSilenceByScope(t *testing.T) {
	env := newM11S3aEnv(t, "m11s3a-scope-"+newUUID()[:8])
	orgID := env.org()
	base := time.Now().UTC().Truncate(time.Second)

	ch := env.createWebhookChannel(t, "scope-wh", "http://127.0.0.1:1/hook", "s3a-secret")
	env.createRoute(t, "scope-route", `{}`, ch)

	dev, series := m11s3aDeviceAndSeries(t, orgID, env.site(), "scope-dev", "m11.s3a.scope")
	rule := env.m11CreateRule(t, "scope-rule", "threshold", "warning",
		`{"agg":"max","op":"gt","value":5,"window":"30s","for_duration":"0s","recovery":{"for_duration":"0s"}}`,
		`{"metric_key":"m11.s3a.scope"}`)

	silenceID := env.createSilence(t, `{"scope":{"sites":["`+env.siteID+`"]}}`, "site-wide change freeze", 90*time.Second)

	m11WriteSamples(t, orgID, series, []time.Time{base}, []float64{9})
	env.evaluate(t, base)
	fp := alertsFingerprint(t, env.m11Env, rule, dev, `{}`)
	open, ok := m11OpenAlert(t, orgID, fp)
	if !ok || open["state"] != alerts.StateSuppressed {
		t.Fatalf("scope-silenced alert = %v ok=%v, want suppressed", open, ok)
	}
	alertID := open["id"].(uuid.UUID)
	row := m11s3aAlert(t, orgID, alertID)
	if row["suppression_reason"] != alerts.SuppressionSilence {
		t.Fatalf("reason = %v, want silence", row["suppression_reason"])
	}
	if n := m11s3aDeliveryCount(t, orgID, alertID, alerts.EventActivated); n != 0 {
		t.Fatalf("activated deliveries under scope silence = %d, want 0", n)
	}
	// The silence expires cleanly at ends_at (no delete needed); re-evaluate
	// while still firing after the expiry: reactivated and re-notified.
	m11WriteSamples(t, orgID, series, []time.Time{base.Add(2 * time.Minute)}, []float64{9})
	env.evaluate(t, base.Add(2*time.Minute))
	row = m11s3aAlert(t, orgID, alertID)
	if row["state"] != alerts.StateActive || row["suppression_reason"] != "" {
		t.Fatalf("after silence expiry = %v, want active/cleared", row)
	}
	if n := m11s3aDeliveryCount(t, orgID, alertID, alerts.EventReactivated); n != 1 {
		t.Fatalf("reactivated deliveries after expiry = %d, want 1", n)
	}
	// The expired silence is still listed (history) but inactive.
	res := env.do(t, http.MethodGet, "/v1/silences", "")
	if res.Status != http.StatusOK || len(dataList(t, res.Body)) != 1 {
		t.Fatalf("list silences after expiry: %d %v", res.Status, res.Body)
	}
	if dataList(t, res.Body)[0]["active"] != false {
		t.Fatalf("expired silence still active: %v", res.Body)
	}
	// DELETE is idempotent per object identity (exercised here for cleanup).
	res = env.do(t, http.MethodDelete, "/v1/silences/"+silenceID, "")
	if res.Status != http.StatusNoContent {
		t.Fatalf("delete expired silence: %d %v", res.Status, res.Body)
	}
}

func TestM11S3aActiveAlertEntersWindowAndResolvesSilently(t *testing.T) {
	env := newM11S3aEnv(t, "m11s3a-enter-"+newUUID()[:8])
	orgID := env.org()
	base := time.Now().UTC().Truncate(time.Second)

	ch := env.createWebhookChannel(t, "enter-wh", "http://127.0.0.1:1/hook", "s3a-secret")
	env.createRoute(t, "enter-route", `{}`, ch)

	dev, series := m11s3aDeviceAndSeries(t, orgID, env.site(), "enter-dev", "m11.s3a.enter")
	rule := env.m11CreateRule(t, "enter-rule", "threshold", "critical",
		`{"agg":"max","op":"gt","value":5,"window":"30s","for_duration":"0s","recovery":{"for_duration":"0s"}}`,
		`{"metric_key":"m11.s3a.enter"}`)

	// The alert fires and notifies before the window.
	m11WriteSamples(t, orgID, series, []time.Time{base}, []float64{10})
	env.evaluate(t, base)
	fp := alertsFingerprint(t, env.m11Env, rule, dev, `{}`)
	open, ok := m11OpenAlert(t, orgID, fp)
	if !ok || open["state"] != alerts.StateActive {
		t.Fatalf("alert = %v ok=%v, want active", open, ok)
	}
	alertID := open["id"].(uuid.UUID)

	env.createWindow(t, "planned work", `{"sites":["`+env.siteID+`"]}`, base.Add(30*time.Second), base.Add(10*time.Minute))
	m11WriteSamples(t, orgID, series, []time.Time{base.Add(time.Minute)}, []float64{10})
	env.evaluate(t, base.Add(time.Minute))
	row := m11s3aAlert(t, orgID, alertID)
	if row["state"] != alerts.StateSuppressed || row["suppression_reason"] != alerts.SuppressionMaintenance {
		t.Fatalf("active alert entering window = %v, want suppressed/maintenance", row)
	}

	// Recovery inside the window: resolves, keeps the reason, no resolve
	// notification (the transition was suppressed).
	m11WriteSamples(t, orgID, series, []time.Time{base.Add(2 * time.Minute)}, []float64{1})
	env.evaluate(t, base.Add(2*time.Minute))
	row = m11s3aAlert(t, orgID, alertID)
	if row["state"] != alerts.StateResolved {
		t.Fatalf("state = %v, want resolved", row["state"])
	}
	if row["suppression_reason"] != alerts.SuppressionMaintenance {
		t.Fatalf("reason after resolve = %v, want maintenance", row["suppression_reason"])
	}
	if n := m11s3aDeliveryCount(t, orgID, alertID, alerts.EventResolved); n != 0 {
		t.Fatalf("resolved deliveries during window = %d, want 0", n)
	}
	// Exactly one delivery ever exists for this alert (the original activation).
	var total int
	err := ownerPool.QueryRow(context.Background(), `SELECT count(*) FROM notification_deliveries WHERE org_id = $1 AND alert_id = $2`, orgID, alertID).Scan(&total)
	if err != nil {
		t.Fatalf("count deliveries: %v", err)
	}
	if total != 1 {
		t.Fatalf("total deliveries = %d, want only the pre-window activation", total)
	}
}
