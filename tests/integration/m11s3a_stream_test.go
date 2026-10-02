package integration

// M11-S3a SSE stream contract end to end: the canonical alert.fired /
// alert.resolved / alert.updated events, the id/event/data envelope, session
// auth, Last-Event-ID resume from the retained buffer, the PostgreSQL replay
// fallback for older gaps, and site-scope filtering (docs/12 §22.16,
// P2-AC-33).

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/modules/alerts"
	"github.com/argus-platform/argus/internal/platform/authz"
)

func TestM11S3aStreamLifecycleEnvelopeAndReplay(t *testing.T) {
	env := newM11S3aEnv(t, "m11s3a-stream-"+newUUID()[:8])
	orgID := env.org()
	base := time.Now().UTC().Truncate(time.Second)

	// Unauthenticated stream attempts are rejected by the session middleware.
	anon := &http.Client{Timeout: 5 * time.Second}
	res := doRequest(t, anon, http.MethodGet, env.srv.URL+"/v1/streams/events", "", nil)
	requireProblem(t, res, http.StatusUnauthorized, "auth.unauthenticated")

	dev, series := m11s3aDeviceAndSeries(t, orgID, env.site(), "stream-dev", "m11.s3a.stream")
	rule := env.m11CreateRule(t, "stream-rule", "threshold", "critical",
		`{"agg":"max","op":"gt","value":5,"window":"30s","for_duration":"0s","recovery":{"for_duration":"0s"}}`,
		`{"metric_key":"m11.s3a.stream"}`)

	stream := env.openStream(t, "")
	defer stream.close()

	// Fire the alert: the stream delivers the canonical alert.fired frame.
	m11WriteSamples(t, orgID, series, []time.Time{base}, []float64{10})
	env.evaluate(t, base)
	fp := alertsFingerprint(t, env.m11Env, rule, dev, `{}`)
	open, ok := m11OpenAlert(t, orgID, fp)
	if !ok {
		t.Fatal("alert missing after evaluation")
	}
	alertID := open["id"].(uuid.UUID)

	fired, ok := stream.next(5 * time.Second)
	if !ok {
		t.Fatal("no alert.fired frame received")
	}
	if fired.Event != alerts.StreamEventFired || fired.Data["event_kind"] != alerts.EventActivated {
		t.Fatalf("first frame = %+v, want alert.fired/activated", fired)
	}
	if fired.ID == "" {
		t.Fatal("alert.fired frame has no id (Last-Event-ID resume impossible)")
	}
	if fired.Data["alert_id"] != alertID.String() || fired.Data["severity"] != "critical" {
		t.Fatalf("fired data = %v", fired.Data)
	}
	if fired.Data["site_id"] != env.siteID || fired.Data["device_id"] != dev.String() {
		t.Fatalf("fired scope fields = %v", fired.Data)
	}
	if fired.Data["incident_id"] != nil || fired.Data["suppressed"] != false {
		t.Fatalf("fired forward-compat fields = %v", fired.Data)
	}
	// The SSE id is the committed alert_events row id.
	var dbEventID uuid.UUID
	must(t, ownerPool.QueryRow(context.Background(), `
		SELECT id FROM alert_events WHERE alert_id = $1 AND kind = 'activated' ORDER BY ts DESC, id DESC LIMIT 1`,
		alertID).Scan(&dbEventID))
	if fired.ID != dbEventID.String() {
		t.Fatalf("SSE id = %s, want alert_events id %s", fired.ID, dbEventID)
	}

	// Acknowledgment arrives as alert.updated.
	res = env.do(t, http.MethodPost, "/v1/alerts/"+alertID.String()+"/ack", "{}")
	if res.Status != http.StatusOK {
		t.Fatalf("ack: %d %v", res.Status, res.Body)
	}
	ack, ok := stream.next(5 * time.Second)
	if !ok || ack.Event != alerts.StreamEventUpdated || ack.Data["event_kind"] != alerts.EventAcknowledged {
		t.Fatalf("ack frame = %+v ok=%v", ack, ok)
	}

	// Manual resolve arrives as alert.resolved.
	res = env.do(t, http.MethodPost, "/v1/alerts/"+alertID.String()+"/resolve", m11JSON(t, map[string]any{"reason": "fixed"}))
	if res.Status != http.StatusOK {
		t.Fatalf("resolve: %d %v", res.Status, res.Body)
	}
	resolved, ok := stream.next(5 * time.Second)
	if !ok || resolved.Event != alerts.StreamEventResolved || resolved.Data["event_kind"] != alerts.EventManualResolved {
		t.Fatalf("resolved frame = %+v ok=%v", resolved, ok)
	}

	// PostgreSQL replay (the canonical gap fallback) returns everything after
	// the Last-Event-ID keyset.
	replayed, err := env.svc.ReplayEvents(context.Background(), orgID, dbEventID, authz.Scope{Unrestricted: true}, 100)
	must(t, err)
	if len(replayed) < 2 {
		t.Fatalf("PG replay events = %d, want >= 2 (ack + resolved)", len(replayed))
	}
	if replayed[0].Name != alerts.StreamEventUpdated || replayed[0].Kind != alerts.EventAcknowledged {
		t.Fatalf("PG replay[0] = %+v, want acknowledged", replayed[0])
	}
	foundResolved := false
	for _, ev := range replayed {
		if ev.Name == alerts.StreamEventResolved {
			foundResolved = true
		}
	}
	if !foundResolved {
		t.Fatal("PG replay missing the resolved event")
	}

	// Last-Event-ID resume from the retained in-memory buffer: reconnect with
	// the activated event id and receive the ack + resolved frames again.
	resume := env.openStream(t, dbEventID.String())
	defer resume.close()
	r1, ok := resume.next(5 * time.Second)
	if !ok || r1.Data["event_kind"] != alerts.EventAcknowledged {
		t.Fatalf("resume frame 1 = %+v ok=%v, want acknowledged", r1, ok)
	}
	r2, ok := resume.next(5 * time.Second)
	if !ok || r2.Event != alerts.StreamEventResolved {
		t.Fatalf("resume frame 2 = %+v ok=%v, want resolved", r2, ok)
	}
}

func TestM11S3aStreamScopeFiltering(t *testing.T) {
	env := newM11S3aEnv(t, "m11s3a-stream-scope-"+newUUID()[:8])
	orgID := env.org()
	base := time.Now().UTC().Truncate(time.Second)

	// A viewer bound to site B must never see site A events.
	siteB, err := uuid.NewV7()
	must(t, err)
	_, err = ownerPool.Exec(context.Background(), `
		INSERT INTO sites (id, org_id, name) VALUES ($1, $2, 'HQ-B')`, siteB, orgID)
	must(t, err)
	boundID := m11AddUser(t, orgID, "stream-bound-"+env.slug+"@dev.local", "viewer")
	bindID, err := uuid.NewV7()
	must(t, err)
	_, err = ownerPool.Exec(context.Background(), `
		INSERT INTO user_scope_bindings (id, org_id, user_id, scope_type, scope_id)
		VALUES ($1, $2, $3, 'site', $4)`, bindID, orgID, boundID, siteB)
	must(t, err)
	bound, _ := m11LoginClient(t, env.srv, env.slug, "stream-bound-"+env.slug+"@dev.local")
	boundStream := openStreamAs(t, env.srv, bound, "")
	defer boundStream.close()

	dev, series := m11s3aDeviceAndSeries(t, orgID, env.site(), "stream-scope-dev", "m11.s3a.stream.scope")
	rule := env.m11CreateRule(t, "stream-scope-rule", "threshold", "warning",
		`{"agg":"max","op":"gt","value":5,"window":"30s","for_duration":"0s","recovery":{"for_duration":"0s"}}`,
		`{"metric_key":"m11.s3a.stream.scope"}`)
	m11WriteSamples(t, orgID, series, []time.Time{base}, []float64{10})
	env.evaluate(t, base)
	fp := alertsFingerprint(t, env.m11Env, rule, dev, `{}`)
	if open, ok := m11OpenAlert(t, orgID, fp); !ok || open["state"] != alerts.StateActive {
		t.Fatalf("alert = %v ok=%v, want active", open, ok)
	}

	// The in-memory buffer holds the event, but the bound connection receives
	// nothing for the out-of-scope site.
	if frame, ok := boundStream.next(700 * time.Millisecond); ok {
		t.Fatalf("bound stream received an out-of-scope frame: %+v", frame)
	}
	// The PostgreSQL replay applies the same scope filter deterministically.
	replayed, err := env.svc.ReplayEvents(context.Background(), orgID, uuid.Nil, authz.Scope{Sites: []uuid.UUID{siteB}}, 100)
	must(t, err)
	if len(replayed) != 0 {
		t.Fatalf("bound PG replay = %d events, want 0", len(replayed))
	}
	// The org-wide caller still sees them.
	replayed, err = env.svc.ReplayEvents(context.Background(), orgID, uuid.Nil, authz.Scope{Unrestricted: true}, 100)
	must(t, err)
	if len(replayed) == 0 {
		t.Fatal("org-wide PG replay saw no events")
	}
}
