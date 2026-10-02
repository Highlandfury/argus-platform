package integration

// M11-S2 integration suites: channel/route/delivery APIs, the real-DB
// alert -> notify end-to-end path (signed webhooks), persisted retry and
// suppression semantics, secret hygiene, authz isolation, and the curated
// default rule pack. Unit tests cover the adapter wires and the scheduler
// math; these suites pin what the database and the API contract observe.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/modules/alerts"
	"github.com/argus-platform/argus/internal/modules/notify"
)

// Markers stored in write-only secret fields; none may appear in API
// responses, server logs, or at-rest columns outside the vault envelope.
const (
	m11s2SMTPMarker    = "hunter2-smtp-marker"
	m11s2WebhookMarker = "whsec-e2e-marker"
	m11s2SlackMarker   = "slack-secret-marker"
	m11s2TeamsMarker   = "teams-secret-marker"
	// Rejected-write fixtures (names intentionally avoid credential-like
	// identifiers; the values are synthetic test markers).
	m11s2ConflictSig = "whsec-conflict-marker"
	m11s2ViewerSig   = "whsec-viewer-marker"
	m11s2BoundSig    = "whsec-bound-marker"
)

var m11s2Markers = []string{m11s2SMTPMarker, m11s2WebhookMarker, m11s2SlackMarker, m11s2TeamsMarker, m11s2ConflictSig, m11s2ViewerSig, m11s2BoundSig}

func m11s2Slug(prefix string) string {
	return prefix + "-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
}

// webhookHit is one received webhook delivery, signature already verified.
type webhookHit struct {
	body      []byte
	payload   map[string]any
	event     string
	delivery  string
	dedupKey  string
	verifyErr error
}

// newWebhookReceiver starts a receiver that verifies the canonical
// X-Argus-Signature scheme for every request and records what arrived.
func newWebhookReceiver(t *testing.T, secret string) (*httptest.Server, func() []webhookHit) {
	t.Helper()
	var (
		mu   sync.Mutex
		hits []webhookHit
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		hit := webhookHit{
			body:     body,
			event:    r.Header.Get("X-Argus-Event"),
			delivery: r.Header.Get("X-Argus-Delivery"),
			dedupKey: r.Header.Get("X-Argus-Dedup-Key"),
			verifyErr: notify.VerifySignature(secret,
				r.Header.Get("X-Argus-Timestamp"), r.Header.Get("X-Argus-Signature"), body, time.Now().UTC()),
		}
		_ = json.Unmarshal(body, &hit.payload)
		mu.Lock()
		hits = append(hits, hit)
		mu.Unlock()
		if hit.verifyErr != nil {
			http.Error(w, hit.verifyErr.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []webhookHit {
		mu.Lock()
		defer mu.Unlock()
		out := make([]webhookHit, len(hits))
		copy(out, hits)
		return out
	}
}

// m11s2BodyLeaks reports whether any secret marker appears in a response.
func m11s2BodyLeaks(t *testing.T, body any) bool {
	t.Helper()
	raw, err := json.Marshal(body)
	must(t, err)
	for _, marker := range m11s2Markers {
		if strings.Contains(string(raw), marker) {
			return true
		}
	}
	return false
}

// m11s2PlaintextHits counts at-rest rows whose non-vault columns contain any
// secret marker (config or raw envelope bytes; the vault envelope must hold
// ciphertext only).
func m11s2PlaintextHits(t *testing.T, orgID uuid.UUID) int {
	t.Helper()
	hits := 0
	for _, marker := range m11s2Markers {
		var n int
		must(t, ownerPool.QueryRow(context.Background(), `
			SELECT count(*) FROM notification_channels
			WHERE org_id = $1
			  AND (config::text ILIKE '%' || $2 || '%'
			   OR encode(coalesce(secret_enc, ''::bytea), 'escape') ILIKE '%' || $2 || '%')`,
			orgID, marker).Scan(&n))
		hits += n
	}
	return hits
}

// m11s2AssertFailedAttempt pins one failed delivery row and its next retry.
func m11s2AssertFailedAttempt(t *testing.T, row map[string]any, attempts int, wantNext time.Time) {
	t.Helper()
	if row["status"] != notify.StatusFailed {
		t.Fatalf("delivery status = %v, want failed", row["status"])
	}
	if row["attempts"] != attempts {
		t.Fatalf("delivery attempts = %v, want %d", row["attempts"], attempts)
	}
	next, ok := row["next_attempt_at"].(*time.Time)
	if !ok || next == nil || !next.UTC().Equal(wantNext.UTC()) {
		t.Fatalf("next_attempt_at = %v, want %s", row["next_attempt_at"], wantNext.UTC())
	}
}

// m11s2RealAlert inserts one real alerts row (owner fixtures: the delivery
// alert_id FK requires it) and returns its id plus canonical fingerprint.
func m11s2RealAlert(t *testing.T, orgID, ruleID uuid.UUID, ruleVersion int, dev uuid.UUID, severity string, at time.Time) (uuid.UUID, string) {
	t.Helper()
	id, err := uuid.NewV7()
	must(t, err)
	fp := fmt.Sprintf("%x", sha256.Sum256([]byte("m11s2-"+id.String())))
	_, err = ownerPool.Exec(context.Background(), `
		INSERT INTO alerts (id, org_id, rule_id, rule_version, fingerprint, resource_type, resource_id,
			dimension_subset, state, severity, value, started_at, last_evaluated_at, created_at)
		VALUES ($1, $2, $3, $4, $5, 'device', $6, '{}'::jsonb, 'active', $7,
			'{"value":10,"op":"gt","threshold":5}'::jsonb, $8, $8, $8)`,
		id, orgID, ruleID, ruleVersion, fp, dev, severity, at)
	must(t, err)
	return id, fp
}

// TestM11S2MigrationRLSInvariants pins the tenant-isolation shape of the new
// tables: RLS enabled and forced on every notification table.
func TestM11S2MigrationRLSInvariants(t *testing.T) {
	rows, err := ownerPool.Query(context.Background(), `
		SELECT relname, relrowsecurity, relforcerowsecurity
		FROM pg_class
		WHERE relname IN ('notification_channels', 'notification_routes', 'notification_deliveries')`)
	must(t, err)
	defer rows.Close()
	seen := map[string][2]bool{}
	for rows.Next() {
		var (
			name  string
			rls   bool
			force bool
		)
		must(t, rows.Scan(&name, &rls, &force))
		seen[name] = [2]bool{rls, force}
	}
	must(t, rows.Err())
	for _, table := range []string{"notification_channels", "notification_routes", "notification_deliveries"} {
		got, ok := seen[table]
		if !ok || !got[0] || !got[1] {
			t.Fatalf("%s: present=%v rls=%v force=%v, want present+rls+force", table, ok, got[0], got[1])
		}
	}
}

// TestM11S2ChannelRouteAPIAndSecretHygiene covers the full channel/route
// lifecycle through the router and proves secrets stay write-only: vault
// envelope at rest, nothing in responses or logs.
func TestM11S2ChannelRouteAPIAndSecretHygiene(t *testing.T) {
	env := newM11S2Env(t, m11s2Slug("m11s2-api"))
	orgID := env.org()

	// One channel per canonical kind, each with a marker in its secret.
	smtpRes := env.do(t, http.MethodPost, "/v1/notification/channels", m11JSON(t, map[string]any{
		"kind": "smtp",
		"name": "smtp-primary",
		"config": map[string]any{
			"host": "smtp.example.test", "port": 587, "from": "argus@example.test",
			"to": []string{"ops@example.test"}, "starttls": true,
		},
		"secret": map[string]any{"password": m11s2SMTPMarker},
	}))
	if smtpRes.Status != http.StatusCreated {
		t.Fatalf("create smtp channel: %d %v", smtpRes.Status, smtpRes.Body)
	}
	smtpID, _ := smtpRes.Body["id"].(string)
	if smtpID == "" {
		t.Fatalf("created smtp channel without id: %v", smtpRes.Body)
	}
	if has, _ := smtpRes.Body["has_secret"].(bool); !has {
		t.Fatalf("smtp channel must report has_secret: %v", smtpRes.Body)
	}
	if m11s2BodyLeaks(t, smtpRes.Body) {
		t.Fatal("create channel response echoed a secret")
	}

	webhookID := env.createWebhookChannel(t, "webhook-primary", "https://receiver.example.test/hook", m11s2WebhookMarker)

	slackRes := env.do(t, http.MethodPost, "/v1/notification/channels", m11JSON(t, map[string]any{
		"kind": "slack", "name": "slack-ops",
		"config": map[string]any{"channel": "#ops"},
		"secret": map[string]any{"webhook_url": "https://hooks.slack.test/" + m11s2SlackMarker},
	}))
	if slackRes.Status != http.StatusCreated {
		t.Fatalf("create slack channel: %d %v", slackRes.Status, slackRes.Body)
	}
	teamsRes := env.do(t, http.MethodPost, "/v1/notification/channels", m11JSON(t, map[string]any{
		"kind": "teams", "name": "teams-noc",
		"config": map[string]any{},
		"secret": map[string]any{"webhook_url": "https://outlook.example.test/" + m11s2TeamsMarker},
	}))
	if teamsRes.Status != http.StatusCreated {
		t.Fatalf("create teams channel: %d %v", teamsRes.Status, teamsRes.Body)
	}

	// Listing and reading never expose secret material.
	listRes := env.do(t, http.MethodGet, "/v1/notification/channels", "")
	if listRes.Status != http.StatusOK {
		t.Fatalf("list channels: %d %v", listRes.Status, listRes.Body)
	}
	channels := dataList(t, listRes.Body)
	if len(channels) < 4 {
		t.Fatalf("channels listed = %d, want >= 4", len(channels))
	}
	if m11s2BodyLeaks(t, listRes.Body) {
		t.Fatal("channel list leaked a secret")
	}
	getRes := env.do(t, http.MethodGet, "/v1/notification/channels/"+smtpID, "")
	if getRes.Status != http.StatusOK {
		t.Fatalf("get channel: %d %v", getRes.Status, getRes.Body)
	}
	if m11s2BodyLeaks(t, getRes.Body) {
		t.Fatal("channel read leaked a secret")
	}

	// Duplicate names conflict deterministically.
	conflict := env.do(t, http.MethodPost, "/v1/notification/channels", m11JSON(t, map[string]any{
		"kind": "webhook", "name": "webhook-primary",
		"config": map[string]any{"url": "https://other.example.test/hook", "payload": "summary"},
		"secret": map[string]any{"signing_secret": m11s2ConflictSig},
	}))
	if conflict.Status != http.StatusConflict {
		t.Fatalf("duplicate channel name: %d %v, want 409", conflict.Status, conflict.Body)
	}

	// Update and disable are reflected on read.
	patch := env.do(t, http.MethodPatch, "/v1/notification/channels/"+smtpID, m11JSON(t, map[string]any{
		"name": "smtp-renamed", "enabled": false,
	}))
	if patch.Status != http.StatusOK || patch.Body["name"] != "smtp-renamed" || patch.Body["enabled"] != false {
		t.Fatalf("patch channel: %d %v", patch.Status, patch.Body)
	}

	// Routes: create, invalid match fails closed, disable, delete, 404.
	routeID := env.createRoute(t, "route-all", `{}`, webhookID)
	routesRes := env.do(t, http.MethodGet, "/v1/notification/routes", "")
	if routesRes.Status != http.StatusOK || len(dataList(t, routesRes.Body)) < 1 {
		t.Fatalf("list routes: %d %v", routesRes.Status, routesRes.Body)
	}
	badMatch := env.do(t, http.MethodPost, "/v1/notification/routes", m11JSON(t, map[string]any{
		"name": "bad-route", "match": map[string]any{"severity": []string{"urgent"}},
		"channel_ids": []string{webhookID},
	}))
	if badMatch.Status != http.StatusBadRequest {
		t.Fatalf("invalid route match: %d %v, want 400", badMatch.Status, badMatch.Body)
	}
	disabled := env.do(t, http.MethodPatch, "/v1/notification/routes/"+routeID, m11JSON(t, map[string]any{"enabled": false}))
	if disabled.Status != http.StatusOK || disabled.Body["enabled"] != false {
		t.Fatalf("patch route: %d %v", disabled.Status, disabled.Body)
	}
	del := env.do(t, http.MethodDelete, "/v1/notification/routes/"+routeID, "")
	if del.Status != http.StatusOK && del.Status != http.StatusNoContent {
		t.Fatalf("delete route: %d %v", del.Status, del.Body)
	}
	gone := env.do(t, http.MethodGet, "/v1/notification/routes/"+routeID, "")
	if gone.Status != http.StatusNotFound {
		t.Fatalf("deleted route read: %d %v, want 404", gone.Status, gone.Body)
	}

	// Deliveries: real empty list plus deterministic filter validation.
	if got := env.deliveries(t, ""); len(got) != 0 {
		t.Fatalf("deliveries before any alert = %d, want 0", len(got))
	}
	badFilter := env.do(t, http.MethodGet, "/v1/notification/deliveries?filter%5Bstatus%5D=bogus", "")
	if badFilter.Status != http.StatusBadRequest {
		t.Fatalf("invalid delivery status filter: %d %v, want 400", badFilter.Status, badFilter.Body)
	}

	// At rest: vault envelopes present, zero plaintext anywhere.
	var encCount int
	must(t, ownerPool.QueryRow(context.Background(), `
		SELECT count(*) FROM notification_channels WHERE org_id = $1 AND secret_enc IS NOT NULL`, orgID).Scan(&encCount))
	if encCount < 4 {
		t.Fatalf("vault envelopes = %d, want >= 4", encCount)
	}
	if hits := m11s2PlaintextHits(t, orgID); hits != 0 {
		t.Fatalf("plaintext secret marker rows at rest = %d, want 0", hits)
	}
	logs := env.logs.String()
	for _, marker := range m11s2Markers {
		if strings.Contains(logs, marker) {
			t.Fatalf("server log leaked secret marker %q", marker)
		}
	}
}

// TestM11S2EndToEndSignedWebhookDeliveryAndResolve drives a real threshold
// alert from activation through the notification pipeline to a signed webhook
// receiver, then through recovery/resolve.
func TestM11S2EndToEndSignedWebhookDeliveryAndResolve(t *testing.T) {
	env := newM11S2Env(t, m11s2Slug("m11s2-e2e"))
	orgID := env.org()
	base := time.Now().UTC().Truncate(time.Second)

	receiver, hits := newWebhookReceiver(t, m11s2WebhookMarker)
	channelID := env.createWebhookChannel(t, "e2e-webhook", receiver.URL, m11s2WebhookMarker)
	channelUUID := uuid.MustParse(channelID)
	env.createRoute(t, "e2e-route", `{}`, channelID)

	dev := m11Device(t, orgID, env.site(), "e2e-dev", "switch")
	series := m11Series(t, orgID, dev, "m11.e2e.gauge", map[string]string{"probe": "e2e"}, "count")
	var ts []time.Time
	var vals []float64
	for i := -24; i <= 24; i++ {
		at := base.Add(time.Duration(i) * 10 * time.Second)
		v := 1.0
		if !at.After(base.Add(time.Minute)) {
			v = 10
		}
		ts = append(ts, at)
		vals = append(vals, v)
	}
	m11WriteSamples(t, orgID, series, ts, vals)

	rule := env.m11CreateRule(t, "e2e-rule", "threshold", "critical",
		`{"agg":"avg","op":"gt","value":5,"window":"30s","for_duration":"1m","recovery":{"for_duration":"1m"}}`,
		`{"metric_key":"m11.e2e.gauge"}`)

	// First true evaluation opens a pending alert (no notification yet).
	env.evaluate(t, base)
	fp := alertsFingerprint(t, env.m11Env, rule, dev, `{"probe":"e2e"}`)
	if alert, ok := m11OpenAlert(t, orgID, fp); !ok || alert["state"] != "pending" {
		t.Fatalf("first evaluation: alert = %v ok=%v, want pending", alert, ok)
	}

	// for_duration reached: activation is committed and enqueued.
	env.evaluate(t, base.Add(time.Minute))
	open, ok := m11OpenAlert(t, orgID, fp)
	if !ok || open["state"] != alerts.StateActive {
		t.Fatalf("activation: alert = %v ok=%v, want active", open, ok)
	}
	alertID := open["id"].(uuid.UUID)
	if trs := env.recorder.transitions(); len(trs) != 1 || trs[0].Event.Kind != alerts.EventActivated {
		t.Fatalf("recorded transitions = %+v, want one activated", trs)
	}

	row := ownerDelivery(t, orgID, channelUUID, alertID)
	if row["status"] != notify.StatusPending || row["attempts"] != 0 {
		t.Fatalf("enqueued delivery = %v, want pending attempts 0", row)
	}
	if row["dedup_key"] != notify.DedupKey(channelUUID, alertID, alerts.EventActivated) {
		t.Fatalf("dedup key = %v, want canonical activated key", row["dedup_key"])
	}
	if !strings.Contains(row["subject"].(string), "e2e-rule") {
		t.Fatalf("subject = %q, want the rule name", row["subject"])
	}

	// Worker pass: signed webhook delivery.
	if n := env.processDue(t, env.engine, base.Add(time.Minute)); n < 1 {
		t.Fatalf("process due after activation = %d, want >= 1", n)
	}
	got := hits()
	if len(got) != 1 {
		t.Fatalf("webhook hits after activation = %d, want 1", len(got))
	}
	hit := got[0]
	if hit.verifyErr != nil {
		t.Fatalf("webhook signature verification: %v", hit.verifyErr)
	}
	if hit.event != notify.EventFired {
		t.Fatalf("X-Argus-Event = %q, want %q", hit.event, notify.EventFired)
	}
	if hit.delivery != row["id"].(uuid.UUID).String() {
		t.Fatalf("X-Argus-Delivery = %q, want delivery row id %s", hit.delivery, row["id"])
	}
	if hit.payload["event"] != notify.EventFired {
		t.Fatalf("payload event = %v, want %q", hit.payload["event"], notify.EventFired)
	}
	data, _ := hit.payload["data"].(map[string]any)
	if data["alert_id"] != alertID.String() || data["severity"] != "critical" {
		t.Fatalf("payload data = %v, want alert_id %s severity critical", data, alertID)
	}
	if data["state"] != alerts.StateActive {
		t.Fatalf("payload state = %v, want active", data["state"])
	}
	wantRef := "https://argus.example/alerts/" + alertID.String()
	if data["evidence_ref"] != wantRef {
		t.Fatalf("payload evidence_ref = %v, want %s", data["evidence_ref"], wantRef)
	}
	if ack, _ := data["ack_url"].(string); !strings.HasSuffix(ack, alertID.String()+"#ack") {
		t.Fatalf("payload ack_url = %v, want alert link for %s", data["ack_url"], alertID)
	}

	row = ownerDelivery(t, orgID, channelUUID, alertID)
	if row["status"] != notify.StatusDelivered || row["attempts"] != 1 {
		t.Fatalf("delivered row = %v, want delivered attempts 1", row)
	}
	if code, ok := row["response_code"].(*int); !ok || code == nil || *code != http.StatusOK {
		t.Fatalf("response_code = %v, want 200", row["response_code"])
	}
	if row["delivered_at"] == nil {
		t.Fatalf("delivered_at = nil, want timestamp")
	}

	// Recovery: false evaluation resolves the alert and notifies again.
	env.evaluate(t, base.Add(3*time.Minute))
	if resolved, ok := m11OpenAlert(t, orgID, fp); ok {
		t.Fatalf("recovery must resolve the alert, still open: %v", resolved)
	}
	if trs := env.recorder.transitions(); len(trs) != 2 || trs[1].Event.Kind != alerts.EventResolved {
		t.Fatalf("recorded transitions = %+v, want activated then resolved", trs)
	}
	if n := env.processDue(t, env.engine, base.Add(3*time.Minute)); n < 1 {
		t.Fatalf("process due after resolve = %d, want >= 1", n)
	}
	got = hits()
	if len(got) != 2 {
		t.Fatalf("webhook hits after resolve = %d, want 2", len(got))
	}
	if got[1].event != notify.EventResolved || got[1].verifyErr != nil {
		t.Fatalf("resolve hit = %v err=%v, want alert.resolved and valid signature", got[1].event, got[1].verifyErr)
	}
	rdata, _ := got[1].payload["data"].(map[string]any)
	if rdata["state"] != alerts.StateResolved {
		t.Fatalf("resolve payload state = %v, want resolved", rdata["state"])
	}

	rows := ownerAllDeliveries(t, orgID, channelUUID)
	if len(rows) != 2 {
		t.Fatalf("deliveries after resolve = %d, want 2", len(rows))
	}
	if rows[0]["dedup_key"] == rows[1]["dedup_key"] {
		t.Fatalf("activated and resolved deliveries must not share a dedup key")
	}
	for _, r := range rows {
		if r["status"] != notify.StatusDelivered || r["attempts"] != 1 {
			t.Fatalf("delivery row = %v, want delivered attempts 1", r)
		}
	}

	// The ledger API exposes both transitions with working filters.
	if got := env.deliveries(t, "filter[channel_id]="+channelID); len(got) != 2 {
		t.Fatalf("deliveries by channel = %d, want 2", len(got))
	}
	if got := env.deliveries(t, "filter[status]=delivered"); len(got) != 2 {
		t.Fatalf("deliveries by status = %d, want 2", len(got))
	}
	if got := env.deliveries(t, "filter[alert_id]="+alertID.String()); len(got) != 2 {
		t.Fatalf("deliveries by alert = %d, want 2", len(got))
	}

	// The channel test endpoint proves the wire end to end as well.
	testRes := env.do(t, http.MethodPost, "/v1/notification/channels/"+channelID+"/test", "")
	if testRes.Status < 200 || testRes.Status > 299 {
		t.Fatalf("channel test endpoint: %d %v", testRes.Status, testRes.Body)
	}
	if got := hits(); len(got) != 3 || got[2].verifyErr != nil {
		t.Fatalf("webhook hits after test = %d, want 3 valid", len(got))
	}
}

// TestM11S2RetryDuplicateAndThrottle pins the persisted delivery semantics:
// retry rows and their next attempt, duplicate-content suppression, and the
// per-route severity token bucket.
func TestM11S2RetryDuplicateAndThrottle(t *testing.T) {
	env := newM11S2Env(t, m11s2Slug("m11s2-retry"))
	orgID := env.org()
	base := time.Now().UTC().Truncate(time.Second)
	env.clock.Set(base)

	scripted := &scriptedTransport{outcomes: []sendOutcome{failingOutcome(), failingOutcome()}}
	engine := env.installEngine(t, map[string]notify.Transport{notify.KindWebhook: scripted})

	channelID := env.createWebhookChannel(t, "retry-webhook", "https://receiver.invalid/hook", "whsec-retry-marker")
	channelUUID := uuid.MustParse(channelID)
	env.createRoute(t, "retry-route", `{}`, channelID)

	dev := m11Device(t, orgID, env.site(), "retry-dev", "router")
	rule := env.m11CreateRule(t, "retry-rule", "threshold", "critical",
		`{"agg":"avg","op":"gt","value":5,"window":"30s"}`, `{"metric_key":"m11.retry"}`)

	alertID, alertFP := m11s2RealAlert(t, orgID, rule.RuleID, rule.Version, dev, "critical", base)
	alert := alerts.Alert{
		ID: alertID, OrgID: orgID, RuleID: rule.RuleID, RuleVersion: rule.Version,
		Fingerprint: alertFP, ResourceType: "device", ResourceID: dev,
		State: alerts.StateActive, Severity: "critical",
		Value:     []byte(`{"value":10,"op":"gt","threshold":5}`),
		StartedAt: base, SiteID: env.site(), CreatedAt: base,
	}
	engine.Transitioned(context.Background(), alerts.Transition{
		Alert: alert,
		Event: alerts.AlertEvent{Kind: alerts.EventActivated, AlertID: alertID, Ts: base},
	})

	row := ownerDelivery(t, orgID, channelUUID, alertID)
	if row["status"] != notify.StatusPending || row["attempts"] != 0 {
		t.Fatalf("first enqueue = %v, want pending attempts 0", row)
	}

	// Attempt 1 fails -> retry at created+1m.
	if n := env.processDue(t, engine, base); n < 1 {
		t.Fatalf("process due attempt 1 = %d", n)
	}
	row = ownerDelivery(t, orgID, channelUUID, alertID)
	m11s2AssertFailedAttempt(t, row, 1, base.Add(time.Minute))
	if scripted.sendCount() != 1 {
		t.Fatalf("sends after attempt 1 = %d, want 1", scripted.sendCount())
	}

	// Attempt 2 fails -> next = failure instant + 5m (now-relative backoff).
	if n := env.processDue(t, engine, base.Add(time.Minute)); n < 1 {
		t.Fatalf("process due attempt 2 = %d", n)
	}
	row = ownerDelivery(t, orgID, channelUUID, alertID)
	m11s2AssertFailedAttempt(t, row, 2, base.Add(6*time.Minute))
	if scripted.sendCount() != 2 {
		t.Fatalf("sends after attempt 2 = %d, want 2", scripted.sendCount())
	}

	// Attempt 3 succeeds and the same row finalizes as delivered.
	if n := env.processDue(t, engine, base.Add(6*time.Minute)); n < 1 {
		t.Fatalf("process due attempt 3 = %d", n)
	}
	row = ownerDelivery(t, orgID, channelUUID, alertID)
	if row["status"] != notify.StatusDelivered || row["attempts"] != 3 {
		t.Fatalf("attempt 3 row = %v, want delivered attempts 3", row)
	}
	if scripted.sendCount() != 3 {
		t.Fatalf("sends after attempt 3 = %d, want 3", scripted.sendCount())
	}

	// The identical (channel, alert, event kind) inside 5 min is suppressed
	// with a dead-letter record and no send.
	env.clock.Set(base.Add(4 * time.Minute))
	engine.Transitioned(context.Background(), alerts.Transition{
		Alert: alert,
		Event: alerts.AlertEvent{Kind: alerts.EventActivated, AlertID: alertID, Ts: base.Add(4 * time.Minute)},
	})
	rows := ownerAllDeliveries(t, orgID, channelUUID)
	if len(rows) != 2 {
		t.Fatalf("rows after duplicate = %d, want 2", len(rows))
	}
	dup := rows[1]
	if dup["status"] != notify.StatusDeadLetter ||
		!strings.Contains(dup["response_excerpt"].(string), "duplicate content") {
		t.Fatalf("duplicate row = %v, want dead_letter duplicate suppression", dup)
	}
	if scripted.sendCount() != 3 {
		t.Fatalf("sends after suppressed duplicate = %d, want 3", scripted.sendCount())
	}

	// Per-route severity token bucket: the 6th info notification is throttled.
	infoChannel := env.createWebhookChannel(t, "info-webhook", "https://receiver.invalid/info", "whsec-info-marker")
	infoChannelUUID := uuid.MustParse(infoChannel)
	env.createRoute(t, "info-route", `{"severity":["info"]}`, infoChannel)
	infoRule := env.m11CreateRule(t, "info-rule", "threshold", "info",
		`{"agg":"avg","op":"gt","value":5,"window":"30s"}`, `{"metric_key":"m11.info"}`)
	env.clock.Set(base.Add(10 * time.Minute))
	for i := 0; i < 6; i++ {
		id, fp := m11s2RealAlert(t, orgID, infoRule.RuleID, infoRule.Version, dev, "info", base.Add(10*time.Minute))
		engine.Transitioned(context.Background(), alerts.Transition{
			Alert: alerts.Alert{
				ID: id, OrgID: orgID, RuleID: infoRule.RuleID, RuleVersion: infoRule.Version,
				Fingerprint: fp, ResourceType: "device", ResourceID: dev,
				State: alerts.StateActive, Severity: "info",
				Value:     []byte(`{"value":9,"op":"gt","threshold":5}`),
				StartedAt: base.Add(10 * time.Minute), SiteID: env.site(), CreatedAt: base.Add(10 * time.Minute),
			},
			Event: alerts.AlertEvent{Kind: alerts.EventActivated, AlertID: id, Ts: base.Add(10 * time.Minute)},
		})
	}
	infoRows := ownerAllDeliveries(t, orgID, infoChannelUUID)
	pending, throttled := 0, 0
	for _, r := range infoRows {
		switch r["status"] {
		case notify.StatusPending:
			pending++
		case notify.StatusDeadLetter:
			if strings.Contains(r["response_excerpt"].(string), "severity bucket exhausted") {
				throttled++
			}
		}
	}
	if len(infoRows) != 6 || pending != 5 || throttled != 1 {
		t.Fatalf("info rows = %d pending=%d throttled=%d, want 6/5/1", len(infoRows), pending, throttled)
	}
}

// TestM11S2AuthzScopeAndCrossTenantIsolation pins the capability and tenancy
// boundaries of the new API surface.
func TestM11S2AuthzScopeAndCrossTenantIsolation(t *testing.T) {
	env := newM11S2Env(t, m11s2Slug("m11s2-authz"))
	orgID := env.org()

	channelID := env.createWebhookChannel(t, "authz-webhook", "https://receiver.invalid/authz", "whsec-authz-marker")
	routeID := env.createRoute(t, "authz-route", `{}`, channelID)

	// Viewer: alert.read surfaces yes; integration.write / alertrule.write no.
	viewerEmail := "viewer-" + m11s2Slug("v") + "@dev.local"
	m11AddUser(t, orgID, viewerEmail, "viewer")
	viewer, viewerCSRF := m11LoginClient(t, env.srv, env.slug, viewerEmail)

	res := doRequest(t, viewer, http.MethodGet, env.srv.URL+"/v1/notification/deliveries", "", nil)
	if res.Status != http.StatusOK {
		t.Fatalf("viewer deliveries: %d %v, want 200 (alert.read)", res.Status, res.Body)
	}
	res = doRequest(t, viewer, http.MethodGet, env.srv.URL+"/v1/notification/channels", "", nil)
	if res.Status != http.StatusForbidden {
		t.Fatalf("viewer channel list: %d %v, want 403", res.Status, res.Body)
	}
	res = doRequest(t, viewer, http.MethodPost, env.srv.URL+"/v1/notification/channels", m11JSON(t, map[string]any{
		"kind": "webhook", "name": "viewer-webhook",
		"config": map[string]any{"url": "https://receiver.invalid/viewer", "payload": "summary"},
		"secret": map[string]any{"signing_secret": m11s2ViewerSig},
	}), map[string]string{"X-CSRF-Token": viewerCSRF})
	if res.Status != http.StatusForbidden {
		t.Fatalf("viewer channel create: %d %v, want 403", res.Status, res.Body)
	}
	res = doRequest(t, viewer, http.MethodGet, env.srv.URL+"/v1/notification/routes", "", nil)
	if res.Status != http.StatusForbidden {
		t.Fatalf("viewer route list: %d %v, want 403", res.Status, res.Body)
	}
	res = doRequest(t, viewer, http.MethodPost, env.srv.URL+"/v1/alert-rules:install-defaults", "", map[string]string{"X-CSRF-Token": viewerCSRF})
	if res.Status != http.StatusForbidden {
		t.Fatalf("viewer install-defaults: %d %v, want 403", res.Status, res.Body)
	}

	// Unauthenticated access is rejected before any tenancy work.
	res = doRequest(t, &http.Client{Timeout: 5 * time.Second}, http.MethodGet, env.srv.URL+"/v1/notification/channels", "", nil)
	if res.Status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated channels: %d %v, want 401", res.Status, res.Body)
	}

	// A second org cannot see the first org's channel or route (RLS).
	other := newM11S2Env(t, m11s2Slug("m11s2-other"))
	res = other.do(t, http.MethodGet, "/v1/notification/channels/"+channelID, "")
	if res.Status != http.StatusNotFound {
		t.Fatalf("cross-tenant channel read: %d %v, want 404", res.Status, res.Body)
	}
	res = other.do(t, http.MethodGet, "/v1/notification/routes/"+routeID, "")
	if res.Status != http.StatusNotFound {
		t.Fatalf("cross-tenant route read: %d %v, want 404", res.Status, res.Body)
	}

	// A site-bound admin holds no org-scoped notification capability.
	boundEmail := "bound-" + m11s2Slug("b") + "@dev.local"
	boundID := m11AddUser(t, orgID, boundEmail, "admin")
	bindID, err := uuid.NewV7()
	must(t, err)
	_, err = ownerPool.Exec(context.Background(), `
		INSERT INTO user_scope_bindings (id, org_id, user_id, scope_type, scope_id)
		VALUES ($1, $2, $3, 'site', $4)`, bindID, orgID, boundID, env.site())
	must(t, err)
	bound, boundCSRF := m11LoginClient(t, env.srv, env.slug, boundEmail)
	res = doRequest(t, bound, http.MethodPost, env.srv.URL+"/v1/notification/channels", m11JSON(t, map[string]any{
		"kind": "webhook", "name": "bound-webhook",
		"config": map[string]any{"url": "https://receiver.invalid/bound", "payload": "summary"},
		"secret": map[string]any{"signing_secret": m11s2BoundSig},
	}), map[string]string{"X-CSRF-Token": boundCSRF})
	if res.Status != http.StatusForbidden {
		t.Fatalf("site-bound channel create: %d %v, want 403", res.Status, res.Body)
	}
	res = doRequest(t, bound, http.MethodGet, env.srv.URL+"/v1/notification/channels", "", nil)
	if res.Status != http.StatusForbidden {
		t.Fatalf("site-bound channel list: %d %v, want 403", res.Status, res.Body)
	}
}

// TestM11S2InstallDefaultPackIsIdempotent pins the P2-AC-32 curated pack
// install path: installs once, then reports zero new rules.
func TestM11S2InstallDefaultPackIsIdempotent(t *testing.T) {
	env := newM11S2Env(t, m11s2Slug("m11s2-defaults"))

	first := env.do(t, http.MethodPost, "/v1/alert-rules:install-defaults", "")
	if first.Status != http.StatusOK {
		t.Fatalf("install defaults: %d %v", first.Status, first.Body)
	}
	installed, _ := first.Body["installed"].(float64)
	if installed < 1 {
		t.Fatalf("installed = %v, want >= 1", first.Body["installed"])
	}
	second := env.do(t, http.MethodPost, "/v1/alert-rules:install-defaults", "")
	if second.Status != http.StatusOK {
		t.Fatalf("reinstall defaults: %d %v", second.Status, second.Body)
	}
	if again, _ := second.Body["installed"].(float64); again != 0 {
		t.Fatalf("second install installed = %v, want 0 (idempotent)", second.Body["installed"])
	}
	list := env.do(t, http.MethodGet, "/v1/alert-rules", "")
	if list.Status != http.StatusOK || len(dataList(t, list.Body)) == 0 {
		t.Fatalf("rules after install: %d %v", list.Status, list.Body)
	}
}

// TestM11S2EnsureDefaultsSeedsEmptyOrg pins the scheduler's new-org seeding
// seam (P2-AC-32): a brand-new org installs the pack exactly once.
func TestM11S2EnsureDefaultsSeedsEmptyOrg(t *testing.T) {
	env := newM11S2Env(t, m11s2Slug("m11s2-seed"))

	n, err := env.svc.EnsureDefaults(context.Background(), env.org())
	must(t, err)
	if n < 1 {
		t.Fatalf("EnsureDefaults installed = %d, want >= 1", n)
	}
	again, err := env.svc.EnsureDefaults(context.Background(), env.org())
	must(t, err)
	if again != 0 {
		t.Fatalf("second EnsureDefaults installed = %d, want 0 (never had-any-rules guard)", again)
	}
}
