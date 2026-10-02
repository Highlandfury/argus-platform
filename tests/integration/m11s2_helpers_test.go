package integration

// Shared fixture for the M11-S2 notification suites: a logged-in tenant with
// the real alerts + notify stack, a file-backed dev vault, and a transition
// recorder whose downstream engine can be swapped for scripted transports.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/api"
	"github.com/argus-platform/argus/internal/modules/alerts"
	"github.com/argus-platform/argus/internal/modules/identity"
	"github.com/argus-platform/argus/internal/modules/notify"
	"github.com/argus-platform/argus/internal/modules/tenancy"
	"github.com/argus-platform/argus/internal/platform/authz"
	"github.com/argus-platform/argus/internal/platform/secrets"
	"github.com/argus-platform/argus/internal/platform/telemetry"
)

// recordingSink captures committed transitions and forwards them to the
// currently installed engine. Tests swap in an engine with scripted
// transports without rewiring the alerts service.
type recordingSink struct {
	mu       sync.Mutex
	engine   *notify.Engine
	recorded []alerts.Transition
}

func (r *recordingSink) Transitioned(ctx context.Context, tr alerts.Transition) {
	r.mu.Lock()
	r.recorded = append(r.recorded, tr)
	target := r.engine
	r.mu.Unlock()
	if target != nil {
		target.Transitioned(ctx, tr)
	}
}

func (r *recordingSink) setEngine(e *notify.Engine) {
	r.mu.Lock()
	r.engine = e
	r.mu.Unlock()
}

func (r *recordingSink) transitions() []alerts.Transition {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]alerts.Transition, len(r.recorded))
	copy(out, r.recorded)
	return out
}

// testNotifyVault is the file-backed dev KEK in a throwaway directory (the
// same M7 seam used by the credentials suites).
func testNotifyVault(t *testing.T) *secrets.Vault {
	t.Helper()
	kek, err := secrets.LoadOrCreateLocalKMS(secrets.LocalConfig{
		Path:          filepath.Join(t.TempDir(), "master.key"),
		KeyID:         "it-m11s2",
		AllowGenerate: true,
	})
	must(t, err)
	return secrets.New(kek)
}

// m11s2Env is one logged-in tenant with the alerts + notification stack.
type m11s2Env struct {
	*m11Env
	notifySvc *notify.Service
	engine    *notify.Engine
	vault     *secrets.Vault
	recorder  *recordingSink
	logs      *bytes.Buffer
}

func newM11S2Env(t *testing.T, slug string) *m11s2Env {
	t.Helper()
	seed := seedLoginUser(t, slug, "HQ-"+slug)

	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	clock := &m11Clock{now: time.Now().UTC().Truncate(time.Second)}
	svc := alerts.New(appPool, authz.New(appPool))
	svc.Now = clock.Now
	eval := alerts.NewEvaluator(appPool, alerts.EvaluatorOptions{Now: clock.Now, Logger: logger})
	vault := testNotifyVault(t)
	notifySvc := notify.New(appPool, vault)
	notifySvc.SetAuthorizer(authz.New(appPool))
	notifySvc.Now = clock.Now
	engine := notify.NewEngine(appPool, vault, notify.EngineOptions{
		Now: clock.Now, Logger: logger, BaseURL: "https://argus.example", Auth: authPool,
	})
	recorder := &recordingSink{engine: engine}
	svc.SetSink(recorder)
	eval.SetSink(recorder)

	tenancySvc := tenancy.New(appPool, authPool)
	identitySvc, err := identity.New(appPool, authPool, tenancySvc)
	must(t, err)
	router := api.NewRouter(api.Options{
		Logger:       logger,
		Telemetry:    telemetry.New("it-m11s2", "0", "0"),
		Version:      "it",
		Commit:       "it",
		Identity:     identitySvc,
		Tenancy:      tenancySvc,
		Alerts:       svc,
		Notify:       notifySvc,
		NotifyEngine: engine,
	})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	jar, err := cookiejar.New(nil)
	must(t, err)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	res := doRequest(t, client, http.MethodPost, srv.URL+"/v1/auth/login", loginBody(slug, "it-password"), nil)
	if res.Status != http.StatusOK {
		t.Fatalf("login: status %d body %v", res.Status, res.Body)
	}
	csrf := cookieByName(res, "argus_csrf")
	if csrf == nil {
		t.Fatal("login did not set argus_csrf")
	}
	base := &m11Env{
		srv: srv, client: client, slug: slug,
		orgID: seed.OrgID, siteID: seed.SiteID, userID: seed.UserID, csrf: csrf.Value,
		svc: svc, eval: eval, clock: clock,
	}
	return &m11s2Env{
		m11Env: base, notifySvc: notifySvc, engine: engine, vault: vault,
		recorder: recorder, logs: logs,
	}
}

// scriptedTransport is a deterministic notify.Transport for retry/breaker
// tests: outcomes are consumed in order; once exhausted sends succeed.
type scriptedTransport struct {
	mu       sync.Mutex
	outcomes []sendOutcome
	sends    int
	messages []notify.Message
}

type sendOutcome struct {
	code    int
	excerpt string
	err     error
}

func (s *scriptedTransport) Send(_ context.Context, _ notify.Channel, _ []byte, msg notify.Message) (int, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sends++
	s.messages = append(s.messages, msg)
	if len(s.outcomes) == 0 {
		return http.StatusOK, "ok", nil
	}
	out := s.outcomes[0]
	s.outcomes = s.outcomes[1:]
	return out.code, out.excerpt, out.err
}

func (s *scriptedTransport) sendCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sends
}

func failingOutcome() sendOutcome {
	return sendOutcome{code: http.StatusServiceUnavailable, excerpt: "boom", err: errScriptedFailure}
}

var errScriptedFailure = errors.New("scripted provider failure")

// m11s2FakeEngine builds an engine with the given transport override and
// installs it as the recorder's downstream (the alerts sinks stay untouched).
func (e *m11s2Env) installEngine(t *testing.T, transports map[string]notify.Transport) *notify.Engine {
	t.Helper()
	engine := notify.NewEngine(appPool, e.vault, notify.EngineOptions{
		Now:        e.clock.Now,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		BaseURL:    "https://argus.example",
		Transports: transports,
		Auth:       authPool,
	})
	e.recorder.setEngine(engine)
	return engine
}

// createWebhookChannel creates a webhook channel through the API and returns
// its id.
func (e *m11s2Env) createWebhookChannel(t *testing.T, name, url, signingSecret string) string {
	t.Helper()
	body := map[string]any{
		"kind":   notify.KindWebhook,
		"name":   name,
		"config": map[string]any{"url": url, "payload": notify.PayloadSummary},
		"secret": map[string]any{"signing_secret": signingSecret},
	}
	res := e.do(t, http.MethodPost, "/v1/notification/channels", m11JSON(t, body))
	if res.Status != http.StatusCreated {
		t.Fatalf("create webhook channel: %d %v", res.Status, res.Body)
	}
	id, _ := res.Body["id"].(string)
	if id == "" {
		t.Fatalf("created channel without id: %v", res.Body)
	}
	return id
}

// createRoute creates a route through the API and returns its id.
func (e *m11s2Env) createRoute(t *testing.T, name, match string, channelIDs ...string) string {
	t.Helper()
	body := map[string]any{
		"name":        name,
		"match":       json.RawMessage(match),
		"channel_ids": channelIDs,
	}
	res := e.do(t, http.MethodPost, "/v1/notification/routes", m11JSON(t, body))
	if res.Status != http.StatusCreated {
		t.Fatalf("create route: %d %v", res.Status, res.Body)
	}
	id, _ := res.Body["id"].(string)
	if id == "" {
		t.Fatalf("created route without id: %v", res.Body)
	}
	return id
}

// deliveries lists the delivery log with the given raw query string.
func (e *m11s2Env) deliveries(t *testing.T, query string) []map[string]any {
	t.Helper()
	path := "/v1/notification/deliveries"
	if query != "" {
		path += "?" + query
	}
	res := e.do(t, http.MethodGet, path, "")
	if res.Status != http.StatusOK {
		t.Fatalf("list deliveries: %d %v", res.Status, res.Body)
	}
	return dataList(t, res.Body)
}

// processDue runs one deterministic worker pass at `at`.
func (e *m11s2Env) processDue(t *testing.T, engine *notify.Engine, at time.Time) int {
	t.Helper()
	n, err := engine.ProcessDue(context.Background(), e.org(), at.UTC(), 100)
	must(t, err)
	return n
}

// ownerDelivery loads one delivery row through the owner role (test
// assertions only) for one alert on the channel.
func ownerDelivery(t *testing.T, orgID, channelID, alertID uuid.UUID) map[string]any {
	t.Helper()
	rows, err := ownerPool.Query(context.Background(), `
		SELECT id, status, attempts, next_attempt_at, response_code, response_excerpt,
		       dedup_key, subject, body, delivered_at
		FROM notification_deliveries
		WHERE org_id = $1 AND channel_id = $2 AND alert_id = $3
		ORDER BY created_at DESC, id DESC`, orgID, channelID, alertID)
	must(t, err)
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var (
			id          uuid.UUID
			status      string
			attempts    int
			nextAt      *time.Time
			code        *int
			excerpt     string
			dedupKey    string
			subject     string
			body        string
			deliveredAt *time.Time
		)
		must(t, rows.Scan(&id, &status, &attempts, &nextAt, &code, &excerpt,
			&dedupKey, &subject, &body, &deliveredAt))
		out = append(out, map[string]any{
			"id": id, "status": status, "attempts": attempts, "next_attempt_at": nextAt,
			"response_code": code, "response_excerpt": excerpt, "dedup_key": dedupKey,
			"subject": subject, "body": body, "delivered_at": deliveredAt,
		})
	}
	must(t, rows.Err())
	if len(out) != 1 {
		t.Fatalf("delivery rows for alert %s on channel %s = %d, want 1", alertID, channelID, len(out))
	}
	return out[0]
}

// ownerAllDeliveries returns every delivery row of a channel, oldest first.
func ownerAllDeliveries(t *testing.T, orgID, channelID uuid.UUID) []map[string]any {
	t.Helper()
	rows, err := ownerPool.Query(context.Background(), `
		SELECT id, status, attempts, dedup_key, response_excerpt, response_code
		FROM notification_deliveries
		WHERE org_id = $1 AND channel_id = $2
		ORDER BY created_at, id`, orgID, channelID)
	must(t, err)
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var (
			id       uuid.UUID
			status   string
			attempts int
			dedup    string
			excerpt  string
			code     *int
		)
		must(t, rows.Scan(&id, &status, &attempts, &dedup, &excerpt, &code))
		out = append(out, map[string]any{
			"id": id, "status": status, "attempts": attempts,
			"dedup_key": dedup, "response_excerpt": excerpt, "response_code": code,
		})
	}
	must(t, rows.Err())
	return out
}
