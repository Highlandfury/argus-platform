package integration

// Shared fixtures for the M11-S1 alert-engine suites: a logged-in tenant with
// the real alerts service/evaluator wired, deterministic clocks, and
// device/series/sample/poll-health seeding through the RLS-enforced app pool.

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/argus-platform/argus/internal/api"
	"github.com/argus-platform/argus/internal/modules/alerts"
	"github.com/argus-platform/argus/internal/modules/identity"
	"github.com/argus-platform/argus/internal/modules/metrics"
	"github.com/argus-platform/argus/internal/modules/tenancy"
	"github.com/argus-platform/argus/internal/platform/authz"
	"github.com/argus-platform/argus/internal/platform/database"
	"github.com/argus-platform/argus/internal/platform/telemetry"
)

// m11Clock is a race-free injectable clock shared by the service and
// evaluator (tests advance it explicitly; nothing sleeps).
type m11Clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *m11Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now.UTC()
}

func (c *m11Clock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t.UTC()
}

// m11Env is one logged-in tenant with the alerts API + evaluator wired.
type m11Env struct {
	srv    *httptest.Server
	client *http.Client
	slug   string
	orgID  string
	siteID string
	userID string
	csrf   string
	svc    *alerts.Service
	eval   *alerts.Evaluator
	clock  *m11Clock
}

func newM11Env(t *testing.T, slug string) *m11Env {
	t.Helper()
	seed := seedLoginUser(t, slug, "HQ-"+slug)

	svc := alerts.New(appPool, authz.New(appPool))
	clock := &m11Clock{now: time.Now().UTC().Truncate(time.Second)}
	svc.Now = clock.Now
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	eval := alerts.NewEvaluator(appPool, alerts.EvaluatorOptions{Now: clock.Now, Logger: logger})

	tenancySvc := tenancy.New(appPool, authPool)
	identitySvc, err := identity.New(appPool, authPool, tenancySvc)
	must(t, err)
	router := api.NewRouter(api.Options{
		Logger:    logger,
		Telemetry: telemetry.New("it-m11", "0", "0"),
		Version:   "it",
		Commit:    "it",
		Identity:  identitySvc,
		Tenancy:   tenancySvc,
		Alerts:    svc,
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
	return &m11Env{
		srv: srv, client: client, slug: slug,
		orgID: seed.OrgID, siteID: seed.SiteID, userID: seed.UserID, csrf: csrf.Value,
		svc: svc, eval: eval, clock: clock,
	}
}

func (e *m11Env) org() uuid.UUID  { return uuid.MustParse(e.orgID) }
func (e *m11Env) site() uuid.UUID { return uuid.MustParse(e.siteID) }

// do performs an authenticated request carrying the session CSRF token.
func (e *m11Env) do(t *testing.T, method, path, body string) apiResponse {
	t.Helper()
	return doRequest(t, e.client, method, e.srv.URL+path, body, map[string]string{"X-CSRF-Token": e.csrf})
}

// evaluate runs one deterministic EvaluateOnce at `at` and returns the
// summary. The injected clock follows so lifecycle calls see the same instant.
func (e *m11Env) evaluate(t *testing.T, at time.Time) alerts.Summary {
	t.Helper()
	e.clock.Set(at)
	sum, err := e.eval.EvaluateOnce(context.Background(), e.org(), at.UTC())
	must(t, err)
	return sum
}

// m11Actor is the seeded admin.
func (e *m11Env) actor() alerts.Actor {
	return alerts.Actor{UserID: uuid.MustParse(e.userID)}
}

// m11CreateRule creates a rule through the service (unrestricted admin).
func (e *m11Env) m11CreateRule(t *testing.T, name, ruleType, severity, condition, selector string) alerts.Rule {
	t.Helper()
	rule, err := e.svc.CreateRule(context.Background(), e.org(), e.actor(), alerts.RuleCreateInput{
		Name: name, Type: ruleType, Severity: severity,
		ConditionJSON: []byte(condition), SelectorJSON: []byte(selector),
	}, authz.Scope{Unrestricted: true})
	must(t, err)
	return rule
}

// m11Device creates a live device through the app pool (RLS path).
func m11Device(t *testing.T, orgID, siteID uuid.UUID, name, kind string) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	must(t, err)
	must(t, database.WithTenant(context.Background(), appPool, orgID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO devices (id, org_id, site_id, name, kind) VALUES ($1, $2, $3, $4, $5)`,
			id, orgID, siteID, name, kind)
		return err
	}))
	return id
}

func m11Collector(t *testing.T, orgID, siteID uuid.UUID, name string) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	must(t, err)
	must(t, database.WithTenant(context.Background(), appPool, orgID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO collectors (id, org_id, site_id, name, status) VALUES ($1, $2, $3, $4, 'active')`,
			id, orgID, siteID, name)
		return err
	}))
	return id
}

// m11Series creates one device metric series and returns its id.
func m11Series(t *testing.T, orgID, deviceID uuid.UUID, metricKey string, dims map[string]string, unit string) int64 {
	t.Helper()
	canonical, dimHash, err := metrics.CanonicalizeDimensions(dims)
	must(t, err)
	var id int64
	must(t, database.WithTenant(context.Background(), appPool, orgID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO metric_series (org_id, device_id, metric_key, dimensions, dim_hash, unit)
			VALUES ($1, $2, $3, $4::jsonb, $5, $6)
			RETURNING id`,
			orgID, deviceID, metricKey, string(canonical), dimHash, unit).Scan(&id)
	}))
	return id
}

// m11WriteSamples inserts raw samples through the app pool.
func m11WriteSamples(t *testing.T, orgID uuid.UUID, seriesID int64, ts []time.Time, values []float64) {
	t.Helper()
	if len(ts) != len(values) {
		t.Fatalf("m11WriteSamples: %d timestamps vs %d values", len(ts), len(values))
	}
	if len(ts) == 0 {
		return
	}
	must(t, database.WithTenant(context.Background(), appPool, orgID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO metric_samples (org_id, series_id, ts, value)
			SELECT $1, $2, t, v FROM unnest($3::timestamptz[], $4::float8[]) AS x(t, v)`,
			orgID, seriesID, ts, values)
		return err
	}))
}

// m11ConstantSamples writes n samples spaced by step ending at `end` (inclusive).
func m11ConstantSamples(t *testing.T, orgID uuid.UUID, seriesID int64, end time.Time, step time.Duration, n int, value float64) {
	t.Helper()
	ts := make([]time.Time, 0, n)
	vals := make([]float64, 0, n)
	for i := n - 1; i >= 0; i-- {
		ts = append(ts, end.Add(-time.Duration(i)*step))
		vals = append(vals, value)
	}
	m11WriteSamples(t, orgID, seriesID, ts, vals)
}

// m11PollHealth inserts one scheduled poll-health row.
func m11PollHealth(t *testing.T, orgID, collectorID, deviceID uuid.UUID, at time.Time, outcome string, consecutive int) {
	t.Helper()
	id, err := uuid.NewV7()
	must(t, err)
	must(t, database.WithTenant(context.Background(), appPool, orgID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO poll_health (id, org_id, collector_id, device_id, ts, poll_type, latency_ms, outcome, error_class, consecutive_failures, origin)
			VALUES ($1, $2, $3, $4, $5, 'icmp', 1, $6, '', $7, 'scheduled')`,
			id, orgID, collectorID, deviceID, at, outcome, consecutive)
		return err
	}))
}

// m11OpenAlert loads the fingerprint's open alert directly (owner role; test
// assertions only).
func m11OpenAlert(t *testing.T, orgID uuid.UUID, fingerprint string) (map[string]any, bool) {
	t.Helper()
	ctx := context.Background()
	var (
		id      uuid.UUID
		state   string
		value   []byte
		ruleID  uuid.UUID
		version int
	)
	err := ownerPool.QueryRow(ctx, `
		SELECT id, state, value, rule_id, rule_version FROM alerts
		WHERE org_id = $1 AND fingerprint = $2 AND state <> 'resolved'
		ORDER BY created_at DESC LIMIT 1`, orgID, fingerprint).Scan(&id, &state, &value, &ruleID, &version)
	if err != nil {
		return nil, false
	}
	return map[string]any{"id": id, "state": state, "value": value, "rule_id": ruleID, "rule_version": version}, true
}

func m11CountAlerts(t *testing.T, orgID uuid.UUID, ruleID uuid.UUID) []map[string]any {
	t.Helper()
	rows, err := ownerPool.Query(context.Background(), `
		SELECT id, state, suppression_reason, fingerprint FROM alerts
		WHERE org_id = $1 AND rule_id = $2 ORDER BY created_at, id`, orgID, ruleID)
	must(t, err)
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var (
			id     uuid.UUID
			fp     string
			state  string
			reason string
		)
		must(t, rows.Scan(&id, &state, &reason, &fp))
		out = append(out, map[string]any{"id": id, "state": state, "suppression_reason": reason, "fingerprint": fp})
	}
	must(t, rows.Err())
	return out
}

func m11EventKinds(t *testing.T, orgID, alertID uuid.UUID) []string {
	t.Helper()
	rows, err := ownerPool.Query(context.Background(), `
		SELECT kind FROM alert_events WHERE org_id = $1 AND alert_id = $2 ORDER BY ts, id`, orgID, alertID)
	must(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var kind string
		must(t, rows.Scan(&kind))
		out = append(out, kind)
	}
	must(t, rows.Err())
	return out
}

func m11Contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// alertsFingerprint builds the canonical fingerprint for a device target with
// the given canonical dimensions JSON.
func alertsFingerprint(t *testing.T, _ *m11Env, rule alerts.Rule, deviceID uuid.UUID, canonicalDims string) string {
	t.Helper()
	return alerts.Fingerprint(rule.RuleID, "device", deviceID, []byte(canonicalDims))
}

// m11Unrestricted is the admin's resolved scope (no bindings).
func m11Unrestricted() authz.Scope { return authz.Scope{Unrestricted: true} }

func newCookieJar(t *testing.T) http.CookieJar {
	t.Helper()
	jar, err := cookiejar.New(nil)
	must(t, err)
	return jar
}
