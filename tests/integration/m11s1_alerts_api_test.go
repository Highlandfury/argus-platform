package integration

// M11-S1 API acceptance: rule CRUD with immutable versioning + dry-run
// validation, the alerts list/detail surface, lifecycle ops (ack/snooze/
// resolve/comment) with snooze reactivation, and authz/scope/cross-tenant
// isolation on the real router.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/argus-platform/argus/internal/platform/database"
	"github.com/argus-platform/argus/internal/platform/security"
)

func m11JSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	must(t, err)
	return string(raw)
}

// m11AddUser inserts a user with a known password hash (owner role: fixtures
// only) and returns its id.
func m11AddUser(t *testing.T, orgID uuid.UUID, email, role string) uuid.UUID {
	t.Helper()
	hash, err := security.HashPassword("it-password")
	must(t, err)
	id, err := uuid.NewV7()
	must(t, err)
	_, err = ownerPool.Exec(context.Background(), `
		INSERT INTO users (id, org_id, email, password_hash, role) VALUES ($1, $2, $3, $4, $5)`,
		id, orgID, email, hash, role)
	must(t, err)
	return id
}

// m11LoginClient logs in an existing user and returns the cookie client plus
// the CSRF token.
func m11LoginClient(t *testing.T, srv *httptest.Server, slug, email string) (*http.Client, string) {
	t.Helper()
	jar := newCookieJar(t)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	body := m11JSON(t, map[string]string{"org_slug": slug, "email": email, "password": "it-password"})
	res := doRequest(t, client, http.MethodPost, srv.URL+"/v1/auth/login", body, nil)
	if res.Status != http.StatusOK {
		t.Fatalf("login %s: status %d body %v", email, res.Status, res.Body)
	}
	csrf := cookieByName(res, "argus_csrf")
	if csrf == nil {
		t.Fatalf("login %s did not set argus_csrf", email)
	}
	return client, csrf.Value
}

// TestM11S1RuleAPICRUDVersioningAndValidate covers the full rule lifecycle
// through the router: create v1, dry-run validation, immutable PATCH v2,
// pinned version reads, DELETE-as-disable v3, and deterministic problems.
func TestM11S1RuleAPICRUDVersioningAndValidate(t *testing.T) {
	env := newM11Env(t, "m11-api-"+newUUID()[:8])

	// Empty list.
	res := env.do(t, http.MethodGet, "/v1/alert-rules", "")
	if res.Status != http.StatusOK || len(dataList(t, res.Body)) != 0 {
		t.Fatalf("empty rule list: %d %v", res.Status, res.Body)
	}

	// Validation problem with field errors.
	res = env.do(t, http.MethodPost, "/v1/alert-rules", `{}`)
	requireProblem(t, res, http.StatusBadRequest, "validation.failed")
	if errs, ok := res.Body["errors"].([]any); !ok || len(errs) == 0 {
		t.Fatalf("validation problem lacks errors[]: %v", res.Body)
	}
	// Unknown body field is rejected.
	res = env.do(t, http.MethodPost, "/v1/alert-rules",
		`{"name":"x","type":"threshold","severity":"info","condition":{},"scope_selector":{},"bogus":1}`)
	requireProblem(t, res, http.StatusBadRequest, "validation.failed")

	create := map[string]any{
		"name":     "WAN loss",
		"type":     "threshold",
		"severity": "critical",
		"condition": map[string]any{
			"agg": "avg", "op": "gt", "value": 5, "window": "1m", "for_duration": "3m",
		},
		"scope_selector": map[string]any{"metric_key": "net.icmp.loss_pct"},
	}
	res = env.do(t, http.MethodPost, "/v1/alert-rules", m11JSON(t, create))
	if res.Status != http.StatusCreated {
		t.Fatalf("create rule: status %d body %v", res.Status, res.Body)
	}
	ruleID, _ := res.Body["rule_id"].(string)
	if ruleID == "" || res.Body["version"] != float64(1) || res.Body["enabled"] != true {
		t.Fatalf("created rule payload = %v", res.Body)
	}

	// Dry-run validation: valid and invalid shapes both answer 200.
	res = env.do(t, http.MethodPost, "/v1/alert-rules:validate", m11JSON(t, create))
	if res.Status != http.StatusOK || res.Body["valid"] != true {
		t.Fatalf("validate valid: %d %v", res.Status, res.Body)
	}
	bad := map[string]any{"name": "bad", "type": "threshold", "severity": "info",
		"condition": map[string]any{"op": "around", "value": 1, "window": "1m"}, "scope_selector": map[string]any{"metric_key": "m"}}
	res = env.do(t, http.MethodPost, "/v1/alert-rules:validate", m11JSON(t, bad))
	if res.Status != http.StatusOK || res.Body["valid"] != false {
		t.Fatalf("validate invalid: %d %v", res.Status, res.Body)
	}
	if errs, ok := res.Body["errors"].([]any); !ok || len(errs) == 0 {
		t.Fatalf("invalid validate lacks errors: %v", res.Body)
	}

	// PATCH writes version 2; version 1 stays readable.
	res = env.do(t, http.MethodPatch, "/v1/alert-rules/"+ruleID,
		`{"name":"WAN loss (tightened)","condition":{"agg":"avg","op":"gt","value":3,"window":"1m","for_duration":"3m"}}`)
	if res.Status != http.StatusOK || res.Body["version"] != float64(2) || res.Body["name"] != "WAN loss (tightened)" {
		t.Fatalf("patch rule: %d %v", res.Status, res.Body)
	}
	if cond, ok := res.Body["condition"].(map[string]any); !ok || cond["value"] != float64(3) {
		t.Fatalf("patched condition = %v", res.Body["condition"])
	}
	res = env.do(t, http.MethodGet, "/v1/alert-rules/"+ruleID+"?version=1", "")
	if res.Status != http.StatusOK || res.Body["version"] != float64(1) || res.Body["name"] != "WAN loss" {
		t.Fatalf("pinned version 1: %d %v", res.Status, res.Body)
	}
	res = env.do(t, http.MethodGet, "/v1/alert-rules/"+ruleID, "")
	if res.Status != http.StatusOK || res.Body["version"] != float64(2) {
		t.Fatalf("latest version: %d %v", res.Status, res.Body)
	}

	// DELETE disables: version 3 with enabled=false, history preserved.
	res = env.do(t, http.MethodDelete, "/v1/alert-rules/"+ruleID, "")
	if res.Status != http.StatusOK || res.Body["version"] != float64(3) || res.Body["enabled"] != false {
		t.Fatalf("delete/disable: %d %v", res.Status, res.Body)
	}

	// Unknown rule and pinned unknown version are 404s.
	res = env.do(t, http.MethodGet, "/v1/alert-rules/"+newUUID(), "")
	requireProblem(t, res, http.StatusNotFound, "alert_rule.not_found")
	res = env.do(t, http.MethodGet, "/v1/alert-rules/"+ruleID+"?version=99", "")
	requireProblem(t, res, http.StatusNotFound, "alert_rule.not_found")

	// Unauthenticated + missing CSRF are rejected before the handler.
	fresh := newCookieJar(t)
	anon := &http.Client{Jar: fresh, Timeout: 10 * time.Second}
	res = doRequest(t, anon, http.MethodGet, env.srv.URL+"/v1/alert-rules", "", nil)
	requireProblem(t, res, http.StatusUnauthorized, "auth.unauthenticated")
	res = doRequest(t, env.client, http.MethodPost, env.srv.URL+"/v1/alert-rules", `{}`, nil)
	requireProblem(t, res, http.StatusForbidden, "auth.csrf")

	// Cross-tenant isolation: another org cannot see the rule.
	other := newM11Env(t, "m11-api-other-"+newUUID()[:8])
	res = doRequest(t, other.client, http.MethodGet, other.srv.URL+"/v1/alert-rules/"+ruleID, "", nil)
	requireProblem(t, res, http.StatusNotFound, "alert_rule.not_found")
}

// TestM11S1LifecycleAPIAndSnoozeReactivation drives a real evaluated alert
// through ack/comment/snooze/resolve and proves the snooze reactivation rule.
func TestM11S1LifecycleAPIAndSnoozeReactivation(t *testing.T) {
	env := newM11Env(t, "m11-life-"+newUUID()[:8])
	orgID := env.org()
	base := time.Now().UTC().Truncate(time.Second)

	dev := m11Device(t, orgID, env.site(), "m11-life", "switch")
	series := m11Series(t, orgID, dev, "m11.life", nil, "count")
	m11ConstantSamples(t, orgID, series, base.Add(2*time.Minute), 10*time.Second, 25, 9)

	rule := env.m11CreateRule(t, "life", "threshold", "critical",
		`{"agg":"avg","op":"gt","value":5,"window":"30s","for_duration":"0s"}`,
		`{"metric_key":"m11.life"}`)
	env.evaluate(t, base)

	res := env.do(t, http.MethodGet, "/v1/alerts?filter[state]=active&filter[severity]=critical&filter[rule_id]="+rule.RuleID.String(), "")
	if res.Status != http.StatusOK {
		t.Fatalf("list alerts: %d %v", res.Status, res.Body)
	}
	items := dataList(t, res.Body)
	if len(items) != 1 {
		t.Fatalf("active alerts = %d, want 1 (%v)", len(items), res.Body)
	}
	alertID, _ := items[0]["id"].(string)
	if alertID == "" || items[0]["fingerprint"] == "" {
		t.Fatalf("alert payload = %v", items[0])
	}

	res = env.do(t, http.MethodGet, "/v1/alerts/"+alertID, "")
	if res.Status != http.StatusOK {
		t.Fatalf("alert detail: %d %v", res.Status, res.Body)
	}
	if events, ok := res.Body["events"].([]any); !ok || len(events) == 0 {
		t.Fatalf("detail has no events: %v", res.Body)
	}

	// Ack.
	res = env.do(t, http.MethodPost, "/v1/alerts/"+alertID+"/ack", "")
	if res.Status != http.StatusOK || res.Body["state"] != "acknowledged" {
		t.Fatalf("ack: %d %v", res.Status, res.Body)
	}
	res = env.do(t, http.MethodPost, "/v1/alerts/"+alertID+"/comment", `{"comment":"investigating"}`)
	if res.Status != http.StatusOK {
		t.Fatalf("comment: %d %v", res.Status, res.Body)
	}

	// Snooze for 60s; evaluation continues while snoozed.
	res = env.do(t, http.MethodPost, "/v1/alerts/"+alertID+"/snooze", `{"duration_seconds":60,"reason":"window"}`)
	if res.Status != http.StatusOK || res.Body["state"] != "snoozed" || res.Body["snooze_until"] == nil {
		t.Fatalf("snooze: %d %v", res.Status, res.Body)
	}
	env.evaluate(t, base.Add(30*time.Second))
	res = env.do(t, http.MethodGet, "/v1/alerts/"+alertID, "")
	if res.Body["state"] != "snoozed" {
		t.Fatalf("snoozed alert left snooze early: %v", res.Body["state"])
	}
	if res.Body["last_evaluated_at"] == nil {
		t.Fatalf("snoozed alert stopped evaluating: %v", res.Body)
	}

	// After expiry with the condition still true -> reactivated.
	env.evaluate(t, base.Add(61*time.Second))
	res = env.do(t, http.MethodGet, "/v1/alerts/"+alertID, "")
	if res.Body["state"] != "active" {
		t.Fatalf("snooze expiry state = %v, want active (reactivated)", res.Body["state"])
	}
	if !m11Contains(m11EventKinds(t, orgID, uuid.MustParse(alertID)), "reactivated") {
		t.Fatalf("timeline missing reactivated: %v", m11EventKinds(t, orgID, uuid.MustParse(alertID)))
	}

	// Resolve requires a reason.
	res = env.do(t, http.MethodPost, "/v1/alerts/"+alertID+"/resolve", `{}`)
	requireProblem(t, res, http.StatusBadRequest, "validation.failed")
	res = env.do(t, http.MethodPost, "/v1/alerts/"+alertID+"/resolve", `{"reason":"operator resolved"}`)
	if res.Status != http.StatusOK || res.Body["state"] != "resolved" {
		t.Fatalf("resolve: %d %v", res.Status, res.Body)
	}
	if !m11Contains(m11EventKinds(t, orgID, uuid.MustParse(alertID)), "manual_resolved") {
		t.Fatal("timeline missing manual_resolved")
	}

	// State conflicts and not-found are deterministic.
	res = env.do(t, http.MethodPost, "/v1/alerts/"+alertID+"/ack", "")
	requireProblem(t, res, http.StatusConflict, "alert.state_conflict")
	res = env.do(t, http.MethodPost, "/v1/alerts/"+newUUID()+"/ack", "")
	requireProblem(t, res, http.StatusNotFound, "alert.not_found")
	res = env.do(t, http.MethodPost, "/v1/alerts/"+alertID+"/snooze", `{"duration_seconds":0}`)
	requireProblem(t, res, http.StatusBadRequest, "validation.failed")
	res = env.do(t, http.MethodGet, "/v1/alerts?filter[state]=bogus", "")
	requireProblem(t, res, http.StatusBadRequest, "validation.failed")
}

// TestM11S1AuthzScopeAndCrossTenantIsolation covers the capability matrix
// (viewer alert.read only), site-bound scope filtering with deterministic
// 403/404, rule-target scope enforcement, and tenant isolation.
func TestM11S1AuthzScopeAndCrossTenantIsolation(t *testing.T) {
	env := newM11Env(t, "m11-authz-"+newUUID()[:8])
	orgID := env.org()
	base := time.Now().UTC().Truncate(time.Second)

	dev := m11Device(t, orgID, env.site(), "m11-authz", "switch")
	series := m11Series(t, orgID, dev, "m11.authz", nil, "count")
	m11ConstantSamples(t, orgID, series, base, 10*time.Second, 6, 9)
	rule := env.m11CreateRule(t, "authz", "threshold", "warning",
		`{"agg":"max","op":"gt","value":5,"window":"30s","for_duration":"0s"}`,
		`{"metric_key":"m11.authz"}`)
	env.evaluate(t, base)
	rows := m11CountAlerts(t, orgID, rule.RuleID)
	if len(rows) != 1 {
		t.Fatalf("alert rows = %d, want 1", len(rows))
	}
	alertID := rows[0]["id"].(uuid.UUID).String()

	// Viewer: alert.read yes; alert lifecycle and rules no.
	viewerID := m11AddUser(t, orgID, "viewer-"+env.slug+"@dev.local", "viewer")
	_ = viewerID
	viewer, viewerCSRF := m11LoginClient(t, env.srv, env.slug, "viewer-"+env.slug+"@dev.local")
	res := doRequest(t, viewer, http.MethodGet, env.srv.URL+"/v1/alerts", "", nil)
	if res.Status != http.StatusOK {
		t.Fatalf("viewer alert list: %d %v", res.Status, res.Body)
	}
	res = doRequest(t, viewer, http.MethodGet, env.srv.URL+"/v1/alert-rules", "", nil)
	requireProblem(t, res, http.StatusForbidden, "auth.forbidden")
	res = doRequest(t, viewer, http.MethodPost, env.srv.URL+"/v1/alerts/"+alertID+"/ack", "",
		map[string]string{"X-CSRF-Token": viewerCSRF})
	requireProblem(t, res, http.StatusForbidden, "auth.forbidden")
	res = doRequest(t, viewer, http.MethodPost, env.srv.URL+"/v1/alert-rules", `{}`,
		map[string]string{"X-CSRF-Token": viewerCSRF})
	requireProblem(t, res, http.StatusForbidden, "auth.forbidden")

	// Site-bound user: sees nothing of site A, cannot target it.
	siteB, err := uuid.NewV7()
	must(t, err)
	_, err = ownerPool.Exec(context.Background(), `
		INSERT INTO sites (id, org_id, name) VALUES ($1, $2, 'HQ-B')`, siteB, orgID)
	must(t, err)
	boundID := m11AddUser(t, orgID, "bound-"+env.slug+"@dev.local", "admin")
	bindID, err := uuid.NewV7()
	must(t, err)
	_, err = ownerPool.Exec(context.Background(), `
		INSERT INTO user_scope_bindings (id, org_id, user_id, scope_type, scope_id)
		VALUES ($1, $2, $3, 'site', $4)`, bindID, orgID, boundID, siteB)
	must(t, err)
	bound, boundCSRF := m11LoginClient(t, env.srv, env.slug, "bound-"+env.slug+"@dev.local")

	res = doRequest(t, bound, http.MethodGet, env.srv.URL+"/v1/alerts", "", nil)
	if res.Status != http.StatusOK || len(dataList(t, res.Body)) != 0 {
		t.Fatalf("bound alert list: %d %v (site A alert must be invisible)", res.Status, res.Body)
	}
	res = doRequest(t, bound, http.MethodGet, env.srv.URL+"/v1/alerts/"+alertID, "", nil)
	requireProblem(t, res, http.StatusNotFound, "alert.not_found")
	res = doRequest(t, bound, http.MethodGet, env.srv.URL+"/v1/alerts?filter[device_id]="+dev.String(), "", nil)
	requireProblem(t, res, http.StatusForbidden, "auth.forbidden")

	// Rule targeting: out-of-scope site denied; in-scope site allowed; an
	// org-wide selector requires org-wide scope.
	outRule := map[string]any{
		"name": "out", "type": "threshold", "severity": "info",
		"condition":      map[string]any{"op": "gt", "value": 1, "window": "1m"},
		"scope_selector": map[string]any{"metric_key": "m11.authz", "sites": []string{env.siteID}},
	}
	res = doRequest(t, bound, http.MethodPost, env.srv.URL+"/v1/alert-rules", m11JSON(t, outRule),
		map[string]string{"X-CSRF-Token": boundCSRF})
	requireProblem(t, res, http.StatusForbidden, "auth.forbidden")

	inRule := map[string]any{
		"name": "in", "type": "threshold", "severity": "info",
		"condition":      map[string]any{"op": "gt", "value": 1, "window": "1m"},
		"scope_selector": map[string]any{"metric_key": "m11.authz", "sites": []string{siteB.String()}},
	}
	res = doRequest(t, bound, http.MethodPost, env.srv.URL+"/v1/alert-rules", m11JSON(t, inRule),
		map[string]string{"X-CSRF-Token": boundCSRF})
	if res.Status != http.StatusCreated {
		t.Fatalf("in-scope rule create: %d %v", res.Status, res.Body)
	}

	orgWide := map[string]any{
		"name": "wide", "type": "threshold", "severity": "info",
		"condition":      map[string]any{"op": "gt", "value": 1, "window": "1m"},
		"scope_selector": map[string]any{"metric_key": "m11.authz"},
	}
	res = doRequest(t, bound, http.MethodPost, env.srv.URL+"/v1/alert-rules", m11JSON(t, orgWide),
		map[string]string{"X-CSRF-Token": boundCSRF})
	requireProblem(t, res, http.StatusForbidden, "auth.forbidden")

	// Cross-tenant: the other org cannot read the rule or the alert.
	other := newM11Env(t, "m11-authz-other-"+newUUID()[:8])
	res = doRequest(t, other.client, http.MethodGet, other.srv.URL+"/v1/alert-rules/"+rule.RuleID.String(), "", nil)
	requireProblem(t, res, http.StatusNotFound, "alert_rule.not_found")
	res = doRequest(t, other.client, http.MethodGet, other.srv.URL+"/v1/alerts/"+alertID, "", nil)
	requireProblem(t, res, http.StatusNotFound, "alert.not_found")

	// RLS probes on the three M11 tables: tenant A transactions see zero of
	// tenant B's rows (RLS only, no application filter), and an unscoped app
	// connection sees nothing (default-deny).
	otherOrg := other.org()
	ctx := context.Background()
	for _, table := range []string{"alert_rules", "alerts", "alert_events"} {
		var foreign int
		must(t, database.WithTenant(ctx, appPool, orgID, func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE org_id = $1`, otherOrg).Scan(&foreign)
		}))
		if foreign != 0 {
			t.Fatalf("tenant A sees %d foreign rows in %s", foreign, table)
		}
		var unscoped int
		must(t, appPool.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&unscoped))
		if unscoped != 0 {
			t.Fatalf("unscoped read of %s returned %d rows (RLS default-deny broken)", table, unscoped)
		}
	}
	// Cross-tenant INSERT is refused by WITH CHECK.
	err = database.WithTenant(ctx, appPool, orgID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO alert_rules (org_id, rule_id, version, name, type, severity, condition, scope_selector)
			VALUES ($1, $2, 1, 'intruder', 'threshold', 'info', '{}'::jsonb, '{}'::jsonb)`, otherOrg, uuid.New())
		return err
	})
	if got := pgErrCode(err); got != sqlstateInsufficientPrivilege {
		t.Fatalf("cross-tenant alert_rules insert: want SQLSTATE %s, got %q (%v)", sqlstateInsufficientPrivilege, got, err)
	}
}
