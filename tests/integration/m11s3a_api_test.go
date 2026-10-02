package integration

// M11-S3a API, capability and scope contract: maintenance-window CRUD,
// silence create/list/delete (capability alert.silence, docs/12 §22.9),
// site-bound target enforcement with deterministic 403/404, viewer denial,
// cross-tenant isolation and RLS invariants for the two new tables.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/argus-platform/argus/internal/platform/database"
)

func TestM11S3aSuppressionAPIAndAuthz(t *testing.T) {
	env := newM11S3aEnv(t, "m11s3a-authz-"+newUUID()[:8])
	orgID := env.org()
	base := time.Now().UTC().Truncate(time.Second)

	// One firing alert in site A for the alert_id silence checks.
	dev, series := m11s3aDeviceAndSeries(t, orgID, env.site(), "authz-dev", "m11.s3a.authz")
	rule := env.m11CreateRule(t, "authz-rule", "threshold", "info",
		`{"agg":"max","op":"gt","value":5,"window":"30s","for_duration":"0s","recovery":{"for_duration":"0s"}}`,
		`{"metric_key":"m11.s3a.authz"}`)
	m11WriteSamples(t, orgID, series, []time.Time{base}, []float64{9})
	env.evaluate(t, base)
	fp := alertsFingerprint(t, env.m11Env, rule, dev, `{}`)
	open, ok := m11OpenAlert(t, orgID, fp)
	if !ok {
		t.Fatal("alert missing")
	}
	alertID := open["id"].(uuid.UUID).String()

	// --- Maintenance window CRUD round trip (org-wide admin) ---
	windowID := env.createWindow(t, "authz-window", `{"sites":["`+env.siteID+`"]}`, base.Add(-time.Hour), base.Add(time.Hour))
	res := env.do(t, http.MethodGet, "/v1/maintenance-windows/"+windowID, "")
	if res.Status != http.StatusOK || res.Body["name"] != "authz-window" {
		t.Fatalf("get window: %d %v", res.Status, res.Body)
	}
	if res.Body["active"] != true {
		t.Fatalf("window active = %v, want true", res.Body["active"])
	}
	res = env.do(t, http.MethodPatch, "/v1/maintenance-windows/"+windowID, m11JSON(t, map[string]any{"name": "renamed"}))
	if res.Status != http.StatusOK || res.Body["name"] != "renamed" {
		t.Fatalf("patch window: %d %v", res.Status, res.Body)
	}
	res = env.do(t, http.MethodGet, "/v1/maintenance-windows?limit=1", "")
	if res.Status != http.StatusOK || len(dataList(t, res.Body)) != 1 {
		t.Fatalf("list windows: %d %v", res.Status, res.Body)
	}
	res = env.do(t, http.MethodDelete, "/v1/maintenance-windows/"+windowID, "")
	if res.Status != http.StatusNoContent {
		t.Fatalf("delete window: %d %v", res.Status, res.Body)
	}
	res = env.do(t, http.MethodGet, "/v1/maintenance-windows/"+windowID, "")
	requireProblem(t, res, http.StatusNotFound, "maintenance_window.not_found")

	// --- Validation ---
	res = env.do(t, http.MethodPost, "/v1/maintenance-windows", m11JSON(t, map[string]any{
		"name": "bad", "starts_at": base.Format(time.RFC3339), "ends_at": base.Add(-time.Minute).Format(time.RFC3339),
	}))
	requireProblem(t, res, http.StatusBadRequest, "validation.failed")
	res = env.do(t, http.MethodPost, "/v1/maintenance-windows", m11JSON(t, map[string]any{
		"name": "bad", "bogus": true, "starts_at": base.Format(time.RFC3339), "ends_at": base.Add(time.Hour).Format(time.RFC3339),
	}))
	requireProblem(t, res, http.StatusBadRequest, "validation.failed")
	res = env.do(t, http.MethodPost, "/v1/maintenance-windows", m11JSON(t, map[string]any{
		"name": "bad", "scope": map[string]any{"metric_key": "x"},
		"starts_at": base.Format(time.RFC3339), "ends_at": base.Add(time.Hour).Format(time.RFC3339),
	}))
	requireProblem(t, res, http.StatusBadRequest, "validation.failed")

	// --- Silence create/list/delete + validation ---
	silenceID := env.createSilence(t, `{"alert_id":"`+alertID+`"}`, "ticket 42", time.Minute)
	res = env.do(t, http.MethodGet, "/v1/silences", "")
	if res.Status != http.StatusOK || len(dataList(t, res.Body)) != 1 {
		t.Fatalf("list silences: %d %v", res.Status, res.Body)
	}
	sil := dataList(t, res.Body)[0]
	if sil["reason"] != "ticket 42" || sil["active"] != true {
		t.Fatalf("silence payload = %v", sil)
	}
	res = env.do(t, http.MethodPost, "/v1/silences", m11JSON(t, map[string]any{"match": map[string]any{}, "reason": "x", "duration_seconds": 60}))
	requireProblem(t, res, http.StatusBadRequest, "validation.failed")
	res = env.do(t, http.MethodPost, "/v1/silences", m11JSON(t, map[string]any{
		"match": map[string]any{"alert_id": alertID}, "reason": "x", "duration_seconds": int((31 * 24 * time.Hour).Seconds()),
	}))
	requireProblem(t, res, http.StatusBadRequest, "validation.failed")
	// Fingerprint-only silences are allowed for org-wide callers.
	fpSilence := env.createSilence(t, `{"fingerprint":"`+fp+`"}`, "fingerprint silence", time.Minute)
	res = env.do(t, http.MethodDelete, "/v1/silences/"+fpSilence, "")
	if res.Status != http.StatusNoContent {
		t.Fatalf("delete fingerprint silence: %d %v", res.Status, res.Body)
	}

	// --- Viewer: alert.read only, never alert.silence ---
	m11AddUser(t, orgID, "viewer-"+env.slug+"@dev.local", "viewer")
	viewer, viewerCSRF := m11LoginClient(t, env.srv, env.slug, "viewer-"+env.slug+"@dev.local")
	res = doRequest(t, viewer, http.MethodGet, env.srv.URL+"/v1/maintenance-windows", "", nil)
	requireProblem(t, res, http.StatusForbidden, "auth.forbidden")
	res = doRequest(t, viewer, http.MethodPost, env.srv.URL+"/v1/silences", m11JSON(t, map[string]any{
		"match": map[string]any{"alert_id": alertID}, "reason": "x", "duration_seconds": 60,
	}), map[string]string{"X-CSRF-Token": viewerCSRF})
	requireProblem(t, res, http.StatusForbidden, "auth.forbidden")

	// --- Site-bound admin: only in-scope targets; org-wide scope denied ---
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

	outWindow := map[string]any{
		"name": "out", "scope": map[string]any{"sites": []string{env.siteID}},
		"starts_at": base.Format(time.RFC3339), "ends_at": base.Add(time.Hour).Format(time.RFC3339),
	}
	res = doRequest(t, bound, http.MethodPost, env.srv.URL+"/v1/maintenance-windows", m11JSON(t, outWindow),
		map[string]string{"X-CSRF-Token": boundCSRF})
	requireProblem(t, res, http.StatusForbidden, "auth.forbidden")

	orgWideWindow := map[string]any{
		"name": "wide", "starts_at": base.Format(time.RFC3339), "ends_at": base.Add(time.Hour).Format(time.RFC3339),
	}
	res = doRequest(t, bound, http.MethodPost, env.srv.URL+"/v1/maintenance-windows", m11JSON(t, orgWideWindow),
		map[string]string{"X-CSRF-Token": boundCSRF})
	requireProblem(t, res, http.StatusForbidden, "auth.forbidden")

	inWindow := map[string]any{
		"name": "in", "scope": map[string]any{"sites": []string{siteB.String()}},
		"starts_at": base.Format(time.RFC3339), "ends_at": base.Add(time.Hour).Format(time.RFC3339),
	}
	res = doRequest(t, bound, http.MethodPost, env.srv.URL+"/v1/maintenance-windows", m11JSON(t, inWindow),
		map[string]string{"X-CSRF-Token": boundCSRF})
	if res.Status != http.StatusCreated {
		t.Fatalf("in-scope window create: %d %v", res.Status, res.Body)
	}
	boundWindowID, _ := res.Body["id"].(string)

	// The org-wide window created earlier (none in this env after delete) is
	// invisible; only the bound site's window is listed.
	res = doRequest(t, bound, http.MethodGet, env.srv.URL+"/v1/maintenance-windows", "", nil)
	if res.Status != http.StatusOK || len(dataList(t, res.Body)) != 1 {
		t.Fatalf("bound window list: %d %v", res.Status, res.Body)
	}
	if dataList(t, res.Body)[0]["id"] != boundWindowID {
		t.Fatalf("bound list leaked an out-of-scope window: %v", res.Body)
	}

	// Silence targeting: out-of-scope alert id and fingerprint-only denied;
	// in-scope scope allowed.
	res = doRequest(t, bound, http.MethodPost, env.srv.URL+"/v1/silences", m11JSON(t, map[string]any{
		"match": map[string]any{"alert_id": alertID}, "reason": "x", "duration_seconds": 60,
	}), map[string]string{"X-CSRF-Token": boundCSRF})
	requireProblem(t, res, http.StatusForbidden, "auth.forbidden")
	res = doRequest(t, bound, http.MethodPost, env.srv.URL+"/v1/silences", m11JSON(t, map[string]any{
		"match": map[string]any{"fingerprint": fp}, "reason": "x", "duration_seconds": 60,
	}), map[string]string{"X-CSRF-Token": boundCSRF})
	requireProblem(t, res, http.StatusForbidden, "auth.forbidden")
	res = doRequest(t, bound, http.MethodPost, env.srv.URL+"/v1/silences", m11JSON(t, map[string]any{
		"match":  map[string]any{"scope": map[string]any{"sites": []string{siteB.String()}}},
		"reason": "in-scope", "duration_seconds": 60,
	}), map[string]string{"X-CSRF-Token": boundCSRF})
	if res.Status != http.StatusCreated {
		t.Fatalf("in-scope silence create: %d %v", res.Status, res.Body)
	}

	// --- Cross-tenant isolation ---
	other := newM11S3aEnv(t, "m11s3a-authz-other-"+newUUID()[:8])
	res = doRequest(t, other.client, http.MethodGet, other.srv.URL+"/v1/maintenance-windows/"+boundWindowID, "", nil)
	requireProblem(t, res, http.StatusNotFound, "maintenance_window.not_found")
	res = doRequest(t, other.client, http.MethodDelete, other.srv.URL+"/v1/silences/"+silenceID, "",
		map[string]string{"X-CSRF-Token": other.csrf})
	requireProblem(t, res, http.StatusNotFound, "alert_silence.not_found")

	// --- RLS invariants on the two new tables ---
	otherOrg := other.org()
	ctx := context.Background()
	for _, table := range []string{"maintenance_windows", "silences"} {
		var unscoped int
		must(t, appPool.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&unscoped))
		if unscoped != 0 {
			t.Fatalf("unscoped read of %s returned %d rows (RLS default-deny broken)", table, unscoped)
		}
		var foreign int
		must(t, database.WithTenant(ctx, appPool, orgID, func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE org_id = $1`, otherOrg).Scan(&foreign)
		}))
		if foreign != 0 {
			t.Fatalf("tenant A sees %d foreign rows in %s", foreign, table)
		}
		inserts := map[string]string{
			"maintenance_windows": `INSERT INTO maintenance_windows (id, org_id, name, scope, starts_at, ends_at)
				VALUES ($1, $2, 'intruder', '{}'::jsonb, now(), now() + interval '1 hour')`,
			"silences": `INSERT INTO silences (id, org_id, match, reason, starts_at, ends_at)
				VALUES ($1, $2, '{"fingerprint":"` + fp + `"}'::jsonb, 'intruder', now(), now() + interval '1 hour')`,
		}
		err = database.WithTenant(ctx, appPool, orgID, func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, inserts[table], uuid.New(), otherOrg)
			return err
		})
		if got := pgErrCode(err); got != sqlstateInsufficientPrivilege {
			t.Fatalf("cross-tenant %s insert: want SQLSTATE %s, got %q (%v)", table, sqlstateInsufficientPrivilege, got, err)
		}
	}
}
