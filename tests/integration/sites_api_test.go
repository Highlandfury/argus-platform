package integration

// M7-S4a: the devices inventory UI needs a site picker, backed by the
// session-protected tenancy read GET /v1/sites (id + name for the caller's
// org). This file pins its authz/isolation semantics in the M7-S3 test style:
// 401 before session, org-wide RLS isolation, stable cursor pagination, and
// the deliberate difference that tenancy reads carry no inventory/credential
// capability+scope metadata; inventory scope bindings still deny out-of-scope
// device writes.

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestSitesListAuthzIsolation is the S-26 security-suite entry (registered in
// security_suite_test.go): the site picker must never leak another tenant's
// sites and must behave uniformly for every authenticated role.
func TestSitesListAuthzIsolation(t *testing.T) {
	env := newInventoryEnv(t, "sites-"+newUUID()[:8])
	second := createSite(t, env.orgID, "S2-"+env.slug)

	// Unauthenticated: 401 problem+json before any data is returned.
	anon := &http.Client{Timeout: 10 * time.Second}
	res := doRequest(t, anon, http.MethodGet, env.srv.URL+"/v1/sites", "", nil)
	requireProblem(t, res, http.StatusUnauthorized, "auth.unauthenticated")

	// Admin: the org's sites with exactly the id + name projection.
	res = env.do(t, http.MethodGet, "/v1/sites?limit=100", "")
	if res.Status != http.StatusOK {
		t.Fatalf("admin list: status %d body %v", res.Status, res.Body)
	}
	rows := dataList(t, res.Body)
	if len(rows) != 2 {
		t.Fatalf("admin list = %d sites, want 2: %v", len(rows), rows)
	}
	names := map[string]string{}
	for _, row := range rows {
		if len(row) != 2 {
			t.Fatalf("site payload keys = %v, want exactly id + name", row)
		}
		id, _ := row["id"].(string)
		name, _ := row["name"].(string)
		if id == "" || name == "" {
			t.Fatalf("site payload missing id/name: %v", row)
		}
		names[id] = name
	}
	if names[env.siteID] != "HQ-"+env.slug || names[second] != "S2-"+env.slug {
		t.Fatalf("admin site names = %v", names)
	}

	// Cursor pagination is stable and bounded (id-ordered).
	res = env.do(t, http.MethodGet, "/v1/sites?limit=1", "")
	if res.Status != http.StatusOK {
		t.Fatalf("page 1: status %d body %v", res.Status, res.Body)
	}
	page1 := dataList(t, res.Body)
	cursor, _ := res.Body["next_cursor"].(string)
	if len(page1) != 1 || cursor == "" {
		t.Fatalf("page 1 = %d rows cursor %q, want 1 row + cursor", len(page1), cursor)
	}
	res = env.do(t, http.MethodGet, "/v1/sites?limit=1&cursor="+cursor, "")
	page2 := dataList(t, res.Body)
	if res.Status != http.StatusOK || len(page2) != 1 || page2[0]["id"] == page1[0]["id"] {
		t.Fatalf("page 2: status %d rows %v", res.Status, page2)
	}
	if res.Body["next_cursor"] != nil && res.Body["next_cursor"] != "" {
		t.Fatalf("page 2 cursor = %v, want empty/null (2 sites total)", res.Body["next_cursor"])
	}

	// Input validation maps to problem+json.
	for _, path := range []string{"/v1/sites?limit=0", "/v1/sites?limit=101", "/v1/sites?cursor=not-a-uuid"} {
		res = env.do(t, http.MethodGet, path, "")
		requireProblem(t, res, http.StatusBadRequest, "validation.failed")
	}

	// Viewer: the tenancy read is session-gated only — every authenticated role
	// may resolve site names (no inventory capability vocabulary applies).
	_, viewerEmail := seedUserWithRole(t, env, "viewer")
	viewer, _ := loginAs(t, env, viewerEmail)
	res = doRequest(t, viewer, http.MethodGet, env.srv.URL+"/v1/sites?limit=100", "", nil)
	if res.Status != http.StatusOK || len(dataList(t, res.Body)) != 2 {
		t.Fatalf("viewer list: status %d body %v", res.Status, res.Body)
	}

	// Tenant isolation: org B sees its own site only; A's ids/names never leak.
	other := newInventoryEnv(t, "sites-other-"+newUUID()[:8])
	res = other.do(t, http.MethodGet, "/v1/sites?limit=100", "")
	if res.Status != http.StatusOK {
		t.Fatalf("other list: status %d body %v", res.Status, res.Body)
	}
	otherRows := dataList(t, res.Body)
	if len(otherRows) != 1 || otherRows[0]["id"] != other.siteID {
		t.Fatalf("other list = %v, want only %s", otherRows, other.siteID)
	}
	payload := toJSON(t, res.Body)
	for _, needle := range []string{env.siteID, "HQ-" + env.slug, second, "S2-" + env.slug} {
		if strings.Contains(payload, needle) {
			t.Fatalf("org B sees org A site data %q: %s", needle, payload)
		}
	}

	// Scope (P2-D5) currently governs inventory resources: a site-bound admin
	// can still resolve the org's site list (needed by the picker; limiting it
	// to bound sites is a tenancy-RBAC follow-up), but device writes to an
	// out-of-scope site are still denied 403.
	adminID, adminEmail := seedUserWithRole(t, env, "admin")
	bindScope(t, env.orgID, adminID, "site", env.siteID)
	scoped, scopedCSRF := loginAs(t, env, adminEmail)
	res = doRequest(t, scoped, http.MethodGet, env.srv.URL+"/v1/sites?limit=100", "", nil)
	if res.Status != http.StatusOK || len(dataList(t, res.Body)) != 2 {
		t.Fatalf("site-bound list: status %d body %v", res.Status, res.Body)
	}
	createBody := `{"site_id":"` + second + `","name":"scoped-foreign-` + newUUID()[:8] + `","kind":"switch"}`
	res = doRequest(t, scoped, http.MethodPost, env.srv.URL+"/v1/devices", createBody,
		map[string]string{"X-CSRF-Token": scopedCSRF})
	requireProblem(t, res, http.StatusForbidden, "auth.forbidden")
}
