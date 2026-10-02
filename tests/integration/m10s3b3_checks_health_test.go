package integration

// M10-S3b-3 (Phase 2): the operator checks / poll-health read surface —
// GET /v1/checks (org-wide cursor ledger, newest first by default) and
// GET /v1/poll-health (bounded recent feed). Covers filters, cursor
// paging/ordering, scope narrowing, the deterministic 403 on an explicit
// out-of-scope device filter (M7 list rule), cross-tenant invisibility,
// capability/authz, and the poll-health window bounds.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

// createDeviceAtSite posts a manual device into an explicit site (the
// inventoryEnv helper always targets the env's seeded site).
func createDeviceAtSite(t *testing.T, env *m10Env, siteID, name, mgmtIP string) uuid.UUID {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"site_id": siteID, "name": name, "kind": "switch", "mgmt_ip": mgmtIP,
	})
	must(t, err)
	res := env.api.do(t, http.MethodPost, "/v1/devices", string(raw))
	if res.Status != http.StatusCreated {
		t.Fatalf("create device %s: status %d body %v", name, res.Status, res.Body)
	}
	id, _ := res.Body["id"].(string)
	return mustUUID(t, id)
}

// insertDeviceCheck seeds one device_checks row with an explicit (UUIDv7
// shaped, ordered) id so ledger ordering assertions are deterministic.
func insertDeviceCheck(t *testing.T, id, orgID, deviceID uuid.UUID, pollType, status string, createdAt time.Time, completedAt *time.Time, outcome, class string, latency *int) {
	t.Helper()
	_, err := ownerPool.Exec(context.Background(), `
		INSERT INTO device_checks
			(id, org_id, device_id, collector_id, poll_type, status, requested_by, request_key, created_at, completed_at, outcome, error_class, latency_ms)
		VALUES ($1, $2, $3, NULL, $4, $5, NULL, $6, $7, $8, $9, $10, $11)`,
		id, orgID, deviceID, pollType, status, "req-"+id.String(), createdAt, completedAt, outcome, class, latency)
	must(t, err)
}

// insertHealthRow seeds one poll_health row with an explicit poll type and
// origin.
func insertHealthRow(t *testing.T, orgID, collectorID, deviceID uuid.UUID, ts time.Time, pollType, outcome, class string, latency, failures int, origin string) {
	t.Helper()
	_, err := ownerPool.Exec(context.Background(), `
		INSERT INTO poll_health
			(id, org_id, collector_id, device_id, ts, poll_type, latency_ms, outcome, error_class, consecutive_failures, origin)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		newUUID(), orgID, collectorID, deviceID, ts, pollType, latency, outcome, class, failures, origin)
	must(t, err)
}

func ptrInt(v int) *int { return &v }

// TestM10S3b3ChecksLedgerAPI pins GET /v1/checks: newest first by default
// (order=asc opt-in), cursor paging by check id, the status/poll_type/device
// filters, deterministic 403 for explicit out-of-scope device filters, scope
// narrowing, viewer read access and cross-tenant invisibility.
func TestM10S3b3ChecksLedgerAPI(t *testing.T) {
	env := newM10Env(t, "m10s3b3-checks-"+newUUID()[:8])
	ctx := context.Background()
	orgUUID := env.org()
	devA := mustUUID(t, env.api.createDevice(t, "s3b3-checks-a", map[string]any{"mgmt_ip": "192.0.2.201"}))
	siteB := createSite(t, env.api.orgID, "s3b3-site-b-"+newUUID()[:8])
	devB := createDeviceAtSite(t, env, siteB, "s3b3-checks-b", "192.0.2.202")

	// Four ordered ledger rows: A completed, A failed, A pending, B completed.
	base := time.Now().UTC().Truncate(time.Second)
	completed1 := base.Add(-2 * time.Minute)
	completed2 := base.Add(-time.Minute)
	id1 := uuid.MustParse("0198d5a3-0000-7000-8000-000000000101")
	id2 := uuid.MustParse("0198d5a3-0000-7000-8000-000000000102")
	id3 := uuid.MustParse("0198d5a3-0000-7000-8000-000000000103")
	id4 := uuid.MustParse("0198d5a3-0000-7000-8000-000000000104")
	insertDeviceCheck(t, id1, orgUUID, devA, "icmp", "completed", base.Add(-3*time.Minute), &completed1, "success", "", ptrInt(5))
	insertDeviceCheck(t, id2, orgUUID, devA, "snmp", "failed", base.Add(-2*time.Minute), &completed2, "", "expired", nil)
	insertDeviceCheck(t, id3, orgUUID, devA, "icmp", "pending", base.Add(-time.Minute), nil, "", "", nil)
	insertDeviceCheck(t, id4, orgUUID, devB, "snmp", "completed", base, &completed2, "failure", "timeout", ptrInt(1000))

	// Default order is newest first (descending UUIDv7 ids), paged by cursor.
	res := env.api.do(t, http.MethodGet, "/v1/checks?limit=2", "")
	if res.Status != http.StatusOK {
		t.Fatalf("checks list: status %d body %v", res.Status, res.Body)
	}
	page1 := dataList(t, res.Body)
	if len(page1) != 2 || page1[0]["check_id"] != id4.String() || page1[1]["check_id"] != id3.String() {
		t.Fatalf("desc page1 = %v, want id4 then id3", page1)
	}
	if res.Body["has_more"] != true {
		t.Fatalf("desc page1 has_more = %v, want true", res.Body["has_more"])
	}
	cursor, _ := res.Body["next_cursor"].(string)
	if cursor != id3.String() {
		t.Fatalf("next_cursor = %q, want %s", cursor, id3)
	}
	res = env.api.do(t, http.MethodGet, "/v1/checks?limit=2&cursor="+cursor, "")
	if res.Status != http.StatusOK {
		t.Fatalf("checks page2: status %d body %v", res.Status, res.Body)
	}
	page2 := dataList(t, res.Body)
	if len(page2) != 2 || page2[0]["check_id"] != id2.String() || page2[1]["check_id"] != id1.String() {
		t.Fatalf("desc page2 = %v, want id2 then id1", page2)
	}
	if res.Body["has_more"] != false {
		t.Fatalf("desc page2 has_more = %v, want false", res.Body["has_more"])
	}
	if page1[0]["status"] != "completed" || page1[0]["outcome"] != "failure" ||
		page1[0]["error_class"] != "timeout" || page1[0]["latency_ms"] != float64(1000) {
		t.Fatalf("check payload = %v", page1[0])
	}
	if page1[0]["device_id"] != devB.String() {
		t.Fatalf("check device_id = %v, want %s", page1[0]["device_id"], devB)
	}

	// order=asc mirrors the devices-list additive order contract.
	res = env.api.do(t, http.MethodGet, "/v1/checks?order=asc", "")
	asc := dataList(t, res.Body)
	if len(asc) != 4 || asc[0]["check_id"] != id1.String() || asc[3]["check_id"] != id4.String() {
		t.Fatalf("asc list = %v", asc)
	}

	// Filters: status, poll_type, device_id.
	res = env.api.do(t, http.MethodGet, "/v1/checks?filter[status]=failed", "")
	if rows := dataList(t, res.Body); len(rows) != 1 || rows[0]["check_id"] != id2.String() {
		t.Fatalf("filter[status]=failed = %v", rows)
	}
	res = env.api.do(t, http.MethodGet, "/v1/checks?filter[status]=pending", "")
	if rows := dataList(t, res.Body); len(rows) != 1 || rows[0]["check_id"] != id3.String() {
		t.Fatalf("filter[status]=pending = %v", rows)
	}
	res = env.api.do(t, http.MethodGet, "/v1/checks?filter[poll_type]=snmp", "")
	if rows := dataList(t, res.Body); len(rows) != 2 || rows[0]["check_id"] != id4.String() || rows[1]["check_id"] != id2.String() {
		t.Fatalf("filter[poll_type]=snmp = %v", rows)
	}
	res = env.api.do(t, http.MethodGet, "/v1/checks?filter[device_id]="+devA.String(), "")
	if rows := dataList(t, res.Body); len(rows) != 3 || rows[0]["check_id"] != id3.String() {
		t.Fatalf("filter[device_id]=A = %v", rows)
	}

	// Validation problems.
	for _, path := range []string{
		"/v1/checks?filter[status]=bogus",
		"/v1/checks?filter[poll_type]=tcp",
		"/v1/checks?filter[device_id]=not-a-uuid",
		"/v1/checks?order=sideways",
		"/v1/checks?cursor=not-a-uuid",
		"/v1/checks?limit=0",
		"/v1/checks?limit=101",
	} {
		res = env.api.do(t, http.MethodGet, path, "")
		requireProblem(t, res, http.StatusBadRequest, "validation.failed")
	}

	// Unrestricted caller: an unknown device id is a valid filter over an
	// empty set (no existence oracle), never an error.
	res = env.api.do(t, http.MethodGet, "/v1/checks?filter[device_id]="+newUUID(), "")
	if res.Status != http.StatusOK || len(dataList(t, res.Body)) != 0 {
		t.Fatalf("unknown device filter = %d %v", res.Status, res.Body)
	}

	// A real API-created check is the newest ledger row (UUIDv7 ordering).
	raw, _, _, err := env.svc.CreateEnrollmentToken(ctx, orgUUID, mustUUID(t, env.api.siteID), time.Hour, nil)
	must(t, err)
	_, _ = env.enrollIdentity(t, "collector-s3b3-checks", raw)
	created := env.createCheck(t, devA.String(), "icmp", newUUID())
	if created.Status != http.StatusAccepted {
		t.Fatalf("create check: %d %v", created.Status, created.Body)
	}
	createdID, _ := created.Body["check_id"].(string)
	res = env.api.do(t, http.MethodGet, "/v1/checks?limit=5", "")
	if rows := dataList(t, res.Body); len(rows) != 5 || rows[0]["check_id"] != createdID {
		t.Fatalf("API-created check not newest: %v", rows)
	}

	// Authz: unauthenticated denied before capability; viewer holds device.read.
	anon := &http.Client{Timeout: 10 * time.Second}
	res = doRequest(t, anon, http.MethodGet, env.api.srv.URL+"/v1/checks", "", nil)
	requireProblem(t, res, http.StatusUnauthorized, "auth.unauthenticated")
	_, viewerEmail := seedUserWithRole(t, env.api, "viewer")
	viewer, _ := loginAs(t, env.api, viewerEmail)
	res = doRequest(t, viewer, http.MethodGet, env.api.srv.URL+"/v1/checks", "", nil)
	if res.Status != http.StatusOK {
		t.Fatalf("viewer checks list: %d %v", res.Status, res.Body)
	}

	// Site-scoped admin: only site B's check is visible; an explicit
	// out-of-scope (or unknown) device filter is the deterministic 403.
	scopedID, scopedEmail := seedUserWithRole(t, env.api, "admin")
	bindScope(t, env.api.orgID, scopedID, "site", siteB)
	scoped, _ := loginAs(t, env.api, scopedEmail)
	res = doRequest(t, scoped, http.MethodGet, env.api.srv.URL+"/v1/checks", "", nil)
	if res.Status != http.StatusOK {
		t.Fatalf("scoped checks list: %d %v", res.Status, res.Body)
	}
	if rows := dataList(t, res.Body); len(rows) != 1 || rows[0]["check_id"] != id4.String() {
		t.Fatalf("scoped rows = %v, want only site B check %s", rows, id4)
	}
	res = doRequest(t, scoped, http.MethodGet, env.api.srv.URL+"/v1/checks?filter[device_id]="+devA.String(), "", nil)
	requireProblem(t, res, http.StatusForbidden, "auth.forbidden")
	res = doRequest(t, scoped, http.MethodGet, env.api.srv.URL+"/v1/checks?filter[device_id]="+newUUID(), "", nil)
	requireProblem(t, res, http.StatusForbidden, "auth.forbidden")
	res = doRequest(t, scoped, http.MethodGet, env.api.srv.URL+"/v1/checks?filter[device_id]="+devB.String(), "", nil)
	if res.Status != http.StatusOK || len(dataList(t, res.Body)) != 1 {
		t.Fatalf("in-scope device filter = %d %v", res.Status, res.Body)
	}

	// Cross-tenant: org B sees none of org A's ledger, even with the filter.
	other := newM10Env(t, "m10s3b3-checks-b-"+newUUID()[:8])
	res = other.api.do(t, http.MethodGet, "/v1/checks", "")
	if res.Status != http.StatusOK || len(dataList(t, res.Body)) != 0 {
		t.Fatalf("cross-tenant list = %d %v", res.Status, res.Body)
	}
	res = other.api.do(t, http.MethodGet, "/v1/checks?filter[device_id]="+devA.String(), "")
	if res.Status != http.StatusOK || len(dataList(t, res.Body)) != 0 {
		t.Fatalf("cross-tenant device filter = %d %v", res.Status, res.Body)
	}
}

// TestM10S3b3PollHealthFeedAPI pins GET /v1/poll-health: the bounded window
// (default 1 h, max 24 h), ts-desc ordering, outcome/poll_type/device_id
// filters, limit bounds, scope narrowing and cross-tenant invisibility.
func TestM10S3b3PollHealthFeedAPI(t *testing.T) {
	env := newM10Env(t, "m10s3b3-health-"+newUUID()[:8])
	orgUUID, siteA := env.org(), env.site()
	devA := mustUUID(t, env.api.createDevice(t, "s3b3-health-a", map[string]any{"mgmt_ip": "192.0.2.211"}))
	siteB := createSite(t, env.api.orgID, "s3b3-hsite-b-"+newUUID()[:8])
	devB := createDeviceAtSite(t, env, siteB, "s3b3-health-b", "192.0.2.212")
	collectorID := seedCollectorRow(t, orgUUID, siteA, "s3b3-health-collector")

	now := time.Now().UTC().Truncate(time.Second)
	insertHealthRow(t, orgUUID, collectorID, devA, now.Add(-10*time.Minute), "icmp", "failure", "timeout", 1000, 4, "scheduled")
	insertHealthRow(t, orgUUID, collectorID, devA, now.Add(-20*time.Minute), "snmp", "success", "", 12, 0, "scheduled")
	insertHealthRow(t, orgUUID, collectorID, devB, now.Add(-30*time.Minute), "icmp", "failure", "unreachable", 1005, 7, "scheduled")
	insertHealthRow(t, orgUUID, collectorID, devA, now.Add(-6*time.Hour), "icmp", "failure", "timeout", 1000, 1, "scheduled")
	insertHealthRow(t, orgUUID, collectorID, devA, now.Add(-25*time.Hour), "icmp", "failure", "timeout", 1000, 1, "scheduled")

	// Default window (now-1h): the three recent rows, newest first.
	res := env.api.do(t, http.MethodGet, "/v1/poll-health", "")
	if res.Status != http.StatusOK {
		t.Fatalf("poll-health feed: status %d body %v", res.Status, res.Body)
	}
	if since, _ := res.Body["since"].(string); since == "" {
		t.Fatalf("feed response lacks since echo: %v", res.Body)
	}
	rows := dataList(t, res.Body)
	if len(rows) != 3 {
		t.Fatalf("default window rows = %d, want 3 (%v)", len(rows), rows)
	}
	if rows[0]["checked_at"] != now.Add(-10*time.Minute).Format(time.RFC3339) ||
		rows[0]["outcome"] != "failure" || rows[0]["error_class"] != "timeout" ||
		rows[0]["consecutive_failures"] != float64(4) || rows[0]["latency_ms"] != float64(1000) {
		t.Fatalf("newest row = %v", rows[0])
	}
	if rows[1]["poll_type"] != "snmp" || rows[2]["device_id"] != devB.String() {
		t.Fatalf("feed ordering = %v", rows)
	}

	// Filters.
	res = env.api.do(t, http.MethodGet, "/v1/poll-health?outcome=failure", "")
	if got := dataList(t, res.Body); len(got) != 2 || got[0]["checked_at"] != now.Add(-10*time.Minute).Format(time.RFC3339) {
		t.Fatalf("outcome=failure = %v", got)
	}
	res = env.api.do(t, http.MethodGet, "/v1/poll-health?poll_type=snmp", "")
	if got := dataList(t, res.Body); len(got) != 1 || got[0]["outcome"] != "success" {
		t.Fatalf("poll_type=snmp = %v", got)
	}
	res = env.api.do(t, http.MethodGet, "/v1/poll-health?device_id="+devA.String(), "")
	if got := dataList(t, res.Body); len(got) != 2 || got[1]["device_id"] != devA.String() {
		t.Fatalf("device_id=A = %v", got)
	}
	res = env.api.do(t, http.MethodGet, "/v1/poll-health?limit=2", "")
	if got := dataList(t, res.Body); len(got) != 2 {
		t.Fatalf("limit=2 = %d rows", len(got))
	}

	// Wide window within the 24 h bound includes the 6 h row; the 25 h row is
	// never visible.
	res = env.api.do(t, http.MethodGet, "/v1/poll-health?since="+now.Add(-7*time.Hour).Format(time.RFC3339), "")
	if got := dataList(t, res.Body); len(got) != 4 || got[3]["checked_at"] != now.Add(-6*time.Hour).Format(time.RFC3339) {
		t.Fatalf("since=now-7h = %v", got)
	}

	// Window and validation bounds.
	for _, path := range []string{
		"/v1/poll-health?since=" + now.Add(-25*time.Hour).Format(time.RFC3339),
		"/v1/poll-health?since=" + now.Add(5*time.Minute).Format(time.RFC3339),
		"/v1/poll-health?since=not-a-time",
		"/v1/poll-health?outcome=maybe",
		"/v1/poll-health?poll_type=tcp",
		"/v1/poll-health?device_id=not-a-uuid",
		"/v1/poll-health?limit=0",
		"/v1/poll-health?limit=201",
	} {
		res = env.api.do(t, http.MethodGet, path, "")
		requireProblem(t, res, http.StatusBadRequest, "validation.failed")
	}

	// Authz: unauthenticated denied; viewer holds device.read.
	anon := &http.Client{Timeout: 10 * time.Second}
	res = doRequest(t, anon, http.MethodGet, env.api.srv.URL+"/v1/poll-health", "", nil)
	requireProblem(t, res, http.StatusUnauthorized, "auth.unauthenticated")
	_, viewerEmail := seedUserWithRole(t, env.api, "viewer")
	viewer, _ := loginAs(t, env.api, viewerEmail)
	res = doRequest(t, viewer, http.MethodGet, env.api.srv.URL+"/v1/poll-health", "", nil)
	if res.Status != http.StatusOK {
		t.Fatalf("viewer feed: %d %v", res.Status, res.Body)
	}

	// Scope: a site-B caller sees only site B's row; explicit out-of-scope (or
	// unknown) device filters are the deterministic 403.
	scopedID, scopedEmail := seedUserWithRole(t, env.api, "admin")
	bindScope(t, env.api.orgID, scopedID, "site", siteB)
	scoped, _ := loginAs(t, env.api, scopedEmail)
	res = doRequest(t, scoped, http.MethodGet, env.api.srv.URL+"/v1/poll-health", "", nil)
	if res.Status != http.StatusOK {
		t.Fatalf("scoped feed: %d %v", res.Status, res.Body)
	}
	if got := dataList(t, res.Body); len(got) != 1 || got[0]["device_id"] != devB.String() {
		t.Fatalf("scoped feed rows = %v", got)
	}
	res = doRequest(t, scoped, http.MethodGet, env.api.srv.URL+"/v1/poll-health?device_id="+devA.String(), "", nil)
	requireProblem(t, res, http.StatusForbidden, "auth.forbidden")
	res = doRequest(t, scoped, http.MethodGet, env.api.srv.URL+"/v1/poll-health?device_id="+newUUID(), "", nil)
	requireProblem(t, res, http.StatusForbidden, "auth.forbidden")

	// Cross-tenant: org B's feed is empty even with org A's device filter.
	other := newM10Env(t, "m10s3b3-health-b-"+newUUID()[:8])
	res = other.api.do(t, http.MethodGet, "/v1/poll-health", "")
	if res.Status != http.StatusOK || len(dataList(t, res.Body)) != 0 {
		t.Fatalf("cross-tenant feed = %d %v", res.Status, res.Body)
	}
	res = other.api.do(t, http.MethodGet, "/v1/poll-health?device_id="+devA.String(), "")
	if res.Status != http.StatusOK || len(dataList(t, res.Body)) != 0 {
		t.Fatalf("cross-tenant device filter = %d %v", res.Status, res.Body)
	}
}
