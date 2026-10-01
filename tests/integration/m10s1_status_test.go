package integration

// M10-S1 (Phase 2): device status rollups derived from scheduled poll health.
// Covers the classification state machine (up/down/unknown), threshold and
// freshness windows, on-demand exclusion, the single and bulk API shapes,
// pagination compatibility, and scope/tenant isolation.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

// insertPollHealthOrigin seeds one poll_health row with an explicit origin.
func insertPollHealthOrigin(t *testing.T, orgID, collectorID, deviceID uuid.UUID, ts time.Time, latency int, outcome, class string, failures int, origin string) {
	t.Helper()
	_, err := ownerPool.Exec(context.Background(), `
		INSERT INTO poll_health (id, org_id, collector_id, device_id, ts, poll_type, latency_ms, outcome, error_class, consecutive_failures, origin)
		VALUES ($1, $2, $3, $4, $5, 'icmp', $6, $7, $8, $9, $10)`,
		newUUID(), orgID, collectorID, deviceID, ts, latency, outcome, class, failures, origin)
	must(t, err)
}

func statusBody(t *testing.T, res apiResponse) map[string]any {
	t.Helper()
	if res.Status != http.StatusOK {
		t.Fatalf("status query: status %d body %v", res.Status, res.Body)
	}
	return res.Body
}

func TestM10S1DeviceStatusClassificationAndAPI(t *testing.T) {
	env := newM10S1Env(t, "m10s1-status-"+newUUID()[:8])
	orgUUID := mustUUID(t, env.orgID)
	siteUUID := mustUUID(t, env.siteID)
	collectorID := seedCollectorRow(t, orgUUID, siteUUID, "m10s1-status-collector")
	deviceID := mustUUID(t, env.createDevice(t, "m10s1-status-dev", nil))
	path := "/v1/devices/" + deviceID.String() + "/status"

	// No scheduled health at all: unknown with null probe fields.
	body := statusBody(t, env.do(t, http.MethodGet, path, ""))
	if body["status"] != "unknown" || body["since"] != nil || body["last_outcome"] != nil || body["last_checked_at"] != nil {
		t.Fatalf("empty status = %v", body)
	}
	if body["down_threshold"] != float64(3) || body["freshness_seconds"] != float64(1200) {
		t.Fatalf("policy fields = %v", body)
	}

	now := time.Now().UTC().Truncate(time.Second)
	t1 := now.Add(-30 * time.Second)
	insertPollHealthOrigin(t, orgUUID, collectorID, deviceID, t1, 12, "success", "", 0, "scheduled")
	body = statusBody(t, env.do(t, http.MethodGet, path, ""))
	if body["status"] != "up" || body["since"] != t1.Format(time.RFC3339) {
		t.Fatalf("success status = %v", body)
	}
	if body["last_outcome"] != "success" || body["last_latency_ms"] != float64(12) || body["consecutive_failures"] != float64(0) || body["last_checked_at"] != t1.Format(time.RFC3339) {
		t.Fatalf("success probe fields = %v", body)
	}

	// One and two consecutive failures stay below the threshold (up).
	t2 := now.Add(-20 * time.Second)
	t3 := now.Add(-10 * time.Second)
	t4 := now.Add(-5 * time.Second)
	insertPollHealthOrigin(t, orgUUID, collectorID, deviceID, t2, 5, "failure", "timeout", 1, "scheduled")
	body = statusBody(t, env.do(t, http.MethodGet, path, ""))
	if body["status"] != "up" || body["consecutive_failures"] != float64(1) || body["last_error_class"] != "timeout" {
		t.Fatalf("1-failure status = %v", body)
	}
	insertPollHealthOrigin(t, orgUUID, collectorID, deviceID, t3, 5, "failure", "timeout", 2, "scheduled")
	body = statusBody(t, env.do(t, http.MethodGet, path, ""))
	if body["status"] != "up" {
		t.Fatalf("2-failure status = %v", body)
	}

	// The third consecutive failure flips the rollup to down; since is the
	// first failure of the outage (t2), not the threshold row.
	insertPollHealthOrigin(t, orgUUID, collectorID, deviceID, t4, 5, "failure", "timeout", 3, "scheduled")
	body = statusBody(t, env.do(t, http.MethodGet, path, ""))
	if body["status"] != "down" || body["since"] != t2.Format(time.RFC3339) {
		t.Fatalf("down status = %v", body)
	}
	if body["consecutive_failures"] != float64(3) || body["last_error_class"] != "timeout" {
		t.Fatalf("down probe fields = %v", body)
	}

	// Recovery restarts the up period at the recovery row.
	t5 := now.Add(-2 * time.Second)
	insertPollHealthOrigin(t, orgUUID, collectorID, deviceID, t5, 3, "success", "", 0, "scheduled")
	body = statusBody(t, env.do(t, http.MethodGet, path, ""))
	if body["status"] != "up" || body["since"] != t5.Format(time.RFC3339) || body["last_outcome"] != "success" {
		t.Fatalf("recovery status = %v", body)
	}
}

func TestM10S1DeviceStatusFreshnessAndOrigin(t *testing.T) {
	env := newM10S1Env(t, "m10s1-fresh-"+newUUID()[:8])
	orgUUID := mustUUID(t, env.orgID)
	siteUUID := mustUUID(t, env.siteID)
	collectorID := seedCollectorRow(t, orgUUID, siteUUID, "m10s1-fresh-collector")
	now := time.Now().UTC().Truncate(time.Second)

	// Stale scheduled health: unknown, since = when the newest row expired.
	stale := mustUUID(t, env.createDevice(t, "m10s1-stale", nil))
	staleTs := now.Add(-25 * time.Minute)
	insertPollHealthOrigin(t, orgUUID, collectorID, stale, staleTs, 9, "success", "", 0, "scheduled")
	body := statusBody(t, env.do(t, http.MethodGet, "/v1/devices/"+stale.String()+"/status", ""))
	if body["status"] != "unknown" {
		t.Fatalf("stale status = %v, want unknown", body)
	}
	if body["since"] != staleTs.Add(20*time.Minute).Format(time.RFC3339) {
		t.Fatalf("unknown since = %v", body["since"])
	}
	if body["last_checked_at"] != staleTs.Format(time.RFC3339) || body["last_outcome"] != "success" {
		t.Fatalf("unknown last fields = %v", body)
	}

	// A stale failure streak is unknown too (freshness wins).
	staleFail := mustUUID(t, env.createDevice(t, "m10s1-stalefail", nil))
	insertPollHealthOrigin(t, orgUUID, collectorID, staleFail, staleTs, 9, "failure", "timeout", 9, "scheduled")
	body = statusBody(t, env.do(t, http.MethodGet, "/v1/devices/"+staleFail.String()+"/status", ""))
	if body["status"] != "unknown" {
		t.Fatalf("stale failures = %v, want unknown", body)
	}

	// On-demand checks never drive the rollup: a fresh on-demand failure with
	// a high failure count leaves the device unknown (no scheduled rows).
	onDemand := mustUUID(t, env.createDevice(t, "m10s1-ondemand", nil))
	insertPollHealthOrigin(t, orgUUID, collectorID, onDemand, now.Add(-5*time.Second), 4, "failure", "timeout", 5, "on_demand")
	body = statusBody(t, env.do(t, http.MethodGet, "/v1/devices/"+onDemand.String()+"/status", ""))
	if body["status"] != "unknown" || body["last_outcome"] != nil || body["last_checked_at"] != nil {
		t.Fatalf("on-demand-only status = %v, want unknown with null probe fields", body)
	}

	// A fresh on-demand row does not refresh a stale scheduled row either.
	mixed := mustUUID(t, env.createDevice(t, "m10s1-mixed", nil))
	insertPollHealthOrigin(t, orgUUID, collectorID, mixed, staleTs, 9, "success", "", 0, "scheduled")
	insertPollHealthOrigin(t, orgUUID, collectorID, mixed, now.Add(-5*time.Second), 4, "success", "", 0, "on_demand")
	body = statusBody(t, env.do(t, http.MethodGet, "/v1/devices/"+mixed.String()+"/status", ""))
	if body["status"] != "unknown" || body["last_checked_at"] != staleTs.Format(time.RFC3339) {
		t.Fatalf("mixed-origin status = %v, want unknown from the stale scheduled row", body)
	}
}

func TestM10S1DeviceStatusBulkConsistency(t *testing.T) {
	env := newM10S1Env(t, "m10s1-bulk-"+newUUID()[:8])
	orgUUID := mustUUID(t, env.orgID)
	siteUUID := mustUUID(t, env.siteID)
	collectorID := seedCollectorRow(t, orgUUID, siteUUID, "m10s1-bulk-collector")
	now := time.Now().UTC().Truncate(time.Second)

	upDevice := mustUUID(t, env.createDevice(t, "m10s1-bulk-up", nil))
	downDevice := mustUUID(t, env.createDevice(t, "m10s1-bulk-down", nil))
	insertPollHealthOrigin(t, orgUUID, collectorID, upDevice, now.Add(-time.Minute), 7, "success", "", 0, "scheduled")
	for i, failures := range []int{3, 2, 1} {
		insertPollHealthOrigin(t, orgUUID, collectorID, downDevice, now.Add(-time.Duration(i+1)*time.Minute), 6, "failure", "timeout", failures, "scheduled")
	}

	res := env.do(t, http.MethodGet, "/v1/devices?include=status", "")
	if res.Status != http.StatusOK {
		t.Fatalf("bulk status: status %d body %v", res.Status, res.Body)
	}
	devices := dataList(t, res.Body)
	if len(devices) < 2 {
		t.Fatalf("bulk devices = %d, want >= 2", len(devices))
	}
	byID := map[string]map[string]any{}
	for _, d := range devices {
		byID[d["id"].(string)] = d
	}
	// The existing inventory `status` field is untouched; the rollup is nested.
	if byID[upDevice.String()]["status"] != "new" {
		t.Fatalf("inventory status clobbered: %v", byID[upDevice.String()])
	}
	upStatus := byID[upDevice.String()]["poll_status"].(map[string]any)
	downStatus := byID[downDevice.String()]["poll_status"].(map[string]any)
	if upStatus["status"] != "up" || downStatus["status"] != "down" {
		t.Fatalf("bulk rollups = %v / %v", upStatus, downStatus)
	}

	// Bulk and single must agree.
	for _, tc := range []struct {
		id   string
		bulk map[string]any
	}{{upDevice.String(), upStatus}, {downDevice.String(), downStatus}} {
		single := statusBody(t, env.do(t, http.MethodGet, "/v1/devices/"+tc.id+"/status", ""))
		for _, key := range []string{"status", "since", "last_outcome", "last_error_class", "last_latency_ms", "consecutive_failures", "last_checked_at"} {
			if single[key] != tc.bulk[key] {
				t.Fatalf("single/bulk disagree on %s for %s: %v vs %v", key, tc.id, single[key], tc.bulk[key])
			}
		}
	}

	// Pagination rules are unchanged and every page carries the rollup.
	res = env.do(t, http.MethodGet, "/v1/devices?include=status&limit=1", "")
	if res.Status != http.StatusOK || res.Body["has_more"] != true {
		t.Fatalf("page1: status %d body %v", res.Status, res.Body)
	}
	first := dataList(t, res.Body)
	if first[0]["poll_status"] == nil {
		t.Fatalf("page1 missing poll_status: %v", first[0])
	}
	cursor, _ := res.Body["next_cursor"].(string)
	if cursor == "" {
		t.Fatal("missing next_cursor")
	}
	res = env.do(t, http.MethodGet, "/v1/devices?include=status&limit=1&cursor="+cursor, "")
	if res.Status != http.StatusOK {
		t.Fatalf("page2: status %d body %v", res.Status, res.Body)
	}
	if second := dataList(t, res.Body); len(second) != 1 || second[0]["poll_status"] == nil {
		t.Fatalf("page2 missing poll_status: %v", second)
	}

	// The include allowlist is strict.
	requireProblem(t, env.do(t, http.MethodGet, "/v1/devices?include=identity", ""), http.StatusBadRequest, "validation.failed")
}

func TestM10S1DeviceStatusAuthzAndScope(t *testing.T) {
	env := newM10S1Env(t, "m10s1-authz-"+newUUID()[:8])
	orgUUID := mustUUID(t, env.orgID)
	deviceID := mustUUID(t, env.createDevice(t, "m10s1-authz-dev", nil))
	path := "/v1/devices/" + deviceID.String() + "/status"

	// Anonymous: 401 before capability.
	anon := &http.Client{Timeout: 10 * time.Second}
	if res := doRequest(t, anon, http.MethodGet, env.srv.URL+path, "", nil); res.Status != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d, want 401", res.Status)
	}
	// Viewer holds device.read.
	_, viewerEmail := seedUserWithRole(t, env, "viewer")
	viewer, _ := loginAs(t, env, viewerEmail)
	if res := doRequest(t, viewer, http.MethodGet, env.srv.URL+path, "", nil); res.Status != http.StatusOK {
		t.Fatalf("viewer status = %d body %v", res.Status, res.Body)
	}
	// Site-scoped viewer cannot see the device (uniform 404).
	site2 := createSite(t, env.orgID, "S2-"+env.slug)
	scoped, _ := loginAs(t, env, seedViewerForSite(t, env, site2))
	requireProblem(t, doRequest(t, scoped, http.MethodGet, env.srv.URL+path, "", nil), http.StatusNotFound, "device.not_found")
	// The bulk list honors the same scope: the device is filtered out.
	res := doRequest(t, scoped, http.MethodGet, env.srv.URL+"/v1/devices?include=status", "", nil)
	if res.Status != http.StatusOK {
		t.Fatalf("scoped bulk: %d", res.Status)
	}
	for _, d := range dataList(t, res.Body) {
		if d["id"] == deviceID.String() {
			t.Fatalf("out-of-scope device leaked in bulk status: %v", d)
		}
	}
	// Malformed and foreign ids are the same 404.
	requireProblem(t, env.do(t, http.MethodGet, "/v1/devices/not-a-uuid/status", ""), http.StatusNotFound, "device.not_found")
	envB := newM10S1Env(t, "m10s1-authz-b-"+newUUID()[:8])
	requireProblem(t, envB.do(t, http.MethodGet, path, ""), http.StatusNotFound, "device.not_found")
	_ = orgUUID
}
