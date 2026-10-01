package integration

// M9-S1 (Phase 2): polling foundation acceptance — poll targets in the signed
// policy bundle, device-scoped ICMP sample ingest, poll_health persistence on
// the existing batch ack/claim path, tenant isolation/RLS, the read API and
// the canonical 90-day retention (P2-AC-14 partial, P2-AC-20, P2-AC-06 style).

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
	"github.com/argus-platform/argus/internal/api"
	cpolicy "github.com/argus-platform/argus/internal/collector/policy"
	"github.com/argus-platform/argus/internal/modules/collectors"
	"github.com/argus-platform/argus/internal/modules/identity"
	"github.com/argus-platform/argus/internal/modules/ingest"
	"github.com/argus-platform/argus/internal/modules/inventory"
	"github.com/argus-platform/argus/internal/modules/pollhealth"
	"github.com/argus-platform/argus/internal/modules/tenancy"
	"github.com/argus-platform/argus/internal/platform/database"
	"github.com/argus-platform/argus/internal/platform/telemetry"
)

// newM9APIEnv wires the public router with the M9 poll-health surface on top of
// the inventory test environment (so the inventory API test helpers apply).
func newM9APIEnv(t *testing.T, slug string) *inventoryEnv {
	t.Helper()
	seed := seedLoginUser(t, slug, "HQ-"+slug)

	tenancySvc := tenancy.New(appPool, authPool)
	identitySvc, err := identity.New(appPool, authPool, tenancySvc)
	must(t, err)
	inv := inventory.New(appPool, nil)
	router := api.NewRouter(api.Options{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Telemetry:  telemetry.New("it-m9", "0", "0"),
		Version:    "it",
		Commit:     "it",
		Identity:   identitySvc,
		Tenancy:    tenancySvc,
		Inventory:  inv,
		PollHealth: pollhealth.New(appPool),
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
	return &inventoryEnv{
		srv:    srv,
		client: client,
		slug:   slug,
		orgID:  seed.OrgID,
		siteID: seed.SiteID,
		csrf:   csrf.Value,
	}
}

// insertPollHealth seeds one poll_health row (owner role; superuser bypasses
// RLS, so the test can place rows in any tenant).
func insertPollHealth(t *testing.T, orgID, collectorID, deviceID uuid.UUID, ts time.Time, latency int, outcome, class string, failures int) {
	t.Helper()
	_, err := ownerPool.Exec(context.Background(), `
		INSERT INTO poll_health (id, org_id, collector_id, device_id, ts, poll_type, latency_ms, outcome, error_class, consecutive_failures)
		VALUES ($1, $2, $3, $4, $5, 'icmp', $6, $7, $8, $9)`,
		newUUID(), orgID, collectorID, deviceID, ts, latency, outcome, class, failures)
	must(t, err)
}

// seedCollectorRow creates a minimal collector row for FK-bound health rows.
func seedCollectorRow(t *testing.T, orgID, siteID uuid.UUID, name string) uuid.UUID {
	t.Helper()
	id := uuid.MustParse(newUUID())
	_, err := ownerPool.Exec(context.Background(), `
		INSERT INTO collectors (id, org_id, site_id, name, status, enrolled_at, policy_version)
		VALUES ($1, $2, $3, $4, 'active', now(), 0)`, id, orgID, siteID, name)
	must(t, err)
	return id
}

func createM9Device(t *testing.T, orgID, siteID uuid.UUID, name, mgmtIP, profile string) uuid.UUID {
	t.Helper()
	inv := inventory.New(appPool, nil)
	var ip *string
	if mgmtIP != "" {
		ip = &mgmtIP
	}
	d, err := inv.CreateDevice(context.Background(), orgID, inventory.CreateDeviceInput{
		SiteID:      siteID,
		Name:        name,
		Kind:        "switch",
		PollProfile: profile,
		MgmtIP:      ip,
	}, inventory.Actor{})
	must(t, err)
	return d.ID
}

// TestM9PolicyBundleTargets proves the signed bundle carries exactly the live
// devices with a management IP, with the device's poll profile as the tier,
// and that the signature still verifies with the pinned key.
func TestM9PolicyBundleTargets(t *testing.T) {
	ctx := context.Background()
	env := startM3Env(t)
	orgID, siteID, _ := devTenant(t, "m9-policy-"+newUUID()[:8])
	orgUUID, siteUUID := mustUUID(t, orgID), mustUUID(t, siteID)

	liveA := createM9Device(t, orgUUID, siteUUID, "m9-live-a", "192.0.2.10", "fast")
	_ = createM9Device(t, orgUUID, siteUUID, "m9-no-ip", "", "standard")
	liveC := createM9Device(t, orgUUID, siteUUID, "m9-live-c", "192.0.2.12", "slow")
	deleted := createM9Device(t, orgUUID, siteUUID, "m9-deleted", "192.0.2.13", "standard")
	inv := inventory.New(appPool, nil)
	must(t, inv.DeleteDevice(ctx, orgUUID, deleted, inventory.Actor{}))

	raw, _, _, err := env.svc.CreateEnrollmentToken(ctx, orgUUID, siteUUID, time.Hour, nil)
	must(t, err)
	id, _ := env.enrollIdentity(t, "collector-m9-policy", raw)

	sp, err := env.svc.LatestPolicy(ctx, orgUUID, mustUUID(t, id.CollectorID))
	must(t, err)
	if sp == nil {
		t.Fatal("no policy issued at enrollment")
	}
	if _, err := cpolicy.VerifyAndValidate(sp.Document, sp.Signature, env.ca.PolicySigningPublicKeyDER()); err != nil {
		t.Fatalf("signed bundle with targets does not verify: %v", err)
	}

	var doc collectors.PolicyDocument
	must(t, json.Unmarshal(sp.Document, &doc))
	if len(doc.Targets) != 2 {
		t.Fatalf("targets = %+v, want live A and C only", doc.Targets)
	}
	byID := map[string]collectors.PolicyTarget{}
	for _, tg := range doc.Targets {
		byID[tg.DeviceID] = tg
	}
	a, ok := byID[liveA.String()]
	if !ok || a.Tier != "fast" || a.MgmtIP != "192.0.2.10" || a.Name != "m9-live-a" {
		t.Fatalf("target A = %+v ok=%v", a, ok)
	}
	if c, ok := byID[liveC.String()]; !ok || c.Tier != "slow" {
		t.Fatalf("target C = %+v ok=%v", c, ok)
	}

	allow, err := ingest.AllowlistFromPolicy(sp.Document)
	must(t, err)
	for _, key := range []string{"net.icmp.reachable", "net.icmp.rtt_ms", "net.icmp.loss_pct"} {
		if _, ok := allow[key]; !ok {
			t.Fatalf("policy allowlist missing %s", key)
		}
	}
}

// sendM9Batch sends one raw MetricBatch on the m4 test stream.
func sendM9Batch(t *testing.T, r *rawBatchStream, batch *collectorv1.MetricBatch) {
	t.Helper()
	must(t, r.stream.Send(&collectorv1.ClientMessage{
		Msg: &collectorv1.ClientMessage_Batch{Batch: batch},
	}))
}

func icmpSample(deviceID string, key string, unit string, value float64, ts time.Time) *collectorv1.MetricSample {
	return &collectorv1.MetricSample{
		MetricKey: key, Unit: unit, Value: value, DeviceId: deviceID, Ts: timestamppb.New(ts),
	}
}

func icmpHealth(deviceID string, ts time.Time) *collectorv1.PollHealth {
	return &collectorv1.PollHealth{
		DeviceId:  deviceID,
		PollType:  "icmp",
		LatencyMs: 7,
		Outcome:   "success",
		CheckedAt: timestamppb.New(ts),
	}
}

// TestM9PollHealthIngestRoundTrip proves device-scoped ICMP samples and
// poll-health records persist through the existing collector stream batch
// claim/ack path, and that a replayed batch is deduplicated.
func TestM9PollHealthIngestRoundTrip(t *testing.T) {
	ctx := context.Background()
	env, id, store, orgID := m4Env(t, "m9-ingest-"+newUUID()[:8])
	orgUUID := mustUUID(t, orgID)

	var siteID uuid.UUID
	must(t, ownerPool.QueryRow(ctx, `SELECT id FROM sites WHERE org_id = $1 ORDER BY created_at LIMIT 1`, orgUUID).Scan(&siteID))
	deviceID := createM9Device(t, orgUUID, siteID, "m9-poll-dev", "192.0.2.44", "standard")

	rs := dialBatchStream(t, env, id, store)
	now := time.Now().UTC().Truncate(time.Second)
	device := deviceID.String()
	batch := &collectorv1.MetricBatch{
		BatchSeq:  1,
		CreatedAt: timestamppb.Now(),
		Samples: []*collectorv1.MetricSample{
			icmpSample(device, "net.icmp.reachable", "state", 1, now),
			icmpSample(device, "net.icmp.rtt_ms", "ms", 4.5, now),
			icmpSample(device, "net.icmp.loss_pct", "percent", 0, now),
		},
		Health: []*collectorv1.PollHealth{icmpHealth(device, now)},
	}
	sendM9Batch(t, rs, batch)
	res := rs.result(t)
	if res.GetStatus() != collectorv1.BatchResult_STATUS_OK {
		t.Fatalf("batch status = %v (%s)", res.GetStatus(), res.GetReason())
	}
	if res.GetAcceptedSamples() != 3 {
		t.Fatalf("accepted samples = %d, want 3", res.GetAcceptedSamples())
	}

	var deviceSeries int
	must(t, ownerPool.QueryRow(ctx, `
		SELECT count(*) FROM metric_series WHERE org_id = $1 AND device_id = $2`, orgUUID, deviceID).Scan(&deviceSeries))
	if deviceSeries != 3 {
		t.Fatalf("device series = %d, want 3", deviceSeries)
	}
	var samples int
	must(t, ownerPool.QueryRow(ctx, `
		SELECT count(*) FROM metric_samples ms
		JOIN metric_series s ON s.id = ms.series_id
		WHERE s.org_id = $1 AND s.device_id = $2`, orgUUID, deviceID).Scan(&samples))
	if samples != 3 {
		t.Fatalf("device samples = %d, want 3", samples)
	}

	var (
		gotLatency int
		gotOutcome string
		gotPoll    string
	)
	must(t, ownerPool.QueryRow(ctx, `
		SELECT latency_ms, outcome, poll_type FROM poll_health
		WHERE org_id = $1 AND device_id = $2`, orgUUID, deviceID).Scan(&gotLatency, &gotOutcome, &gotPoll))
	if gotLatency != 7 || gotOutcome != "success" || gotPoll != "icmp" {
		t.Fatalf("poll_health = %d/%s/%s", gotLatency, gotOutcome, gotPoll)
	}

	// Replay the same batch_seq with different payload: exactly one delivery
	// wins, health and samples are not duplicated.
	replay := &collectorv1.MetricBatch{
		BatchSeq:  1,
		CreatedAt: timestamppb.Now(),
		Health:    []*collectorv1.PollHealth{icmpHealth(device, now.Add(time.Minute))},
	}
	sendM9Batch(t, rs, replay)
	if res := rs.result(t); res.GetStatus() != collectorv1.BatchResult_STATUS_DUPLICATE {
		t.Fatalf("replay status = %v (%s), want DUPLICATE", res.GetStatus(), res.GetReason())
	}
	var healthRows int
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM poll_health WHERE org_id = $1 AND device_id = $2`, orgUUID, deviceID).Scan(&healthRows))
	if healthRows != 1 {
		t.Fatalf("poll_health rows after replay = %d, want 1", healthRows)
	}
}

// TestM9PollHealthCrossTenantIngestRejected: a collector can never write a
// sample or health record for a device outside its own tenant; the whole batch
// is rejected permanently and nothing lands.
func TestM9PollHealthCrossTenantIngestRejected(t *testing.T) {
	ctx := context.Background()
	env, id, store, orgID := m4Env(t, "m9-iso-a-"+newUUID()[:8])
	orgA := mustUUID(t, orgID)

	// Tenant B: a device the org A collector must not touch.
	orgB, siteB, _ := devTenant(t, "m9-iso-b-"+newUUID()[:8])
	orgBUUID, siteBUUID := mustUUID(t, orgB), mustUUID(t, siteB)
	ipB := "192.0.2.99"
	devB, err := inventory.New(appPool, nil).CreateDevice(ctx, orgBUUID, inventory.CreateDeviceInput{
		SiteID: siteBUUID, Name: "m9-iso-b-dev", Kind: "switch", MgmtIP: &ipB,
	}, inventory.Actor{})
	must(t, err)

	rs := dialBatchStream(t, env, id, store)
	now := time.Now().UTC().Truncate(time.Second)
	batch := &collectorv1.MetricBatch{
		BatchSeq:  11,
		CreatedAt: timestamppb.Now(),
		Samples:   []*collectorv1.MetricSample{icmpSample(devB.ID.String(), "net.icmp.reachable", "state", 1, now)},
		Health:    []*collectorv1.PollHealth{icmpHealth(devB.ID.String(), now)},
	}
	sendM9Batch(t, rs, batch)
	res := rs.result(t)
	if res.GetStatus() != collectorv1.BatchResult_STATUS_REJECTED || res.GetReason() != "validation.device_not_found" {
		t.Fatalf("cross-tenant batch = %v/%s, want REJECTED/validation.device_not_found", res.GetStatus(), res.GetReason())
	}
	var series, health int
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM metric_series WHERE org_id = $1 AND device_id = $2`, orgA, devB.ID).Scan(&series))
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM poll_health WHERE org_id = $1 AND device_id = $2`, orgA, devB.ID).Scan(&health))
	if series != 0 || health != 0 {
		t.Fatalf("cross-tenant write landed: series=%d health=%d", series, health)
	}
}

// TestM9PollHealthRLSIsolation probes the table-level tenancy directly.
func TestM9PollHealthRLSIsolation(t *testing.T) {
	ctx := context.Background()
	orgA, siteA, _ := devTenant(t, "m9-rls-a-"+newUUID()[:8])
	orgB, siteB, _ := devTenant(t, "m9-rls-b-"+newUUID()[:8])
	orgAUUID, orgBUUID := mustUUID(t, orgA), mustUUID(t, orgB)
	collectorID := seedCollectorRow(t, orgAUUID, mustUUID(t, siteA), "m9-rls-collector")
	devA := createM9Device(t, orgAUUID, mustUUID(t, siteA), "m9-rls-dev", "192.0.2.60", "standard")
	_ = siteB
	insertPollHealth(t, orgAUUID, collectorID, devA, time.Now().UTC(), 3, "success", "", 0)

	// Org B's tenant context cannot see org A's rows even with an explicit predicate.
	var seenByB int
	must(t, database.WithTenant(ctx, appPool, orgBUUID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM poll_health WHERE org_id = $1`, orgAUUID).Scan(&seenByB)
	}))
	if seenByB != 0 {
		t.Fatalf("org B sees %d org A poll_health rows", seenByB)
	}
	// No tenant context: RLS denies every row.
	var noContext int
	must(t, appPool.QueryRow(ctx, `SELECT count(*) FROM poll_health`).Scan(&noContext))
	if noContext != 0 {
		t.Fatalf("unset context sees %d poll_health rows", noContext)
	}
	// The owning tenant sees its row.
	var seenByA int
	must(t, database.WithTenant(ctx, appPool, orgAUUID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM poll_health WHERE device_id = $1`, devA).Scan(&seenByA)
	}))
	if seenByA != 1 {
		t.Fatalf("org A sees %d rows, want 1", seenByA)
	}
}

// TestM9PollHealthAPI covers authz/capability/scope, pagination and
// cross-tenant behavior of GET /v1/devices/{id}/poll-health.
func TestM9PollHealthAPI(t *testing.T) {
	env := newM9APIEnv(t, "m9-api-"+newUUID()[:8])
	orgUUID := mustUUID(t, env.orgID)
	siteUUID := mustUUID(t, env.siteID)
	collectorID := seedCollectorRow(t, orgUUID, siteUUID, "m9-api-collector")
	deviceID := mustUUID(t, env.createDevice(t, "m9-api-dev", nil))
	base := time.Now().UTC().Truncate(time.Second)
	for i, latency := range []int{30, 20, 10} {
		insertPollHealth(t, orgUUID, collectorID, deviceID, base.Add(-time.Duration(i)*time.Minute), latency, "success", "", 0)
	}

	// Newest first, bounded limit, cursor continuation.
	res := env.do(t, http.MethodGet, "/v1/devices/"+deviceID.String()+"/poll-health?limit=2", "")
	if res.Status != http.StatusOK {
		t.Fatalf("poll-health status %d body %v", res.Status, res.Body)
	}
	first := dataList(t, res.Body)
	if len(first) != 2 || res.Body["has_more"] != true {
		t.Fatalf("page1 = %d has_more=%v", len(first), res.Body["has_more"])
	}
	if first[0]["latency_ms"] != float64(30) || first[1]["latency_ms"] != float64(20) {
		t.Fatalf("ordering wrong (want newest first): %v", first)
	}
	cursor, _ := res.Body["next_cursor"].(string)
	if cursor == "" {
		t.Fatal("missing next_cursor")
	}
	res = env.do(t, http.MethodGet, "/v1/devices/"+deviceID.String()+"/poll-health?limit=2&cursor="+cursor, "")
	if res.Status != http.StatusOK || res.Body["has_more"] != false {
		t.Fatalf("page2 status %d has_more=%v", res.Status, res.Body["has_more"])
	}
	if rest := dataList(t, res.Body); len(rest) != 1 || rest[0]["latency_ms"] != float64(10) {
		t.Fatalf("page2 = %v", rest)
	}

	// Validation and enumeration resistance.
	res = env.do(t, http.MethodGet, "/v1/devices/"+deviceID.String()+"/poll-health?limit=0", "")
	requireProblem(t, res, http.StatusBadRequest, "validation.failed")
	res = env.do(t, http.MethodGet, "/v1/devices/"+deviceID.String()+"/poll-health?cursor=not-base64!", "")
	requireProblem(t, res, http.StatusBadRequest, "validation.failed")
	res = env.do(t, http.MethodGet, "/v1/devices/"+newUUID()+"/poll-health", "")
	requireProblem(t, res, http.StatusNotFound, "device.not_found")

	// Unauthenticated: 401 before capability.
	anon := &http.Client{Timeout: 10 * time.Second}
	res = doRequest(t, anon, http.MethodGet, env.srv.URL+"/v1/devices/"+deviceID.String()+"/poll-health", "", nil)
	requireProblem(t, res, http.StatusUnauthorized, "auth.unauthenticated")

	// Viewer holds device.read: reads allowed.
	_, viewerEmail := seedUserWithRole(t, env, "viewer")
	viewer, viewerCSRF := loginAs(t, env, viewerEmail)
	res = doRequest(t, viewer, http.MethodGet, env.srv.URL+"/v1/devices/"+deviceID.String()+"/poll-health", "", nil)
	if res.Status != http.StatusOK {
		t.Fatalf("viewer read: status %d body %v", res.Status, res.Body)
	}
	_ = viewerCSRF

	// Scope binding to another site hides the device (uniform 404).
	site2 := createSite(t, env.orgID, "S2-"+env.slug)
	viewer2, _ := loginAs(t, env, seedViewerForSite(t, env, site2))
	res = doRequest(t, viewer2, http.MethodGet, env.srv.URL+"/v1/devices/"+deviceID.String()+"/poll-health", "", nil)
	requireProblem(t, res, http.StatusNotFound, "device.not_found")

	// Cross-tenant: org B cannot read org A's device poll health.
	other := newM9APIEnv(t, "m9-api-b-"+newUUID()[:8])
	res = other.do(t, http.MethodGet, "/v1/devices/"+deviceID.String()+"/poll-health", "")
	requireProblem(t, res, http.StatusNotFound, "device.not_found")
}

// seedViewerForSite inserts a viewer restricted to one site.
func seedViewerForSite(t *testing.T, env *inventoryEnv, siteID string) string {
	t.Helper()
	userID, email := seedUserWithRole(t, env, "viewer")
	bindScope(t, env.orgID, userID, "site", siteID)
	return email
}

// TestM9PollHealthSchemaAndRetention pins the migration 000015 contract:
// hypertable, 1-day chunks, FORCE RLS and the canonical 90-day retention that
// actually drops old chunks.
func TestM9PollHealthSchemaAndRetention(t *testing.T) {
	ctx := context.Background()

	var dims int
	must(t, ownerPool.QueryRow(ctx,
		`SELECT num_dimensions FROM timescaledb_information.hypertables WHERE hypertable_name = 'poll_health'`).Scan(&dims))
	if dims != 1 {
		t.Fatalf("poll_health num_dimensions = %d, want 1", dims)
	}
	var interval string
	must(t, ownerPool.QueryRow(ctx,
		`SELECT time_interval::text FROM timescaledb_information.dimensions WHERE hypertable_name = 'poll_health'`).Scan(&interval))
	if interval != "1 day" {
		t.Fatalf("poll_health chunk interval = %q, want \"1 day\"", interval)
	}
	var dropAfter string
	must(t, ownerPool.QueryRow(ctx, `
		SELECT config->>'drop_after' FROM timescaledb_information.jobs
		WHERE proc_name = 'policy_retention' AND hypertable_name = 'poll_health'`).Scan(&dropAfter))
	if dropAfter != "90 days" {
		t.Fatalf("retention = %q, want \"90 days\"", dropAfter)
	}
	var rls, forced bool
	must(t, ownerPool.QueryRow(ctx,
		`SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'poll_health'`).Scan(&rls, &forced))
	if !rls || !forced {
		t.Fatalf("poll_health RLS enabled=%v forced=%v, want true/true", rls, forced)
	}

	// Retention mechanics: an old chunk is droppable, a recent one is not.
	orgID, siteID, _ := devTenant(t, "m9-ret-"+newUUID()[:8])
	orgUUID, siteUUID := mustUUID(t, orgID), mustUUID(t, siteID)
	collectorID := seedCollectorRow(t, orgUUID, siteUUID, "m9-ret-collector")
	dev := createM9Device(t, orgUUID, siteUUID, "m9-ret-dev", "192.0.2.77", "standard")
	insertPollHealth(t, orgUUID, collectorID, dev, time.Now().UTC().Add(-100*24*time.Hour), 1, "success", "", 0)
	insertPollHealth(t, orgUUID, collectorID, dev, time.Now().UTC(), 2, "success", "", 0)

	if _, err := ownerPool.Exec(ctx,
		`SELECT drop_chunks('poll_health', older_than => now() - INTERVAL '90 days')`); err != nil {
		t.Fatalf("drop_chunks: %v", err)
	}
	var oldRows, newRows int
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM poll_health WHERE device_id = $1 AND ts < now() - INTERVAL '90 days'`, dev).Scan(&oldRows))
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM poll_health WHERE device_id = $1 AND ts > now() - INTERVAL '89 days'`, dev).Scan(&newRows))
	if oldRows != 0 || newRows != 1 {
		t.Fatalf("after drop_chunks old=%d recent=%d, want 0/1", oldRows, newRows)
	}
}
