package integration

// M10-S0 (Phase 2): the two M9 deferrals — operator-facing device criticality
// (wires the M9-S4 5-minute failure-backoff ceiling, docs/07 §12.3) and
// idempotency-keyed on-demand checks (P2-AC-14 "scheduled and on-demand runs",
// docs/12 §22.1). Everything runs against the containerized database, the real
// in-process collector control plane (mTLS gRPC, signed policy, session
// registry) and the pinned snmpsim fixture; the ICMP probe uses a deterministic
// fake Pinger because CI hosts have no raw-socket capability (same seam the
// M9-S1/S4 suites use).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
	"github.com/argus-platform/argus/internal/api"
	"github.com/argus-platform/argus/internal/collector"
	collectoridentity "github.com/argus-platform/argus/internal/collector/identity"
	"github.com/argus-platform/argus/internal/collector/poll"
	"github.com/argus-platform/argus/internal/collector/spool"
	"github.com/argus-platform/argus/internal/collector/stream"
	"github.com/argus-platform/argus/internal/modules/checks"
	"github.com/argus-platform/argus/internal/modules/collectors"
	"github.com/argus-platform/argus/internal/modules/identity"
	"github.com/argus-platform/argus/internal/modules/inventory"
	"github.com/argus-platform/argus/internal/modules/pollhealth"
	"github.com/argus-platform/argus/internal/modules/tenancy"
	"github.com/argus-platform/argus/internal/platform/database"
	"github.com/argus-platform/argus/internal/platform/telemetry"
)

// decodePolicyDocument unmarshals a signed policy document for target
// assertions.
func decodePolicyDocument(t *testing.T, raw []byte) collectors.PolicyDocument {
	t.Helper()
	var doc collectors.PolicyDocument
	must(t, json.Unmarshal(raw, &doc))
	return doc
}

// m10Env bundles the in-process collector control plane (m3Env) with the public
// API wired for checks, sharing one checks service/session registry.
type m10Env struct {
	*m3Env
	api *inventoryEnv
}

func newM10Env(t *testing.T, slug string) *m10Env {
	t.Helper()
	m3 := startM3Env(t)
	seed := seedLoginUser(t, slug, "HQ-"+slug)

	tenancySvc := tenancy.New(appPool, authPool)
	identitySvc, err := identity.New(appPool, authPool, tenancySvc)
	must(t, err)
	router := api.NewRouter(api.Options{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Telemetry:  telemetry.New("it-m10", "0", "0"),
		Version:    "it",
		Commit:     "it",
		Identity:   identitySvc,
		Tenancy:    tenancySvc,
		Inventory:  inventory.New(appPool, nil),
		PollHealth: pollhealth.New(appPool),
		Checks:     m3.checks,
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
	return &m10Env{
		m3Env: m3,
		api: &inventoryEnv{
			srv: srv, client: client, slug: slug,
			orgID: seed.OrgID, siteID: seed.SiteID, csrf: csrf.Value,
		},
	}
}

func (e *m10Env) org() uuid.UUID  { return uuid.MustParse(e.api.orgID) }
func (e *m10Env) site() uuid.UUID { return uuid.MustParse(e.api.siteID) }

// createCheck posts an on-demand check with the session's CSRF token and the
// supplied Idempotency-Key ("" omits the header on purpose).
func (e *m10Env) createCheck(t *testing.T, deviceID, pollType, key string) apiResponse {
	t.Helper()
	headers := map[string]string{"X-CSRF-Token": e.api.csrf}
	if key != "" {
		headers["Idempotency-Key"] = key
	}
	return doRequest(t, e.api.client, http.MethodPost,
		e.api.srv.URL+"/v1/devices/"+deviceID+"/checks",
		`{"poll_type":"`+pollType+`"}`, headers)
}

func (e *m10Env) getCheck(t *testing.T, checkID string) apiResponse {
	t.Helper()
	return doRequest(t, e.api.client, http.MethodGet, e.api.srv.URL+"/v1/checks/"+checkID, "", nil)
}

// waitCheckStatus polls GET /v1/checks/{id} until the expected status (or fails
// the test at the deadline).
func waitCheckStatus(t *testing.T, env *m10Env, checkID, want string, timeout time.Duration) map[string]any {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last map[string]any
	for time.Now().Before(deadline) {
		res := env.getCheck(t, checkID)
		if res.Status == http.StatusOK {
			last = res.Body
			if res.Body["status"] == want {
				return res.Body
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("check %s did not reach %s within %s (last %v)", checkID, want, timeout, last)
	return nil
}

// waitNoPendingChecks waits until every check of the device is terminal.
func waitNoPendingChecks(t *testing.T, orgID, deviceID uuid.UUID, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var pending int
		must(t, ownerPool.QueryRow(context.Background(),
			`SELECT count(*) FROM device_checks WHERE org_id = $1 AND device_id = $2 AND status = 'pending'`,
			orgID, deviceID).Scan(&pending))
		if pending == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("pending checks did not drain in time")
}

// m10FakePinger is a deterministic Pinger (the raw-socket seam). delay models
// wire time so latency assertions are non-zero.
type m10FakePinger struct {
	mu    sync.Mutex
	rtts  []time.Duration
	err   error
	delay time.Duration
	calls int
}

func (p *m10FakePinger) Ping(context.Context, netip.Addr, int, time.Duration, time.Duration) ([]time.Duration, error) {
	if p.delay > 0 {
		time.Sleep(p.delay)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.err != nil {
		return nil, p.err
	}
	return append([]time.Duration(nil), p.rtts...), nil
}

func (p *m10FakePinger) Close() error { return nil }

func (p *m10FakePinger) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

// m10CheckAdapter maps poll.CheckExecutor onto the stream client's check
// surface (the cmd/argus-collector adapter is the same three lines).
type m10CheckAdapter struct{ runner *poll.CheckExecutor }

func (a m10CheckAdapter) ExecuteCheck(ctx context.Context, req stream.CheckRequest) stream.CheckOutcome {
	res, ok := a.runner.RunCheck(ctx, req.DeviceID, req.PollType)
	if !ok {
		return stream.CheckOutcome{Outcome: poll.OutcomeFailure, ErrorClass: poll.ErrorTargetMissing}
	}
	return stream.CheckOutcome{
		Outcome:    res.Outcome(),
		ErrorClass: res.ErrorClass,
		LatencyMS:  int(res.Latency.Milliseconds()),
	}
}

// dialCheckCollector runs the real collector stream client with on-demand check
// execution enabled. The returned cancel/stopped pair lets tests end the
// session deterministically before opening a raw stream for the same identity.
func (e *m10Env) dialCheckCollector(t *testing.T, id collectoridentity.Identity, store *collectoridentity.Store, runner *poll.CheckExecutor) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	machine := collector.NewMachine(collector.StateNew, nil)
	must(t, machine.Transition(collector.StateReconnecting))
	certPath, keyPath, _, _ := store.Paths()
	keyDER, err := base64StdDecode(id.PolicyKeyDERB64)
	must(t, err)
	client := stream.New(stream.Config{
		StreamAddr:   e.streamAddr,
		CAFile:       e.caFile,
		CertFile:     certPath,
		KeyFile:      keyPath,
		CollectorID:  id.CollectorID,
		PolicyDir:    t.TempDir(),
		PolicyKeyDER: keyDER,
		Checks:       m10CheckAdapter{runner: runner},
	}, machine)
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		_ = client.Run(ctx)
	}()
	// Wait until the session is registered so checks are pushed, not pending.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if e.registry.HasSession(mustUUID(t, id.CollectorID)) {
			return cancel, stopped
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	t.Fatal("collector session did not register")
	return cancel, stopped
}

func m10ICMPRunner(deviceID, ip string, pinger *m10FakePinger, onHealth func(poll.Health)) *poll.CheckExecutor {
	prober := poll.NewICMPProber(poll.ICMPConfig{Pinger: pinger})
	return poll.NewCheckExecutor(prober, func() []poll.Target {
		return []poll.Target{{
			DeviceID: deviceID, MgmtIP: netip.MustParseAddr(ip), Name: deviceID,
			Tier: poll.TierStandard, PollType: poll.PollICMP,
		}}
	}, onHealth)
}

// TestM10S0DeviceCriticalAPIAndPolicy proves the operator-facing criticality
// source end to end: accepted/returned by the inventory API (create, update,
// payload) and carried by the signed policy bundle to the collector.
func TestM10S0DeviceCriticalAPIAndPolicy(t *testing.T) {
	env := newM10Env(t, "m10-crit-"+newUUID()[:8])
	ctx := context.Background()

	dev := env.api.createDevice(t, "m10-critical", map[string]any{
		"mgmt_ip": "192.0.2.30", "critical": true,
	})
	res := env.api.do(t, http.MethodGet, "/v1/devices/"+dev, "")
	if res.Status != http.StatusOK || res.Body["critical"] != true {
		t.Fatalf("created critical device payload: %d %v", res.Status, res.Body)
	}
	res = env.api.do(t, http.MethodPatch, "/v1/devices/"+dev, `{"critical":false}`)
	if res.Status != http.StatusOK || res.Body["critical"] != false {
		t.Fatalf("critical=false patch: %d %v", res.Status, res.Body)
	}
	res = env.api.do(t, http.MethodPatch, "/v1/devices/"+dev, `{"critical":true}`)
	if res.Status != http.StatusOK || res.Body["critical"] != true {
		t.Fatalf("critical=true patch: %d %v", res.Status, res.Body)
	}
	res = env.api.do(t, http.MethodPatch, "/v1/devices/"+dev, `{"critical":"yes"}`)
	requireProblem(t, res, http.StatusBadRequest, "validation.failed")

	// Non-critical default + payload round-trip.
	plain := env.api.createDevice(t, "m10-plain", map[string]any{"mgmt_ip": "192.0.2.31"})
	res = env.api.do(t, http.MethodGet, "/v1/devices/"+plain, "")
	if res.Status != http.StatusOK || res.Body["critical"] != false {
		t.Fatalf("default critical payload: %d %v", res.Status, res.Body)
	}

	// The signed policy bundle carries the flag on the poll targets.
	raw, _, _, err := env.svc.CreateEnrollmentToken(ctx, env.org(), env.site(), time.Hour, nil)
	must(t, err)
	id, _ := env.enrollIdentity(t, "collector-m10-crit", raw)
	sp, err := env.svc.LatestPolicy(ctx, env.org(), mustUUID(t, id.CollectorID))
	must(t, err)
	if sp == nil {
		t.Fatal("no policy issued at enrollment")
	}
	doc := decodePolicyDocument(t, sp.Document)
	byDevice := map[string]bool{}
	for _, tg := range doc.Targets {
		byDevice[tg.DeviceID] = tg.Critical
	}
	if !byDevice[dev] {
		t.Fatalf("critical target flag missing for %s in %+v", dev, doc.Targets)
	}
	if byDevice[plain] {
		t.Fatalf("plain device %s unexpectedly critical", plain)
	}
}

// TestM10S0CriticalBackoffCeilingMechanism drives two real engines (critical vs
// non-critical) on one injected clock with a failing prober: the critical
// target stops doubling at the canonical 5-minute ceiling (300 s) while the
// non-critical target continues toward 15 minutes.
func TestM10S0CriticalBackoffCeilingMechanism(t *testing.T) {
	// TargetFromPolicy carries the flag into the engine target.
	target, err := poll.TargetFromPolicy(poll.TargetSpec{
		DeviceID: uuid.NewString(), MgmtIP: "192.0.2.9", Tier: "standard", PollType: "icmp", Critical: true,
	})
	if err != nil || !target.Critical {
		t.Fatalf("TargetFromPolicy critical = %v err=%v", target.Critical, err)
	}

	clock := &itClock{now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	fail := poll.Result{PollType: poll.PollICMP, Sent: 3, LossPercent: 100, ErrorClass: poll.ErrorTimeout}
	critProber := &s4ScriptedProber{script: []poll.Result{fail}}
	normProber := &s4ScriptedProber{script: []poll.Result{fail}}
	crit := poll.NewEngine(poll.Config{Prober: critProber, Clock: clock, Backoff: poll.AdaptiveBackoff{Rand: s4Rand{0.5}}})
	norm := poll.NewEngine(poll.Config{Prober: normProber, Clock: clock, Backoff: poll.AdaptiveBackoff{Rand: s4Rand{0.5}}})
	crit.ApplyTargets([]poll.Target{{
		DeviceID: "crit", MgmtIP: netip.MustParseAddr("192.0.2.1"),
		Tier: poll.TierStandard, PollType: poll.PollICMP, Critical: true,
	}})
	norm.ApplyTargets([]poll.Target{{
		DeviceID: "norm", MgmtIP: netip.MustParseAddr("192.0.2.2"),
		Tier: poll.TierStandard, PollType: poll.PollICMP,
	}})

	step := func() (int, int) {
		return crit.Step(context.Background(), clock.Now()), norm.Step(context.Background(), clock.Now())
	}
	// 0 s: both probe once -> next 120 s (60 x 2^1).
	if c, n := step(); c != 1 || n != 1 {
		t.Fatalf("t0 probes = %d/%d, want 1/1", c, n)
	}
	clock.Advance(120 * time.Second) // 120 s
	if c, n := step(); c != 1 || n != 1 {
		t.Fatalf("t120 probes = %d/%d, want 1/1", c, n)
	}
	clock.Advance(240 * time.Second) // 360 s
	if c, n := step(); c != 1 || n != 1 {
		t.Fatalf("t360 probes = %d/%d, want 1/1", c, n)
	}
	clock.Advance(300 * time.Second) // 660 s: critical is due again (300 s cap), normal is not (480 s)
	if c, n := step(); c != 1 || n != 0 {
		t.Fatalf("t660 probes = %d/%d, want critical 1 / normal 0 (5-min ceiling)", c, n)
	}
	clock.Advance(300 * time.Second) // 960 s: critical is due again (300 s cap); normal is also due (840 s)
	if c, n := step(); c != 1 || n != 1 {
		t.Fatalf("t960 probes = %d/%d, want 1/1", c, n)
	}
	// Critical probed 5 times by 960 s (0/120/360/660/960); normal probed 4
	// (0/120/360/840) because its third-failure interval is 480 s, not the
	// 300 s critical ceiling.
	if critProber.count() != 5 || normProber.count() != 4 {
		t.Fatalf("total probes critical/normal = %d/%d, want 5/4", critProber.count(), normProber.count())
	}
}

// TestM10S0OnDemandCheckICMPEndToEnd is the headline ICMP check: API 202 ->
// session push -> real ICMPProber (fake pinger) -> CheckResult -> GET completed
// with outcome/latency; the probe also lands in poll_health as origin=on_demand
// with no metric samples.
func TestM10S0OnDemandCheckICMPEndToEnd(t *testing.T) {
	env := newM10Env(t, "m10-icmp-"+newUUID()[:8])
	ctx := context.Background()
	dev := env.api.createDevice(t, "m10-icmp-dev", map[string]any{"mgmt_ip": "192.0.2.44"})

	raw, _, _, err := env.svc.CreateEnrollmentToken(ctx, env.org(), env.site(), time.Hour, nil)
	must(t, err)
	id, store := env.enrollIdentity(t, "collector-m10-icmp", raw)

	pinger := &m10FakePinger{rtts: []time.Duration{time.Millisecond, 2 * time.Millisecond, 3 * time.Millisecond}, delay: 3 * time.Millisecond}
	var mu sync.Mutex
	var health []poll.Health
	runner := m10ICMPRunner(dev, "192.0.2.44", pinger, func(h poll.Health) {
		mu.Lock()
		health = append(health, h)
		mu.Unlock()
	})
	cancel, stopped := env.dialCheckCollector(t, id, store, runner)
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			cancel()
			<-stopped
		})
	}
	defer stop()

	res := env.createCheck(t, dev, "icmp", newUUID())
	if res.Status != http.StatusAccepted {
		t.Fatalf("check create: %d %v", res.Status, res.Body)
	}
	checkID, _ := res.Body["check_id"].(string)
	if checkID == "" || res.Body["status_url"] != "/v1/checks/"+checkID {
		t.Fatalf("check create body = %v", res.Body)
	}
	body := waitCheckStatus(t, env, checkID, checks.StatusCompleted, 15*time.Second)
	if body["outcome"] != "success" || body["error_class"] != "" {
		t.Fatalf("check outcome = %v", body)
	}
	if lat, _ := body["latency_ms"].(float64); lat <= 0 {
		t.Fatalf("check latency = %v, want > 0", body["latency_ms"])
	}
	if pinger.callCount() != 1 {
		t.Fatalf("pinger calls = %d, want 1", pinger.callCount())
	}
	stop()

	mu.Lock()
	hs := append([]poll.Health(nil), health...)
	mu.Unlock()
	if len(hs) != 1 || hs[0].Origin != poll.OriginOnDemand || hs[0].ConsecutiveFailures != 0 {
		t.Fatalf("on-demand health = %+v", hs)
	}

	// The health row reaches the DB through the real spool/gRPC/ingest path.
	rs := dialBatchStream(t, env.m3Env, id, store)
	batch := (&spool.Batch{Seq: 1, At: time.Now().UTC(), Health: toSpoolHealthIT(hs)}).ToProto()
	must(t, rs.stream.Send(&collectorv1.ClientMessage{Msg: &collectorv1.ClientMessage_Batch{Batch: batch}}))
	if r := rs.result(t); r.GetStatus() != collectorv1.BatchResult_STATUS_OK {
		t.Fatalf("health batch result = %v/%s", r.GetStatus(), r.GetReason())
	}
	var origin, outcome string
	var fails int
	must(t, ownerPool.QueryRow(ctx, `
		SELECT origin, outcome, consecutive_failures FROM poll_health
		WHERE org_id = $1 AND device_id = $2 AND poll_type = 'icmp'`, env.org(), mustUUID(t, dev)).
		Scan(&origin, &outcome, &fails))
	if origin != "on_demand" || outcome != "success" || fails != 0 {
		t.Fatalf("poll_health = %s/%s/%d, want on_demand/success/0", origin, outcome, fails)
	}
	var samples int
	must(t, ownerPool.QueryRow(ctx, `
		SELECT count(*) FROM metric_samples ms
		JOIN metric_series s ON s.id = ms.series_id
		WHERE ms.org_id = $1 AND s.device_id = $2`, env.org(), mustUUID(t, dev)).Scan(&samples))
	if samples != 0 {
		t.Fatalf("on-demand check emitted %d metric samples; it must not", samples)
	}
	var collectorID uuid.UUID
	must(t, ownerPool.QueryRow(ctx,
		`SELECT collector_id FROM device_checks WHERE id = $1`, mustUUID(t, checkID)).Scan(&collectorID))
	if collectorID.String() != id.CollectorID {
		t.Fatalf("check routed to collector %s, want %s", collectorID, id.CollectorID)
	}
}

// TestM10S0OnDemandCheckSNMPEndToEnd runs a real SNMP probe against the pinned
// snmpsim fixture through the same check path.
func TestM10S0OnDemandCheckSNMPEndToEnd(t *testing.T) {
	env := newM10Env(t, "m10-snmp-"+newUUID()[:8])
	ctx := context.Background()
	host, port := snmpsimFixture(t)
	if _, err := netip.ParseAddr(host); err != nil {
		t.Fatalf("snmpsim host %q is not an address: %v", host, err)
	}
	dev := env.api.createDevice(t, "m10-snmp-dev", map[string]any{"mgmt_ip": "127.0.0.1", "kind": "switch"})

	raw, _, _, err := env.svc.CreateEnrollmentToken(ctx, env.org(), env.site(), time.Hour, nil)
	must(t, err)
	id, store := env.enrollIdentity(t, "collector-m10-snmp", raw)

	creds := poll.NewStaticCredentialSource()
	creds.Set(dev, v2cCreds("switch"))
	prober := poll.NewSNMPProber(poll.SNMPProberConfig{
		Credentials:   creds,
		ClientFactory: snmpsimFactory(port, 2*time.Second, 1),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	runner := poll.NewCheckExecutor(prober, func() []poll.Target {
		return []poll.Target{{
			DeviceID: dev, MgmtIP: netip.MustParseAddr(host), Name: "m10-snmp-dev",
			Tier: poll.TierStandard, PollType: poll.PollSNMP, Kind: "switch",
		}}
	}, nil)
	cancel, stopped := env.dialCheckCollector(t, id, store, runner)

	res := env.createCheck(t, dev, "snmp", newUUID())
	if res.Status != http.StatusAccepted {
		t.Fatalf("snmp check create: %d %v", res.Status, res.Body)
	}
	checkID, _ := res.Body["check_id"].(string)
	body := waitCheckStatus(t, env, checkID, checks.StatusCompleted, 30*time.Second)
	if body["outcome"] != "success" || body["error_class"] != "" {
		t.Fatalf("snmp check body = %v", body)
	}
	cancel()
	<-stopped
}

// TestM10S0CheckIdempotencyAuthzAndIsolation covers the API contract: replay
// returns the original check with Idempotent-Replayed, missing key/CSRF deny,
// viewer cannot trigger (diagnostic.run), scope and tenant isolation are
// 404-uniform, and device_checks obeys RLS.
func TestM10S0CheckIdempotencyAuthzAndIsolation(t *testing.T) {
	env := newM10Env(t, "m10-authz-"+newUUID()[:8])
	ctx := context.Background()
	dev := env.api.createDevice(t, "m10-authz-dev", map[string]any{"mgmt_ip": "192.0.2.55"})

	// A registered (offline) collector is enough to accept the check requests.
	raw, _, _, err := env.svc.CreateEnrollmentToken(ctx, env.org(), env.site(), time.Hour, nil)
	must(t, err)
	_, _ = env.enrollIdentity(t, "collector-m10-authz", raw)

	key := "idem-" + newUUID()
	first := env.createCheck(t, dev, "icmp", key)
	if first.Status != http.StatusAccepted {
		t.Fatalf("first check: %d %v", first.Status, first.Body)
	}
	checkID, _ := first.Body["check_id"].(string)
	replay := env.createCheck(t, dev, "icmp", key)
	if replay.Status != http.StatusAccepted || replay.Body["check_id"] != checkID {
		t.Fatalf("replay = %d %v, want the original check %s", replay.Status, replay.Body, checkID)
	}
	if replay.Header.Get("Idempotent-Replayed") != "true" {
		t.Fatalf("replay header = %q, want Idempotent-Replayed true", replay.Header.Get("Idempotent-Replayed"))
	}
	var rows int
	must(t, ownerPool.QueryRow(ctx, `SELECT count(*) FROM device_checks WHERE org_id = $1 AND request_key = $2`,
		env.org(), key).Scan(&rows))
	if rows != 1 {
		t.Fatalf("idempotent replay created %d rows, want 1", rows)
	}

	// Missing Idempotency-Key / CSRF are refused before any state change.
	noKey := env.createCheck(t, dev, "icmp", "")
	requireProblem(t, noKey, http.StatusBadRequest, "validation.failed")
	noCSRF := doRequest(t, env.api.client, http.MethodPost, env.api.srv.URL+"/v1/devices/"+dev+"/checks",
		`{"poll_type":"icmp"}`, map[string]string{"Idempotency-Key": "no-csrf-" + newUUID()})
	requireProblem(t, noCSRF, http.StatusForbidden, "auth.csrf")
	badType := env.createCheck(t, dev, "tcp", "bad-type-"+newUUID())
	requireProblem(t, badType, http.StatusBadRequest, "validation.failed")

	// Viewer: reads allowed, triggering denied (canonical docs/04 §6.4).
	_, viewerEmail := seedUserWithRole(t, env.api, "viewer")
	viewer, viewerCSRF := loginAs(t, env.api, viewerEmail)
	res := doRequest(t, viewer, http.MethodGet, env.api.srv.URL+"/v1/checks/"+checkID, "", nil)
	if res.Status != http.StatusOK {
		t.Fatalf("viewer check read: %d %v", res.Status, res.Body)
	}
	res = doRequest(t, viewer, http.MethodPost, env.api.srv.URL+"/v1/devices/"+dev+"/checks",
		`{"poll_type":"icmp"}`, map[string]string{"X-CSRF-Token": viewerCSRF, "Idempotency-Key": "viewer-" + newUUID()})
	requireProblem(t, res, http.StatusForbidden, "auth.forbidden")

	// Site-scoped admin (bound to another site): foreign device/check are 404.
	otherSite := createSite(t, env.api.orgID, "m10-other-"+newUUID()[:8])
	scopedID, scopedEmail := seedUserWithRole(t, env.api, "admin")
	bindScope(t, env.api.orgID, scopedID, "site", otherSite)
	scoped, scopedCSRF := loginAs(t, env.api, scopedEmail)
	res = doRequest(t, scoped, http.MethodGet, env.api.srv.URL+"/v1/checks/"+checkID, "", nil)
	requireProblem(t, res, http.StatusNotFound, "check.not_found")
	res = doRequest(t, scoped, http.MethodPost, env.api.srv.URL+"/v1/devices/"+dev+"/checks",
		`{"poll_type":"icmp"}`, map[string]string{"X-CSRF-Token": scopedCSRF, "Idempotency-Key": "scoped-" + newUUID()})
	requireProblem(t, res, http.StatusNotFound, "device.not_found")

	// Cross-tenant: org B sees neither the check nor the device.
	other := newM10Env(t, "m10-iso-"+newUUID()[:8])
	res = other.getCheck(t, checkID)
	requireProblem(t, res, http.StatusNotFound, "check.not_found")
	res = other.createCheck(t, dev, "icmp", newUUID())
	requireProblem(t, res, http.StatusNotFound, "device.not_found")

	// RLS floor: org B's tenant transaction and the unset context see nothing.
	var seen int
	must(t, database.WithTenant(ctx, appPool, other.org(), func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM device_checks WHERE id = $1`, mustUUID(t, checkID)).Scan(&seen)
	}))
	if seen != 0 {
		t.Fatalf("org B sees %d org A check rows", seen)
	}
	must(t, appPool.QueryRow(ctx, `SELECT count(*) FROM device_checks`).Scan(&seen))
	if seen != 0 {
		t.Fatalf("unset context sees %d device_checks rows", seen)
	}
}

// TestM10S0CheckOfflinePendingRedeliveryAndLimits pins the bounded pending
// semantics: an offline collector leaves requests pending, the per-device
// ceiling rejects excess with 409, the TTL fails stale rows as expired, and a
// reconnect redelivers and completes them.
func TestM10S0CheckOfflinePendingRedeliveryAndLimits(t *testing.T) {
	env := newM10Env(t, "m10-offline-"+newUUID()[:8])
	ctx := context.Background()
	dev := env.api.createDevice(t, "m10-offline-dev", map[string]any{"mgmt_ip": "192.0.2.66"})

	raw, _, _, err := env.svc.CreateEnrollmentToken(ctx, env.org(), env.site(), time.Hour, nil)
	must(t, err)
	id, store := env.enrollIdentity(t, "collector-m10-offline", raw)

	// No stream is connected: requests are accepted and stay pending.
	var ids []string
	for i := 0; i < checks.PendingLimit; i++ {
		res := env.createCheck(t, dev, "icmp", fmt.Sprintf("offline-%d-%s", i, newUUID()))
		if res.Status != http.StatusAccepted {
			t.Fatalf("offline check %d: %d %v", i, res.Status, res.Body)
		}
		ids = append(ids, res.Body["check_id"].(string))
	}
	if body := env.getCheck(t, ids[0]).Body; body["status"] != checks.StatusPending {
		t.Fatalf("offline check status = %v, want pending", body["status"])
	}
	over := env.createCheck(t, dev, "icmp", "offline-over-"+newUUID())
	requireProblem(t, over, http.StatusConflict, "check.pending_limit")

	// Backdating a pending row past the TTL expires it (lazily on read) and
	// frees one slot.
	var expiredID uuid.UUID
	must(t, ownerPool.QueryRow(ctx, `
		UPDATE device_checks SET created_at = now() - INTERVAL '20 minutes'
		WHERE id = $1 RETURNING id`, mustUUID(t, ids[0])).Scan(&expiredID))
	expired := env.getCheck(t, ids[0]).Body
	if expired["status"] != checks.StatusFailed || expired["error_class"] != checks.ClassExpired {
		t.Fatalf("expired check = %v", expired)
	}
	afterExpire := env.createCheck(t, dev, "icmp", "offline-after-expire-"+newUUID())
	if afterExpire.Status != http.StatusAccepted {
		t.Fatalf("check after expiry: %d %v", afterExpire.Status, afterExpire.Body)
	}

	// Reconnect: redelivery completes every pending check.
	pinger := &m10FakePinger{rtts: []time.Duration{time.Millisecond}}
	runner := m10ICMPRunner(dev, "192.0.2.66", pinger, nil)
	cancel, stopped := env.dialCheckCollector(t, id, store, runner)
	defer func() { cancel(); <-stopped }()
	waitNoPendingChecks(t, env.org(), mustUUID(t, dev), 30*time.Second)

	var completed, failed int
	must(t, ownerPool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE status = 'completed'), count(*) FILTER (WHERE status = 'failed')
		FROM device_checks WHERE org_id = $1 AND device_id = $2`, env.org(), mustUUID(t, dev)).Scan(&completed, &failed))
	// PendingLimit checks were redelivered on reconnect; the backdated one was
	// failed as expired before redelivery.
	if completed != checks.PendingLimit || failed != 1 {
		t.Fatalf("terminal checks completed=%d failed=%d, want %d/1", completed, failed, checks.PendingLimit)
	}
}

// TestM10S0CheckResultReplayDoesNotDoubleApply sends a second, contradictory
// CheckResult after completion (wire + service) and proves the first terminal
// outcome wins.
func TestM10S0CheckResultReplayDoesNotDoubleApply(t *testing.T) {
	env := newM10Env(t, "m10-replay-"+newUUID()[:8])
	ctx := context.Background()
	dev := env.api.createDevice(t, "m10-replay-dev", map[string]any{"mgmt_ip": "192.0.2.77"})

	raw, _, _, err := env.svc.CreateEnrollmentToken(ctx, env.org(), env.site(), time.Hour, nil)
	must(t, err)
	id, store := env.enrollIdentity(t, "collector-m10-replay", raw)

	pinger := &m10FakePinger{rtts: []time.Duration{time.Millisecond, 2 * time.Millisecond, 3 * time.Millisecond}, delay: 2 * time.Millisecond}
	runner := m10ICMPRunner(dev, "192.0.2.77", pinger, nil)
	cancel, stopped := env.dialCheckCollector(t, id, store, runner)
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			cancel()
			<-stopped
		})
	}
	defer stop()

	res := env.createCheck(t, dev, "icmp", newUUID())
	checkID, _ := res.Body["check_id"].(string)
	waitCheckStatus(t, env, checkID, checks.StatusCompleted, 15*time.Second)
	stop()

	var (
		firstOutcome string
		firstClass   string
		firstLatency int
		firstDone    time.Time
	)
	must(t, ownerPool.QueryRow(ctx, `
		SELECT outcome, error_class, latency_ms, completed_at FROM device_checks WHERE id = $1`, mustUUID(t, checkID)).
		Scan(&firstOutcome, &firstClass, &firstLatency, &firstDone))
	if firstOutcome != "success" || firstClass != "" {
		t.Fatalf("first outcome/class = %s/%s", firstOutcome, firstClass)
	}

	// Wire replay from the same collector with contradictory values.
	rs := dialBatchStream(t, env.m3Env, id, store)
	must(t, rs.stream.Send(&collectorv1.ClientMessage{
		Msg: &collectorv1.ClientMessage_CheckResult{CheckResult: &collectorv1.CheckResult{
			CheckId: checkID, Outcome: "failure", ErrorClass: "timeout", LatencyMs: 9999,
		}},
	}))
	time.Sleep(300 * time.Millisecond)
	var outcome, class string
	var latency int
	var done time.Time
	must(t, ownerPool.QueryRow(ctx, `
		SELECT outcome, error_class, latency_ms, completed_at FROM device_checks WHERE id = $1`, mustUUID(t, checkID)).
		Scan(&outcome, &class, &latency, &done))
	if outcome != firstOutcome || class != firstClass || latency != firstLatency || !done.Equal(firstDone) {
		t.Fatalf("replayed result changed the row: %s/%s/%d/%s (first %s/%s/%d/%s)",
			outcome, class, latency, done, firstOutcome, firstClass, firstLatency, firstDone)
	}

	// Service-level replay reports applied=false and a foreign collector id is
	// rejected by the collector_id guard.
	applied, err := env.checks.RecordCheckResult(ctx, env.org(), mustUUID(t, id.CollectorID), &collectorv1.CheckResult{
		CheckId: checkID, Outcome: "failure", ErrorClass: "timeout", LatencyMs: 1,
	})
	must(t, err)
	if applied {
		t.Fatal("service replay double-applied")
	}
	applied, err = env.checks.RecordCheckResult(ctx, env.org(), uuid.New(), &collectorv1.CheckResult{
		CheckId: checkID, Outcome: "failure", ErrorClass: "timeout", LatencyMs: 1,
	})
	must(t, err)
	if applied {
		t.Fatal("a foreign collector id applied the result")
	}
}
