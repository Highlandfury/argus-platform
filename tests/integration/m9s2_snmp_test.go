package integration

// M9-S2 (Phase 2): SNMP polling acceptance — a pinned snmpsim fixture serves
// a simulated switch (IF-MIB incl. HC counters) and host (hrProcessorLoad);
// the real SNMP prober runs through the S1 scheduler, samples and poll health
// flow through the real spool -> gRPC stream -> ingest path, counter
// wrap/reboot/discontinuity rules are asserted against the fixture, and the
// signed policy carries snmp poll targets for SNMP-bound devices.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
	cpolicy "github.com/argus-platform/argus/internal/collector/policy"
	"github.com/argus-platform/argus/internal/collector/poll"
	"github.com/argus-platform/argus/internal/collector/spool"
	"github.com/argus-platform/argus/internal/modules/collectors"
	"github.com/argus-platform/argus/internal/modules/ingest"
	"github.com/argus-platform/argus/internal/modules/inventory"
)

// snmpsim fixture constants (test-only credentials; M9-S3 replaces fixtures
// with signed-bundle materialization).
const (
	snmpsimV3User    = "argus"
	snmpsimV3AuthKey = "argus-auth-pass" //nolint:gosec // test fixture passphrase
	snmpsimV3PrivKey = "argus-priv-pass" //nolint:gosec // test fixture passphrase
)

var (
	snmpsimMu   sync.Mutex
	snmpsimC    testcontainers.Container
	snmpsimHost string
	snmpsimPort uint16
	snmpsimErr  error
)

// snmpsimFixture starts (once per suite) the pinned snmpsim container built
// from tests/fixtures/snmpsim/Dockerfile and returns its reachable host+port.
func snmpsimFixture(t *testing.T) (string, uint16) {
	t.Helper()
	snmpsimMu.Lock()
	defer snmpsimMu.Unlock()
	if snmpsimC == nil && snmpsimErr == nil {
		snmpsimC, snmpsimHost, snmpsimPort, snmpsimErr = startSNMPSim(context.Background())
	}
	if snmpsimErr != nil {
		t.Fatalf("snmpsim fixture: %v", snmpsimErr)
	}
	return snmpsimHost, snmpsimPort
}

// terminateSNMPSimFixture is called by the suite harness after m.Run.
func terminateSNMPSimFixture() {
	snmpsimMu.Lock()
	defer snmpsimMu.Unlock()
	if snmpsimC != nil {
		_ = testcontainers.TerminateContainer(snmpsimC)
		snmpsimC = nil
	}
}

func startSNMPSim(ctx context.Context) (testcontainers.Container, string, uint16, error) {
	dataDir, err := filepath.Abs(filepath.Join("..", "..", "tests", "fixtures", "snmpsim", "data"))
	if err != nil {
		return nil, "", 0, err
	}
	// Copy the fixture files into the container (portable across Docker
	// environments; no host bind mount needed for a few KB of .snmprec data).
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return nil, "", 0, fmt.Errorf("read snmpsim fixture data: %w", err)
	}
	var files []testcontainers.ContainerFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		files = append(files, testcontainers.ContainerFile{
			HostFilePath:      filepath.Join(dataDir, e.Name()),
			ContainerFilePath: "/data/" + e.Name(),
			FileMode:          0o644,
		})
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				Context:    filepath.Join("..", ".."),
				Dockerfile: "tests/fixtures/snmpsim/Dockerfile",
				Repo:       "argus-snmpsim-m9",
				Tag:        "test",
			},
			ExposedPorts: []string{"1161/udp"},
			Files:        files,
			Cmd: []string{
				"--cache-dir=/tmp/snmpsim-cache",
				"--log-level=info",
				"--process-user=nobody",
				"--process-group=nogroup",
				"--v3-engine-id=auto",
				"--data-dir=/data",
				"--agent-udpv4-endpoint=0.0.0.0:1161",
				"--v3-user=" + snmpsimV3User,
				"--v3-auth-proto=SHA256",
				"--v3-auth-key=" + snmpsimV3AuthKey,
				"--v3-priv-proto=AES",
				"--v3-priv-key=" + snmpsimV3PrivKey,
			},
			WaitingFor: wait.ForLog("Listening at UDP/IPv4").WithStartupTimeout(3 * time.Minute),
		},
		Started: true,
	})
	if err != nil {
		return nil, "", 0, fmt.Errorf("start snmpsim container (is Docker running?): %w", err)
	}
	host, err := c.Host(ctx)
	if err != nil {
		_ = testcontainers.TerminateContainer(c)
		return nil, "", 0, err
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	mapped, err := c.MappedPort(ctx, "1161/udp")
	if err != nil {
		_ = testcontainers.TerminateContainer(c)
		return nil, "", 0, err
	}
	portNum, err := strconv.Atoi(mapped.Port())
	if err != nil {
		_ = testcontainers.TerminateContainer(c)
		return nil, "", 0, fmt.Errorf("snmpsim mapped port %q: %w", mapped.Port(), err)
	}
	port := uint16(portNum) //nolint:gosec // mapped test port is bounded

	// Readiness: retry a v2c GET until the responder answers (the log line can
	// appear before the agent serves).
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		client, cerr := poll.NewGosnmpClient(netip.MustParseAddr(host), poll.SNMPCredentials{
			Version: poll.SNMPVersionV2c, Community: "switch",
		}, poll.ClientConfig{Port: int(port), Timeout: 500 * time.Millisecond, Retries: 0})
		if cerr == nil {
			_, gerr := client.Get([]string{"1.3.6.1.2.1.1.1.0"})
			_ = client.Close()
			if gerr == nil {
				return c, host, port, nil
			}
			lastErr = gerr
		} else {
			lastErr = cerr
		}
		time.Sleep(500 * time.Millisecond)
	}
	_ = testcontainers.TerminateContainer(c)
	return nil, "", 0, fmt.Errorf("snmpsim not ready: %w", lastErr)
}

// itClock is the integration-test injectable clock for the SNMP prober (the
// scheduler cadence itself is covered by the poll unit tests).
type itClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *itClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *itClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// After implements poll.Clock. The tests drive Step directly and never call
// Run, so the channel is closed immediately (no parking).
func (c *itClock) After(_ time.Duration) <-chan time.Time {
	ch := make(chan time.Time)
	close(ch)
	return ch
}

// snmpsimFactory builds real gosnmp clients against the fixture port.
func snmpsimFactory(port uint16, timeout time.Duration, retries int) poll.ClientFactory {
	return func(addr netip.Addr, creds poll.SNMPCredentials, cfg poll.ClientConfig) (poll.SNMPClient, error) {
		cfg.Port = int(port)
		cfg.Timeout = timeout
		cfg.Retries = retries
		return poll.NewGosnmpClient(addr, creds, cfg)
	}
}

func v2cCreds(community string) poll.SNMPCredentials {
	return poll.SNMPCredentials{Version: poll.SNMPVersionV2c, Community: community}
}

func createM9S2Device(t *testing.T, orgID, siteID uuid.UUID, name, mgmtIP, kind, profile string) uuid.UUID {
	t.Helper()
	ip := mgmtIP
	d, err := inventory.New(appPool, nil).CreateDevice(context.Background(), orgID, inventory.CreateDeviceInput{
		SiteID:      siteID,
		Name:        name,
		Kind:        kind,
		PollProfile: profile,
		MgmtIP:      &ip,
	}, inventory.Actor{})
	must(t, err)
	return d.ID
}

func siteIDForOrg(t *testing.T, orgID uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	must(t, ownerPool.QueryRow(context.Background(),
		`SELECT id FROM sites WHERE org_id = $1 ORDER BY created_at LIMIT 1`, orgID).Scan(&id))
	return id
}

func toSpoolSamplesIT(in []poll.Sample) []spool.Sample {
	out := make([]spool.Sample, len(in))
	for i, s := range in {
		out[i] = spool.Sample{
			MetricKey: s.MetricKey, Unit: s.Unit, Value: s.Value,
			Ts: s.Ts, DeviceID: s.DeviceID, Dimensions: s.Dimensions,
		}
	}
	return out
}

func toSpoolHealthIT(in []poll.Health) []spool.Health {
	out := make([]spool.Health, len(in))
	for i, h := range in {
		out[i] = spool.Health{
			DeviceID: h.DeviceID, PollType: h.PollType, LatencyMS: h.LatencyMS,
			Outcome: h.Outcome, ErrorClass: h.ErrorClass,
			ConsecutiveFailures: h.ConsecutiveFailures, CheckedAt: h.CheckedAt,
			Origin: h.Origin,
		}
	}
	return out
}

// drainSpoolToStream reads every pending spool batch and sends it on the real
// collector gRPC stream, acking each OK result (mirrors transport.Sender).
func drainSpoolToStream(t *testing.T, sp *spool.Spool, rs *rawBatchStream) int {
	t.Helper()
	r, err := sp.Reader()
	must(t, err)
	defer r.Close()
	sent := 0
	for {
		b, err := r.Next()
		must(t, err)
		if b == nil {
			return sent
		}
		must(t, rs.stream.Send(&collectorv1.ClientMessage{
			Msg: &collectorv1.ClientMessage_Batch{Batch: b.ToProto()},
		}))
		res := rs.result(t)
		if res.GetStatus() != collectorv1.BatchResult_STATUS_OK {
			t.Fatalf("spooled batch seq %d: status %v (%s)", b.Seq, res.GetStatus(), res.GetReason())
		}
		must(t, sp.Ack(b.Seq))
		sent++
	}
}

// m9s2Pipeline wires one engine + spool + stream for the end-to-end test.
type m9s2Pipeline struct {
	engine  *poll.Engine
	sp      *spool.Spool
	rs      *rawBatchStream
	mu      sync.Mutex
	samples []poll.Sample
	health  []poll.Health
}

// TestM9S2SNMPPollEndToEnd proves the full path for a switch: scheduler ->
// real SNMP client against the pinned snmpsim fixture -> spool -> gRPC ->
// ingest -> metric_series/metric_samples, with counter wrap, reboot and
// post-reboot behavior asserted from the fixture sequence switch -> swrap ->
// sreset -> sreset (P2-AC-15/16/20).
func TestM9S2SNMPPollEndToEnd(t *testing.T) {
	ctx := context.Background()
	env, id, store, orgID := m4Env(t, "m9s2-e2e-"+newUUID()[:8])
	orgUUID := mustUUID(t, orgID)
	siteID := siteIDForOrg(t, orgUUID)
	deviceID := createM9S2Device(t, orgUUID, siteID, "m9s2-switch", "127.0.0.1", "switch", "standard")
	host, port := snmpsimFixture(t)

	creds := poll.NewStaticCredentialSource()
	creds.Set(deviceID.String(), v2cCreds("switch"))
	clock := &itClock{now: time.Now().UTC()}
	prober := poll.NewSNMPProber(poll.SNMPProberConfig{
		Credentials:   creds,
		ClientFactory: snmpsimFactory(port, 2*time.Second, 1),
		Now:           clock.Now,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	p := &m9s2Pipeline{}
	p.engine = poll.NewEngine(poll.Config{
		Prober:   prober,
		Clock:    clock,
		OnSample: func(s poll.Sample) { p.mu.Lock(); p.samples = append(p.samples, s); p.mu.Unlock() },
		OnHealth: func(h poll.Health) { p.mu.Lock(); p.health = append(p.health, h); p.mu.Unlock() },
	})
	p.engine.ApplyTargets([]poll.Target{{
		DeviceID: deviceID.String(),
		MgmtIP:   netip.MustParseAddr(host),
		Name:     "m9s2-switch",
		Tier:     poll.TierStandard,
		PollType: poll.PollSNMP,
		Kind:     "switch",
	}})
	sp, err := spool.Open(spool.Options{Dir: t.TempDir(), MaxBytes: 8 << 20, FsyncInterval: 10 * time.Millisecond})
	must(t, err)
	t.Cleanup(func() { _ = sp.Close() })
	p.sp = sp
	p.rs = dialBatchStream(t, env, id, store)

	step := func(label string) (samples, health int) {
		t.Helper()
		if n := p.engine.Step(ctx, clock.Now()); n != 1 {
			t.Fatalf("%s: probed %d targets, want 1", label, n)
		}
		p.mu.Lock()
		ss, hs := p.samples, p.health
		p.samples, p.health = nil, nil
		p.mu.Unlock()
		if len(ss) == 0 || len(hs) == 0 {
			t.Fatalf("%s: samples=%d health=%d, want both", label, len(ss), len(hs))
		}
		_, err := p.sp.Append(&spool.Batch{At: time.Now().UTC(), Samples: toSpoolSamplesIT(ss), Health: toSpoolHealthIT(hs)})
		must(t, err)
		drainSpoolToStream(t, p.sp, p.rs)
		return len(ss), len(hs)
	}

	// Poll 1: seed (system + gauges; no counter samples yet).
	if samples, health := step("seed"); samples == 0 || health != 1 {
		t.Fatalf("seed step samples=%d health=%d", samples, health)
	}

	// Poll 2: the same device after a counter wrap without reboot. The
	// scheduler clock advances one standard-tier interval (60 s), so the
	// counter state machine sees an exact 60 s elapsed window.
	clock.Advance(poll.TierInterval(poll.TierStandard))
	creds.Set(deviceID.String(), v2cCreds("swrap"))
	step("wrap")

	// Poll 3: device reboot (sysUpTime drop) + counters reset -> reseed, no
	// false spike.
	clock.Advance(poll.TierInterval(poll.TierStandard))
	creds.Set(deviceID.String(), v2cCreds("sreset"))
	step("reboot")

	// Poll 4: after the reboot baseline, rates flow again (0 B/s fixture).
	clock.Advance(poll.TierInterval(poll.TierStandard))
	step("post-reboot")

	// --- assertion: counter values through the real ingest path ------------
	// Fixture deltas (modular, wrap-aware): in_octets 75, out_octets 1619,
	// in_errors 7 bytes/counts over exactly 60 s.
	assertIfCounterValues(t, orgUUID, deviceID, "net.if.in_octets", "Gi1/0/1", []float64{75.0 / 60.0, 0})
	assertIfCounterValues(t, orgUUID, deviceID, "net.if.out_octets", "Gi1/0/1", []float64{1619.0 / 60.0, 0})
	assertIfCounterValues(t, orgUUID, deviceID, "net.if.in_errors", "Gi1/0/1", []float64{7.0 / 60.0, 0})

	// No false spike anywhere in the device's rate history.
	var maxRate float64
	must(t, ownerPool.QueryRow(ctx, `
		SELECT COALESCE(MAX(ms.value), 0) FROM metric_samples ms
		JOIN metric_series s ON s.id = ms.series_id
		WHERE s.org_id = $1 AND s.device_id = $2 AND s.metric_key = 'net.if.in_octets'`,
		orgUUID, deviceID).Scan(&maxRate))
	if maxRate > 1000 {
		t.Fatalf("in_octets rate history contains a spike: max=%g", maxRate)
	}

	// Interface series carry if_name/if_alias dimensions and never if_index.
	var withIndex int
	must(t, ownerPool.QueryRow(ctx, `
		SELECT count(*) FROM metric_series
		WHERE org_id = $1 AND device_id = $2 AND dimensions ? 'if_index'`, orgUUID, deviceID).Scan(&withIndex))
	if withIndex != 0 {
		t.Fatalf("%d series carry an if_index dimension; ifIndex must never be the identity", withIndex)
	}
	var named int
	must(t, ownerPool.QueryRow(ctx, `
		SELECT count(*) FROM metric_series
		WHERE org_id = $1 AND device_id = $2
		  AND metric_key = 'net.if.in_octets' AND dimensions->>'if_name' = 'Gi1/0/1'
		  AND dimensions->>'if_alias' = 'uplink'`, orgUUID, deviceID).Scan(&named))
	if named != 1 {
		t.Fatalf("if_name/if_alias-dimensioned series = %d, want 1", named)
	}

	// Poll health: four snmp success rows through the same batch path.
	var successes int
	must(t, ownerPool.QueryRow(ctx, `
		SELECT count(*) FROM poll_health
		WHERE org_id = $1 AND device_id = $2 AND poll_type = 'snmp'
		  AND outcome = 'success' AND error_class = ''`, orgUUID, deviceID).Scan(&successes))
	if successes != 4 {
		t.Fatalf("snmp success health rows = %d, want 4", successes)
	}
}

func assertIfCounterValues(t *testing.T, orgID, deviceID uuid.UUID, metricKey, ifName string, want []float64) {
	t.Helper()
	rows, err := ownerPool.Query(context.Background(), `
		SELECT ms.value FROM metric_samples ms
		JOIN metric_series s ON s.id = ms.series_id
		WHERE s.org_id = $1 AND s.device_id = $2 AND s.metric_key = $3
		  AND s.dimensions->>'if_name' = $4
		ORDER BY ms.ts`, orgID, deviceID, metricKey, ifName)
	must(t, err)
	defer rows.Close()
	var got []float64
	for rows.Next() {
		var v float64
		must(t, rows.Scan(&v))
		got = append(got, v)
	}
	must(t, rows.Err())
	if len(got) != len(want) {
		t.Fatalf("%s samples = %v, want %v", metricKey, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s samples = %v, want %v", metricKey, got, want)
		}
	}
}

// TestM9S2SNMPFailureClasses drives the real client into the two canonical
// failure mode classes and asserts they reach poll_health through the same
// spool/stream path: v2c with an unserved community (silent drop -> timeout)
// and v3 authPriv with a wrong auth key (authentication failure).
func TestM9S2SNMPFailureClasses(t *testing.T) {
	ctx := context.Background()
	env, id, store, orgID := m4Env(t, "m9s2-fail-"+newUUID()[:8])
	orgUUID := mustUUID(t, orgID)
	siteID := siteIDForOrg(t, orgUUID)
	host, port := snmpsimFixture(t)
	timeoutDev := createM9S2Device(t, orgUUID, siteID, "m9s2-timeout", "192.0.2.40", "switch", "standard")
	authDev := createM9S2Device(t, orgUUID, siteID, "m9s2-auth", "192.0.2.41", "switch", "standard")

	creds := poll.NewStaticCredentialSource()
	creds.Set(timeoutDev.String(), v2cCreds("no-such-community"))
	creds.Set(authDev.String(), poll.SNMPCredentials{
		Version: poll.SNMPVersionV3, Context: "switch",
		Username:     snmpsimV3User,
		AuthProtocol: "SHA-256", AuthKey: "wrong-auth-pass",
		PrivProtocol: "AES", PrivKey: snmpsimV3PrivKey,
	})
	factory := func(addr netip.Addr, c poll.SNMPCredentials, cfg poll.ClientConfig) (poll.SNMPClient, error) {
		cfg.Port = int(port)
		cfg.Timeout = time.Second
		cfg.Retries = 0
		return poll.NewGosnmpClient(addr, c, cfg)
	}
	prober := poll.NewSNMPProber(poll.SNMPProberConfig{
		Credentials:   creds,
		ClientFactory: factory,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	var mu sync.Mutex
	var health []poll.Health
	engine := poll.NewEngine(poll.Config{
		Prober: prober,
		OnHealth: func(h poll.Health) {
			mu.Lock()
			health = append(health, h)
			mu.Unlock()
		},
	})
	engine.ApplyTargets([]poll.Target{
		{DeviceID: timeoutDev.String(), MgmtIP: netip.MustParseAddr(host), Name: "m9s2-timeout", Tier: poll.TierStandard, PollType: poll.PollSNMP, Kind: "switch"},
		{DeviceID: authDev.String(), MgmtIP: netip.MustParseAddr(host), Name: "m9s2-auth", Tier: poll.TierStandard, PollType: poll.PollSNMP, Kind: "switch"},
	})
	if n := engine.Step(ctx, time.Now()); n != 2 {
		t.Fatalf("probed %d targets, want 2", n)
	}
	mu.Lock()
	hs := health
	mu.Unlock()
	if len(hs) != 2 {
		t.Fatalf("health records = %d, want 2", len(hs))
	}

	sp, err := spool.Open(spool.Options{Dir: t.TempDir(), MaxBytes: 4 << 20, FsyncInterval: 10 * time.Millisecond})
	must(t, err)
	t.Cleanup(func() { _ = sp.Close() })
	rs := dialBatchStream(t, env, id, store)
	_, err = sp.Append(&spool.Batch{At: time.Now().UTC(), Health: toSpoolHealthIT(hs)})
	must(t, err)
	drainSpoolToStream(t, sp, rs)

	classes := map[uuid.UUID]string{}
	rows, err := ownerPool.Query(ctx, `
		SELECT device_id, outcome, error_class, consecutive_failures
		FROM poll_health
		WHERE org_id = $1 AND device_id IN ($2, $3) AND poll_type = 'snmp'`,
		orgUUID, timeoutDev, authDev)
	must(t, err)
	defer rows.Close()
	for rows.Next() {
		var dev uuid.UUID
		var outcome, class string
		var failures int
		must(t, rows.Scan(&dev, &outcome, &class, &failures))
		if outcome != "failure" || failures != 1 {
			t.Fatalf("device %s health = %s/%s failures=%d, want failure/1", dev, outcome, class, failures)
		}
		classes[dev] = class
	}
	must(t, rows.Err())
	if classes[timeoutDev] != poll.ErrorTimeout {
		t.Fatalf("timeout device class = %q, want %q", classes[timeoutDev], poll.ErrorTimeout)
	}
	if classes[authDev] != poll.ErrorAuthFailure {
		t.Fatalf("auth device class = %q, want %q", classes[authDev], poll.ErrorAuthFailure)
	}
	// Failed probes must not invent series.
	var series int
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM metric_series WHERE org_id = $1 AND device_id IN ($2, $3)`,
		orgUUID, timeoutDev, authDev).Scan(&series))
	if series != 0 {
		t.Fatalf("failed probes created %d series, want 0", series)
	}
}

// TestM9S2SNMPHostKindEndToEnd polls the host fixture with HOST-RESOURCES
// template selection by kind and asserts the hrProcessorLoad series lands.
func TestM9S2SNMPHostKindEndToEnd(t *testing.T) {
	ctx := context.Background()
	env, id, store, orgID := m4Env(t, "m9s2-host-"+newUUID()[:8])
	orgUUID := mustUUID(t, orgID)
	siteID := siteIDForOrg(t, orgUUID)
	deviceID := createM9S2Device(t, orgUUID, siteID, "m9s2-host", "127.0.0.1", "host", "standard")
	host, port := snmpsimFixture(t)

	creds := poll.NewStaticCredentialSource()
	creds.Set(deviceID.String(), v2cCreds("host"))
	prober := poll.NewSNMPProber(poll.SNMPProberConfig{
		Credentials:   creds,
		ClientFactory: snmpsimFactory(port, 2*time.Second, 1),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	var mu sync.Mutex
	var samples []poll.Sample
	var health []poll.Health
	engine := poll.NewEngine(poll.Config{
		Prober:   prober,
		OnSample: func(s poll.Sample) { mu.Lock(); samples = append(samples, s); mu.Unlock() },
		OnHealth: func(h poll.Health) { mu.Lock(); health = append(health, h); mu.Unlock() },
	})
	engine.ApplyTargets([]poll.Target{{
		DeviceID: deviceID.String(), MgmtIP: netip.MustParseAddr(host),
		Name: "m9s2-host", Tier: poll.TierStandard, PollType: poll.PollSNMP, Kind: "host",
	}})
	if n := engine.Step(ctx, time.Now()); n != 1 {
		t.Fatalf("probed %d targets, want 1", n)
	}
	mu.Lock()
	ss, hs := samples, health
	mu.Unlock()
	if len(ss) == 0 || len(hs) != 1 || hs[0].ErrorClass != "" {
		t.Fatalf("host probe samples=%d health=%+v", len(ss), hs)
	}
	sp, err := spool.Open(spool.Options{Dir: t.TempDir(), MaxBytes: 4 << 20, FsyncInterval: 10 * time.Millisecond})
	must(t, err)
	t.Cleanup(func() { _ = sp.Close() })
	rs := dialBatchStream(t, env, id, store)
	_, err = sp.Append(&spool.Batch{At: time.Now().UTC(), Samples: toSpoolSamplesIT(ss), Health: toSpoolHealthIT(hs)})
	must(t, err)
	drainSpoolToStream(t, sp, rs)

	var values []float64
	rows, err := ownerPool.Query(ctx, `
		SELECT ms.value FROM metric_samples ms
		JOIN metric_series s ON s.id = ms.series_id
		WHERE s.org_id = $1 AND s.device_id = $2 AND s.metric_key = 'sys.cpu.util'
		  AND s.dimensions->>'cpu' = '2'`, orgUUID, deviceID)
	must(t, err)
	defer rows.Close()
	for rows.Next() {
		var v float64
		must(t, rows.Scan(&v))
		values = append(values, v)
	}
	must(t, rows.Err())
	if len(values) != 1 || values[0] != 42 {
		t.Fatalf("sys.cpu.util cpu=2 values = %v, want [42]", values)
	}
}

// TestM9S2PolicyBundleSNMPTarget proves the signed policy carries an SNMP
// target (poll_type + kind) for devices with an applicable SNMP credential
// binding, and keeps the ICMP target for liveness.
func TestM9S2PolicyBundleSNMPTarget(t *testing.T) {
	ctx := context.Background()
	env := startM3Env(t)
	orgID, siteID, _ := devTenant(t, "m9s2-policy-"+newUUID()[:8])
	orgUUID, siteUUID := mustUUID(t, orgID), mustUUID(t, siteID)
	bound := createM9S2Device(t, orgUUID, siteUUID, "m9s2-bound", "192.0.2.31", "switch", "standard")
	unbound := createM9S2Device(t, orgUUID, siteUUID, "m9s2-unbound", "192.0.2.32", "switch", "standard")

	credID := uuid.MustParse(newUUID())
	_, err := ownerPool.Exec(ctx, `
		INSERT INTO device_credentials (id, org_id, name, kind, data_enc, kms_key_id, key_version, encryption_context, metadata)
		VALUES ($1, $2, 'm9s2-snmp', 'snmp_v2c', ''::bytea, 'test-kek', 1, '{}'::jsonb, '{}'::jsonb)`,
		credID, orgUUID)
	must(t, err)
	_, err = ownerPool.Exec(ctx, `
		INSERT INTO credential_bindings (id, org_id, credential_id, scope_type, scope_id, priority)
		VALUES ($1, $2, $3, 'device', $4, 10)`, uuid.MustParse(newUUID()), orgUUID, credID, bound)
	must(t, err)

	raw, _, _, err := env.svc.CreateEnrollmentToken(ctx, orgUUID, siteUUID, time.Hour, nil)
	must(t, err)
	id, _ := env.enrollIdentity(t, "collector-m9s2-policy", raw)
	sp, err := env.svc.LatestPolicy(ctx, orgUUID, mustUUID(t, id.CollectorID))
	must(t, err)
	if sp == nil {
		t.Fatal("no policy issued at enrollment")
	}
	if _, err := cpolicy.VerifyAndValidate(sp.Document, sp.Signature, env.ca.PolicySigningPublicKeyDER()); err != nil {
		t.Fatalf("signed bundle with snmp targets does not verify: %v", err)
	}

	var doc collectors.PolicyDocument
	must(t, json.Unmarshal(sp.Document, &doc))
	byDevice := map[string][]collectors.PolicyTarget{}
	for _, tg := range doc.Targets {
		byDevice[tg.DeviceID] = append(byDevice[tg.DeviceID], tg)
	}
	boundTargets := byDevice[bound.String()]
	if len(boundTargets) != 2 {
		t.Fatalf("bound device targets = %+v, want icmp+snmp", boundTargets)
	}
	var sawICMP, sawSNMP bool
	for _, tg := range boundTargets {
		switch tg.PollType {
		case "icmp":
			sawICMP = true
		case "snmp":
			sawSNMP = true
			if tg.Kind != "switch" || tg.MgmtIP != "192.0.2.31" {
				t.Fatalf("snmp target = %+v, want kind switch and the device IP", tg)
			}
		}
	}
	if !sawICMP || !sawSNMP {
		t.Fatalf("bound device targets = %+v, want icmp+snmp", boundTargets)
	}
	unboundTargets := byDevice[unbound.String()]
	if len(unboundTargets) != 1 || unboundTargets[0].PollType != "icmp" {
		t.Fatalf("unbound device targets = %+v, want a single icmp target", unboundTargets)
	}

	allow, err := ingest.AllowlistFromPolicy(sp.Document)
	must(t, err)
	for _, key := range []string{
		"net.if.in_octets", "net.if.out_octets", "net.if.in_errors", "net.if.out_errors",
		"net.if.in_discards", "net.if.out_discards", "net.if.oper_status", "sys.uptime_s", "sys.cpu.util",
	} {
		if _, ok := allow[key]; !ok {
			t.Fatalf("policy allowlist missing %s", key)
		}
	}
}

// TestM9S2SNMPSetNeverEmitted is removed: the no-SET guarantee is pinned
// structurally by poll.TestSNMPClientSurfaceHasNoSet (the client interface and
// session surface expose Get/Walk/Close only, with no Set path to call).
