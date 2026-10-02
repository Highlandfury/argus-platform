package integration

// M9-S3 (Phase 2): credential materialization acceptance — real credentials
// created through the credentials service, bound to devices, resolved by the
// M7-S4 resolver, decrypted from the SecretsVault, re-sealed to the
// collector's per-stream X25519 session key inside the signed policy bundle,
// decrypted RAM-only by the collector and used by the real SNMP poller against
// the pinned snmpsim fixtures (v2c and v3 authPriv). Revocation/binding
// removal drops material on the next sync (fail closed), tampering and
// wrong-session keys are rejected, cross-tenant targets never materialize, and
// the disk/log scans pin the RAM-only plaintext discipline.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc"
	grpccreds "google.golang.org/grpc/credentials"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
	"github.com/argus-platform/argus/internal/collector"
	collectoridentity "github.com/argus-platform/argus/internal/collector/identity"
	cpolicy "github.com/argus-platform/argus/internal/collector/policy"
	"github.com/argus-platform/argus/internal/collector/poll"
	"github.com/argus-platform/argus/internal/collector/spool"
	"github.com/argus-platform/argus/internal/collector/stream"
	"github.com/argus-platform/argus/internal/modules/collectors"
	"github.com/argus-platform/argus/internal/modules/credentials"
	"github.com/argus-platform/argus/internal/platform/database"
	"github.com/argus-platform/argus/internal/platform/secrets"
	"github.com/argus-platform/argus/internal/platform/sessioncrypto"
)

// m9s3Env is the M3 control-plane environment with the real SecretsVault, the
// credentials service and the M9-S3 resolver wired.
type m9s3Env struct {
	*m3Env
	orgID  string
	siteID string
	userID string
	creds  *credentials.Service
	logs   *bytes.Buffer
}

func startM9S3Env(t *testing.T, slug string) *m9s3Env {
	t.Helper()
	keyPath := filepath.Join(t.TempDir(), "master.key")
	kek, err := secrets.LoadOrCreateLocalKMS(secrets.LocalConfig{
		Path: keyPath, KeyID: "it-m9s3", AllowGenerate: true,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	must(t, err)
	vault := secrets.New(kek)
	var logs bytes.Buffer
	env := startM3Env(t,
		withCredentialResolver(credentials.NewResolver(appPool, vault)),
		withLogBuffer(&logs),
	)
	orgID, siteID, userID := devTenant(t, slug)
	return &m9s3Env{
		m3Env:  env,
		orgID:  orgID,
		siteID: siteID,
		userID: userID,
		creds:  credentials.New(appPool, vault, nil),
		logs:   &logs,
	}
}

// createCredential seals one secret through the real vault (the same service
// path the HTTP API uses) and returns its id.
func (e *m9s3Env) createCredential(t *testing.T, name, kind, secret string) uuid.UUID {
	t.Helper()
	md, err := e.creds.Create(context.Background(), mustUUID(t, e.orgID), credentials.CreateInput{
		Name: name, Kind: kind, Secret: []byte(secret),
	}, credentials.Actor{})
	must(t, err)
	return mustUUID(t, md.ID)
}

// bindCredential attaches a credential to a scope target.
func (e *m9s3Env) bindCredential(t *testing.T, credentialID uuid.UUID, scopeType string, scopeID uuid.UUID, priority int) {
	t.Helper()
	_, err := e.creds.Bind(context.Background(), mustUUID(t, e.orgID), credentialID, scopeType, scopeID, priority, credentials.Actor{})
	must(t, err)
}

// enrollCollector mints a token and enrolls a collector identity.
func (e *m9s3Env) enrollCollector(t *testing.T, name string) (collectoridentity.Identity, *collectoridentity.Store) {
	t.Helper()
	raw, _, _, err := e.svc.CreateEnrollmentToken(context.Background(),
		mustUUID(t, e.orgID), mustUUID(t, e.siteID), time.Hour, nil)
	must(t, err)
	return e.enrollIdentity(t, name, raw)
}

// m9s3Session is a raw gRPC stream carrying a known X25519 session key.
type m9s3Session struct {
	raw         *rawBatchStream
	seed        []byte
	public      []byte
	hello       *collectorv1.ServerHello
	collectorID uuid.UUID
}

// dialSessionStream opens a stream hello carrying a fresh ephemeral public key
// and returns the ServerHello so tests can inspect the materialized bundle.
func dialSessionStream(t *testing.T, env *m3Env, id collectoridentity.Identity, store *collectoridentity.Store) *m9s3Session {
	t.Helper()
	certPath, keyPath, _, _ := store.Paths()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(env.ca.RootPEM()) {
		t.Fatal("CA PEM parse failed")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	must(t, err)
	conn, err := grpc.NewClient(env.streamAddr, grpc.WithTransportCredentials(grpccreds.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	})))
	must(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	seed, public, err := sessioncrypto.NewKeyPair()
	must(t, err)
	gstream, err := collectorv1.NewCollectorServiceClient(conn).Stream(ctx)
	must(t, err)
	must(t, gstream.Send(&collectorv1.ClientMessage{
		Msg: &collectorv1.ClientMessage_Hello{Hello: &collectorv1.ClientHello{
			CollectorId:      id.CollectorID,
			AgentVersion:     "it-m9s3",
			ProtocolVersion:  1,
			SessionPublicKey: public,
		}},
	}))
	first, err := gstream.Recv()
	must(t, err)
	hello := first.GetHello()
	if hello == nil {
		t.Fatalf("expected ServerHello, got %T", first.GetMsg())
	}
	return &m9s3Session{
		raw:         &rawBatchStream{stream: gstream},
		seed:        seed,
		public:      public,
		hello:       hello,
		collectorID: mustUUID(t, id.CollectorID),
	}
}

// materializedSession verifies the ServerHello policy signature through the
// real collector path and returns its session material.
func materializedSession(t *testing.T, env *m3Env, ss *m9s3Session) *sessioncrypto.Session {
	t.Helper()
	p := ss.hello.GetPolicy()
	if p == nil {
		t.Fatal("ServerHello carried no policy")
	}
	doc, err := cpolicy.VerifyAndValidate(p.GetDocument(), p.GetSignature(), env.ca.PolicySigningPublicKeyDER())
	if err != nil {
		t.Fatalf("materialized bundle does not verify: %v", err)
	}
	if doc.Session == nil {
		t.Fatal("signed bundle carries no session material")
	}
	if doc.Session.OrgID == "" || doc.Session.CollectorID != ss.collectorID.String() {
		t.Fatalf("session context = %+v, want collector %s", doc.Session, ss.collectorID)
	}
	return doc.Session
}

// bundleCredentials decrypts material into a RAM-only source the same way the
// production stream client does.
func bundleCredentials(t *testing.T, seed []byte, session *sessioncrypto.Session, log *slog.Logger) *poll.BundleCredentialSource {
	t.Helper()
	src := poll.NewBundleCredentialSource(log)
	src.SetSessionKey(seed)
	src.ApplySession(session)
	return src
}

func snmpsimProber(t *testing.T, port uint16, creds poll.CredentialSource) *poll.SNMPProber {
	t.Helper()
	return poll.NewSNMPProber(poll.SNMPProberConfig{
		Credentials:   creds,
		ClientFactory: snmpsimFactory(port, 2*time.Second, 1),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

// TestM9S3MaterializedSNMPv2cPollEndToEnd is the P2-AC-19 headline: a real
// credential created through the credentials service and bound to a device is
// resolved, vault-opened, re-sealed to the collector's session key inside the
// signed bundle, decrypted RAM-only, and used to poll the pinned snmpsim
// switch fixture through the real spool -> stream -> ingest path.
func TestM9S3MaterializedSNMPv2cPollEndToEnd(t *testing.T) {
	ctx := context.Background()
	e := startM9S3Env(t, "m9s3-v2c-"+newUUID()[:8])
	orgUUID := mustUUID(t, e.orgID)
	deviceID := createM9S2Device(t, orgUUID, mustUUID(t, e.siteID), "m9s3-switch", "127.0.0.1", "switch", "standard")
	credID := e.createCredential(t, "m9s3-v2c", "snmp_v2c", "switch")
	e.bindCredential(t, credID, "device", deviceID, 10)

	id, store := e.enrollCollector(t, "collector-m9s3-v2c")
	ss := dialSessionStream(t, e.m3Env, id, store)
	session := materializedSession(t, e.m3Env, ss)
	if len(session.Credentials) != 1 {
		t.Fatalf("session records = %d, want 1", len(session.Credentials))
	}
	rec := session.Credentials[0]
	if rec.DeviceID != deviceID.String() || rec.CredentialID != credID.String() || rec.Kind != "snmp_v2c" {
		t.Fatalf("record = %+v", rec)
	}

	src := bundleCredentials(t, ss.seed, session, slog.New(slog.NewTextHandler(io.Discard, nil)))
	creds, ok := src.Lookup(deviceID.String())
	if !ok || creds.Community != "switch" || creds.Version != poll.SNMPVersionV2c {
		t.Fatalf("materialized v2c credentials = %+v ok=%v", creds, ok)
	}

	// Wrong-session key: a different collector session cannot decrypt the same
	// record (fresh ECDH per session + authenticated context).
	otherSeed, _, err := sessioncrypto.NewKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	other := bundleCredentials(t, otherSeed, session, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, ok := other.Lookup(deviceID.String()); ok {
		t.Fatal("material decrypted with the wrong session key")
	}

	host, port := snmpsimFixture(t)
	prober := snmpsimProber(t, port, src)
	clock := &itClock{now: time.Now().UTC()}
	var samples []poll.Sample
	var health []poll.Health
	engine := poll.NewEngine(poll.Config{
		Prober:   prober,
		Clock:    clock,
		OnSample: func(s poll.Sample) { samples = append(samples, s) },
		OnHealth: func(h poll.Health) { health = append(health, h) },
	})
	engine.ApplyTargets([]poll.Target{{
		DeviceID: deviceID.String(), MgmtIP: netip.MustParseAddr(host), Name: "m9s3-switch",
		Tier: poll.TierStandard, PollType: poll.PollSNMP, Kind: "switch",
	}})
	if n := engine.Step(ctx, clock.Now()); n != 1 {
		t.Fatalf("probed %d targets, want 1", n)
	}
	if len(samples) == 0 || len(health) != 1 || health[0].ErrorClass != "" {
		t.Fatalf("materialized v2c poll samples=%d health=%+v", len(samples), health)
	}

	sp, err := spool.Open(spool.Options{Dir: t.TempDir(), MaxBytes: 8 << 20, FsyncInterval: 10 * time.Millisecond})
	must(t, err)
	t.Cleanup(func() { _ = sp.Close() })
	_, err = sp.Append(&spool.Batch{At: time.Now().UTC(), Samples: toSpoolSamplesIT(samples), Health: toSpoolHealthIT(health)})
	must(t, err)
	drainSpoolToStream(t, sp, ss.raw)

	var series, successes int
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM metric_series WHERE org_id = $1 AND device_id = $2`, orgUUID, deviceID).Scan(&series))
	if series == 0 {
		t.Fatal("materialized v2c poll produced no series")
	}
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM poll_health WHERE org_id = $1 AND device_id = $2 AND poll_type = 'snmp'
		   AND outcome = 'success' AND error_class = ''`, orgUUID, deviceID).Scan(&successes))
	if successes != 1 {
		t.Fatalf("success health rows = %d, want 1", successes)
	}
	// The plaintext community must not appear in server-side logs.
	if strings.Contains(e.logs.String(), `"switch"`) {
		t.Fatalf("plaintext community leaked into server logs")
	}
}

// TestM9S3MaterializedSNMPv3PollEndToEnd proves v3 authPriv materialization:
// the vault plaintext is the v3 JSON payload, the collector parses it and the
// real gosnmp client polls the snmpsim host fixture with it.
func TestM9S3MaterializedSNMPv3PollEndToEnd(t *testing.T) {
	ctx := context.Background()
	e := startM9S3Env(t, "m9s3-v3-"+newUUID()[:8])
	orgUUID := mustUUID(t, e.orgID)
	deviceID := createM9S2Device(t, orgUUID, mustUUID(t, e.siteID), "m9s3-host", "127.0.0.1", "host", "standard")
	v3Payload, err := json.Marshal(map[string]string{
		"username":      snmpsimV3User,
		"auth_protocol": "SHA-256",
		"auth_key":      snmpsimV3AuthKey,
		"priv_protocol": "AES",
		"priv_key":      snmpsimV3PrivKey,
		"context":       "host",
	})
	must(t, err)
	credID := e.createCredential(t, "m9s3-v3", "snmp_v3", string(v3Payload))
	e.bindCredential(t, credID, "site", mustUUID(t, e.siteID), 5)

	id, store := e.enrollCollector(t, "collector-m9s3-v3")
	ss := dialSessionStream(t, e.m3Env, id, store)
	session := materializedSession(t, e.m3Env, ss)
	if len(session.Credentials) != 1 || session.Credentials[0].Kind != "snmp_v3" {
		t.Fatalf("session records = %+v, want one snmp_v3", session.Credentials)
	}
	src := bundleCredentials(t, ss.seed, session, slog.New(slog.NewTextHandler(io.Discard, nil)))
	creds, ok := src.Lookup(deviceID.String())
	if !ok || creds.Username != snmpsimV3User || creds.AuthProtocol != "SHA-256" || creds.PrivProtocol != "AES" {
		t.Fatalf("materialized v3 credentials = %+v ok=%v", creds, ok)
	}

	host, port := snmpsimFixture(t)
	prober := snmpsimProber(t, port, src)
	var samples []poll.Sample
	var health []poll.Health
	engine := poll.NewEngine(poll.Config{
		Prober:   prober,
		OnSample: func(s poll.Sample) { samples = append(samples, s) },
		OnHealth: func(h poll.Health) { health = append(health, h) },
	})
	engine.ApplyTargets([]poll.Target{{
		DeviceID: deviceID.String(), MgmtIP: netip.MustParseAddr(host), Name: "m9s3-host",
		Tier: poll.TierStandard, PollType: poll.PollSNMP, Kind: "host",
	}})
	if n := engine.Step(ctx, time.Now()); n != 1 {
		t.Fatalf("probed %d targets, want 1", n)
	}
	if len(samples) == 0 || len(health) != 1 || health[0].ErrorClass != "" {
		t.Fatalf("materialized v3 poll samples=%d health=%+v", len(samples), health)
	}

	sp, err := spool.Open(spool.Options{Dir: t.TempDir(), MaxBytes: 8 << 20, FsyncInterval: 10 * time.Millisecond})
	must(t, err)
	t.Cleanup(func() { _ = sp.Close() })
	_, err = sp.Append(&spool.Batch{At: time.Now().UTC(), Samples: toSpoolSamplesIT(samples), Health: toSpoolHealthIT(health)})
	must(t, err)
	drainSpoolToStream(t, sp, ss.raw)

	var cpu float64
	must(t, ownerPool.QueryRow(ctx, `
		SELECT ms.value FROM metric_samples ms
		JOIN metric_series s ON s.id = ms.series_id
		WHERE s.org_id = $1 AND s.device_id = $2 AND s.metric_key = 'sys.cpu.util'
		  AND s.dimensions->>'cpu' = '2'`, orgUUID, deviceID).Scan(&cpu))
	if cpu != 42 {
		t.Fatalf("materialized v3 sys.cpu.util cpu=2 = %v, want 42", cpu)
	}
	// The v3 keys must never appear in server logs.
	if strings.Contains(e.logs.String(), snmpsimV3AuthKey) || strings.Contains(e.logs.String(), snmpsimV3PrivKey) {
		t.Fatal("v3 key material leaked into server logs")
	}
}

// TestM9S3BindingRemovalDropsCredentialRAMOnly drives the real stream client
// with a RAM-only sink: the materialized credential is usable, persists
// nowhere as plaintext (disk + log scan), disappears on the next policy sync
// after the binding is removed (fail closed), and the session is cleared on
// the revocation disconnect.
func TestM9S3BindingRemovalDropsCredentialRAMOnly(t *testing.T) {
	ctx := context.Background()
	e := startM9S3Env(t, "m9s3-drop-"+newUUID()[:8])
	orgUUID := mustUUID(t, e.orgID)
	deviceID := createM9S2Device(t, orgUUID, mustUUID(t, e.siteID), "m9s3-drop", "127.0.0.1", "switch", "standard")
	sentinel := "m9s3-sentinel-community-" + newUUID()[:8]
	credID := e.createCredential(t, "m9s3-sentinel", "snmp_v2c", sentinel)
	e.bindCredential(t, credID, "device", deviceID, 10)

	id, store := e.enrollCollector(t, "collector-m9s3-drop")
	collectorID := mustUUID(t, id.CollectorID)

	policyDir := t.TempDir()
	var collectorLogs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&collectorLogs, nil))
	credSrc := poll.NewBundleCredentialSource(logger)
	machine := collector.NewMachine(collector.StateNew, nil)
	must(t, machine.Transition(collector.StateReconnecting))
	certPath, keyPath, _, _ := store.Paths()
	keyDER, err := base64StdDecode(id.PolicyKeyDERB64)
	must(t, err)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	client := stream.New(stream.Config{
		StreamAddr:     e.streamAddr,
		CAFile:         e.caFile,
		CertFile:       certPath,
		KeyFile:        keyPath,
		CollectorID:    id.CollectorID,
		AgentVersion:   "it-m9s3",
		PolicyDir:      policyDir,
		PolicyKeyDER:   keyDER,
		AppliedVersion: id.PolicyVersion,
		Credentials:    credSrc,
		Log:            logger,
	}, machine)
	done := make(chan error, 1)
	go func() { done <- client.Run(runCtx) }()

	waitCredential(t, credSrc, deviceID.String(), true)
	creds, _ := credSrc.Lookup(deviceID.String())
	if creds.Community != sentinel {
		t.Fatalf("decrypted community mismatch")
	}

	// RAM-only: the only file the collector wrote is the signed bundle, whose
	// credentials are per-session ciphertext; the sentinel never hits disk or
	// logs (collector or server side). The bundle is persisted asynchronously
	// with the applied policy, so wait for it under load instead of racing the
	// writer.
	var entries []os.DirEntry
	deadline := time.Now().Add(5 * time.Second)
	for {
		entries, err = os.ReadDir(policyDir)
		must(t, err)
		if len(entries) > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(entries) == 0 {
		t.Fatal("expected the applied signed bundle cache")
	}
	for _, ent := range entries {
		if strings.Contains(ent.Name(), "credential") {
			t.Fatalf("credential file created: %s", ent.Name())
		}
		raw, err := os.ReadFile(filepath.Join(policyDir, ent.Name())) //nolint:gosec // path under t.TempDir()
		must(t, err)
		if bytes.Contains(raw, []byte(sentinel)) {
			t.Fatalf("plaintext secret persisted on disk in %s", ent.Name())
		}
	}
	if strings.Contains(collectorLogs.String(), sentinel) || strings.Contains(e.logs.String(), sentinel) {
		t.Fatal("plaintext secret leaked into logs")
	}

	// Binding removal + next sync: the new bundle carries no material for the
	// device; the RAM set is replaced and polling fails closed.
	must(t, e.creds.Unbind(ctx, orgUUID, credID, "device", deviceID, credentials.Actor{}))
	if _, err := e.svc.ResyncPolicy(ctx, orgUUID, collectorID); err != nil {
		t.Fatalf("resync: %v", err)
	}
	pub := e.registry.SessionPublicKey(collectorID)
	if len(pub) == 0 {
		t.Fatal("live session has no materialization key")
	}
	sp, err := e.svc.PolicyForSession(ctx, orgUUID, collectorID, pub)
	must(t, err)
	if !e.registry.PushPolicy(collectorID, sp) {
		t.Fatal("policy push failed")
	}
	waitCredential(t, credSrc, deviceID.String(), false)

	// Probe now reports credential_missing (fail closed, no stale use); the
	// factory must never be reached.
	p := poll.NewSNMPProber(poll.SNMPProberConfig{
		Credentials: credSrc,
		ClientFactory: func(_ netip.Addr, _ poll.SNMPCredentials, _ poll.ClientConfig) (poll.SNMPClient, error) {
			t.Fatal("SNMP client built without materialized credentials")
			return nil, nil
		},
		Logger: logger,
	})
	target, err := poll.TargetFromPolicy(poll.TargetSpec{DeviceID: deviceID.String(), MgmtIP: "127.0.0.1", Tier: "standard", PollType: "snmp", Kind: "switch"})
	must(t, err)
	if res := p.Probe(ctx, target); res.ErrorClass != poll.ErrorCredentialMissing {
		t.Fatalf("post-removal probe class = %q, want %q", res.ErrorClass, poll.ErrorCredentialMissing)
	}

	// Revocation: the server-ordered disconnect ends the session and the
	// client clears the RAM material and session key.
	e.registry.Disconnect(collectorID, collectors.DisconnectMsg{Code: collectorv1.Disconnect_CODE_REVOKED, Reason: "test revoke"})
	select {
	case err := <-done:
		must(t, err)
	case <-time.After(15 * time.Second):
		t.Fatal("stream client did not stop after revocation")
	}
	if credSrc.HasSessionKey() {
		t.Fatal("session key survived the revocation disconnect")
	}
	if _, ok := credSrc.Lookup(deviceID.String()); ok {
		t.Fatal("credentials survived the revocation disconnect")
	}
}

// TestM9S3CrossTenantMaterializationIsolation: materialized records are
// produced per tenant transaction and authenticated to the tenant; org A's
// collector never receives (or can open) org B's material.
func TestM9S3CrossTenantMaterializationIsolation(t *testing.T) {
	e := startM9S3Env(t, "m9s3-xa-"+newUUID()[:8])
	orgA, siteA := mustUUID(t, e.orgID), mustUUID(t, e.siteID)
	deviceA := createM9S2Device(t, orgA, siteA, "m9s3-a", "127.0.0.1", "switch", "standard")
	credA := e.createCredential(t, "m9s3-a-cred", "snmp_v2c", "community-a")
	e.bindCredential(t, credA, "device", deviceA, 10)

	// Tenant B: same process, separate RLS tenant.
	orgBStr, siteBStr, _ := devTenant(t, "m9s3-xb-"+newUUID()[:8])
	orgB, siteB := mustUUID(t, orgBStr), mustUUID(t, siteBStr)
	deviceB := createM9S2Device(t, orgB, siteB, "m9s3-b", "127.0.0.2", "switch", "standard")
	credB, err := e.creds.Create(context.Background(), orgB, credentials.CreateInput{
		Name: "m9s3-b-cred", Kind: "snmp_v2c", Secret: []byte("community-b"),
	}, credentials.Actor{})
	must(t, err)
	_, err = e.creds.Bind(context.Background(), orgB, mustUUID(t, credB.ID), "device", deviceB, 10, credentials.Actor{})
	must(t, err)

	idA, storeA := e.enrollCollector(t, "collector-m9s3-xa")
	ssA := dialSessionStream(t, e.m3Env, idA, storeA)
	sessionA := materializedSession(t, e.m3Env, ssA)
	if len(sessionA.Credentials) != 1 || sessionA.Credentials[0].DeviceID != deviceA.String() {
		t.Fatalf("org A session = %+v, want exactly device A", sessionA.Credentials)
	}

	// Org B's own collector receives org B's material; org A's session seed
	// cannot open it (AAD org/device binding + distinct ECDH).
	rawB, _, _, err := e.svc.CreateEnrollmentToken(context.Background(), orgB, siteB, time.Hour, nil)
	must(t, err)
	idB, storeB := e.enrollIdentity(t, "collector-m9s3-xb", rawB)
	ssB := dialSessionStream(t, e.m3Env, idB, storeB)
	sessionB := materializedSession(t, e.m3Env, ssB)
	if len(sessionB.Credentials) != 1 || sessionB.Credentials[0].DeviceID != deviceB.String() {
		t.Fatalf("org B session = %+v, want exactly device B", sessionB.Credentials)
	}
	for _, rec := range sessionB.Credentials {
		if _, err := sessioncrypto.Open(ssA.seed, sessionB, rec); err == nil {
			t.Fatal("org A session decrypted org B material")
		}
		if _, err := sessioncrypto.Open(ssB.seed, sessionA, rec); err == nil {
			t.Fatal("org B record authenticated against org A context")
		}
	}
}

// TestM9S3BundleTamperRejected pins that the credential material is inside the
// signed payload: any change to the document (including only a credential
// ciphertext byte) or to the signature is rejected by the collector verifier.
func TestM9S3BundleTamperRejected(t *testing.T) {
	e := startM9S3Env(t, "m9s3-tamper-"+newUUID()[:8])
	orgUUID := mustUUID(t, e.orgID)
	deviceID := createM9S2Device(t, orgUUID, mustUUID(t, e.siteID), "m9s3-tamper", "127.0.0.1", "switch", "standard")
	credID := e.createCredential(t, "m9s3-tamper", "snmp_v2c", "switch")
	e.bindCredential(t, credID, "device", deviceID, 10)
	id, store := e.enrollCollector(t, "collector-m9s3-tamper")
	ss := dialSessionStream(t, e.m3Env, id, store)
	p := ss.hello.GetPolicy()
	if p == nil || p.GetDocument() == nil {
		t.Fatal("no materialized policy")
	}
	pub := e.ca.PolicySigningPublicKeyDER()

	// Byte flip anywhere in the document.
	flipped := append([]byte{}, p.GetDocument()...)
	flipped[0] ^= 0xff
	if _, err := cpolicy.VerifyAndValidate(flipped, p.GetSignature(), pub); err == nil {
		t.Fatal("byte-flipped document verified")
	}
	// Signature flip.
	sig := append([]byte{}, p.GetSignature()...)
	sig[0] ^= 0xff
	if _, err := cpolicy.VerifyAndValidate(p.GetDocument(), sig, pub); err == nil {
		t.Fatal("flipped signature verified")
	}
	// Only one ciphertext character changed (still valid JSON, same shape):
	// the Ed25519 signature must reject it.
	var doc map[string]any
	must(t, json.Unmarshal(p.GetDocument(), &doc))
	session, ok := doc["session"].(map[string]any)
	if !ok {
		t.Fatal("no session block in the document map")
	}
	records, ok := session["credentials"].([]any)
	if !ok || len(records) != 1 {
		t.Fatalf("credential records = %v", session["credentials"])
	}
	rec, ok := records[0].(map[string]any)
	if !ok {
		t.Fatal("credential record shape unexpected")
	}
	ct, _ := rec["ciphertext"].(string)
	if ct == "" {
		t.Fatal("no ciphertext")
	}
	replacement := "A"
	if strings.HasPrefix(ct, "A") {
		replacement = "B"
	}
	rec["ciphertext"] = replacement + ct[1:]
	tampered, err := json.Marshal(doc)
	must(t, err)
	if _, err := cpolicy.VerifyAndValidate(tampered, p.GetSignature(), pub); err == nil {
		t.Fatal("ciphertext-only tamper verified")
	}
}

// TestM9S3OrgAndSiteTierMaterialization exercises the resolver tiers end-to-end
// through the real vault: an org-bound credential covers devices in every
// site, a site-bound credential deterministically overrides it for its site
// (canonical precedence), and both arrive as separate materialized records.
func TestM9S3OrgAndSiteTierMaterialization(t *testing.T) {
	e := startM9S3Env(t, "m9s3-tiers-"+newUUID()[:8])
	orgUUID := mustUUID(t, e.orgID)
	siteID := mustUUID(t, e.siteID)
	deviceSite := createM9S2Device(t, orgUUID, siteID, "m9s3-site-tier", "192.0.2.51", "switch", "standard")

	// A second site in the same org, so the org binding is exercised where no
	// site binding exists.
	otherSite := createSiteRow(t, orgUUID, "m9s3-other-site")
	deviceOrg := createM9S2Device(t, orgUUID, mustUUID(t, otherSite), "m9s3-org-tier", "192.0.2.52", "switch", "standard")

	orgCred := e.createCredential(t, "m9s3-org-cred", "snmp_v2c", "switch")
	e.bindCredential(t, orgCred, "org", orgUUID, 1)
	siteCred := e.createCredential(t, "m9s3-site-cred", "snmp_v2c", "host")
	e.bindCredential(t, siteCred, "site", siteID, 50)

	id, store := e.enrollCollector(t, "collector-m9s3-tiers")
	ss := dialSessionStream(t, e.m3Env, id, store)
	session := materializedSession(t, e.m3Env, ss)
	if len(session.Credentials) != 2 {
		t.Fatalf("session records = %d, want 2 (one per SNMP device)", len(session.Credentials))
	}
	communities := map[string]string{}
	for _, rec := range session.Credentials {
		plaintext, err := sessioncrypto.Open(ss.seed, session, rec)
		if err != nil {
			t.Fatalf("open record %s: %v", rec.DeviceID, err)
		}
		communities[rec.DeviceID] = string(plaintext)
		clear(plaintext)
	}
	if communities[deviceOrg.String()] != "switch" {
		t.Fatalf("org-tier device community = %q, want the org-bound community", communities[deviceOrg.String()])
	}
	if communities[deviceSite.String()] != "host" {
		t.Fatalf("site-tier device community = %q, want the site-bound override", communities[deviceSite.String()])
	}
}

// createSiteRow inserts one site through the app path and returns its id.
func createSiteRow(t *testing.T, orgID uuid.UUID, name string) string {
	t.Helper()
	id := newUUID()
	err := database.WithTenant(context.Background(), appPool, orgID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO sites (id, org_id, name) VALUES ($1, $2, $3)`, id, orgID, name)
		return err
	})
	must(t, err)
	return id
}

// waitCredential polls the RAM source until the device's presence matches want.
func waitCredential(t *testing.T, src *poll.BundleCredentialSource, deviceID string, want bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		_, ok := src.Lookup(deviceID)
		if ok == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("credential presence for %s did not become %v in time", deviceID, want)
}
