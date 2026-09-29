package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
	"github.com/argus-platform/argus/internal/api"
	"github.com/argus-platform/argus/internal/collector"
	"github.com/argus-platform/argus/internal/collector/enrollclient"
	collectoridentity "github.com/argus-platform/argus/internal/collector/identity"
	"github.com/argus-platform/argus/internal/collector/stream"
	"github.com/argus-platform/argus/internal/modules/collectors"
	identitymod "github.com/argus-platform/argus/internal/modules/identity"
	"github.com/argus-platform/argus/internal/modules/tenancy"
	"github.com/argus-platform/argus/internal/platform/database"
	"github.com/argus-platform/argus/internal/platform/ratelimit"
	"github.com/argus-platform/argus/internal/platform/telemetry"
)

// m3Env is a full in-process collector control plane (real CA, real gRPC
// servers, real database) for M3 integration tests.
type m3Env struct {
	ca         *collectors.CA
	svc        *collectors.Service
	registry   *collectors.SessionRegistry
	caFile     string
	enrollAddr string
	streamAddr string

	streamSrv *grpc.Server
	mu        sync.Mutex
}

func startM3Env(t *testing.T, opts ...m3Option) *m3Env {
	t.Helper()
	cfg := m3EnvConfig{}
	for _, o := range opts {
		o(&cfg)
	}

	dir := t.TempDir()
	ca, err := collectors.LoadOrCreateCA(filepath.Join(dir, "ca"), []string{"localhost", "127.0.0.1"})
	must(t, err)
	svc := collectors.New(appPool, authPool, ca, nil)
	registry := collectors.NewSessionRegistry()

	enrollTCP, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	var limiter *ratelimit.Limiter
	if cfg.limiter {
		limiter = ratelimit.New(10, 6*time.Second)
	}
	enrollSrv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{*ca.ServerTLS()},
			MinVersion:   tls.VersionTLS12,
		})),
		grpc.MaxRecvMsgSize(1<<20),
	)
	collectorv1.RegisterEnrollmentServiceServer(enrollSrv, collectors.NewEnrollmentServer(svc, limiter, nil))
	go func() { _ = enrollSrv.Serve(enrollTCP) }()

	streamTCP, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	streamSrv := newStreamGRPC(ca, svc, registry)
	go func() { _ = streamSrv.Serve(streamTCP) }()

	t.Cleanup(func() {
		enrollSrv.Stop()
		streamSrv.Stop()
	})

	caFile := filepath.Join(dir, "ca.pem")
	must(t, os.WriteFile(caFile, ca.RootPEM(), 0o600))

	return &m3Env{
		ca:         ca,
		svc:        svc,
		registry:   registry,
		caFile:     caFile,
		enrollAddr: enrollTCP.Addr().String(),
		streamAddr: streamTCP.Addr().String(),
		streamSrv:  streamSrv,
	}
}

func newStreamGRPC(ca *collectors.CA, svc *collectors.Service, registry *collectors.SessionRegistry) *grpc.Server {
	srv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{*ca.ServerTLS()},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    ca.RootPool(),
			MinVersion:   tls.VersionTLS12,
		})),
		grpc.MaxRecvMsgSize(16<<20),
	)
	collectorv1.RegisterCollectorServiceServer(srv, collectors.NewStreamServer(svc, registry, nil))
	return srv
}

// restartStream stops the stream listener and rebinds the same address,
// simulating a server restart while collectors reconnect.
func (e *m3Env) restartStream(t *testing.T) {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.streamSrv.Stop()
	var ln net.Listener
	var err error
	for i := 0; i < 20; i++ {
		ln, err = net.Listen("tcp", e.streamAddr)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	must(t, err)
	e.streamSrv = newStreamGRPC(e.ca, e.svc, e.registry)
	go func() { _ = e.streamSrv.Serve(ln) }()
}

type m3EnvConfig struct {
	limiter bool
}

type m3Option func(*m3EnvConfig)

func withEnrollLimiter() m3Option {
	return func(c *m3EnvConfig) { c.limiter = true }
}

// enrollIdentity performs a full enrollment and writes the identity to disk.
func (e *m3Env) enrollIdentity(t *testing.T, name, token string) (collectoridentity.Identity, *collectoridentity.Store) {
	t.Helper()
	res, err := enrollclient.Enroll(context.Background(), enrollclient.Config{
		EnrollURL:    "https://" + e.enrollAddr,
		CAFile:       e.caFile,
		Token:        token,
		Name:         name,
		AgentVersion: "it",
		Hostname:     "it-host",
		OS:           "linux",
		Timeout:      10 * time.Second,
	})
	must(t, err)

	id := collectoridentity.Identity{
		CollectorID:     res.CollectorID,
		Name:            name,
		ServerEnrollURL: "https://" + e.enrollAddr,
		StreamAddr:      e.streamAddr,
		AgentVersion:    "it",
		CertNotAfter:    res.CertNotAfter,
		EnrolledAt:      time.Now().UTC(),
		PolicyVersion:   res.PolicyVersion,
		PolicyKeyDERB64: base64Std(res.PolicyKeyDER),
	}
	store := collectoridentity.NewStore(t.TempDir())
	must(t, store.Save(id, res.CertPEM, res.KeyPEM, res.CAPEM))
	return id, store
}

func (e *m3Env) newStreamClient(t *testing.T, id collectoridentity.Identity, store *collectoridentity.Store, applied *int64, disconnects *[]collectorv1.Disconnect_Code) (*stream.Client, *collector.Machine) {
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
		OnPolicyApplied: func(v int64) {
			if applied != nil {
				*applied = v
			}
		},
		OnDisconnect: func(code collectorv1.Disconnect_Code, _ string) {
			if disconnects != nil {
				*disconnects = append(*disconnects, code)
			}
		},
	}, machine)
	return client, machine
}

func waitState(t *testing.T, m *collector.Machine, want collector.State, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if m.State() == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("state = %s, want %s within %s", m.State(), want, timeout)
}

// --- small helpers ---------------------------------------------------------

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func base64StdDecode(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

func bigOne() *big.Int { return big.NewInt(1) }

func errorsIsDisconnect(err error) bool {
	var d *stream.DisconnectError
	return errors.As(err, &d)
}

func dialEnroll(t *testing.T, e *m3Env) collectorv1.EnrollmentServiceClient {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(e.ca.RootPEM()) {
		t.Fatal("CA PEM parse failed")
	}
	conn, err := grpc.NewClient(e.enrollAddr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		RootCAs:    pool,
		ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS12,
	})))
	must(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return collectorv1.NewEnrollmentServiceClient(conn)
}

func devTenant(t *testing.T, slug string) (orgID, siteID, userID string) {
	t.Helper()
	tn := seedLoginUser(t, slug, "HQ-"+slug)
	return tn.OrgID, tn.SiteID, tn.UserID
}

// TestM3EnrollmentMatrix covers valid, replay, expired, unknown, malformed,
// duplicate-name, tenant binding, hashed-at-rest, and rate limiting.
func TestM3EnrollmentMatrix(t *testing.T) {
	ctx := context.Background()
	env := startM3Env(t)
	orgID, siteID, userID := devTenant(t, "m3-enroll-"+newUUID()[:8])
	orgUUID := mustUUID(t, orgID)
	siteUUID := mustUUID(t, siteID)
	userUUID := mustUUID(t, userID)

	// 1) valid enrollment
	raw, _, _, err := env.svc.CreateEnrollmentToken(ctx, orgUUID, siteUUID, time.Hour, &userUUID)
	must(t, err)
	id, _ := env.enrollIdentity(t, "collector-happy", raw)

	var (
		dbOrg      string
		dbStatus   string
		dbFingerpr []byte
		usedAt     *time.Time
	)
	must(t, ownerPool.QueryRow(ctx,
		`SELECT org_id::text, status FROM collectors WHERE id = $1`, id.CollectorID).Scan(&dbOrg, &dbStatus))
	if dbOrg != orgID || dbStatus != "pending" {
		t.Fatalf("collector row = (%s,%s), want (%s,pending)", dbOrg, dbStatus, orgID)
	}
	must(t, ownerPool.QueryRow(ctx,
		`SELECT fingerprint_sha256 FROM collector_certificates WHERE collector_id = $1`, id.CollectorID).Scan(&dbFingerpr))
	if len(dbFingerpr) != 32 {
		t.Fatalf("stored fingerprint length = %d", len(dbFingerpr))
	}
	must(t, ownerPool.QueryRow(ctx,
		`SELECT used_at FROM enrollment_tokens WHERE token_hash = $1`, collectors.HashEnrollmentToken(raw)).Scan(&usedAt))
	if usedAt == nil {
		t.Fatal("token not marked used")
	}
	// hashed-at-rest: only the hash is stored
	var hashRows int
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM enrollment_tokens WHERE token_hash = $1`, collectors.HashEnrollmentToken(raw)).Scan(&hashRows))
	if hashRows != 1 {
		t.Fatalf("hash rows = %d", hashRows)
	}

	// 2) replay -> denied (uniform)
	raw2, _, _, err := env.svc.CreateEnrollmentToken(ctx, orgUUID, siteUUID, time.Hour, &userUUID)
	must(t, err)
	_ = raw2
	_, err = enrollclient.Enroll(ctx, enrollclient.Config{
		EnrollURL: "https://" + env.enrollAddr, CAFile: env.caFile, Token: raw, Name: "collector-replay",
		Timeout: 5 * time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "PermissionDenied") {
		t.Fatalf("replay: want PermissionDenied, got %v", err)
	}

	// 3) unknown token -> denied
	_, err = enrollclient.Enroll(ctx, enrollclient.Config{
		EnrollURL: "https://" + env.enrollAddr, CAFile: env.caFile, Token: "arg_enr_" + "unknown",
		Name: "collector-unknown", Timeout: 5 * time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "PermissionDenied") {
		t.Fatalf("unknown token: want PermissionDenied, got %v", err)
	}

	// 4) expired token -> denied (expiry forced directly)
	raw3, tokenID3, _, err := env.svc.CreateEnrollmentToken(ctx, orgUUID, siteUUID, time.Hour, &userUUID)
	must(t, err)
	_, err = ownerPool.Exec(ctx, `UPDATE enrollment_tokens SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 minute' WHERE id = $1`, tokenID3)
	must(t, err)
	_, err = enrollclient.Enroll(ctx, enrollclient.Config{
		EnrollURL: "https://" + env.enrollAddr, CAFile: env.caFile, Token: raw3, Name: "collector-expired",
		Timeout: 5 * time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "PermissionDenied") {
		t.Fatalf("expired: want PermissionDenied, got %v", err)
	}

	// 5) malformed CSR -> InvalidArgument
	raw4, _, _, err := env.svc.CreateEnrollmentToken(ctx, orgUUID, siteUUID, time.Hour, &userUUID)
	must(t, err)
	enrollCli := dialEnroll(t, env)
	_, err = enrollCli.Enroll(ctx, &collectorv1.EnrollRequest{
		EnrollmentToken: raw4, CsrPem: "not-a-csr", CollectorName: "collector-badcsr",
	})
	if err == nil || !strings.Contains(err.Error(), "InvalidArgument") {
		t.Fatalf("malformed CSR: want InvalidArgument, got %v", err)
	}
	// 5b) oversized CSR -> InvalidArgument (16KiB cap)
	raw5, _, _, err := env.svc.CreateEnrollmentToken(ctx, orgUUID, siteUUID, time.Hour, &userUUID)
	must(t, err)
	_, err = enrollCli.Enroll(ctx, &collectorv1.EnrollRequest{
		EnrollmentToken: raw5, CsrPem: strings.Repeat("A", 64*1024), CollectorName: "collector-bigcsr",
	})
	if err == nil || !strings.Contains(err.Error(), "InvalidArgument") {
		t.Fatalf("oversized CSR: want InvalidArgument, got %v", err)
	}

	// 6) duplicate name -> AlreadyExists
	raw6, _, _, err := env.svc.CreateEnrollmentToken(ctx, orgUUID, siteUUID, time.Hour, &userUUID)
	must(t, err)
	_, err = enrollclient.Enroll(ctx, enrollclient.Config{
		EnrollURL: "https://" + env.enrollAddr, CAFile: env.caFile, Token: raw6, Name: "collector-happy",
		Timeout: 5 * time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "AlreadyExists") {
		t.Fatalf("duplicate name: want AlreadyExists, got %v", err)
	}

	// 7) tenant binding: a second org cannot see the first org's collector;
	// an org-A token creates an org-A collector even when the caller is org B.
	otherOrg, _, _ := devTenant(t, "m3-enroll-b-"+newUUID()[:8])
	var visibleUnderB int
	must(t, database.WithTenant(ctx, appPool, mustUUID(t, otherOrg), func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM collectors WHERE id = $1`, id.CollectorID).Scan(&visibleUnderB)
	}))
	if visibleUnderB != 0 {
		t.Fatal("collector leaked across tenants")
	}
}

// TestM3EnrollmentRateLimit: 11th rapid attempt -> ResourceExhausted.
func TestM3EnrollmentRateLimit(t *testing.T) {
	ctx := context.Background()
	env := startM3Env(t, withEnrollLimiter())
	orgID, siteID, userID := devTenant(t, "m3-rl-"+newUUID()[:8])
	orgUUID, siteUUID, userUUID := mustUUID(t, orgID), mustUUID(t, siteID), mustUUID(t, userID)
	raw, _, _, err := env.svc.CreateEnrollmentToken(ctx, orgUUID, siteUUID, time.Hour, &userUUID)
	must(t, err)
	_ = raw

	clients := dialEnroll(t, env)
	for i := 1; i <= 10; i++ {
		if _, err := clients.Enroll(ctx, &collectorv1.EnrollRequest{
			EnrollmentToken: "arg_enr_" + "bad", CsrPem: "x", CollectorName: "rl",
		}); err == nil || !strings.Contains(err.Error(), "PermissionDenied") {
			t.Fatalf("attempt %d: want PermissionDenied, got %v", i, err)
		}
	}
	if _, err := clients.Enroll(ctx, &collectorv1.EnrollRequest{
		EnrollmentToken: "arg_enr_" + "bad", CsrPem: "x", CollectorName: "rl",
	}); err == nil || !strings.Contains(err.Error(), "ResourceExhausted") {
		t.Fatalf("11th attempt: want ResourceExhausted, got %v", err)
	}
}

// TestM3StreamLifecycle: connect -> policy applied/acked -> duplicate
// (newest wins, SUPERSEDED signaled) -> server restart reconnect -> revoke
// terminal.
func TestM3StreamLifecycle(t *testing.T) {
	ctx := context.Background()
	env := startM3Env(t)
	orgID, siteID, userID := devTenant(t, "m3-stream-"+newUUID()[:8])
	orgUUID, siteUUID, userUUID := mustUUID(t, orgID), mustUUID(t, siteID), mustUUID(t, userID)
	raw, _, _, err := env.svc.CreateEnrollmentToken(ctx, orgUUID, siteUUID, time.Hour, &userUUID)
	must(t, err)
	id, store := env.enrollIdentity(t, "collector-stream", raw)
	collectorID := mustUUID(t, id.CollectorID)

	// Client 1: connect, policy v1 applied.
	var applied1 int64
	var disc1 []collectorv1.Disconnect_Code
	c1, m1 := env.newStreamClient(t, id, store, &applied1, &disc1)
	ctx1, cancel1 := context.WithCancel(ctx)
	defer cancel1()
	go func() { _ = c1.Run(ctx1) }()
	waitState(t, m1, collector.StateActive, 10*time.Second)

	// Policy ack lands in the tenant registry.
	deadline := time.Now().Add(5 * time.Second)
	var acked int64
	for time.Now().Before(deadline) {
		must(t, ownerPool.QueryRow(ctx, `SELECT policy_version FROM collectors WHERE id = $1`, collectorID).Scan(&acked))
		if acked >= 1 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if acked < 1 {
		t.Fatalf("policy ack not persisted (acked=%d)", acked)
	}
	if applied1 != 1 {
		t.Fatalf("client applied version = %d, want 1", applied1)
	}

	// Client 2 (duplicate identity): newest wins; client 1 sees SUPERSEDED.
	var applied2 int64
	var disc2 []collectorv1.Disconnect_Code
	c2, m2 := env.newStreamClient(t, id, store, &applied2, &disc2)
	ctx2, cancel2 := context.WithCancel(ctx)
	defer cancel2()
	go func() { _ = c2.Run(ctx2) }()
	waitState(t, m2, collector.StateActive, 10*time.Second)

	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		found := false
		for _, c := range disc1 {
			if c == collectorv1.Disconnect_CODE_SUPERSEDED {
				found = true
			}
		}
		if found {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel1() // simulate the operator stopping the old instance
	if env.registry.ActiveCount() != 1 {
		t.Fatalf("registry active count = %d, want 1", env.registry.ActiveCount())
	}

	// Server restart: client 2 reconnects and returns to ACTIVE.
	env.restartStream(t)
	deadline = time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if m2.State() == collector.StateActive {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if m2.State() != collector.StateActive {
		t.Fatalf("client 2 state after server restart = %s, want ACTIVE", m2.State())
	}

	// Revocation: terminal REVOKED, Run returns nil.
	if _, err := env.svc.RevokeCollector(ctx, orgUUID, collectorID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	env.registry.Disconnect(collectorID, collectors.DisconnectMsg{
		Code:   collectorv1.Disconnect_CODE_REVOKED,
		Reason: "collector revoked",
	})
	waitState(t, m2, collector.StateRevoked, 5*time.Second)
	cancel2()

	// A fresh connection with the revoked identity is rejected before hello.
	var applied3 int64
	c3, m3machine := env.newStreamClient(t, id, store, &applied3, nil)
	ctx3, cancel3 := context.WithCancel(ctx)
	defer cancel3()
	done := make(chan error, 1)
	go func() { done <- c3.Run(ctx3) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("revoked client Run returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		cancel3()
		t.Fatal("revoked client did not terminate")
	}
	if m3machine.State() != collector.StateRevoked {
		t.Fatalf("revoked fresh client state = %s", m3machine.State())
	}
}

// TestM3UnknownIdentityRejected: a client certificate not signed by the
// collector CA cannot open the stream (delegated to TLS chain validation).
func TestM3UnknownIdentityRejected(t *testing.T) {
	env := startM3Env(t)

	// Self-signed certificate from a different (rogue) CA.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: bigOne(),
		Subject:      pkix.Name{CommonName: "rogue"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	must(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	must(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	must(t, os.WriteFile(certPath, certPEM, 0o600))
	must(t, os.WriteFile(keyPath, keyPEM, 0o600))

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	must(t, err)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(env.ca.RootPEM())
	conn, err := grpc.NewClient(env.streamAddr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	})))
	must(t, err)
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	gstream, err := collectorv1.NewCollectorServiceClient(conn).Stream(ctx)
	if err == nil {
		err = gstream.Send(&collectorv1.ClientMessage{
			Msg: &collectorv1.ClientMessage_Hello{Hello: &collectorv1.ClientHello{
				CollectorId: "whatever", ProtocolVersion: 1,
			}},
		})
		if err == nil {
			_, err = gstream.Recv()
		}
	}
	if err == nil {
		t.Fatal("rogue certificate must not establish a stream")
	}
	if errorsIsDisconnect(err) {
		t.Fatalf("rogue certificate produced an application-level disconnect: %v", err)
	}
}

// TestM3EnrollmentHTTPIdempotency: POST /v1/enrollments requires an
// Idempotency-Key; replaying the same key returns the original credential and
// creates only one token row; a new key mints a new credential.
func TestM3EnrollmentHTTPIdempotency(t *testing.T) {
	slug := "m3-http-" + newUUID()[:8]
	tn := seedLoginUser(t, slug, "HQ-"+slug)

	tenancySvc := tenancy.New(appPool, authPool)
	identitySvc, err := identitymod.New(appPool, authPool, tenancySvc)
	must(t, err)
	router := api.NewRouter(api.Options{
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Telemetry:         telemetry.New("it-m3-http", "0", "0"),
		Version:           "it",
		Commit:            "it",
		Identity:          identitySvc,
		Tenancy:           tenancySvc,
		Collectors:        collectors.New(appPool, authPool, nil, nil),
		CollectorSessions: collectors.NewSessionRegistry(),
	})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	must(t, err)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second}

	res := doRequest(t, client, http.MethodPost, srv.URL+"/v1/auth/login", loginBody(slug, "it-password"), nil)
	if res.Status != http.StatusOK {
		t.Fatalf("login: status %d", res.Status)
	}
	csrf := cookieByName(res, "argus_csrf")
	if csrf == nil {
		t.Fatal("login did not set the CSRF cookie")
	}
	body := `{"site_id":"` + tn.SiteID + `","ttl_seconds":3600}`

	// Missing Idempotency-Key -> 400 (documented requirement).
	res = doRequest(t, client, http.MethodPost, srv.URL+"/v1/enrollments", body,
		map[string]string{"X-CSRF-Token": csrf.Value})
	if res.Status != http.StatusBadRequest {
		t.Fatalf("missing key: status %d, want 400", res.Status)
	}

	headers := map[string]string{"X-CSRF-Token": csrf.Value, "Idempotency-Key": "idem-" + newUUID()[:8]}
	first := doRequest(t, client, http.MethodPost, srv.URL+"/v1/enrollments", body, headers)
	if first.Status != http.StatusCreated {
		t.Fatalf("create: status %d body %v", first.Status, first.Body)
	}
	replay := doRequest(t, client, http.MethodPost, srv.URL+"/v1/enrollments", body, headers)
	if replay.Status != http.StatusCreated {
		t.Fatalf("replay: status %d", replay.Status)
	}
	if replay.Body["token"] != first.Body["token"] || replay.Body["id"] != first.Body["id"] {
		t.Fatalf("replay must return the original credential: %v vs %v", replay.Body, first.Body)
	}
	if replay.Header.Get("Idempotency-Replayed") != "true" {
		t.Fatal("replay must be marked Idempotency-Replayed")
	}

	headers2 := map[string]string{"X-CSRF-Token": csrf.Value, "Idempotency-Key": "idem2-" + newUUID()[:8]}
	second := doRequest(t, client, http.MethodPost, srv.URL+"/v1/enrollments", body, headers2)
	if second.Status != http.StatusCreated || second.Body["token"] == first.Body["token"] {
		t.Fatalf("second key must mint a distinct credential: %v", second.Body)
	}

	var tokenCount int
	must(t, ownerPool.QueryRow(context.Background(),
		`SELECT count(*) FROM enrollment_tokens WHERE org_id = $1`, mustUUID(t, tn.OrgID)).Scan(&tokenCount))
	if tokenCount != 2 {
		t.Fatalf("token rows = %d, want 2 (one per distinct Idempotency-Key)", tokenCount)
	}
}
