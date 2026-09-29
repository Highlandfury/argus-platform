// Package enrollclient performs the one-time token -> certificate exchange over
// the token-gated TLS enrollment listener (port 8444).
package enrollclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
	"github.com/argus-platform/argus/internal/collector/policy"
)

// Config is the enrollment input.
type Config struct {
	EnrollURL    string // https://host:8444
	CAFile       string // pinned server CA (operator-provided)
	Token        string
	Name         string
	AgentVersion string
	Hostname     string
	OS           string
	Timeout      time.Duration
}

// Result is the verified enrollment outcome (ready to persist).
type Result struct {
	CollectorID     string
	CertPEM         []byte
	KeyPEM          []byte
	CAPEM           []byte
	CertNotAfter    time.Time
	PolicyDocument  []byte
	PolicySignature []byte
	PolicyVersion   int64
	PolicyKeyDER    []byte
	ServerTime      time.Time
}

// ErrPolicyVerification means the server's initial policy did not verify
// against the key delivered in the same response (protocol violation).
var ErrPolicyVerification = fmt.Errorf("enrollclient: initial policy failed verification")

// Enroll generates a keypair + CSR, calls the enrollment RPC, and verifies the
// signed initial policy before returning anything.
func Enroll(ctx context.Context, cfg Config) (Result, error) {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	caPEM, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return Result{}, fmt.Errorf("enrollclient: read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return Result{}, fmt.Errorf("enrollclient: CA file contains no certificates")
	}

	u, err := url.Parse(cfg.EnrollURL)
	if err != nil || u.Host == "" {
		return Result{}, fmt.Errorf("enrollclient: invalid server URL %q", cfg.EnrollURL)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Result{}, fmt.Errorf("enrollclient: key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: cfg.Name}}, key)
	if err != nil {
		return Result{}, fmt.Errorf("enrollclient: csr: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return Result{}, fmt.Errorf("enrollclient: marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	creds := credentials.NewTLS(&tls.Config{
		RootCAs:    pool,
		ServerName: u.Hostname(),
		MinVersion: tls.VersionTLS12,
	})
	conn, err := grpc.NewClient(u.Host, grpc.WithTransportCredentials(creds))
	if err != nil {
		return Result{}, fmt.Errorf("enrollclient: dial: %w", err)
	}
	defer func() { _ = conn.Close() }()

	client := collectorv1.NewEnrollmentServiceClient(conn)
	resp, err := client.Enroll(ctx, &collectorv1.EnrollRequest{
		EnrollmentToken: cfg.Token,
		CsrPem:          string(csrPEM),
		CollectorName:   cfg.Name,
		AgentVersion:    cfg.AgentVersion,
		Hostname:        cfg.Hostname,
		Os:              cfg.OS,
	})
	if err != nil {
		return Result{}, fmt.Errorf("enrollclient: rpc: %w", err)
	}

	if resp.GetPolicy() == nil || len(resp.GetPolicySigningPublicKey()) == 0 {
		return Result{}, ErrPolicyVerification
	}
	if _, err := policy.VerifyAndValidate(resp.GetPolicy().GetDocument(), resp.GetPolicy().GetSignature(), resp.GetPolicySigningPublicKey()); err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrPolicyVerification, err)
	}

	return Result{
		CollectorID:     resp.GetCollectorId(),
		CertPEM:         []byte(resp.GetClientCertPem()),
		KeyPEM:          keyPEM,
		CAPEM:           caPEM,
		CertNotAfter:    resp.GetCertNotAfter().AsTime(),
		PolicyDocument:  resp.GetPolicy().GetDocument(),
		PolicySignature: resp.GetPolicy().GetSignature(),
		PolicyVersion:   resp.GetPolicy().GetVersion(),
		PolicyKeyDER:    resp.GetPolicySigningPublicKey(),
		ServerTime:      resp.GetServerTime().AsTime(),
	}, nil
}
