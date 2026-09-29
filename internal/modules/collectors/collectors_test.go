package collectors

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func testCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "collector"}}, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestCAIssueLeafIdentity(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir(), []string{"localhost", "127.0.0.1", "server"})
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}
	collectorID := uuid.New()
	leaf, err := ca.IssueLeaf(testCSR(t), collectorID, "dev")
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}

	block, _ := pem.Decode(leaf.CertPEM)
	if block == nil {
		t.Fatal("leaf is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if cert.Subject.CommonName != collectorID.String() {
		t.Fatalf("CN = %q, want %q", cert.Subject.CommonName, collectorID)
	}
	wantURI := "argus://collector/dev/" + collectorID.String()
	if len(cert.URIs) != 1 || cert.URIs[0].String() != wantURI {
		t.Fatalf("SAN URIs = %v, want %s", cert.URIs, wantURI)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("EKU = %v, want clientAuth only", cert.ExtKeyUsage)
	}
	if !cert.NotAfter.After(time.Now().Add(80 * 24 * time.Hour)) {
		t.Fatalf("leaf validity too short: %v", cert.NotAfter)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: ca.RootPool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("leaf does not verify against the CA: %v", err)
	}
	if len(leaf.Fingerprint) != 32 {
		t.Fatalf("fingerprint length = %d, want 32", len(leaf.Fingerprint))
	}
	if !strings.Contains(string(leaf.ChainPEM), "BEGIN CERTIFICATE") {
		t.Fatal("chain PEM malformed")
	}
}

func TestCARejectsNonP256CSR(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir(), []string{"localhost"})
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	_ = pub
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "bad"}}, priv)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	if _, err := ca.IssueLeaf(csrPEM, uuid.New(), "dev"); !errors.Is(err, ErrInvalidCSR) {
		t.Fatalf("want ErrInvalidCSR for Ed25519 CSR, got %v", err)
	}
	if _, err := ca.IssueLeaf([]byte("not-a-csr"), uuid.New(), "dev"); !errors.Is(err, ErrInvalidCSR) {
		t.Fatalf("want ErrInvalidCSR for malformed CSR, got %v", err)
	}
}

func TestPolicySigningRoundTrip(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir(), []string{"localhost"})
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	sp, err := ca.BuildSignedPolicy(1)
	if err != nil {
		t.Fatalf("BuildSignedPolicy: %v", err)
	}
	pub, err := x509.ParsePKIXPublicKey(ca.PolicySigningPublicKeyDER())
	if err != nil {
		t.Fatalf("parse pub: %v", err)
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		t.Fatal("policy public key is not Ed25519")
	}
	if !ed25519.Verify(edPub, sp.Document, sp.Signature) {
		t.Fatal("policy signature must verify with the delivered public key")
	}
	// Tampering must fail.
	tampered := append([]byte{}, sp.Document...)
	tampered[0] ^= 0xFF
	if ed25519.Verify(edPub, tampered, sp.Signature) {
		t.Fatal("tampered policy must not verify")
	}
	if sp.KeyID == "" || len(sp.JitterSalt) != 64 {
		t.Fatalf("policy metadata incomplete: keyID=%q salt=%d chars", sp.KeyID, len(sp.JitterSalt))
	}
	if !strings.Contains(string(sp.Document), `"collector_cpu_percent"`) {
		t.Fatalf("policy document missing the documented metric: %s", sp.Document)
	}
}

func TestEnrollmentTokenFormatAndUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		raw, hash, err := MintEnrollmentToken()
		if err != nil {
			t.Fatalf("MintEnrollmentToken: %v", err)
		}
		if !strings.HasPrefix(raw, EnrollmentTokenPrefix) || len(raw) != len(EnrollmentTokenPrefix)+26 {
			t.Fatalf("token format wrong: %q", raw)
		}
		if seen[raw] {
			t.Fatal("token collision")
		}
		seen[raw] = true
		if len(hash) != 32 {
			t.Fatalf("hash length = %d", len(hash))
		}
		if string(hash) == raw {
			t.Fatal("hash must differ from raw")
		}
		if string(HashEnrollmentToken(raw)) != string(hash) {
			t.Fatal("HashEnrollmentToken mismatch")
		}
	}
}
