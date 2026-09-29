// Package collectors owns the collector identity lifecycle: enrollment
// credentials, the internal CA, certificates, policies, and the registry that
// the gRPC control plane (M3) serves.
package collectors

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/google/uuid"
)

const (
	rootValidity       = 10 * 365 * 24 * time.Hour
	leafValidity       = 90 * 24 * time.Hour
	serverValidity     = 365 * 24 * time.Hour
	clockSkewAllowance = 5 * time.Minute
)

// Errors surfaced by the CA layer.
var (
	ErrInvalidCSR = errors.New("collectors: invalid certificate request (ECDSA P-256 required)")
)

// CA is the internal Phase-1 certificate authority plus the Ed25519 policy
// signing key, loaded or created under one directory.
type CA struct {
	dir       string
	root      *x509.Certificate
	rootKey   *ecdsa.PrivateKey
	rootPool  *x509.CertPool
	rootPEM   []byte
	policyKey ed25519.PrivateKey
	policyIDA string
	policyPub []byte
	serverTLS *tls.Certificate
}

// Leaf is an issued collector certificate.
type Leaf struct {
	CertPEM     []byte
	ChainPEM    []byte
	Serial      string
	Fingerprint []byte // SHA-256 over DER — the mTLS identity map key
	NotBefore   time.Time
	NotAfter    time.Time
}

// LoadOrCreateCA initializes (or loads) the CA material in dir:
//
//	root.pem / root-key.pem          CA certificate + key (0600)
//	policy-signing-key.pem           Ed25519 policy signing key (0600)
//	server.crt / server.key          enrollment-listener TLS certificate
func LoadOrCreateCA(dir string, serverSANs []string) (*CA, error) {
	if dir == "" {
		return nil, errors.New("collectors: CA directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("collectors: create CA dir: %w", err)
	}
	ca := &CA{dir: dir}

	rootCertPath := filepath.Join(dir, "root.pem")
	rootKeyPath := filepath.Join(dir, "root-key.pem")
	switch {
	case fileExists(rootCertPath) && fileExists(rootKeyPath):
		if err := ca.loadRoot(rootCertPath, rootKeyPath); err != nil {
			return nil, err
		}
	default:
		if err := ca.createRoot(rootCertPath, rootKeyPath); err != nil {
			return nil, err
		}
	}

	if err := ca.loadOrCreatePolicyKey(filepath.Join(dir, "policy-signing-key.pem")); err != nil {
		return nil, err
	}
	if err := ca.ensureServerCertificate(serverSANs); err != nil {
		return nil, err
	}
	return ca, nil
}

func (ca *CA) loadRoot(certPath, keyPath string) error {
	certPEM, err := os.ReadFile(certPath) //nolint:gosec // fixed names under the operator-configured CA dir
	if err != nil {
		return fmt.Errorf("collectors: read root cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath) //nolint:gosec // fixed names under the operator-configured CA dir
	if err != nil {
		return fmt.Errorf("collectors: read root key: %w", err)
	}
	ca.rootPEM = certPEM
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return errors.New("collectors: root cert is not PEM")
	}
	if ca.root, err = x509.ParseCertificate(block.Bytes); err != nil {
		return fmt.Errorf("collectors: parse root cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return errors.New("collectors: root key is not PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("collectors: parse root key: %w", err)
	}
	ca.rootKey = key
	ca.rootPool = x509.NewCertPool()
	ca.rootPool.AddCert(ca.root)
	return nil
}

func (ca *CA) createRoot(certPath, keyPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("collectors: generate root key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Argus Phase-1 Internal CA", Organization: []string{"Argus"}},
		NotBefore:             time.Now().Add(-clockSkewAllowance),
		NotAfter:              time.Now().Add(rootValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("collectors: create root cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("collectors: parse new root: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("collectors: marshal root key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return fmt.Errorf("collectors: write root cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("collectors: write root key: %w", err)
	}
	ca.root, ca.rootKey, ca.rootPEM = cert, key, certPEM
	ca.rootPool = x509.NewCertPool()
	ca.rootPool.AddCert(cert)
	return nil
}

func (ca *CA) loadOrCreatePolicyKey(path string) error {
	if fileExists(path) {
		raw, err := os.ReadFile(path) //nolint:gosec // fixed file name under the operator-configured CA dir
		if err != nil {
			return fmt.Errorf("collectors: read policy key: %w", err)
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			return errors.New("collectors: policy key is not PEM")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("collectors: parse policy key: %w", err)
		}
		key, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return errors.New("collectors: policy key is not Ed25519")
		}
		ca.policyKey = key
	} else {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("collectors: generate policy key: %w", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return fmt.Errorf("collectors: marshal policy key: %w", err)
		}
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			return fmt.Errorf("collectors: write policy key: %w", err)
		}
		ca.policyKey = key
	}
	pubDER, err := x509.MarshalPKIXPublicKey(ca.policyKey.Public())
	if err != nil {
		return fmt.Errorf("collectors: marshal policy public key: %w", err)
	}
	ca.policyPub = pubDER
	sum := sha256.Sum256(pubDER)
	ca.policyIDA = hex.EncodeToString(sum[:8])
	return nil
}

func (ca *CA) ensureServerCertificate(sans []string) error {
	want := normalizeSANs(sans)
	certPath := filepath.Join(ca.dir, "server.crt")
	keyPath := filepath.Join(ca.dir, "server.key")
	if fileExists(certPath) && fileExists(keyPath) {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err == nil {
			if leaf, perr := x509.ParseCertificate(cert.Certificate[0]); perr == nil {
				if leaf.NotAfter.After(time.Now().Add(30*24*time.Hour)) && sameSANs(leaf, want) {
					ca.serverTLS = &cert
					return nil
				}
			}
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("collectors: generate server key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "argus-server", Organization: []string{"Argus"}},
		NotBefore:    time.Now().Add(-clockSkewAllowance),
		NotAfter:     time.Now().Add(serverValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	tmpl.DNSNames = append(tmpl.DNSNames, want.dns...)
	tmpl.IPAddresses = append(tmpl.IPAddresses, want.ips...)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.root, &key.PublicKey, ca.rootKey)
	if err != nil {
		return fmt.Errorf("collectors: create server cert: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("collectors: marshal server key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, append(certPEM, ca.rootPEM...), 0o600); err != nil {
		return fmt.Errorf("collectors: write server cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("collectors: write server key: %w", err)
	}
	cert, err := tls.X509KeyPair(append(certPEM, ca.rootPEM...), keyPEM)
	if err != nil {
		return fmt.Errorf("collectors: load new server cert: %w", err)
	}
	ca.serverTLS = &cert
	return nil
}

// RootPool returns the client-verification pool for the mTLS listener.
func (ca *CA) RootPool() *x509.CertPool { return ca.rootPool }

// RootPEM returns the CA certificate in PEM form (distributed to collectors
// by the operator at install time).
func (ca *CA) RootPEM() []byte { return ca.rootPEM }

// ServerTLS returns the enrollment/stream listener certificate.
func (ca *CA) ServerTLS() *tls.Certificate { return ca.serverTLS }

// PolicySigningPublicKeyDER returns the Ed25519 policy key in PKIX DER form
// (delivered in EnrollResponse; collectors pin it).
func (ca *CA) PolicySigningPublicKeyDER() []byte { return ca.policyPub }

// PolicyKeyID identifies the signing key for rotation bookkeeping.
func (ca *CA) PolicyKeyID() string { return ca.policyIDA }

// SignPolicy signs exact policy document bytes (no canonicalization: the bytes
// signed are the bytes served).
func (ca *CA) SignPolicy(document []byte) []byte {
	return ed25519.Sign(ca.policyKey, document)
}

// IssueLeaf validates a PKCS#10 CSR (ECDSA P-256 only) and issues a 90-day
// client certificate bound to collectorID with a SAN URI carrying org + id.
func (ca *CA) IssueLeaf(csrPEM []byte, collectorID uuid.UUID, orgSlug string) (Leaf, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return Leaf{}, ErrInvalidCSR
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return Leaf{}, ErrInvalidCSR
	}
	if err := csr.CheckSignature(); err != nil {
		return Leaf{}, ErrInvalidCSR
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return Leaf{}, ErrInvalidCSR
	}
	serial, err := randomSerial()
	if err != nil {
		return Leaf{}, err
	}
	sanURI, err := url.Parse(fmt.Sprintf("argus://collector/%s/%s", orgSlug, collectorID))
	if err != nil {
		return Leaf{}, fmt.Errorf("collectors: san uri: %w", err)
	}
	notBefore := time.Now().Add(-clockSkewAllowance)
	notAfter := time.Now().Add(leafValidity)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: collectorID.String(), Organization: []string{"Argus Collector"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{sanURI},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.root, pub, ca.rootKey)
	if err != nil {
		return Leaf{}, fmt.Errorf("collectors: sign leaf: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return Leaf{}, fmt.Errorf("collectors: parse leaf: %w", err)
	}
	fp := sha256.Sum256(leaf.Raw)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return Leaf{
		CertPEM:     certPEM,
		ChainPEM:    append(certPEM, ca.rootPEM...),
		Serial:      serial.Text(16),
		Fingerprint: fp[:],
		NotBefore:   notBefore,
		NotAfter:    notAfter,
	}, nil
}

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("collectors: serial: %w", err)
	}
	return serial, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

type sanSet struct {
	dns []string
	ips []net.IP
}

func normalizeSANs(sans []string) sanSet {
	set := sanSet{}
	for _, san := range sans {
		if ip := net.ParseIP(san); ip != nil {
			set.ips = append(set.ips, ip)
		} else if san != "" {
			set.dns = append(set.dns, san)
		}
	}
	sort.Strings(set.dns)
	return set
}

func sameSANs(leaf *x509.Certificate, want sanSet) bool {
	got := normalizeSANs(append(append([]string{}, leaf.DNSNames...), ipsToStrings(leaf.IPAddresses)...))
	if len(got.dns) != len(want.dns) || len(got.ips) != len(want.ips) {
		return false
	}
	for i := range got.dns {
		if got.dns[i] != want.dns[i] {
			return false
		}
	}
	for i := range got.ips {
		if got.ips[i].String() != want.ips[i].String() {
			return false
		}
	}
	return true
}

func ipsToStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}
