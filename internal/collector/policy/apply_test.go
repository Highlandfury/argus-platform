package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/platform/sessioncrypto"
)

func validDocument(t *testing.T, targets []Target) []byte {
	t.Helper()
	doc := Document{
		HeartbeatIntervalSeconds: 30,
		ReportIntervalSeconds:    5,
		BatchMaxSamples:          5000,
		SpoolMaxBytes:            64 << 20,
		Metrics: []Metric{{
			Key: "collector_cpu_percent", Unit: "percent", Source: "collector_cpu",
			IntervalSeconds: 5, Dimensions: map[string]string{"cpu": "total"},
		}},
		Targets: targets,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

func signPolicy(t *testing.T, _ []byte) ([]byte, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	return der, priv
}

func TestVerifyAndValidateWithTargets(t *testing.T) {
	doc := validDocument(t, []Target{{
		DeviceID: "0198d5a3-0000-7000-8000-000000000001",
		MgmtIP:   "192.0.2.10",
		Name:     "edge-1",
		Tier:     "fast",
	}})
	pubDER, priv := signPolicy(t, doc)
	sig := ed25519.Sign(priv, doc)

	got, err := VerifyAndValidate(doc, sig, pubDER)
	if err != nil {
		t.Fatalf("VerifyAndValidate: %v", err)
	}
	if len(got.Targets) != 1 || got.Targets[0].DeviceID != "0198d5a3-0000-7000-8000-000000000001" {
		t.Fatalf("targets = %+v", got.Targets)
	}

	// Tampering must fail signature verification.
	tampered := append([]byte{}, doc...)
	tampered[0] ^= 0xff
	if _, err := VerifyAndValidate(tampered, sig, pubDER); err == nil {
		t.Fatal("tampered document verified")
	}
}

func TestValidateTargetBounds(t *testing.T) {
	valid := []Target{{DeviceID: "0198d5a3-0000-7000-8000-000000000001", MgmtIP: "2001:db8::1", Name: "d", Tier: "slow"}}
	if err := Validate(Document{
		HeartbeatIntervalSeconds: 30, ReportIntervalSeconds: 5, BatchMaxSamples: 5000, SpoolMaxBytes: 1 << 20,
		Metrics: []Metric{{Key: "k", Unit: "u", Source: "s", IntervalSeconds: 1}}, Targets: valid,
	}); err != nil {
		t.Fatalf("valid targets rejected: %v", err)
	}

	// A device may carry one ICMP and one SNMP target (M9-S2); the same
	// (device, normalized poll type) pair twice is a duplicate.
	both := []Target{
		{DeviceID: "0198d5a3-0000-7000-8000-000000000001", MgmtIP: "192.0.2.1", Name: "d", Tier: "fast", PollType: "icmp", Kind: "switch"},
		{DeviceID: "0198d5a3-0000-7000-8000-000000000001", MgmtIP: "192.0.2.1", Name: "d", Tier: "fast", PollType: "snmp", Kind: "switch"},
	}
	if err := Validate(Document{
		HeartbeatIntervalSeconds: 30, ReportIntervalSeconds: 5, BatchMaxSamples: 5000, SpoolMaxBytes: 1 << 20,
		Metrics: []Metric{{Key: "k", Unit: "u", Source: "s", IntervalSeconds: 1}}, Targets: both,
	}); err != nil {
		t.Fatalf("icmp+snmp targets rejected: %v", err)
	}

	cases := map[string][]Target{
		"bad uuid":  {{DeviceID: "not-a-uuid", MgmtIP: "192.0.2.1", Tier: "fast"}},
		"bad ip":    {{DeviceID: "0198d5a3-0000-7000-8000-000000000001", MgmtIP: "nope", Tier: "fast"}},
		"duplicate": {valid[0], valid[0]},
		// Unknown poll types normalize to ICMP, so they collide with the
		// explicit ICMP target.
		"duplicate normalized poll type": {
			valid[0],
			{DeviceID: valid[0].DeviceID, MgmtIP: valid[0].MgmtIP, Name: "d", Tier: "fast", PollType: "bogus"},
		},
		"poll type too long": {{DeviceID: valid[0].DeviceID, MgmtIP: valid[0].MgmtIP, Tier: "fast", PollType: strings.Repeat("x", 17)}},
		"kind too long":      {{DeviceID: valid[0].DeviceID, MgmtIP: valid[0].MgmtIP, Tier: "fast", Kind: strings.Repeat("k", 65)}},
	}
	for name, targets := range cases {
		err := Validate(Document{
			HeartbeatIntervalSeconds: 30, ReportIntervalSeconds: 5, BatchMaxSamples: 5000, SpoolMaxBytes: 1 << 20,
			Metrics: []Metric{{Key: "k", Unit: "u", Source: "s", IntervalSeconds: 1}}, Targets: targets,
		})
		if err == nil {
			t.Fatalf("%s targets accepted", name)
		}
	}

	tooMany := make([]Target, MaxTargets+1)
	err := Validate(Document{
		HeartbeatIntervalSeconds: 30, ReportIntervalSeconds: 5, BatchMaxSamples: 5000, SpoolMaxBytes: 1 << 20,
		Metrics: []Metric{{Key: "k", Unit: "u", Source: "s", IntervalSeconds: 1}}, Targets: tooMany,
	})
	if err == nil {
		t.Fatal("over-limit targets accepted")
	}
}

func TestStoreKeepsLastThreeBundles(t *testing.T) {
	dir := t.TempDir()
	for v := int64(1); v <= 5; v++ {
		if _, err := Store(dir, v, []byte("{}")); err != nil {
			t.Fatalf("store v%d: %v", v, err)
		}
	}
	for _, name := range []string{"policy-v3.json", "policy-v4.json", "policy-v5.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s should be retained: %v", name, err)
		}
	}
	for _, name := range []string{"policy-v1.json", "policy-v2.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s should be pruned (err=%v)", name, err)
		}
	}
	// The newest bundle remains loadable.
	raw, err := os.ReadFile(filepath.Join(dir, "policy-v5.json")) //nolint:gosec // path under t.TempDir()
	if err != nil || string(raw) != "{}" {
		t.Fatalf("load newest: %q err=%v", raw, err)
	}
}

func validSessionMaterial() *sessioncrypto.Session {
	return &sessioncrypto.Session{
		Algorithm:          sessioncrypto.Algorithm,
		EphemeralPublicKey: make([]byte, sessioncrypto.PublicKeyLen),
		OrgID:              uuid.New().String(),
		CollectorID:        uuid.New().String(),
		PolicyVersion:      4,
		Credentials: []sessioncrypto.Credential{{
			DeviceID: uuid.New().String(), CredentialID: uuid.New().String(),
			Kind: "snmp_v2c", Version: 1, Nonce: make([]byte, sessioncrypto.NonceLen),
			Ciphertext: make([]byte, sessioncrypto.MinCiphertextLen),
		}},
	}
}

// TestValidateSessionMaterial pins the M9-S3 additive block: a structurally
// valid session passes validation (including an unknown future algorithm, so
// old collectors still apply the rest of the bundle), while malformed shapes
// reject the document.
func TestValidateSessionMaterial(t *testing.T) {
	base := func() Document {
		return Document{
			HeartbeatIntervalSeconds: 30, ReportIntervalSeconds: 5, BatchMaxSamples: 5000, SpoolMaxBytes: 1 << 20,
			Metrics: []Metric{{Key: "k", Unit: "u", Source: "s", IntervalSeconds: 1}},
		}
	}
	doc := base()
	doc.Session = validSessionMaterial()
	if err := Validate(doc); err != nil {
		t.Fatalf("valid session material rejected: %v", err)
	}

	unknown := validSessionMaterial()
	unknown.Algorithm = "X25519-FUTURE"
	doc = base()
	doc.Session = unknown
	if err := Validate(doc); err != nil {
		t.Fatalf("unknown algorithm must stay structurally valid: %v", err)
	}

	shapes := map[string]func(*sessioncrypto.Session){
		"bad ephemeral key": func(s *sessioncrypto.Session) { s.EphemeralPublicKey = []byte{1, 2, 3} },
		"bad org":           func(s *sessioncrypto.Session) { s.OrgID = "not-a-uuid" },
		"bad device":        func(s *sessioncrypto.Session) { s.Credentials[0].DeviceID = "not-a-uuid" },
		"short nonce":       func(s *sessioncrypto.Session) { s.Credentials[0].Nonce = []byte{1} },
		"short ciphertext":  func(s *sessioncrypto.Session) { s.Credentials[0].Ciphertext = []byte{1} },
		"too many records": func(s *sessioncrypto.Session) {
			s.Credentials = make([]sessioncrypto.Credential, sessioncrypto.MaxCredentials+1)
		},
		"negative policy":     func(s *sessioncrypto.Session) { s.PolicyVersion = -1 },
		"negative credential": func(s *sessioncrypto.Session) { s.Credentials[0].Version = -1 },
	}
	for name, mutate := range shapes {
		t.Run(name, func(t *testing.T) {
			s := validSessionMaterial()
			mutate(s)
			d := base()
			d.Session = s
			if err := Validate(d); err == nil {
				t.Fatalf("malformed session material (%s) accepted", name)
			}
		})
	}
}

// TestVerifyAndValidateMaterializedDocument round-trips a signed document with
// a session block through the exact collector verification path (base64 JSON
// encoding included).
func TestVerifyAndValidateMaterializedDocument(t *testing.T) {
	pubDER, priv := signPolicy(t, nil)
	session := validSessionMaterial()
	doc := Document{
		HeartbeatIntervalSeconds: 30, ReportIntervalSeconds: 5, BatchMaxSamples: 5000, SpoolMaxBytes: 1 << 20,
		Metrics: []Metric{{Key: "k", Unit: "u", Source: "s", IntervalSeconds: 1}},
		Session: session,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sig := ed25519.Sign(priv, raw)
	got, err := VerifyAndValidate(raw, sig, pubDER)
	if err != nil {
		t.Fatalf("VerifyAndValidate materialized: %v", err)
	}
	if got.Session == nil || got.Session.Credentials[0].DeviceID != session.Credentials[0].DeviceID {
		t.Fatalf("session material lost in round trip: %+v", got.Session)
	}
	if len(got.Session.Credentials[0].Ciphertext) != sessioncrypto.MinCiphertextLen {
		t.Fatalf("ciphertext length changed: %d", len(got.Session.Credentials[0].Ciphertext))
	}
}
