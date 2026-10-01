package collectors

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/modules/credentials"
	"github.com/argus-platform/argus/internal/platform/sessioncrypto"
)

// fakeResolver is the in-memory CredentialResolver: real resolution/RLS lives
// in the credentials module (integration-tested there); this pins the policy
// materialization contract. It copies plaintext out per call, exactly like the
// real resolver.
type fakeResolver struct {
	byDevice map[string]fakeResolved
	failWith error
}

type fakeResolved struct {
	plaintext []byte
	kind      string
	version   int
	id        uuid.UUID
}

func (f *fakeResolver) Materialize(_ context.Context, _, deviceID uuid.UUID) ([]byte, credentials.EffectiveCredential, error) {
	if f.failWith != nil {
		return nil, credentials.EffectiveCredential{}, f.failWith
	}
	r, ok := f.byDevice[deviceID.String()]
	if !ok {
		return nil, credentials.EffectiveCredential{}, credentials.ErrNoCredential
	}
	return append([]byte(nil), r.plaintext...), credentials.EffectiveCredential{
		CredentialID: r.id,
		Kind:         r.kind,
		Version:      r.version,
	}, nil
}

func testCA(t *testing.T) *CA {
	t.Helper()
	ca, err := LoadOrCreateCA(t.TempDir(), []string{"localhost"})
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	return ca
}

func sessionTarget(deviceID string, pollType string) PolicyTarget {
	return PolicyTarget{DeviceID: deviceID, MgmtIP: "192.0.2.10", Name: "edge-1", Tier: "standard", PollType: pollType, Kind: "switch"}
}

func verifySigned(t *testing.T, ca *CA, sp *SignedPolicy) {
	t.Helper()
	pub, err := x509.ParsePKIXPublicKey(ca.PolicySigningPublicKeyDER())
	if err != nil {
		t.Fatalf("parse policy pub: %v", err)
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		t.Fatal("policy key is not Ed25519")
	}
	if !ed25519.Verify(edPub, sp.Document, sp.Signature) {
		t.Fatal("materialized policy signature does not verify")
	}
}

// TestMaterializePolicyRoundTrip is the server-side M9-S3 unit acceptance:
// a stored base bundle (no session, no plaintext anywhere) is extended with a
// session block sealed to a collector session key, signed, and decryptable
// only with that key.
func TestMaterializePolicyRoundTrip(t *testing.T) {
	ca := testCA(t)
	deviceA, deviceB := uuid.New(), uuid.New()
	credID := uuid.New()
	baseTargets := []PolicyTarget{
		sessionTarget(deviceA.String(), "snmp"),
		sessionTarget(deviceA.String(), "icmp"),
		sessionTarget(deviceB.String(), "icmp"),
	}
	base, err := ca.BuildSignedPolicyWithTargets(5, baseTargets)
	if err != nil {
		t.Fatalf("base policy: %v", err)
	}
	resolver := &fakeResolver{byDevice: map[string]fakeResolved{
		deviceA.String(): {plaintext: []byte("switch"), kind: "snmp_v2c", version: 2, id: credID},
	}}
	svc := &Service{ca: ca, creds: resolver}

	orgID, collectorID := uuid.New(), uuid.New()
	seed, public, err := sessioncrypto.NewKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	materialized := svc.materializePolicy(context.Background(), orgID, collectorID, base, public)
	if materialized == base {
		t.Fatal("expected a materialized bundle")
	}
	verifySigned(t, ca, materialized)
	if materialized.Version != base.Version {
		t.Fatalf("materialized version = %d, want %d", materialized.Version, base.Version)
	}

	var doc PolicyDocument
	if err := json.Unmarshal(materialized.Document, &doc); err != nil {
		t.Fatalf("unmarshal materialized: %v", err)
	}
	if doc.Session == nil {
		t.Fatal("materialized document has no session block")
	}
	if doc.Session.Algorithm != sessioncrypto.Algorithm || doc.Session.OrgID != orgID.String() || doc.Session.CollectorID != collectorID.String() {
		t.Fatalf("session context = %+v", doc.Session)
	}
	if doc.Session.PolicyVersion != base.Version {
		t.Fatalf("session policy version = %d, want %d", doc.Session.PolicyVersion, base.Version)
	}
	if len(doc.Session.Credentials) != 1 {
		t.Fatalf("session records = %d, want 1 (ICMP-only devices must not materialize)", len(doc.Session.Credentials))
	}
	rec := doc.Session.Credentials[0]
	if rec.DeviceID != deviceA.String() || rec.CredentialID != credID.String() || rec.Kind != "snmp_v2c" || rec.Version != 2 {
		t.Fatalf("record = %+v", rec)
	}
	plaintext, err := sessioncrypto.Open(seed, doc.Session, rec)
	if err != nil || string(plaintext) != "switch" {
		t.Fatalf("open materialized = %q err=%v", plaintext, err)
	}
	clear(plaintext)

	// Wrong session key cannot decrypt.
	otherSeed, _, err := sessioncrypto.NewKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	if _, err := sessioncrypto.Open(otherSeed, doc.Session, rec); !errors.Is(err, sessioncrypto.ErrAuthentication) {
		t.Fatalf("wrong session key err = %v, want ErrAuthentication", err)
	}

	// The base (stored) document is untouched: no session, no plaintext.
	var stored PolicyDocument
	if err := json.Unmarshal(base.Document, &stored); err != nil {
		t.Fatalf("unmarshal base: %v", err)
	}
	if stored.Session != nil {
		t.Fatal("stored base document gained a session block")
	}
	if len(stored.Targets) != len(baseTargets) {
		t.Fatalf("stored targets = %d, want %d", len(stored.Targets), len(baseTargets))
	}
	if string(base.Document) == string(materialized.Document) {
		t.Fatal("materialized document must differ from the stored base")
	}
}

// TestMaterializePolicyFailClosed pins the no-material paths: no resolver, no
// session key, no resolving credential, and non-SNMP kinds all deliver the
// base bundle (collectors then report credential_missing).
func TestMaterializePolicyFailClosed(t *testing.T) {
	ca := testCA(t)
	device := uuid.New()
	base, err := ca.BuildSignedPolicyWithTargets(1, []PolicyTarget{sessionTarget(device.String(), "snmp")})
	if err != nil {
		t.Fatalf("base: %v", err)
	}
	orgID, collectorID := uuid.New(), uuid.New()
	seed, public, err := sessioncrypto.NewKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	_ = seed

	cases := map[string]*Service{
		"no resolver":    {},
		"unresolvable":   {ca: ca, creds: &fakeResolver{byDevice: map[string]fakeResolved{}}},
		"resolver error": {ca: ca, creds: &fakeResolver{failWith: credentials.ErrVaultUnavailable}},
		"non-snmp kind": {ca: ca, creds: &fakeResolver{byDevice: map[string]fakeResolved{
			device.String(): {plaintext: []byte("ssh-private-key"), kind: "ssh_key", version: 1, id: uuid.New()},
		}}},
	}
	for name, svc := range cases {
		t.Run(name, func(t *testing.T) {
			got := svc.materializePolicy(context.Background(), orgID, collectorID, base, public)
			if got != base {
				t.Fatalf("%s: expected the base bundle, got a materialized one", name)
			}
		})
	}

	// No session public key: base bundle.
	svc := &Service{ca: ca, creds: &fakeResolver{byDevice: map[string]fakeResolved{
		device.String(): {plaintext: []byte("c"), kind: "snmp_v2c", version: 1, id: uuid.New()},
	}}}
	if got := svc.materializePolicy(context.Background(), orgID, collectorID, base, nil); got != base {
		t.Fatal("no session key: expected the base bundle")
	}
}

// TestMaterializePolicySealsEveryResolvedDevice pins multi-device bundles.
func TestMaterializePolicySealsEveryResolvedDevice(t *testing.T) {
	ca := testCA(t)
	deviceA, deviceB := uuid.New(), uuid.New()
	base, err := ca.BuildSignedPolicyWithTargets(9, []PolicyTarget{
		sessionTarget(deviceA.String(), "snmp"),
		sessionTarget(deviceB.String(), "snmp"),
	})
	if err != nil {
		t.Fatalf("base: %v", err)
	}
	resolver := &fakeResolver{byDevice: map[string]fakeResolved{
		deviceA.String(): {plaintext: []byte("community-a"), kind: "snmp_v2c", version: 1, id: uuid.New()},
		deviceB.String(): {plaintext: []byte(`{"username":"ops"}`), kind: "snmp_v3", version: 4, id: uuid.New()},
	}}
	svc := &Service{ca: ca, creds: resolver}
	seed, public, err := sessioncrypto.NewKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	sp := svc.materializePolicy(context.Background(), uuid.New(), uuid.New(), base, public)
	var doc PolicyDocument
	if err := json.Unmarshal(sp.Document, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.Session == nil || len(doc.Session.Credentials) != 2 {
		t.Fatalf("session records = %+v, want 2", doc.Session)
	}
	got := map[string]string{}
	for _, rec := range doc.Session.Credentials {
		pt, err := sessioncrypto.Open(seed, doc.Session, rec)
		if err != nil {
			t.Fatalf("open %s: %v", rec.DeviceID, err)
		}
		got[rec.DeviceID] = string(pt)
		clear(pt)
	}
	if got[deviceA.String()] != "community-a" || got[deviceB.String()] != `{"username":"ops"}` {
		t.Fatalf("decrypted material = %+v", got)
	}
}
