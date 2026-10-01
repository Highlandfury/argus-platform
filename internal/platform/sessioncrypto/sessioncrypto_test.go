package sessioncrypto

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func testSession(t *testing.T, creds ...PlainCredential) (seed, public []byte, session *Session) {
	t.Helper()
	seed, public, err := NewKeyPair()
	if err != nil {
		t.Fatalf("NewKeyPair: %v", err)
	}
	session, err = Seal(public, uuid.New().String(), uuid.New().String(), 7, creds)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return seed, public, session
}

func TestSealOpenRoundTrip(t *testing.T) {
	deviceA, credA := uuid.New().String(), uuid.New().String()
	deviceB, credB := uuid.New().String(), uuid.New().String()
	seed, _, session := testSession(t,
		PlainCredential{DeviceID: deviceA, CredentialID: credA, Kind: "snmp_v2c", Version: 1, Plaintext: []byte("community-A")},
		PlainCredential{DeviceID: deviceB, CredentialID: credB, Kind: "snmp_v3", Version: 3, Plaintext: []byte(`{"username":"ops"}`)},
	)
	if session.Algorithm != Algorithm {
		t.Fatalf("algorithm = %q", session.Algorithm)
	}
	if len(session.EphemeralPublicKey) != PublicKeyLen {
		t.Fatalf("ephemeral public key length = %d", len(session.EphemeralPublicKey))
	}
	if session.PolicyVersion != 7 {
		t.Fatalf("policy version = %d", session.PolicyVersion)
	}
	if session.Validate() != nil {
		t.Fatalf("valid session rejected: %v", session.Validate())
	}
	if len(session.Credentials) != 2 {
		t.Fatalf("records = %d", len(session.Credentials))
	}

	got2, err := Open(seed, session, session.Credentials[0])
	if err != nil || string(got2) != "community-A" {
		t.Fatalf("open record 0 = %q err=%v", got2, err)
	}
	got3, err := Open(seed, session, session.Credentials[1])
	if err != nil || string(got3) != `{"username":"ops"}` {
		t.Fatalf("open record 1 = %q err=%v", got3, err)
	}
	clear(got2)
	clear(got3)
}

func TestSealRequiresSessionKeyAndMaterial(t *testing.T) {
	_, public, err := NewKeyPair()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	if _, err := Seal(public[:8], uuid.New().String(), uuid.New().String(), 1, []PlainCredential{{}}); !errors.Is(err, ErrInvalidPublicKey) {
		t.Fatalf("short public key: %v", err)
	}
	if _, err := Seal(public, uuid.New().String(), uuid.New().String(), 1, nil); !errors.Is(err, ErrEmptyMaterial) {
		t.Fatalf("empty material: %v", err)
	}
	if _, err := Seal(public, "not-a-uuid", uuid.New().String(), 1,
		[]PlainCredential{{DeviceID: uuid.New().String(), CredentialID: uuid.New().String(), Kind: "snmp_v2c", Version: 1, Plaintext: []byte("x")}}); err == nil {
		t.Fatal("bad org id accepted")
	}
}

func TestOpenWrongSessionKeyFails(t *testing.T) {
	_, _, session := testSession(t, PlainCredential{
		DeviceID: uuid.New().String(), CredentialID: uuid.New().String(),
		Kind: "snmp_v2c", Version: 1, Plaintext: []byte("secret-community"),
	})
	otherSeed, _, err := NewKeyPair()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	if _, err := Open(otherSeed, session, session.Credentials[0]); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong session key error = %v, want ErrAuthentication", err)
	}
	if _, err := Open([]byte("short"), session, session.Credentials[0]); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("short seed error = %v, want ErrInvalidKey", err)
	}
}

func TestOpenContextBindingFails(t *testing.T) {
	rec := PlainCredential{
		DeviceID: uuid.New().String(), CredentialID: uuid.New().String(),
		Kind: "snmp_v2c", Version: 4, Plaintext: []byte("bound-community"),
	}
	seed, _, session := testSession(t, rec)

	mutations := map[string]func(*Session, *Credential){
		"org":       func(s *Session, _ *Credential) { s.OrgID = uuid.New().String() },
		"collector": func(s *Session, _ *Credential) { s.CollectorID = uuid.New().String() },
		"policy":    func(s *Session, _ *Credential) { s.PolicyVersion++ },
		"device":    func(_ *Session, c *Credential) { c.DeviceID = uuid.New().String() },
		"credential": func(_ *Session, c *Credential) {
			c.CredentialID = uuid.New().String()
		},
		"version": func(_ *Session, c *Credential) { c.Version++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			s := deepCopySession(session)
			c := deepCopyCredential(s.Credentials[0])
			mutate(s, &c)
			if _, err := Open(seed, s, c); !errors.Is(err, ErrAuthentication) {
				t.Fatalf("mutated %s: err = %v, want ErrAuthentication", name, err)
			}
		})
	}
}

// TestOpenCrossRecordCiphertextFails pins that ciphertext sealed for one
// record cannot be presented under another record's identity.
func TestOpenCrossRecordCiphertextFails(t *testing.T) {
	recA := PlainCredential{DeviceID: uuid.New().String(), CredentialID: uuid.New().String(), Kind: "snmp_v2c", Version: 1, Plaintext: []byte("A")}
	recB := PlainCredential{DeviceID: uuid.New().String(), CredentialID: uuid.New().String(), Kind: "snmp_v2c", Version: 1, Plaintext: []byte("B")}
	seed, _, session := testSession(t, recA, recB)
	a, b := session.Credentials[0], session.Credentials[1]
	swapped := Credential{DeviceID: a.DeviceID, CredentialID: a.CredentialID, Kind: a.Kind, Version: a.Version, Nonce: b.Nonce, Ciphertext: b.Ciphertext}
	if _, err := Open(seed, session, swapped); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("cross-record ciphertext err = %v, want ErrAuthentication", err)
	}
}

func TestOpenTamperedCiphertextFails(t *testing.T) {
	seed, _, session := testSession(t, PlainCredential{
		DeviceID: uuid.New().String(), CredentialID: uuid.New().String(),
		Kind: "snmp_v2c", Version: 1, Plaintext: []byte("tamper-me"),
	})
	rec := session.Credentials[0]
	rec.Ciphertext = append([]byte{}, rec.Ciphertext...)
	rec.Ciphertext[0] ^= 0xff
	if _, err := Open(seed, session, rec); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tampered ciphertext err = %v", err)
	}
	rec2 := session.Credentials[0]
	rec2.Nonce = append([]byte{}, rec2.Nonce...)
	rec2.Nonce[0] ^= 0xff
	if _, err := Open(seed, session, rec2); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tampered nonce err = %v", err)
	}
}

func TestSealFreshEphemeralPerBundle(t *testing.T) {
	device, cred := uuid.New().String(), uuid.New().String()
	seed, public, first := testSession(t, PlainCredential{
		DeviceID: device, CredentialID: cred, Kind: "snmp_v2c", Version: 1, Plaintext: []byte("fresh"),
	})
	second, err := Seal(public, first.OrgID, first.CollectorID, first.PolicyVersion,
		[]PlainCredential{{DeviceID: device, CredentialID: cred, Kind: "snmp_v2c", Version: 1, Plaintext: []byte("fresh")}})
	if err != nil {
		t.Fatalf("second seal: %v", err)
	}
	if bytes.Equal(first.EphemeralPublicKey, second.EphemeralPublicKey) {
		t.Fatal("bundles must use fresh server ephemerals")
	}
	if bytes.Equal(first.Credentials[0].Ciphertext, second.Credentials[0].Ciphertext) {
		t.Fatal("fresh nonces must produce distinct ciphertexts")
	}
	got, err := Open(seed, second, second.Credentials[0])
	if err != nil || string(got) != "fresh" {
		t.Fatalf("open second bundle = %q err=%v", got, err)
	}
	clear(got)
}

func TestValidateRejectsMalformedSessions(t *testing.T) {
	valid := Session{
		Algorithm:          Algorithm,
		EphemeralPublicKey: make([]byte, PublicKeyLen),
		OrgID:              uuid.New().String(),
		CollectorID:        uuid.New().String(),
		PolicyVersion:      1,
		Credentials: []Credential{{
			DeviceID: uuid.New().String(), CredentialID: uuid.New().String(),
			Kind: "snmp_v2c", Version: 1, Nonce: make([]byte, NonceLen), Ciphertext: make([]byte, MinCiphertextLen),
		}},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid session rejected: %v", err)
	}
	// An unknown algorithm with a valid structure stays applicable (old
	// collectors apply the rest of the bundle and report credential_missing).
	unknown := valid
	unknown.Algorithm = "X25519-FUTURE"
	if err := unknown.Validate(); err != nil {
		t.Fatalf("unknown algorithm must stay structurally valid: %v", err)
	}

	mutations := map[string]func(*Session){
		"empty algorithm":  func(s *Session) { s.Algorithm = "" },
		"long algorithm":   func(s *Session) { s.Algorithm = strings.Repeat("a", MaxAlgorithmLen+1) },
		"bad ephemeral":    func(s *Session) { s.EphemeralPublicKey = make([]byte, 8) },
		"bad org":          func(s *Session) { s.OrgID = "nope" },
		"bad collector":    func(s *Session) { s.CollectorID = "nope" },
		"negative policy":  func(s *Session) { s.PolicyVersion = -1 },
		"bad device":       func(s *Session) { s.Credentials[0].DeviceID = "nope" },
		"bad credential":   func(s *Session) { s.Credentials[0].CredentialID = "nope" },
		"empty kind":       func(s *Session) { s.Credentials[0].Kind = " " },
		"bad nonce":        func(s *Session) { s.Credentials[0].Nonce = nil },
		"short ciphertext": func(s *Session) { s.Credentials[0].Ciphertext = make([]byte, 4) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			s := deepCopySession(&valid)
			mutate(s)
			if err := s.Validate(); err == nil {
				t.Fatalf("malformed session (%s) accepted", name)
			}
		})
	}
}

func TestPublicFromSeed(t *testing.T) {
	seed, public, err := NewKeyPair()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	got, err := PublicFromSeed(seed)
	if err != nil || !bytes.Equal(got, public) {
		t.Fatalf("PublicFromSeed mismatch err=%v", err)
	}
	if _, err := PublicFromSeed([]byte("short")); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("short seed err = %v", err)
	}
}

func deepCopySession(s *Session) *Session {
	out := *s
	out.EphemeralPublicKey = append([]byte{}, s.EphemeralPublicKey...)
	out.Credentials = make([]Credential, len(s.Credentials))
	for i, c := range s.Credentials {
		out.Credentials[i] = deepCopyCredential(c)
	}
	return &out
}

func deepCopyCredential(c Credential) Credential {
	out := c
	out.Nonce = append([]byte{}, c.Nonce...)
	out.Ciphertext = append([]byte{}, c.Ciphertext...)
	return out
}
