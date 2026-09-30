package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

// testVault builds a vault over a freshly generated master-key file in a
// throwaway directory (dev mode, like the compose server).
func testVault(t *testing.T) *Vault {
	t.Helper()
	kek, err := LoadOrCreateLocalKMS(LocalConfig{
		Path:          filepath.Join(t.TempDir(), "master.key"),
		KeyID:         "test-key",
		AllowGenerate: true,
	})
	if err != nil {
		t.Fatalf("LoadOrCreateLocalKMS: %v", err)
	}
	return New(kek)
}

func TestSealOpenRoundTrip(t *testing.T) {
	vault := testVault(t)
	orgID, secretType, secretID := uuid.New(), "snmp_v2c", uuid.New() //nolint:gosec // test value, not a credential
	plaintext := []byte("community-string-fixture")

	env, err := vault.Seal(orgID, secretType, secretID, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if env.KMSKeyID != "test-key" {
		t.Fatalf("kms_key_id = %q, want test-key", env.KMSKeyID)
	}
	if env.KeyVersion != 1 {
		t.Fatalf("key_version = %d, want 1 (fresh key ring)", env.KeyVersion)
	}
	if len(env.DataEnc) == 0 || env.DataEnc[0] != envelopeFormatV1 {
		t.Fatalf("data_enc must start with the v1 format byte, got %v", env.DataEnc)
	}
	if env.EncryptionContext != (Context{OrgID: orgID, SecretType: secretType, SecretID: secretID, Version: 1}) {
		t.Fatalf("unexpected encryption context: %+v", env.EncryptionContext)
	}

	got, err := vault.Open(env)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("Open returned %q, want %q", got, plaintext)
	}
}

func TestSealUsesFreshDEKAndNonces(t *testing.T) {
	vault := testVault(t)
	orgID, secretID := uuid.New(), uuid.New()

	a, err := vault.Seal(orgID, "snmp_v3", secretID, []byte("same plaintext"))
	if err != nil {
		t.Fatalf("Seal a: %v", err)
	}
	b, err := vault.Seal(orgID, "snmp_v3", secretID, []byte("same plaintext"))
	if err != nil {
		t.Fatalf("Seal b: %v", err)
	}
	if bytes.Equal(a.DataEnc, b.DataEnc) {
		t.Fatal("two seals of the same plaintext produced identical envelopes (DEK/nonce reuse)")
	}
}

func TestSealRejectsInvalidContext(t *testing.T) {
	vault := testVault(t)
	cases := []struct {
		name       string
		orgID      uuid.UUID
		secretType string
		secretID   uuid.UUID
	}{
		{"nil org", uuid.Nil, "snmp_v2c", uuid.New()},
		{"empty type", uuid.New(), "", uuid.New()},
		{"blank type", uuid.New(), "  ", uuid.New()},
		{"nil secret", uuid.New(), "snmp_v2c", uuid.Nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := vault.Seal(tc.orgID, tc.secretType, tc.secretID, []byte("x")); !errors.Is(err, ErrInvalidContext) {
				t.Fatalf("Seal: want ErrInvalidContext, got %v", err)
			}
		})
	}
}

// TestOpenRejectsWrongContext proves the AAD binding: an envelope opened under
// any other org, secret type, secret id, or version fails closed.
func TestOpenRejectsWrongContext(t *testing.T) {
	vault := testVault(t)
	orgID, secretType, secretID := uuid.New(), "snmp_v2c", uuid.New() //nolint:gosec // test value, not a credential
	env, err := vault.Seal(orgID, secretType, secretID, []byte("bound secret"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(*Envelope)
		wantErr error
	}{
		{"wrong org", func(e *Envelope) { e.EncryptionContext.OrgID = uuid.New() }, ErrAuthentication},
		{"wrong type", func(e *Envelope) { e.EncryptionContext.SecretType = "snmp_v3" }, ErrAuthentication},
		{"wrong secret", func(e *Envelope) { e.EncryptionContext.SecretID = uuid.New() }, ErrAuthentication},
		{"wrong version", func(e *Envelope) {
			e.EncryptionContext.Version = 2
			e.KeyVersion = 2
		}, ErrMalformedEnvelope},
		{"zero context", func(e *Envelope) { e.EncryptionContext = Context{} }, ErrInvalidContext},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := env
			tc.mutate(&bad)
			if _, err := vault.Open(bad); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Open with %s: want %v, got %v", tc.name, tc.wantErr, err)
			}
		})
	}
}

// TestOpenDetectsTampering flips one byte at a time across the header, wrapped
// DEK, nonces, and ciphertext: every mutation must fail closed.
func TestOpenDetectsTampering(t *testing.T) {
	vault := testVault(t)
	env, err := vault.Seal(uuid.New(), "ssh_paramiko", uuid.New(), bytes.Repeat([]byte("p"), 32))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	offsets := []int{
		0,                           // format version
		1,                           // wrap algorithm
		2,                           // data algorithm
		3,                           // reserved
		5,                           // key version low byte
		20,                          // inside the wrapped DEK
		headerLen + wrappedDEKLenV1, // first data-nonce byte
		len(env.DataEnc) - 1,        // last ciphertext/tag byte
	}
	for _, off := range offsets {
		t.Run(string(rune('A'+off%26))+string(rune('0'+off%10)), func(t *testing.T) {
			bad := env
			bad.DataEnc = append([]byte(nil), env.DataEnc...)
			bad.DataEnc[off] ^= 0x02
			if _, err := vault.Open(bad); err == nil {
				t.Fatalf("Open succeeded after flipping byte %d", off)
			}
		})
	}
}

func TestOpenRejectsWrongKeyIdentityOrMaterial(t *testing.T) {
	vaultA := testVault(t)
	env, err := vaultA.Seal(uuid.New(), "snmp_v2c", uuid.New(), []byte("key identity"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Same key id, different key material: authentication must fail.
	otherKEK, err := LoadOrCreateLocalKMS(LocalConfig{
		Path:          filepath.Join(t.TempDir(), "other.key"),
		KeyID:         "test-key",
		AllowGenerate: true,
	})
	if err != nil {
		t.Fatalf("LoadOrCreateLocalKMS: %v", err)
	}
	if _, err := New(otherKEK).Open(env); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("Open with different key material: want ErrAuthentication, got %v", err)
	}

	// Different key id: rejected before touching key material.
	thirdKEK, err := LoadOrCreateLocalKMS(LocalConfig{
		Path:          filepath.Join(t.TempDir(), "third.key"),
		KeyID:         "another-key",
		AllowGenerate: true,
	})
	if err != nil {
		t.Fatalf("LoadOrCreateLocalKMS: %v", err)
	}
	if _, err := New(thirdKEK).Open(env); !errors.Is(err, ErrKeyIDMismatch) {
		t.Fatalf("Open with different key id: want ErrKeyIDMismatch, got %v", err)
	}
}

// TestEnvelopeCarriesNoPlaintext checks the no-plaintext-at-rest property at
// the envelope level (NFR-SEC-002): the plaintext appears in no part of the
// sealed bytes or their JSON projection.
func TestEnvelopeCarriesNoPlaintext(t *testing.T) {
	vault := testVault(t)
	plaintext := []byte("plaintext-token-" + uuid.NewString())

	env, err := vault.Seal(uuid.New(), "snmp_v3", uuid.New(), plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(env.DataEnc, plaintext) {
		t.Fatal("plaintext appears inside data_enc")
	}
	projected, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	if bytes.Contains(projected, plaintext) {
		t.Fatal("plaintext appears in the serialized envelope")
	}
}

func TestContextJSONMapping(t *testing.T) {
	want := Context{OrgID: uuid.New(), SecretType: "snmp_v2c", SecretID: uuid.New(), Version: 3} //nolint:gosec // test value, not a credential
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"org_id", "secret_type", "secret_id", "version"} {
		if _, ok := fields[key]; !ok {
			t.Fatalf("context JSON missing %q: %s", key, raw)
		}
	}
	got, err := ParseContext(raw)
	if err != nil {
		t.Fatalf("ParseContext: %v", err)
	}
	if got != want {
		t.Fatalf("ParseContext = %+v, want %+v", got, want)
	}

	for _, bad := range []string{"", "not-json", "{}", `{"org_id":"00000000-0000-0000-0000-000000000000","secret_type":"x","secret_id":"00000000-0000-0000-0000-000000000001","version":1}`} {
		if _, err := ParseContext([]byte(bad)); !errors.Is(err, ErrInvalidContext) {
			t.Fatalf("ParseContext(%q): want ErrInvalidContext, got %v", bad, err)
		}
	}
}
