package credentials

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestProjectCredentialNeverCarriesSecretMaterial is the API-safety pin: the
// metadata projection structurally cannot serialize the envelope columns or
// any plaintext sentinel, while the persistence model still has them.
func TestProjectCredentialNeverCarriesSecretMaterial(t *testing.T) {
	const sentinel = "SENTINEL-SECRET-do-not-serialize" //nolint:gosec // test sentinel, not a credential
	id := uuid.MustParse("11111111-1111-7111-8111-111111111111")
	rotated := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	row := Credential{
		ID:                id,
		OrgID:             uuid.MustParse("22222222-2222-7222-8222-222222222222"),
		Name:              "core-snmp",
		Kind:              "snmp_v2c",
		DataEnc:           []byte(sentinel),
		KMSKeyID:          "argus-local",
		KeyVersion:        7,
		EncryptionContext: json.RawMessage(`{"org_id":"22222222-2222-7222-8222-222222222222","secret_type":"snmp_v2c","secret_id":"11111111-1111-7111-8111-111111111111","version":7}`),
		Metadata:          json.RawMessage(`{"username":"ops"}`),
		RotatedAt:         &rotated,
		CreatedAt:         rotated.Add(-time.Hour),
		UpdatedAt:         rotated,
	}
	binding := Binding{
		ID:           uuid.MustParse("33333333-3333-7333-8333-333333333333"),
		OrgID:        row.OrgID,
		CredentialID: id,
		ScopeType:    "site",
		ScopeID:      uuid.MustParse("44444444-4444-7444-8444-444444444444"),
		Priority:     10,
		CreatedAt:    rotated,
	}

	raw, err := json.Marshal(ProjectCredential(row, []Binding{binding}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	payload := string(raw)
	for _, forbidden := range []string{
		sentinel, "data_enc", "encryption_context", "kms_key_id", "key_version", "argus-local",
	} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("metadata payload leaks %q: %s", forbidden, payload)
		}
	}
	for _, want := range []string{`"name":"core-snmp"`, `"kind":"snmp_v2c"`, `"username":"ops"`, `"scope_type":"site"`, `"priority":10`} {
		if !strings.Contains(payload, want) {
			t.Fatalf("metadata payload missing %s: %s", want, payload)
		}
	}

	// Separation is structural: the persistence model has the envelope columns
	// (the projection must never embed it).
	typ := reflect.TypeOf(Credential{})
	for _, field := range []string{"DataEnc", "KMSKeyID", "KeyVersion", "EncryptionContext"} {
		if _, ok := typ.FieldByName(field); !ok {
			t.Fatalf("persistence model lost field %s", field)
		}
	}
	if _, ok := reflect.TypeOf(CredentialMetadata{}).FieldByName("DataEnc"); ok {
		t.Fatal("metadata projection must not have envelope fields")
	}
}

// TestEnvelopeRebuildsContext pins the row -> vault envelope conversion.
func TestEnvelopeRebuildsContext(t *testing.T) {
	id := uuid.New()
	org := uuid.New()
	row := Credential{
		ID:                id,
		OrgID:             org,
		DataEnc:           []byte("ciphertext"),
		KMSKeyID:          "argus-local",
		KeyVersion:        2,
		EncryptionContext: json.RawMessage(`{"org_id":"` + org.String() + `","secret_type":"snmp_v3","secret_id":"` + id.String() + `","version":2}`),
	}
	env, err := row.Envelope()
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	if env.KMSKeyID != "argus-local" || env.KeyVersion != 2 {
		t.Fatalf("envelope fields = %+v", env)
	}
	if env.EncryptionContext.OrgID != org || env.EncryptionContext.SecretID != id || env.EncryptionContext.SecretType != "snmp_v3" {
		t.Fatalf("envelope context = %+v", env.EncryptionContext)
	}

	bad := row
	bad.EncryptionContext = json.RawMessage(`{"org_id":"not-a-uuid"}`)
	if _, err := bad.Envelope(); err == nil {
		t.Fatal("malformed encryption context must fail closed")
	}
}
