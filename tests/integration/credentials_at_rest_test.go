package integration

// M7-S2 (Phase 2): credential envelope encryption at rest (P2-AC-05,
// NFR-SEC-002). A real device_credentials row is written from SecretsVault
// output through the owner pool (the migration/setup role, mirroring the
// storage contract from migrations/000009), then the test proves:
//  1. the stored bytes decrypt only through the vault with the right
//     encryption context (wrong org/type/id/version and wrong key fail);
//  2. a full text dump of the row/table contains no plaintext, and the vault
//     logs no key material or plaintext;
//  3. deleting the key material (crypto-shredding) makes the envelope
//     unreadable while the database row itself survives.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/platform/secrets"
)

func TestCredentialsAtRestEnvelope(t *testing.T) {
	ctx := context.Background()
	tn := seedTenant(t, "m7-s2-"+newUUID()[:8])

	// Dev binding (P2-D2): file-backed KEK in a throwaway directory. The log
	// capture doubles as the vault-level no-leak scan.
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	keyPath := filepath.Join(t.TempDir(), "master.key")
	kek, err := secrets.LoadOrCreateLocalKMS(secrets.LocalConfig{
		Path: keyPath, KeyID: "it-local", AllowGenerate: true, Logger: logger,
	})
	must(t, err)
	vault := secrets.New(kek)

	credID := uuid.New()
	secretType := "snmp_v2c"
	plaintext := []byte("community-s3cr3t-" + newUUID())

	env, err := vault.Seal(mustUUID(t, tn.OrgID), secretType, credID, plaintext)
	must(t, err)
	if env.KeyVersion != 1 || env.KMSKeyID != "it-local" {
		t.Fatalf("unexpected envelope metadata: key_version=%d kms_key_id=%q", env.KeyVersion, env.KMSKeyID)
	}
	if bytes.Contains(env.DataEnc, plaintext) {
		t.Fatal("plaintext appears inside the sealed envelope")
	}

	contextJSON, err := json.Marshal(env.EncryptionContext)
	must(t, err)

	// The storage row is written through the owner pool exactly as the
	// credentials module will store it (owner = migration/setup role).
	_, err = ownerPool.Exec(ctx,
		`INSERT INTO device_credentials (id, org_id, name, kind, data_enc, kms_key_id, key_version, encryption_context)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)`,
		credID.String(), tn.OrgID, "cred-"+tn.Slug, secretType,
		env.DataEnc, env.KMSKeyID, env.KeyVersion, string(contextJSON))
	must(t, err)

	// Reload the row the way the credentials module will: columns -> Envelope.
	var (
		dataEnc    []byte
		kmsKeyID   string
		keyVersion int
		rawContext []byte
	)
	must(t, ownerPool.QueryRow(ctx,
		`SELECT data_enc, kms_key_id, key_version, encryption_context
		 FROM device_credentials WHERE id = $1`, credID.String()).
		Scan(&dataEnc, &kmsKeyID, &keyVersion, &rawContext))

	storedCtx, err := secrets.ParseContext(rawContext)
	must(t, err)
	stored := secrets.Envelope{
		DataEnc:           dataEnc,
		KMSKeyID:          kmsKeyID,
		KeyVersion:        keyVersion,
		EncryptionContext: storedCtx,
	}

	// (1) The stored bytes open through the vault with the right context...
	got, err := vault.Open(stored)
	must(t, err)
	if !bytes.Equal(got, plaintext) {
		t.Fatal("vault returned different plaintext")
	}

	t.Run("wrong_context_fails", func(t *testing.T) {
		cases := []struct {
			name   string
			mutate func(*secrets.Envelope)
		}{
			{"org", func(e *secrets.Envelope) { e.EncryptionContext.OrgID = uuid.New() }},
			{"secret_type", func(e *secrets.Envelope) { e.EncryptionContext.SecretType = "snmp_v3" }},
			{"secret_id", func(e *secrets.Envelope) { e.EncryptionContext.SecretID = uuid.New() }},
			{"version", func(e *secrets.Envelope) {
				e.EncryptionContext.Version = 2
				e.KeyVersion = 2
			}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				bad := stored
				tc.mutate(&bad)
				if _, err := vault.Open(bad); err == nil {
					t.Fatalf("Open succeeded with a %s-mutated context", tc.name)
				}
			})
		}
	})

	t.Run("wrong_key_fails", func(t *testing.T) {
		otherKEK, err := secrets.LoadOrCreateLocalKMS(secrets.LocalConfig{
			Path: filepath.Join(t.TempDir(), "other.key"), KeyID: "it-local", AllowGenerate: true,
		})
		must(t, err)
		if _, err := secrets.New(otherKEK).Open(stored); err == nil {
			t.Fatal("a different key file opened the envelope")
		}
	})

	// (2) Full text dumps: no plaintext anywhere (NFR-SEC-002).
	var rowDump string
	must(t, ownerPool.QueryRow(ctx,
		`SELECT row_to_json(dc)::text FROM device_credentials dc WHERE id = $1`, credID.String()).Scan(&rowDump))
	if rowDump == "" {
		t.Fatal("empty row dump")
	}
	if strings.Contains(rowDump, string(plaintext)) {
		t.Fatal("plaintext appears in the row dump")
	}
	if bytes.Contains(dataEnc, plaintext) {
		t.Fatal("plaintext appears in data_enc")
	}
	var tableDump string
	must(t, ownerPool.QueryRow(ctx,
		`SELECT COALESCE(string_agg(row_to_json(dc)::text, E'\n'), '') FROM device_credentials dc`).Scan(&tableDump))
	if strings.Contains(tableDump, string(plaintext)) {
		t.Fatal("plaintext appears in the table dump")
	}

	// (3) Crypto-shredding: deleting the key material leaves the row in place
	// and makes the envelope unreadable. Without the dev-only generation flag
	// a missing file fails closed at load; with it a fresh key is generated
	// and the old envelope can no longer be opened.
	must(t, os.Remove(keyPath))
	if _, err := secrets.LoadOrCreateLocalKMS(secrets.LocalConfig{Path: keyPath, KeyID: "it-local"}); !errors.Is(err, secrets.ErrKeyFileMissing) {
		t.Fatalf("missing key file outside dev: want ErrKeyFileMissing, got %v", err)
	}
	shreddedKEK, err := secrets.LoadOrCreateLocalKMS(secrets.LocalConfig{
		Path: keyPath, KeyID: "it-local", AllowGenerate: true, Logger: logger,
	})
	must(t, err)
	if _, err := secrets.New(shreddedKEK).Open(stored); err == nil {
		t.Fatal("envelope still readable after crypto-shredding")
	}
	var rows int
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM device_credentials WHERE id = $1`, credID.String()).Scan(&rows))
	if rows != 1 {
		t.Fatalf("credential row missing after crypto-shredding: %d rows", rows)
	}

	// Vault logs (dev key generation warnings) carry no key material and no
	// plaintext.
	logText := logs.String()
	escapedPath, err := json.Marshal(keyPath)
	must(t, err)
	if !strings.Contains(logText, `"level":"WARN"`) || !strings.Contains(logText, string(escapedPath)) {
		t.Fatalf("expected the dev-generation warning naming the key path; captured %d bytes", len(logText))
	}
	if strings.Contains(logText, string(plaintext)) {
		t.Fatal("plaintext appears in vault logs")
	}
	keyFileRaw, err := os.ReadFile(keyPath)
	must(t, err)
	var keyRing struct {
		Keys map[string][]byte `json:"keys"`
	}
	must(t, json.Unmarshal(keyFileRaw, &keyRing))
	for version, key := range keyRing.Keys {
		if bytes.Contains(logs.Bytes(), key) {
			t.Fatalf("raw key material of version %s appears in vault logs", version)
		}
	}
}
