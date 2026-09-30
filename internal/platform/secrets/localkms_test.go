package secrets

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func randomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, aesKeyLen)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

// writeKeyRing fabricates a key ring file for rotation/shredding scenarios.
func writeKeyRing(t *testing.T, path, keyID string, current int, keys map[int][]byte) {
	t.Helper()
	ring := keyRingFile{
		Format:         keyRingFormat,
		KeyID:          keyID,
		CurrentVersion: current,
		Keys:           map[string][]byte{},
	}
	for version, key := range keys {
		ring.Keys[strconv.Itoa(version)] = key
	}
	raw, err := json.MarshalIndent(ring, "", "  ")
	if err != nil {
		t.Fatalf("marshal key ring: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write key ring: %v", err)
	}
}

func mustLoadLocalKMS(t *testing.T, cfg LocalConfig) *LocalKMS {
	t.Helper()
	kek, err := LoadOrCreateLocalKMS(cfg)
	if err != nil {
		t.Fatalf("LoadOrCreateLocalKMS: %v", err)
	}
	return kek
}

func TestLocalKMSGeneratesVersionOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "master.key")
	kek := mustLoadLocalKMS(t, LocalConfig{Path: path, KeyID: "gen-key", AllowGenerate: true})
	if kek.KeyID() != "gen-key" {
		t.Fatalf("KeyID = %q", kek.KeyID())
	}
	if kek.CurrentVersion() != 1 {
		t.Fatalf("CurrentVersion = %d, want 1", kek.CurrentVersion())
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("master key file not written: %v", err)
	}

	vault := New(kek)
	env, err := vault.Seal(uuid.New(), "snmp_v2c", uuid.New(), []byte("generated"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if env.KeyVersion != 1 {
		t.Fatalf("sealed key version = %d, want 1", env.KeyVersion)
	}
	if _, err := vault.Open(env); err != nil {
		t.Fatalf("Open: %v", err)
	}
}

// TestLocalKMSKeyVersionHandling covers rotation representability: a new
// current version is used for new seals, older versions stay readable while
// their material is present, and removing or replacing material fails closed.
func TestLocalKMSKeyVersionHandling(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ring.json")
	v1, v2 := randomKey(t), randomKey(t)
	writeKeyRing(t, path, "ring-key", 2, map[int][]byte{1: v1, 2: v2})

	kek2 := mustLoadLocalKMS(t, LocalConfig{Path: path, KeyID: "ring-key"})
	vault2 := New(kek2)
	envV2, err := vault2.Seal(uuid.New(), "snmp_v2c", uuid.New(), []byte("sealed under v2"))
	if err != nil {
		t.Fatalf("Seal under v2: %v", err)
	}
	if envV2.KeyVersion != 2 {
		t.Fatalf("key version = %d, want 2", envV2.KeyVersion)
	}
	if _, err := vault2.Open(envV2); err != nil {
		t.Fatalf("Open v2 envelope: %v", err)
	}

	// Version 2 material removed: the v1 vault cannot read the v2 envelope.
	writeKeyRing(t, path, "ring-key", 1, map[int][]byte{1: v1})
	kek1 := mustLoadLocalKMS(t, LocalConfig{Path: path, KeyID: "ring-key"})
	if _, err := New(kek1).Open(envV2); !errors.Is(err, ErrUnknownKeyVersion) {
		t.Fatalf("removed v2 material: want ErrUnknownKeyVersion, got %v", err)
	}
	// New seals now use version 1 and round-trip.
	envV1, err := New(kek1).Seal(uuid.New(), "snmp_v3", uuid.New(), []byte("sealed under v1"))
	if err != nil {
		t.Fatalf("Seal under v1: %v", err)
	}
	if envV1.KeyVersion != 1 {
		t.Fatalf("key version = %d, want 1", envV1.KeyVersion)
	}
	if _, err := New(kek1).Open(envV1); err != nil {
		t.Fatalf("Open v1 envelope: %v", err)
	}

	// Same version number, different material: authentication fails.
	writeKeyRing(t, path, "ring-key", 2, map[int][]byte{1: v1, 2: randomKey(t)})
	kek2b := mustLoadLocalKMS(t, LocalConfig{Path: path, KeyID: "ring-key"})
	if _, err := New(kek2b).Open(envV2); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("replaced v2 material: want ErrAuthentication, got %v", err)
	}
}

// TestLocalKMSCryptoShredding: deleting the key file makes every envelope
// unreadable. Outside dev the load fails closed; in dev a fresh key is
// generated and the old material is gone for good.
func TestLocalKMSCryptoShredding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	kek := mustLoadLocalKMS(t, LocalConfig{Path: path, KeyID: "shred", AllowGenerate: true})
	vault := New(kek)
	env, err := vault.Seal(uuid.New(), "snmp_v3", uuid.New(), []byte("shred me"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := vault.Open(env); err != nil {
		t.Fatalf("Open before shred: %v", err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove key file: %v", err)
	}
	if _, err := LoadOrCreateLocalKMS(LocalConfig{Path: path, KeyID: "shred"}); !errors.Is(err, ErrKeyFileMissing) {
		t.Fatalf("missing key file outside dev: want ErrKeyFileMissing, got %v", err)
	}
	regenerated := mustLoadLocalKMS(t, LocalConfig{Path: path, KeyID: "shred", AllowGenerate: true})
	if _, err := New(regenerated).Open(env); err == nil {
		t.Fatal("envelope still readable after crypto-shredding")
	}
	// The regenerated key is fully functional for new material.
	env2, err := New(regenerated).Seal(uuid.New(), "snmp_v3", uuid.New(), []byte("new secret"))
	if err != nil {
		t.Fatalf("Seal after regeneration: %v", err)
	}
	if _, err := New(regenerated).Open(env2); err != nil {
		t.Fatalf("Open after regeneration: %v", err)
	}
}

func TestLocalKMSNeverOverwritesInvalidFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	garbage := []byte("this is not a key ring")
	if err := os.WriteFile(path, garbage, 0o600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	if _, err := LoadOrCreateLocalKMS(LocalConfig{Path: path, KeyID: "x", AllowGenerate: true}); err == nil {
		t.Fatal("invalid key file must fail even in dev (never overwrite key material)")
	}
	raw, err := os.ReadFile(path) //nolint:gosec // test fixture path
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(raw, garbage) {
		t.Fatal("invalid key file was modified")
	}
}

func TestLocalKMSKeyIDMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	_ = mustLoadLocalKMS(t, LocalConfig{Path: path, KeyID: "key-a", AllowGenerate: true})
	if _, err := LoadOrCreateLocalKMS(LocalConfig{Path: path, KeyID: "key-b"}); err == nil {
		t.Fatal("loading a key ring under a different key_id must fail")
	}
}

func TestLocalKMSConfigValidation(t *testing.T) {
	for _, cfg := range []LocalConfig{
		{KeyID: "x", AllowGenerate: true},
		{Path: "   ", KeyID: "x", AllowGenerate: true},
		{Path: filepath.Join(t.TempDir(), "master.key"), AllowGenerate: true},
	} {
		if _, err := LoadOrCreateLocalKMS(cfg); err == nil {
			t.Fatalf("config %+v must be rejected", cfg)
		}
	}
}

// TestLocalKMSLogsNoKeyMaterial runs the dev generation and a seal/open cycle
// with a captured logger, then scans it for the key material (raw, base64,
// hex) and the plaintext.
func TestLocalKMSLogsNoKeyMaterial(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	path := filepath.Join(t.TempDir(), "master.key")
	kek := mustLoadLocalKMS(t, LocalConfig{Path: path, KeyID: "log-key", AllowGenerate: true, Logger: logger})

	raw, err := os.ReadFile(path) //nolint:gosec // test fixture path
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	var ring keyRingFile
	if err := json.Unmarshal(raw, &ring); err != nil {
		t.Fatalf("parse key file: %v", err)
	}
	key := ring.Keys["1"]
	if len(key) != aesKeyLen {
		t.Fatalf("key material is %d bytes, want %d", len(key), aesKeyLen)
	}

	plaintext := []byte("log-scan-token-" + uuid.NewString())
	vault := New(kek)
	env, err := vault.Seal(uuid.New(), "snmp_v2c", uuid.New(), plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := vault.Open(env); err != nil {
		t.Fatalf("Open: %v", err)
	}

	logBytes := logs.Bytes()
	logText := logs.String()
	if logText == "" {
		t.Fatal("expected the dev-generation warning, captured nothing")
	}
	if !strings.Contains(logText, `"level":"WARN"`) {
		t.Fatalf("expected a WARN entry, got: %s", logText)
	}
	escapedPath, err := json.Marshal(path)
	if err != nil {
		t.Fatalf("marshal path: %v", err)
	}
	if !strings.Contains(logText, string(escapedPath)) {
		t.Fatalf("warning does not name the key file path: %s", logText)
	}
	if bytes.Contains(logBytes, key) {
		t.Fatal("raw key material appears in logs")
	}
	if strings.Contains(logText, string(plaintext)) {
		t.Fatal("plaintext appears in logs")
	}
	for _, encoded := range []string{
		base64.StdEncoding.EncodeToString(key),
		base64.RawStdEncoding.EncodeToString(key),
		base64.URLEncoding.EncodeToString(key),
		hex.EncodeToString(key),
	} {
		if strings.Contains(logText, encoded) {
			t.Fatal("an encoding of the key material appears in logs")
		}
	}
}

func TestLocalKMSGeneratedFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are not enforced on windows")
	}
	path := filepath.Join(t.TempDir(), "nested", "master.key")
	_ = mustLoadLocalKMS(t, LocalConfig{Path: path, KeyID: "perm-key", AllowGenerate: true})
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("master key file mode = %o, want 600", perm)
	}
}
