package secrets

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// LocalConfig configures the file-backed KEK provider (the P2-D2 dev/on-prem
// binding for the SecretsVault).
type LocalConfig struct {
	// Path is the master-key file (ARGUS_SECRETS_KEY_FILE). The file is a
	// JSON key ring holding one or more 32-byte KEK versions; it is created
	// with mode 0600 where the platform supports it.
	Path string
	// KeyID is the identifier recorded in every envelope as kms_key_id
	// (ARGUS_SECRETS_KEY_ID).
	KeyID string
	// AllowGenerate enables generate-and-write on first use. Callers must set
	// it only when ARGUS_ENV=dev; everywhere else a missing key file fails
	// closed (P2-D2). Existing key files are never overwritten.
	AllowGenerate bool
	// Logger receives the dev-generation warning and a permissions warning;
	// it may be nil. Key material is never written to it.
	Logger *slog.Logger
}

// LocalKMS is the file-backed KEK backend: an immutable key ring of 32-byte
// KEKs loaded from the master-key file. It is safe for concurrent use.
type LocalKMS struct {
	keyID   string
	current int
	keys    map[int][]byte
}

var _ KEKWrapper = (*LocalKMS)(nil)

// keyRingFile is the on-disk JSON format. It is self-describing via Format
// and carries multiple key versions so rotation is representable: add a new
// version, move current_version, keep the old keys for older envelopes.
type keyRingFile struct {
	Format         int               `json:"format"`
	KeyID          string            `json:"key_id"`
	CurrentVersion int               `json:"current_version"`
	Keys           map[string][]byte `json:"keys"` // decimal version -> 32-byte key
}

const (
	keyRingFormat = 1
)

// LoadOrCreateLocalKMS loads the master-key file at cfg.Path. When the file
// is missing and cfg.AllowGenerate is set (ARGUS_ENV=dev only), a fresh
// 32-byte KEK at version 1 is generated, written with mode 0600, and a
// warning is logged. Otherwise a missing file fails closed with
// ErrKeyFileMissing, and an existing-but-invalid file is an error — never
// overwritten, since that would silently shred every encrypted secret.
func LoadOrCreateLocalKMS(cfg LocalConfig) (*LocalKMS, error) {
	if strings.TrimSpace(cfg.Path) == "" {
		return nil, errors.New("secrets: master key file path is required")
	}
	if strings.TrimSpace(cfg.KeyID) == "" {
		return nil, errors.New("secrets: wrapping key id is required")
	}

	raw, err := os.ReadFile(cfg.Path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("secrets: read master key file: %w", err)
		}
		if !cfg.AllowGenerate {
			return nil, fmt.Errorf("%w: %s (generation is dev-only; set ARGUS_SECRETS_KEY_FILE)", ErrKeyFileMissing, cfg.Path)
		}
		return generateLocalKMS(cfg)
	}
	kms, err := parseKeyRing(cfg, raw)
	if err != nil {
		return nil, err
	}
	warnLoosePermissions(cfg)
	return kms, nil
}

// generateLocalKMS writes a new single-version key ring. The file is created
// with O_EXCL so a concurrent generator cannot be clobbered; a partial write
// is removed rather than left to poison future starts.
func generateLocalKMS(cfg LocalConfig) (*LocalKMS, error) {
	if err := os.MkdirAll(filepath.Dir(cfg.Path), 0o700); err != nil {
		return nil, fmt.Errorf("secrets: create key directory: %w", err)
	}
	key := make([]byte, aesKeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("secrets: generate master key: %w", err)
	}
	ring := keyRingFile{
		Format:         keyRingFormat,
		KeyID:          cfg.KeyID,
		CurrentVersion: 1,
		Keys:           map[string][]byte{"1": key},
	}
	data, err := json.MarshalIndent(ring, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("secrets: encode master key file: %w", err)
	}

	f, err := os.OpenFile(cfg.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		// Another process won the race; use what it wrote.
		raw, readErr := os.ReadFile(cfg.Path)
		if readErr != nil {
			return nil, fmt.Errorf("secrets: read master key file: %w", readErr)
		}
		return parseKeyRing(cfg, raw)
	}
	if err != nil {
		return nil, fmt.Errorf("secrets: create master key file: %w", err)
	}
	complete := false
	defer func() {
		if !complete {
			_ = f.Close()
			_ = os.Remove(cfg.Path)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return nil, fmt.Errorf("secrets: write master key file: %w", err)
	}
	if err := f.Sync(); err != nil {
		return nil, fmt.Errorf("secrets: sync master key file: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("secrets: close master key file: %w", err)
	}
	complete = true

	if err := os.Chmod(cfg.Path, 0o600); err != nil && runtime.GOOS != "windows" {
		return nil, fmt.Errorf("secrets: tighten master key file permissions: %w", err)
	}
	if cfg.Logger != nil {
		cfg.Logger.Warn("secrets: generated a development master key file (P2-D2 dev binding; keep it safe and backed up)",
			"path", cfg.Path, "key_id", cfg.KeyID, "key_version", 1)
	}
	return newLocalKMS(cfg.KeyID, 1, map[int][]byte{1: key}), nil
}

// parseKeyRing validates a loaded file: format, key id, non-empty key set,
// every key exactly 32 bytes, and a current version that has material.
func parseKeyRing(cfg LocalConfig, raw []byte) (*LocalKMS, error) {
	var ring keyRingFile
	if err := json.Unmarshal(raw, &ring); err != nil {
		return nil, fmt.Errorf("secrets: parse master key file %s: %w", cfg.Path, err)
	}
	if ring.Format != keyRingFormat {
		return nil, fmt.Errorf("secrets: master key file %s: unsupported format %d", cfg.Path, ring.Format)
	}
	if ring.KeyID != cfg.KeyID {
		return nil, fmt.Errorf("secrets: master key file %s: key_id %q does not match configured %q", cfg.Path, ring.KeyID, cfg.KeyID)
	}
	keys := make(map[int][]byte, len(ring.Keys))
	for rawVersion, key := range ring.Keys {
		version, err := strconv.Atoi(rawVersion)
		if err != nil || version <= 0 || version > 0xffff {
			return nil, fmt.Errorf("secrets: master key file %s: invalid key version %q", cfg.Path, rawVersion)
		}
		if len(key) != aesKeyLen {
			return nil, fmt.Errorf("secrets: master key file %s: key version %d is %d bytes, want %d", cfg.Path, version, len(key), aesKeyLen)
		}
		keys[version] = key
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("secrets: master key file %s: no keys", cfg.Path)
	}
	if _, ok := keys[ring.CurrentVersion]; !ok {
		return nil, fmt.Errorf("secrets: master key file %s: current_version %d has no key", cfg.Path, ring.CurrentVersion)
	}
	return newLocalKMS(cfg.KeyID, ring.CurrentVersion, keys), nil
}

func newLocalKMS(keyID string, current int, keys map[int][]byte) *LocalKMS {
	return &LocalKMS{keyID: keyID, current: current, keys: keys}
}

// warnLoosePermissions flags a readable-by-others key file on platforms that
// enforce POSIX modes. It never changes the file.
func warnLoosePermissions(cfg LocalConfig) {
	if cfg.Logger == nil || runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(cfg.Path)
	if err != nil {
		return
	}
	if info.Mode().Perm()&0o077 != 0 {
		cfg.Logger.Warn("secrets: master key file is accessible to other users",
			"path", cfg.Path, "mode", info.Mode().Perm().String())
	}
}

// KeyID implements KEKWrapper.
func (k *LocalKMS) KeyID() string { return k.keyID }

// CurrentVersion implements KEKWrapper.
func (k *LocalKMS) CurrentVersion() int { return k.current }

// WrapDEK implements KEKWrapper: AES-256-GCM over the DEK with a fresh nonce,
// returning nonce||ciphertext+tag.
func (k *LocalKMS) WrapDEK(dek, aad []byte) ([]byte, int, error) {
	if len(dek) != dekLen {
		return nil, 0, fmt.Errorf("secrets: dek is %d bytes, want %d", len(dek), dekLen)
	}
	key, ok := k.keys[k.current]
	if !ok {
		return nil, 0, fmt.Errorf("%w: %d", ErrUnknownKeyVersion, k.current)
	}
	nonce, ciphertext, err := sealGCM(key, aad, dek)
	if err != nil {
		return nil, 0, fmt.Errorf("secrets: wrap dek: %w", err)
	}
	return append(nonce, ciphertext...), k.current, nil
}

// UnwrapDEK implements KEKWrapper. A version whose material is gone (never
// loaded, rotated away, or deleted for crypto-shredding) returns
// ErrUnknownKeyVersion; altered bytes or a wrong AAD return ErrAuthentication.
func (k *LocalKMS) UnwrapDEK(version int, wrapped, aad []byte) ([]byte, error) {
	key, ok := k.keys[version]
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrUnknownKeyVersion, version)
	}
	if len(wrapped) != wrappedDEKLenV1 {
		return nil, fmt.Errorf("%w: wrapped dek is %d bytes, want %d", ErrMalformedEnvelope, len(wrapped), wrappedDEKLenV1)
	}
	dek, err := openGCM(key, aad, wrapped[:nonceLen], wrapped[nonceLen:])
	if err != nil {
		return nil, err
	}
	if len(dek) != dekLen {
		return nil, fmt.Errorf("%w: unwrapped dek is %d bytes, want %d", ErrMalformedEnvelope, len(dek), dekLen)
	}
	return dek, nil
}
