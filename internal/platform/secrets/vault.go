// Package secrets implements the SecretsVault: envelope encryption for
// write-only secret material (device credentials; Phase-2 M7-S2, P2-D2).
//
// Model (canonical docs/14-security-multisite-multitenant.md §24.5): every
// secret is encrypted with its own data key (DEK) under AES-256-GCM, and the
// DEK is wrapped by a key-encryption key (KEK) held by a key backend. Phase 2
// binds the KEK to a local master-key file (localkms.go, decision P2-D2); an
// external KMS/HSM binds behind KEKWrapper later without changing the stored
// envelope format or any caller.
//
// Storage contract (migrations/000009_credentials.up.sql): Envelope maps 1:1
// to the device_credentials columns data_enc, kms_key_id, key_version and
// encryption_context. The canonical encryption context {org_id, secret_type,
// secret_id, version} is the AAD of both GCM layers, so an envelope cannot be
// replayed under a different tenant, record, or envelope version.
//
// Plaintext exists only in process memory during Seal/Open. It never appears
// in errors, logs, or the envelope bytes.
package secrets

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// Sentinel errors returned (wrapped) by the vault and the key backend.
// Callers use errors.Is; none of them carries plaintext.
var (
	ErrInvalidContext     = errors.New("secrets: invalid encryption context")
	ErrMalformedEnvelope  = errors.New("secrets: malformed envelope")
	ErrUnsupportedVersion = errors.New("secrets: unsupported envelope format version")
	ErrAuthentication     = errors.New("secrets: envelope authentication failed")
	ErrKeyIDMismatch      = errors.New("secrets: envelope key id does not match the vault key")
	ErrUnknownKeyVersion  = errors.New("secrets: unknown key version")
	ErrKeyFileMissing     = errors.New("secrets: master key file is missing")
)

// Context is the canonical encryption context (AAD) of docs/14 §24.5:
// {org_id, secret_type, secret_id, version}. SecretType is the credential
// kind (snmp_v2c, snmp_v3, ...); Version is the envelope generation recorded
// in key_version — this slice equates the canonical context version with the
// envelope key version, so any re-seal (rotation of the DEK or KEK) bumps it.
// A future split into secret-version vs key-version arrives with a new
// envelope format version.
type Context struct {
	OrgID      uuid.UUID `json:"org_id"`
	SecretType string    `json:"secret_type"`
	SecretID   uuid.UUID `json:"secret_id"`
	Version    int       `json:"version"`
}

func (c Context) validate() error {
	switch {
	case c.OrgID == uuid.Nil:
		return fmt.Errorf("%w: org_id is required", ErrInvalidContext)
	case strings.TrimSpace(c.SecretType) == "":
		return fmt.Errorf("%w: secret_type is required", ErrInvalidContext)
	case c.SecretID == uuid.Nil:
		return fmt.Errorf("%w: secret_id is required", ErrInvalidContext)
	case c.Version <= 0:
		return fmt.Errorf("%w: version must be positive", ErrInvalidContext)
	}
	return nil
}

// ParseContext parses and validates the encryption_context column (jsonb) of
// a device_credentials row. It is the inverse of marshaling Context with
// encoding/json and is the intended way to rebuild an Envelope from a row.
func ParseContext(raw []byte) (Context, error) {
	var c Context
	if err := json.Unmarshal(raw, &c); err != nil {
		return Context{}, fmt.Errorf("%w: %v", ErrInvalidContext, err)
	}
	if err := c.validate(); err != nil {
		return Context{}, err
	}
	return c, nil
}

// Envelope is one sealed secret exactly as stored in device_credentials.
type Envelope struct {
	DataEnc           []byte  // data_enc: versioned envelope (wrapped DEK + nonces + GCM ciphertext)
	KMSKeyID          string  // kms_key_id: identifier of the wrapping key
	KeyVersion        int     // key_version: KEK/envelope generation, 1-based
	EncryptionContext Context // encryption_context: canonical AAD
}

// SecretsVault is the minimal envelope-encryption boundary needed by the
// credentials API (M7-S4) and collector dispatch (M9).
//
// Open must be called with an Envelope assembled from a row that was already
// resolved in tenant scope (RLS): the encryption context inside the envelope
// binds the ciphertext to {org, type, id, version} and Open verifies it
// against the key material, but the vault cannot know which row the caller
// meant to read. Callers must not mix columns of different rows.
type SecretsVault interface {
	// Seal encrypts plaintext under a fresh per-secret DEK wrapped by the
	// current KEK version. The returned Envelope is the storage row.
	Seal(orgID uuid.UUID, secretType string, secretID uuid.UUID, plaintext []byte) (Envelope, error)
	// Open decrypts an Envelope. It fails (ErrAuthentication) when the
	// encryption context, key id, version, or any envelope byte was altered.
	Open(env Envelope) ([]byte, error)
}

// KEKWrapper is the key-encryption-key backend boundary. Phase 2 ships
// LocalKMS (local master-key file, P2-D2); an external KMS/HSM binds here in
// V2 without changing the envelope format or the SecretsVault callers.
//
// Implementations must be safe for concurrent use and must not log or keep
// references to the DEK beyond the call.
type KEKWrapper interface {
	// KeyID identifies the wrapping key set (recorded as kms_key_id).
	KeyID() string
	// CurrentVersion is the version used for new seals.
	CurrentVersion() int
	// WrapDEK encrypts a 32-byte DEK under the current KEK with aad bound to
	// the result, returning the wrapped form and the version actually used.
	WrapDEK(dek, aad []byte) (wrapped []byte, version int, err error)
	// UnwrapDEK reverses WrapDEK for the given key version.
	UnwrapDEK(version int, wrapped, aad []byte) ([]byte, error)
}

// Vault is the SecretsVault implementation: envelope logic over a KEKWrapper.
type Vault struct {
	kek KEKWrapper
}

var _ SecretsVault = (*Vault)(nil)

// New builds a vault over the given KEK backend (e.g. LoadOrCreateLocalKMS).
func New(kek KEKWrapper) *Vault {
	return &Vault{kek: kek}
}

func (v *Vault) ready() error {
	if v == nil || v.kek == nil {
		return errors.New("secrets: vault has no key backend")
	}
	return nil
}

// Seal implements SecretsVault.
func (v *Vault) Seal(orgID uuid.UUID, secretType string, secretID uuid.UUID, plaintext []byte) (Envelope, error) {
	if err := v.ready(); err != nil {
		return Envelope{}, err
	}
	ctx := Context{
		OrgID:      orgID,
		SecretType: secretType,
		SecretID:   secretID,
		Version:    v.kek.CurrentVersion(),
	}
	if err := ctx.validate(); err != nil {
		return Envelope{}, err
	}

	dek := make([]byte, dekLen)
	if _, err := rand.Read(dek); err != nil {
		return Envelope{}, fmt.Errorf("secrets: generate dek: %w", err)
	}
	defer clear(dek)

	wrappedDEK, version, err := v.kek.WrapDEK(dek, wrapAAD(ctx))
	if err != nil {
		return Envelope{}, fmt.Errorf("secrets: wrap dek: %w", err)
	}
	if version != ctx.Version {
		return Envelope{}, fmt.Errorf("secrets: key version changed during seal (context %d, wrap %d)", ctx.Version, version)
	}

	dataNonce, ciphertext, err := sealGCM(dek, dataAAD(ctx), plaintext)
	if err != nil {
		return Envelope{}, fmt.Errorf("secrets: encrypt secret: %w", err)
	}
	dataEnc, err := encodeEnvelopeV1(ctx.Version, wrappedDEK, dataNonce, ciphertext)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{
		DataEnc:           dataEnc,
		KMSKeyID:          v.kek.KeyID(),
		KeyVersion:        ctx.Version,
		EncryptionContext: ctx,
	}, nil
}

// Open implements SecretsVault.
func (v *Vault) Open(env Envelope) ([]byte, error) {
	if err := v.ready(); err != nil {
		return nil, err
	}
	if env.KMSKeyID != v.kek.KeyID() {
		return nil, fmt.Errorf("%w: envelope %q, vault %q", ErrKeyIDMismatch, env.KMSKeyID, v.kek.KeyID())
	}
	ctx := env.EncryptionContext
	if err := ctx.validate(); err != nil {
		return nil, err
	}
	if ctx.Version != env.KeyVersion {
		return nil, fmt.Errorf("%w: context version %d does not match key_version %d", ErrMalformedEnvelope, ctx.Version, env.KeyVersion)
	}

	parsed, err := decodeEnvelope(env.DataEnc)
	if err != nil {
		return nil, err
	}
	if parsed.keyVersion != env.KeyVersion {
		return nil, fmt.Errorf("%w: header key version %d does not match key_version %d", ErrMalformedEnvelope, parsed.keyVersion, env.KeyVersion)
	}

	dek, err := v.kek.UnwrapDEK(parsed.keyVersion, parsed.wrappedDEK, wrapAAD(ctx))
	if err != nil {
		return nil, fmt.Errorf("secrets: unwrap dek: %w", err)
	}
	defer clear(dek)

	plaintext, err := openGCM(dek, dataAAD(ctx), parsed.dataNonce, parsed.ciphertext)
	if err != nil {
		return nil, fmt.Errorf("secrets: decrypt secret: %w", err)
	}
	return plaintext, nil
}
