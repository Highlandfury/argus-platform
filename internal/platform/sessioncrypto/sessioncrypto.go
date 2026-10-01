// Package sessioncrypto implements the M9-S3 credential materialization
// crypto: per-bundle X25519 ECDH against the collector's per-stream ephemeral
// key, HKDF-SHA256 key derivation, and AES-256-GCM sealing under an
// authenticated context that binds the organization, collector, credential,
// device and versions.
//
// Canonical basis: docs/14-security-multisite-multitenant.md §24.5 —
// credentials are "delivered to collectors only for devices/sites they poll,
// encrypted to the collector's ephemeral session key (HPKE-like: ECDH + AEAD
// over the mTLS channel, fresh key per session, no persistence); collector
// keeps plaintext only in RAM". The canonical documents do not name a curve,
// KDF or AEAD; the phase-2 delivery brief directs a conservative choice when
// they are silent, so this build fixes X25519 + HKDF-SHA256 + AES-256-GCM
// (the HPKE base-mode primitives with an explicit AAD context) and records the
// choice in docs/phase-2/M9_EVIDENCE.md.
//
// Freshness: the collector contributes one ephemeral keypair per stream
// session (RAM-only, never persisted); every materialized bundle additionally
// carries a fresh server ephemeral key, so each bundle is independently
// decryptable within its session and no ciphertext can be replayed into a
// different session or a different collector.
//
// Plaintext discipline: plaintext exists only inside Seal/Open call frames and
// the caller's RAM. Nothing in this package logs, caches, or returns it inside
// an error; authentication failures collapse to ErrAuthentication without
// echoing any input material.
package sessioncrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// Algorithm identifies the materialization suite carried in bundles. It is a
// versioned, closed string: collectors refuse unknown values fail-closed
// (records become credential_missing) while keeping the rest of the bundle
// applicable.
const Algorithm = "X25519-HKDF-SHA256-AES-256-GCM"

const (
	// SeedLen is the X25519 private-scalar length.
	SeedLen = 32
	// PublicKeyLen is the X25519 public-key length.
	PublicKeyLen = 32
	// NonceLen is the AES-GCM nonce length.
	NonceLen = 12
	// KeyLen is the derived AEAD key length (AES-256).
	KeyLen = 32
	// MinCiphertextLen is the GCM tag length; shorter ciphertexts are malformed.
	MinCiphertextLen = 16
	// MaxCredentials bounds the credential records a bundle may carry
	// (mirrors the server-side MaxPolicyTargets ceiling).
	MaxCredentials = 10000
	// MaxCiphertextLen bounds one sealed secret (defense against a malformed
	// signed document; real SNMP secrets are a few hundred bytes).
	MaxCiphertextLen = 64 << 10
	// MaxAlgorithmLen bounds the algorithm string.
	MaxAlgorithmLen = 64
)

// hkdfInfo domain-separates the credential key schedule.
const hkdfInfo = "argus-policy-credential/v1"

// aadDomain domain-separates the authenticated context rendering.
const aadDomain = "argus-policy-credential/v1"

// Errors surfaced to callers. None carries plaintext or key material.
var (
	ErrInvalidPublicKey = errors.New("sessioncrypto: invalid session public key")
	ErrInvalidKey       = errors.New("sessioncrypto: invalid session key")
	ErrInvalidSession   = errors.New("sessioncrypto: invalid session material")
	ErrAuthentication   = errors.New("sessioncrypto: material authentication failed")
	ErrEmptyMaterial    = errors.New("sessioncrypto: no credentials to materialize")
)

// Session is the per-bundle materialization block carried inside the signed
// policy document. Its fields (except the credential ciphertexts) are
// non-secret and are also the authenticated context inputs both sides use to
// reconstruct the per-record AAD.
type Session struct {
	Algorithm          string       `json:"algorithm"`
	EphemeralPublicKey []byte       `json:"ephemeral_public_key"`
	OrgID              string       `json:"org_id"`
	CollectorID        string       `json:"collector_id"`
	PolicyVersion      int64        `json:"policy_version"`
	Credentials        []Credential `json:"credentials"`
}

// Credential is one sealed credential record. Kind is the credential kind
// (snmp_v2c | snmp_v3) the collector uses to parse the plaintext it decrypts;
// Version is the stored envelope key_version at resolution time.
type Credential struct {
	DeviceID     string `json:"device_id"`
	CredentialID string `json:"credential_id"`
	Kind         string `json:"kind"`
	Version      int    `json:"version"`
	Nonce        []byte `json:"nonce"`
	Ciphertext   []byte `json:"ciphertext"`
}

// PlainCredential is one pre-seal input: the resolved device, credential
// identity, kind/version metadata and the vault-opened plaintext.
type PlainCredential struct {
	DeviceID     string
	CredentialID string
	Kind         string
	Version      int
	Plaintext    []byte
}

// NewKeyPair generates a fresh X25519 keypair for one collector stream
// session. The returned seed must stay in RAM and be zeroed when the session
// ends (poll.BundleCredentialSource does this).
func NewKeyPair() (seed, public []byte, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("sessioncrypto: generate keypair: %w", err)
	}
	return priv.Bytes(), priv.PublicKey().Bytes(), nil
}

// PublicFromSeed derives the X25519 public key for a stored seed.
func PublicFromSeed(seed []byte) ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		return nil, ErrInvalidKey
	}
	return priv.PublicKey().Bytes(), nil
}

// Validate bounds-checks a session block. It deliberately does not reject a
// non-empty unknown Algorithm: an old collector must still apply the rest of a
// valid signed bundle, reporting credential_missing for material it cannot
// understand (fail closed, no bundle-wide DoS from a future algorithm).
func (s *Session) Validate() error {
	if s == nil {
		return fmt.Errorf("%w: nil session", ErrInvalidSession)
	}
	if len(s.Algorithm) == 0 || len(s.Algorithm) > MaxAlgorithmLen {
		return fmt.Errorf("%w: algorithm length %d", ErrInvalidSession, len(s.Algorithm))
	}
	if len(s.EphemeralPublicKey) != PublicKeyLen {
		return fmt.Errorf("%w: ephemeral public key length %d", ErrInvalidSession, len(s.EphemeralPublicKey))
	}
	if _, err := uuid.Parse(s.OrgID); err != nil {
		return fmt.Errorf("%w: org_id is not a UUID", ErrInvalidSession)
	}
	if _, err := uuid.Parse(s.CollectorID); err != nil {
		return fmt.Errorf("%w: collector_id is not a UUID", ErrInvalidSession)
	}
	if s.PolicyVersion < 0 {
		return fmt.Errorf("%w: negative policy version", ErrInvalidSession)
	}
	if len(s.Credentials) > MaxCredentials {
		return fmt.Errorf("%w: %d credential records exceed the %d ceiling", ErrInvalidSession, len(s.Credentials), MaxCredentials)
	}
	for _, c := range s.Credentials {
		if _, err := uuid.Parse(c.DeviceID); err != nil {
			return fmt.Errorf("%w: credential device_id is not a UUID", ErrInvalidSession)
		}
		if _, err := uuid.Parse(c.CredentialID); err != nil {
			return fmt.Errorf("%w: credential_id is not a UUID", ErrInvalidSession)
		}
		if strings.TrimSpace(c.Kind) == "" || len(c.Kind) > 32 {
			return fmt.Errorf("%w: credential kind length %d", ErrInvalidSession, len(c.Kind))
		}
		if c.Version < 0 {
			return fmt.Errorf("%w: negative credential version", ErrInvalidSession)
		}
		if len(c.Nonce) != NonceLen {
			return fmt.Errorf("%w: nonce length %d", ErrInvalidSession, len(c.Nonce))
		}
		if len(c.Ciphertext) < MinCiphertextLen || len(c.Ciphertext) > MaxCiphertextLen {
			return fmt.Errorf("%w: ciphertext length %d", ErrInvalidSession, len(c.Ciphertext))
		}
	}
	return nil
}

// Seal materializes credentials to the collector's session public key. It
// generates a fresh server ephemeral keypair for this bundle, derives the AEAD
// key from the X25519 shared secret, and seals every plaintext with a fresh
// random nonce under the per-record authenticated context. The caller keeps
// ownership of the Plaintext slices and must zero them after Seal returns.
func Seal(recipientPublic []byte, orgID, collectorID string, policyVersion int64, creds []PlainCredential) (*Session, error) {
	if len(recipientPublic) != PublicKeyLen {
		return nil, ErrInvalidPublicKey
	}
	if _, err := uuid.Parse(orgID); err != nil {
		return nil, fmt.Errorf("%w: org_id is not a UUID", ErrInvalidSession)
	}
	if _, err := uuid.Parse(collectorID); err != nil {
		return nil, fmt.Errorf("%w: collector_id is not a UUID", ErrInvalidSession)
	}
	if policyVersion < 0 {
		return nil, fmt.Errorf("%w: negative policy version", ErrInvalidSession)
	}
	if len(creds) == 0 {
		return nil, ErrEmptyMaterial
	}
	if len(creds) > MaxCredentials {
		return nil, fmt.Errorf("%w: %d credentials exceed the %d ceiling", ErrInvalidSession, len(creds), MaxCredentials)
	}

	curve := ecdh.X25519()
	recipient, err := curve.NewPublicKey(recipientPublic)
	if err != nil {
		return nil, ErrInvalidPublicKey
	}
	ephemeral, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sessioncrypto: generate ephemeral: %w", err)
	}
	shared, err := ephemeral.ECDH(recipient)
	if err != nil {
		return nil, fmt.Errorf("sessioncrypto: ecdh: %w", err)
	}
	defer clear(shared)
	ephemeralPublic := ephemeral.PublicKey().Bytes()
	key, err := deriveKey(shared, ephemeralPublic, recipientPublic)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	out := &Session{
		Algorithm:          Algorithm,
		EphemeralPublicKey: ephemeralPublic,
		OrgID:              orgID,
		CollectorID:        collectorID,
		PolicyVersion:      policyVersion,
		Credentials:        make([]Credential, 0, len(creds)),
	}
	for _, c := range creds {
		if _, err := uuid.Parse(c.DeviceID); err != nil {
			return nil, fmt.Errorf("%w: device_id is not a UUID", ErrInvalidSession)
		}
		if _, err := uuid.Parse(c.CredentialID); err != nil {
			return nil, fmt.Errorf("%w: credential_id is not a UUID", ErrInvalidSession)
		}
		if strings.TrimSpace(c.Kind) == "" || len(c.Kind) > 32 {
			return nil, fmt.Errorf("%w: credential kind length %d", ErrInvalidSession, len(c.Kind))
		}
		if c.Version < 0 {
			return nil, fmt.Errorf("%w: negative credential version", ErrInvalidSession)
		}
		if len(c.Plaintext) == 0 {
			return nil, fmt.Errorf("%w: empty credential plaintext", ErrInvalidSession)
		}
		nonce := make([]byte, NonceLen)
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("sessioncrypto: generate nonce: %w", err)
		}
		aad := recordAAD(out, c.DeviceID, c.CredentialID, c.Version)
		out.Credentials = append(out.Credentials, Credential{
			DeviceID:     c.DeviceID,
			CredentialID: c.CredentialID,
			Kind:         c.Kind,
			Version:      c.Version,
			Nonce:        nonce,
			Ciphertext:   gcm.Seal(nil, nonce, c.Plaintext, aad),
		})
	}
	return out, nil
}

// Open decrypts one credential record with the collector's session seed. The
// session block and record identity are authenticated: any mismatch in org,
// collector, device, credential id, credential version or policy version — or
// a different session key — fails with ErrAuthentication and no detail.
func Open(seed []byte, s *Session, rec Credential) ([]byte, error) {
	if len(seed) != SeedLen || s == nil || len(s.EphemeralPublicKey) != PublicKeyLen {
		return nil, ErrInvalidKey
	}
	private, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		return nil, ErrInvalidKey
	}
	remote, err := ecdh.X25519().NewPublicKey(s.EphemeralPublicKey)
	if err != nil {
		return nil, ErrInvalidSession
	}
	shared, err := private.ECDH(remote)
	if err != nil {
		return nil, ErrAuthentication
	}
	defer clear(shared)
	key, err := deriveKey(shared, s.EphemeralPublicKey, private.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	defer clear(key)
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	aad := recordAAD(s, rec.DeviceID, rec.CredentialID, rec.Version)
	plaintext, err := gcm.Open(nil, rec.Nonce, rec.Ciphertext, aad)
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

// deriveKey runs HKDF-SHA256 over the ECDH shared secret. The salt binds both
// ephemeral public keys (session freshness); the info string domain-separates
// the credential key schedule.
func deriveKey(shared, ephemeralPublic, recipientPublic []byte) ([]byte, error) {
	salt := sha256.Sum256(append(append([]byte{}, ephemeralPublic...), recipientPublic...))
	key, err := hkdf.Key(sha256.New, shared, salt[:], hkdfInfo, KeyLen)
	if err != nil {
		return nil, fmt.Errorf("sessioncrypto: hkdf: %w", err)
	}
	return key, nil
}

// recordAAD renders the authenticated context in a stable, unambiguous byte
// form. Both sides derive it from the session block plus the record identity,
// so changing any bound field invalidates the AEAD tag. It never contains
// secret material.
func recordAAD(s *Session, deviceID, credentialID string, credentialVersion int) []byte {
	var b strings.Builder
	b.WriteString(aadDomain)
	b.WriteString("\norg_id=")
	b.WriteString(s.OrgID)
	b.WriteString("\ncollector_id=")
	b.WriteString(s.CollectorID)
	b.WriteString("\ndevice_id=")
	b.WriteString(deviceID)
	b.WriteString("\ncredential_id=")
	b.WriteString(credentialID)
	b.WriteString("\ncredential_version=")
	b.WriteString(strconv.Itoa(credentialVersion))
	b.WriteString("\npolicy_version=")
	b.WriteString(strconv.FormatInt(s.PolicyVersion, 10))
	return []byte(b.String())
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("sessioncrypto: AES-256 requires a %d-byte key", KeyLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("sessioncrypto: cipher: %w", err)
	}
	return cipher.NewGCM(block)
}
