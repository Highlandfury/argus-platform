package poll

import (
	"log/slog"
	"sync"

	"github.com/argus-platform/argus/internal/platform/sessioncrypto"
)

// BundleCredentialSource is the M9-S3 CredentialSource: it holds the SNMP
// credentials decrypted from the newest verified signed policy bundle, in RAM
// only. It is written by the control stream (per session) and read by the SNMP
// prober (concurrently), so all state is mutex-guarded.
//
// Discipline:
//   - The session private seed is a RAM-only copy; it is zeroed and mlock-ed
//     best-effort on Linux (memlock_linux.go) and never written anywhere.
//   - Decrypted plaintext is zeroed as soon as it has been parsed into the
//     SNMP session shape.
//   - Every applied bundle atomically REPLACES the credential set: a bundle
//     without material (binding removed, collector revoked, downgrade to a
//     collector without a session key) drops the previous set, so polling
//     fails closed with credential_missing instead of using stale material.
//   - Nothing here logs or stores secret bytes.
type BundleCredentialSource struct {
	mu       sync.RWMutex
	seed     []byte
	locked   bool
	byDevice map[string]SNMPCredentials
	log      *slog.Logger
}

// invalidCredential is stored for a record that decrypted but whose payload
// does not describe a usable credential. Keeping a present-but-invalid entry
// (rather than dropping it) makes the prober report the existing
// credential_invalid poll-health class instead of credential_missing.
var invalidCredential = SNMPCredentials{Version: "invalid"} //nolint:gosec // sentinel shape, not a secret

// NewBundleCredentialSource returns an empty RAM-only source.
func NewBundleCredentialSource(log *slog.Logger) *BundleCredentialSource {
	if log == nil {
		log = slog.Default()
	}
	return &BundleCredentialSource{log: log}
}

// SetSessionKey installs the per-stream ephemeral X25519 seed (copied; mlock
// best-effort). Calling it again replaces the previous seed and clears any
// material decrypted under it.
func (s *BundleCredentialSource) SetSessionKey(seed []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearLocked()
	s.seed = append([]byte(nil), seed...)
	s.locked = mlock(s.seed)
}

// ApplySession decrypts the material of one verified policy bundle and
// atomically replaces the RAM credential set. It never returns an error: a
// certificate that cannot be decrypted or parsed yields credential_missing /
// credential_invalid at probe time (fail closed), never a stale credential and
// never a bundle rejection.
func (s *BundleCredentialSource) ApplySession(session *sessioncrypto.Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make(map[string]SNMPCredentials, 0)
	switch {
	case session == nil:
		// No material: revocation/removal/downgrade path. Replace with empty.
	case session.Algorithm != sessioncrypto.Algorithm:
		s.log.Warn("policy credential material uses an unsupported algorithm; credentials unavailable",
			"algorithm", session.Algorithm, "policy_version", session.PolicyVersion)
	case len(s.seed) == 0:
		s.log.Warn("policy credential material received without a session key; credentials unavailable",
			"policy_version", session.PolicyVersion)
	default:
		for _, rec := range session.Credentials {
			plaintext, err := sessioncrypto.Open(s.seed, session, rec)
			if err != nil {
				// Undecryptable (wrong session key, tampered context): no
				// record -> credential_missing, the fail-closed class.
				s.log.Warn("credential material could not be decrypted; device will report credential_missing",
					"device_id", rec.DeviceID, "credential_id", rec.CredentialID)
				continue
			}
			creds, err := ParseCredentialPayload(rec.Kind, plaintext)
			clear(plaintext)
			if err != nil {
				s.log.Warn("credential material is malformed; device will report credential_invalid",
					"device_id", rec.DeviceID, "credential_id", rec.CredentialID, "kind", rec.Kind)
				next[rec.DeviceID] = invalidCredential
				continue
			}
			next[rec.DeviceID] = creds
		}
	}
	clear(s.byDevice)
	s.byDevice = next
}

// Clear drops the session key and all decrypted material (session end,
// disconnect, revocation).
func (s *BundleCredentialSource) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearLocked()
}

// Lookup implements CredentialSource.
func (s *BundleCredentialSource) Lookup(deviceID string) (SNMPCredentials, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.byDevice[deviceID]
	return c, ok
}

// HasSessionKey reports whether a session key is installed (used by tests and
// startup diagnostics; never exposes key material).
func (s *BundleCredentialSource) HasSessionKey() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.seed) == sessioncrypto.SeedLen
}

func (s *BundleCredentialSource) clearLocked() {
	if len(s.seed) > 0 {
		clear(s.seed)
		if s.locked {
			munlock(s.seed)
		}
		s.seed = nil
		s.locked = false
	}
	clear(s.byDevice)
	s.byDevice = nil
}

// ChainCredentialSource consults sources in order; the first source that
// resolves a device wins. The M9-S3 bundle source is chained first, with the
// M9-S2 fixture/env source (dev-only) as the fallback so fixture tests and
// manual dev runs keep working without materialized credentials.
type ChainCredentialSource []CredentialSource

// NewChainCredentialSource builds an ordered credential source chain.
func NewChainCredentialSource(sources ...CredentialSource) ChainCredentialSource {
	return ChainCredentialSource(sources)
}

// Lookup implements CredentialSource.
func (c ChainCredentialSource) Lookup(deviceID string) (SNMPCredentials, bool) {
	for _, src := range c {
		if src == nil {
			continue
		}
		if creds, ok := src.Lookup(deviceID); ok {
			return creds, true
		}
	}
	return SNMPCredentials{}, false
}
