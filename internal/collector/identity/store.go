// Package identity persists the collector's enrollment result: private key,
// client certificate, pinned CA, and metadata (SPEC §27.3).
package identity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Identity is the persisted collector identity metadata.
type Identity struct {
	CollectorID     string    `json:"collector_id"`
	Name            string    `json:"name"`
	ServerEnrollURL string    `json:"server_enroll_url"`
	StreamAddr      string    `json:"stream_addr"`
	AgentVersion    string    `json:"agent_version"`
	CertNotAfter    time.Time `json:"cert_not_after"`
	EnrolledAt      time.Time `json:"enrolled_at"`
	PolicyVersion   int64     `json:"policy_version"`
	PolicyKeyDERB64 string    `json:"policy_signing_key_der_b64"`
}

// Store manages the on-disk identity under the collector data directory.
type Store struct {
	dir string
}

// NewStore returns a store rooted at dir.
func NewStore(dir string) *Store { return &Store{dir: dir} }

// Paths returns the identity file paths.
func (s *Store) Paths() (certPath, keyPath, caPath, jsonPath string) {
	return filepath.Join(s.dir, "cert.pem"),
		filepath.Join(s.dir, "key.pem"),
		filepath.Join(s.dir, "ca.pem"),
		filepath.Join(s.dir, "collector.json")
}

// Load reads the persisted identity. ok=false when not enrolled yet.
func (s *Store) Load() (Identity, bool, error) {
	_, _, _, jsonPath := s.Paths()
	raw, err := os.ReadFile(jsonPath) //nolint:gosec // path derived from the operator-configured data dir
	if err != nil {
		if os.IsNotExist(err) {
			return Identity{}, false, nil
		}
		return Identity{}, false, fmt.Errorf("identity: read: %w", err)
	}
	var id Identity
	if err := json.Unmarshal(raw, &id); err != nil {
		return Identity{}, false, fmt.Errorf("identity: parse: %w", err)
	}
	if id.CollectorID == "" {
		return Identity{}, false, fmt.Errorf("identity: missing collector_id")
	}
	return id, true, nil
}

// Save writes the identity material atomically (key at 0600).
func (s *Store) Save(id Identity, certPEM, keyPEM, caPEM []byte) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("identity: mkdir: %w", err)
	}
	certPath, keyPath, caPath, jsonPath := s.Paths()
	raw, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return fmt.Errorf("identity: marshal: %w", err)
	}
	writes := []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{certPath, certPEM, 0o600},
		{keyPath, keyPEM, 0o600},
		{caPath, caPEM, 0o600},
		{jsonPath, raw, 0o600},
	}
	for _, w := range writes {
		tmp := w.path + ".tmp"
		if err := os.WriteFile(tmp, w.data, w.mode); err != nil {
			return fmt.Errorf("identity: write %s: %w", w.path, err)
		}
		if err := os.Rename(tmp, w.path); err != nil {
			return fmt.Errorf("identity: commit %s: %w", w.path, err)
		}
	}
	return nil
}

// UpdatePolicyVersion rewrites collector.json with a new applied policy version.
func (s *Store) UpdatePolicyVersion(id Identity, version int64) error {
	_, _, _, jsonPath := s.Paths()
	id.PolicyVersion = version
	raw, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(jsonPath, raw, 0o600)
}
