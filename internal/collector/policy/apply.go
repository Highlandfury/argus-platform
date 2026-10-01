// Package policy verifies and validates server policy bundles before they are
// applied (collectors must never silently accept malformed or unauthorized
// policy — SPEC §11, failure test T5 analog).
package policy

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/platform/sessioncrypto"
)

// ErrVerification is returned when the Ed25519 signature does not match.
var ErrVerification = errors.New("policy: signature verification failed")

// ErrValidation is returned when the document is structurally invalid.
var ErrValidation = errors.New("policy: document invalid")

// PolicyRetention is the number of signed bundles kept on disk for rollback
// (canonical docs/15: "applies atomically, keeps last 3 bundles"). The newest
// bundle is always the applied one.
const PolicyRetention = 3

// MaxTargets bounds the poll-target list a document may carry (mirrors the
// server-side collectors.MaxPolicyTargets ceiling).
const MaxTargets = 10000

// Document mirrors the Phase-1 policy payload plus the M9-S1 poll targets and
// the M9-S3 per-session credential material.
type Document struct {
	HeartbeatIntervalSeconds int      `json:"heartbeat_interval_seconds"`
	ReportIntervalSeconds    int      `json:"report_interval_seconds"`
	BatchMaxSamples          int      `json:"batch_max_samples"`
	SpoolMaxBytes            int64    `json:"spool_max_bytes"`
	Metrics                  []Metric `json:"metrics"`
	// Targets are the per-device poll targets (M9-S1). Absent in Phase-1
	// documents; validated when present.
	Targets []Target `json:"targets,omitempty"`
	// Session is the M9-S3 per-bundle credential material (ciphertext sealed
	// to this stream session's ephemeral key). Absent in Phase-1/2 documents
	// and ignored by collectors that do not implement it.
	Session *sessioncrypto.Session `json:"session,omitempty"`
}

// Metric is one instructed metric source.
type Metric struct {
	Key             string            `json:"key"`
	Unit            string            `json:"unit"`
	Source          string            `json:"source"`
	IntervalSeconds int               `json:"interval_seconds"`
	Dimensions      map[string]string `json:"dimensions,omitempty"`
}

// Target is one device the collector should poll (M9-S1; extended in M9-S2).
// Tier values are the canonical §12.4 tiers; unknown tier strings are
// normalized by the poll engine (never a policy rejection: one operator typo
// must not disable polling for the whole collector). PollType selects ICMP or
// SNMP (unknown values normalize to ICMP); Kind selects SNMP template packs.
// Critical (M10-S0) lowers the adaptive failure-backoff ceiling to 5 minutes.
type Target struct {
	DeviceID string `json:"device_id"`
	MgmtIP   string `json:"mgmt_ip"`
	Name     string `json:"name"`
	Tier     string `json:"tier"`
	PollType string `json:"poll_type,omitempty"`
	Kind     string `json:"kind,omitempty"`
	Critical bool   `json:"critical,omitempty"`
}

// VerifyAndValidate checks the signature against the pinned Ed25519 key and
// bounds-checks the document. The document is signed as exact bytes.
func VerifyAndValidate(document, signature, pubKeyDER []byte) (Document, error) {
	pub, err := x509.ParsePKIXPublicKey(pubKeyDER)
	if err != nil {
		return Document{}, fmt.Errorf("%w: %w", ErrVerification, err)
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return Document{}, fmt.Errorf("%w: pinned key is not Ed25519", ErrVerification)
	}
	if !ed25519.Verify(edPub, document, signature) {
		return Document{}, ErrVerification
	}
	var doc Document
	if err := json.Unmarshal(document, &doc); err != nil {
		return Document{}, fmt.Errorf("%w: %w", ErrValidation, err)
	}
	if err := Validate(doc); err != nil {
		return Document{}, err
	}
	return doc, nil
}

// Validate bounds-checks a document (shared by the verify path and the
// producer's load path).
func Validate(doc Document) error {
	if doc.HeartbeatIntervalSeconds < 5 || doc.HeartbeatIntervalSeconds > 600 {
		return fmt.Errorf("%w: heartbeat_interval_seconds out of range", ErrValidation)
	}
	if doc.ReportIntervalSeconds < 1 || doc.ReportIntervalSeconds > 3600 {
		return fmt.Errorf("%w: report_interval_seconds out of range", ErrValidation)
	}
	if doc.BatchMaxSamples < 100 || doc.BatchMaxSamples > 10000 {
		return fmt.Errorf("%w: batch_max_samples out of range", ErrValidation)
	}
	if doc.SpoolMaxBytes < 1<<20 || doc.SpoolMaxBytes > 1<<34 {
		return fmt.Errorf("%w: spool_max_bytes out of range", ErrValidation)
	}
	if len(doc.Metrics) == 0 || len(doc.Metrics) > 100 {
		return fmt.Errorf("%w: metrics list size invalid", ErrValidation)
	}
	for _, m := range doc.Metrics {
		if m.Key == "" || m.Unit == "" || m.Source == "" {
			return fmt.Errorf("%w: metric missing key/unit/source", ErrValidation)
		}
		if m.IntervalSeconds < 1 || m.IntervalSeconds > 3600 {
			return fmt.Errorf("%w: metric interval out of range", ErrValidation)
		}
	}
	if len(doc.Targets) > MaxTargets {
		return fmt.Errorf("%w: targets list exceeds %d", ErrValidation, MaxTargets)
	}
	if doc.Session != nil {
		// Structural bounds only: an unknown algorithm with a well-formed
		// shape stays applicable (the material is then ignored per record and
		// the device reports credential_missing instead of the whole bundle
		// being rejected).
		if err := doc.Session.Validate(); err != nil {
			return fmt.Errorf("%w: session material: %w", ErrValidation, err)
		}
	}
	seen := make(map[string]bool, len(doc.Targets))
	for _, t := range doc.Targets {
		if _, err := uuid.Parse(t.DeviceID); err != nil {
			return fmt.Errorf("%w: target device_id %q is not a UUID", ErrValidation, t.DeviceID)
		}
		// One device may carry an ICMP and an SNMP target (M9-S2); duplicates
		// of the same (device, poll type) pair are rejected. Unknown poll
		// types normalize to ICMP in the engine, so the duplicate key uses the
		// same normalization.
		dupKey := t.DeviceID + ":" + normalizePolicyPollType(t.PollType)
		if seen[dupKey] {
			return fmt.Errorf("%w: duplicate target device_id %q poll_type %q", ErrValidation, t.DeviceID, t.PollType)
		}
		seen[dupKey] = true
		addr, err := netip.ParseAddr(t.MgmtIP)
		if err != nil || !addr.IsValid() {
			return fmt.Errorf("%w: target %s mgmt_ip %q is not an IP address", ErrValidation, t.DeviceID, t.MgmtIP)
		}
		if len(t.Name) > 200 {
			return fmt.Errorf("%w: target %s name exceeds 200 chars", ErrValidation, t.DeviceID)
		}
		if len(t.Tier) > 32 {
			return fmt.Errorf("%w: target %s tier exceeds 32 chars", ErrValidation, t.DeviceID)
		}
		if len(t.PollType) > 16 {
			return fmt.Errorf("%w: target %s poll_type exceeds 16 chars", ErrValidation, t.DeviceID)
		}
		if len(t.Kind) > 64 {
			return fmt.Errorf("%w: target %s kind exceeds 64 chars", ErrValidation, t.DeviceID)
		}
	}
	return nil
}

// normalizePolicyPollType mirrors poll.NormalizePollType without importing the
// poll package into the policy validator (keeps the dependency direction
// policy -> validation only).
func normalizePolicyPollType(s string) string {
	if strings.EqualFold(strings.TrimSpace(s), "snmp") {
		return "snmp"
	}
	return "icmp"
}

// Store writes a validated policy version atomically under dir and keeps the
// newest PolicyRetention bundles (canonical docs/15: last 3 bundles for
// rollback). Pruning is best-effort: a failed unlink never fails the apply.
func Store(dir string, version int64, document []byte) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, fmt.Sprintf("policy-v%d.json", version))
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, document, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	prune(dir)
	return path, nil
}

// policyVersion parses `policy-v<n>.json`; ok=false for any other name.
func policyVersion(name string) (int64, bool) {
	if !strings.HasPrefix(name, "policy-v") || !strings.HasSuffix(name, ".json") {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(name, "policy-v"), ".json"), 10, 64)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

// prune removes all but the newest PolicyRetention bundle files.
func prune(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type bundle struct {
		name    string
		version int64
	}
	var bundles []bundle
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if v, ok := policyVersion(e.Name()); ok {
			bundles = append(bundles, bundle{name: e.Name(), version: v})
		}
	}
	sort.Slice(bundles, func(i, j int) bool { return bundles[i].version > bundles[j].version })
	for _, b := range bundles[min(PolicyRetention, len(bundles)):] {
		_ = os.Remove(filepath.Join(dir, b.name))
	}
}

// LoadAndValidate reads a stored policy document (signature was verified when
// it was accepted; structural validation is re-applied) for the producer and
// batcher wiring.
func LoadAndValidate(dir string, version int64) (Document, error) {
	if version <= 0 {
		return Document{}, fmt.Errorf("%w: no applied policy version", ErrValidation)
	}
	path := filepath.Join(dir, fmt.Sprintf("policy-v%d.json", version))
	raw, err := os.ReadFile(path) //nolint:gosec // path derived from the operator-configured policy dir
	if err != nil {
		return Document{}, fmt.Errorf("policy: load v%d: %w", version, err)
	}
	var doc Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Document{}, fmt.Errorf("%w: %w", ErrValidation, err)
	}
	if err := Validate(doc); err != nil {
		return Document{}, err
	}
	return doc, nil
}
