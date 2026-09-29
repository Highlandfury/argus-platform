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
	"os"
	"path/filepath"
)

// ErrVerification is returned when the Ed25519 signature does not match.
var ErrVerification = errors.New("policy: signature verification failed")

// ErrValidation is returned when the document is structurally invalid.
var ErrValidation = errors.New("policy: document invalid")

// Document mirrors the Phase-1 policy payload.
type Document struct {
	HeartbeatIntervalSeconds int      `json:"heartbeat_interval_seconds"`
	ReportIntervalSeconds    int      `json:"report_interval_seconds"`
	BatchMaxSamples          int      `json:"batch_max_samples"`
	SpoolMaxBytes            int64    `json:"spool_max_bytes"`
	Metrics                  []Metric `json:"metrics"`
}

// Metric is one instructed metric source.
type Metric struct {
	Key             string            `json:"key"`
	Unit            string            `json:"unit"`
	Source          string            `json:"source"`
	IntervalSeconds int               `json:"interval_seconds"`
	Dimensions      map[string]string `json:"dimensions,omitempty"`
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
	if doc.HeartbeatIntervalSeconds < 5 || doc.HeartbeatIntervalSeconds > 600 {
		return Document{}, fmt.Errorf("%w: heartbeat_interval_seconds out of range", ErrValidation)
	}
	if doc.ReportIntervalSeconds < 1 || doc.ReportIntervalSeconds > 3600 {
		return Document{}, fmt.Errorf("%w: report_interval_seconds out of range", ErrValidation)
	}
	if doc.BatchMaxSamples < 100 || doc.BatchMaxSamples > 10000 {
		return Document{}, fmt.Errorf("%w: batch_max_samples out of range", ErrValidation)
	}
	if doc.SpoolMaxBytes < 1<<20 || doc.SpoolMaxBytes > 1<<34 {
		return Document{}, fmt.Errorf("%w: spool_max_bytes out of range", ErrValidation)
	}
	if len(doc.Metrics) == 0 || len(doc.Metrics) > 100 {
		return Document{}, fmt.Errorf("%w: metrics list size invalid", ErrValidation)
	}
	for _, m := range doc.Metrics {
		if m.Key == "" || m.Unit == "" || m.Source == "" {
			return Document{}, fmt.Errorf("%w: metric missing key/unit/source", ErrValidation)
		}
		if m.IntervalSeconds < 1 || m.IntervalSeconds > 3600 {
			return Document{}, fmt.Errorf("%w: metric interval out of range", ErrValidation)
		}
	}
	return doc, nil
}

// Store writes a validated policy version atomically under dir.
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
	return path, nil
}
