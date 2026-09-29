package collectors

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// PolicyDocument is the Phase-1 policy payload delivered to collectors
// (SPEC §11). The exact serialized bytes are signed; collectors verify the
// signature before applying anything.
type PolicyDocument struct {
	HeartbeatIntervalSeconds int            `json:"heartbeat_interval_seconds"`
	ReportIntervalSeconds    int            `json:"report_interval_seconds"`
	BatchMaxSamples          int            `json:"batch_max_samples"`
	SpoolMaxBytes            int64          `json:"spool_max_bytes"`
	Metrics                  []PolicyMetric `json:"metrics"`
}

// PolicyMetric describes one metric the collector should produce.
type PolicyMetric struct {
	Key             string            `json:"key"`
	Unit            string            `json:"unit"`
	Source          string            `json:"source"`
	IntervalSeconds int               `json:"interval_seconds"`
	Dimensions      map[string]string `json:"dimensions,omitempty"`
}

// DefaultPolicyDocument is the Phase-1 policy: one collector-local metric,
// documented intervals and bounds.
func DefaultPolicyDocument() PolicyDocument {
	return PolicyDocument{
		HeartbeatIntervalSeconds: 30,
		ReportIntervalSeconds:    5,
		BatchMaxSamples:          5000,
		SpoolMaxBytes:            64 << 20,
		Metrics: []PolicyMetric{{
			Key:             "collector_cpu_percent",
			Unit:            "percent",
			Source:          "collector_cpu",
			IntervalSeconds: 5,
			Dimensions:      map[string]string{"cpu": "total"},
		}},
	}
}

// SignedPolicy is a policy version with its signature and metadata.
type SignedPolicy struct {
	Version    int64
	Document   []byte
	Signature  []byte
	KeyID      string
	JitterSalt string
}

// BuildSignedPolicy serializes the document and signs it with the CA's
// Ed25519 policy key.
func (ca *CA) BuildSignedPolicy(version int64) (*SignedPolicy, error) {
	doc, err := json.Marshal(DefaultPolicyDocument())
	if err != nil {
		return nil, fmt.Errorf("collectors: marshal policy: %w", err)
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("collectors: jitter salt: %w", err)
	}
	return &SignedPolicy{
		Version:    version,
		Document:   doc,
		Signature:  ca.SignPolicy(doc),
		KeyID:      ca.PolicyKeyID(),
		JitterSalt: hex.EncodeToString(salt),
	}, nil
}
