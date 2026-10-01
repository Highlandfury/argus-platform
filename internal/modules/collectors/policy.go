package collectors

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// PolicyDocument is the Phase-1 policy payload delivered to collectors
// (SPEC §11). The exact serialized bytes are signed; collectors verify the
// signature before applying anything. M9-S1 adds `targets` additively: the
// old document shape remains valid, and a collector that does not understand
// targets ignores the field.
type PolicyDocument struct {
	HeartbeatIntervalSeconds int            `json:"heartbeat_interval_seconds"`
	ReportIntervalSeconds    int            `json:"report_interval_seconds"`
	BatchMaxSamples          int            `json:"batch_max_samples"`
	SpoolMaxBytes            int64          `json:"spool_max_bytes"`
	Metrics                  []PolicyMetric `json:"metrics"`
	// Targets are the per-device poll targets for the org (M9-S1). Only live
	// devices with a management IP are included.
	Targets []PolicyTarget `json:"targets,omitempty"`
}

// PolicyMetric describes one metric the collector should produce.
type PolicyMetric struct {
	Key             string            `json:"key"`
	Unit            string            `json:"unit"`
	Source          string            `json:"source"`
	IntervalSeconds int               `json:"interval_seconds"`
	Dimensions      map[string]string `json:"dimensions,omitempty"`
}

// PolicyTarget is one device the collector should poll (M9-S1). Tier is the
// device's poll_profile (`fast|standard|slow|inventory` per docs/07 §12.4);
// the collector normalizes unknown tiers to `standard` so one bad operator
// value can never invalidate the whole signed policy.
type PolicyTarget struct {
	DeviceID string `json:"device_id"`
	MgmtIP   string `json:"mgmt_ip"`
	Name     string `json:"name"`
	Tier     string `json:"tier"`
}

// MaxPolicyTargets bounds the targets list a policy document may carry. The
// canonical per-collector budget is ~1,500 devices (docs/07 §12.8); 10,000 is
// the documented hard ceiling.
const MaxPolicyTargets = 10000

// DefaultPolicyDocument is the Phase-1 policy: one collector-local metric,
// documented intervals and bounds, no poll targets.
func DefaultPolicyDocument() PolicyDocument {
	return policyDocument(nil)
}

// policyDocument builds the full M9-S1 policy document: the Phase-1 collector
// metric plus the ICMP poll metric allowlist (P2-AC-14) and the per-device
// poll targets.
func policyDocument(targets []PolicyTarget) PolicyDocument {
	return PolicyDocument{
		HeartbeatIntervalSeconds: 30,
		ReportIntervalSeconds:    5,
		BatchMaxSamples:          5000,
		SpoolMaxBytes:            64 << 20,
		Metrics: []PolicyMetric{
			{
				Key:             "collector_cpu_percent",
				Unit:            "percent",
				Source:          "collector_cpu",
				IntervalSeconds: 5,
				Dimensions:      map[string]string{"cpu": "total"},
			},
			// M9-S1 ICMP poll metrics (P2-AC-14). Keys follow the canonical
			// dotted namespaced naming (docs/08 §5: `net.if.in_octets`,
			// `wan.latency.p95_ms`); units are the documented strings used by
			// the ingest validator.
			{Key: "net.icmp.reachable", Unit: "state", Source: "icmp", IntervalSeconds: 30},
			{Key: "net.icmp.rtt_ms", Unit: "ms", Source: "icmp", IntervalSeconds: 30},
			{Key: "net.icmp.loss_pct", Unit: "percent", Source: "icmp", IntervalSeconds: 30},
			// M9-S2b adaptive-backoff telemetry is NOT part of this slice.
		},
		Targets: targets,
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

// BuildSignedPolicy serializes the document (no poll targets) and signs it
// with the CA's Ed25519 policy key.
func (ca *CA) BuildSignedPolicy(version int64) (*SignedPolicy, error) {
	return ca.BuildSignedPolicyWithTargets(version, nil)
}

// BuildSignedPolicyWithTargets serializes the document including the M9-S1
// per-device poll targets and signs it with the CA's Ed25519 policy key. The
// exact bytes are stored and forwarded unchanged; signature verification is
// unchanged.
func (ca *CA) BuildSignedPolicyWithTargets(version int64, targets []PolicyTarget) (*SignedPolicy, error) {
	if len(targets) > MaxPolicyTargets {
		return nil, fmt.Errorf("collectors: policy targets %d exceed the %d ceiling", len(targets), MaxPolicyTargets)
	}
	doc, err := json.Marshal(policyDocument(targets))
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
