package collectors

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"testing"
)

// TestPolicyTargetsRoundTrip pins the M9-S1 additive bundle change: per-device
// poll targets are serialized into the signed document and the signature still
// verifies with the delivered public key; the ICMP metric allowlist is present.
func TestPolicyTargetsRoundTrip(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir(), []string{"localhost"})
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	targets := []PolicyTarget{
		{DeviceID: "0198d5a3-0000-7000-8000-000000000001", MgmtIP: "192.0.2.10", Name: "edge-1", Tier: "fast", PollType: "icmp", Kind: "switch"},
		{DeviceID: "0198d5a3-0000-7000-8000-000000000001", MgmtIP: "192.0.2.10", Name: "edge-1", Tier: "fast", PollType: "snmp", Kind: "switch"},
		{DeviceID: "0198d5a3-0000-7000-8000-000000000002", MgmtIP: "192.0.2.11", Name: "core-1", Tier: "standard", PollType: "icmp", Kind: "router"},
	}
	sp, err := ca.BuildSignedPolicyWithTargets(3, targets)
	if err != nil {
		t.Fatalf("BuildSignedPolicyWithTargets: %v", err)
	}

	var doc PolicyDocument
	if err := json.Unmarshal(sp.Document, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Targets) != 3 || doc.Targets[0].DeviceID != targets[0].DeviceID {
		t.Fatalf("targets = %+v", doc.Targets)
	}
	if doc.Targets[1].PollType != "snmp" || doc.Targets[1].Kind != "switch" {
		t.Fatalf("snmp target = %+v, want poll_type/kind preserved", doc.Targets[1])
	}
	if doc.Targets[2].PollType != "icmp" || doc.Targets[2].Kind != "router" {
		t.Fatalf("icmp target = %+v, want kind preserved", doc.Targets[2])
	}
	keys := map[string]bool{}
	for _, m := range doc.Metrics {
		keys[m.Key] = true
	}
	for _, want := range []string{
		"collector_cpu_percent",
		"net.icmp.reachable", "net.icmp.rtt_ms", "net.icmp.loss_pct",
		"sys.uptime_s", "sys.cpu.util", "net.if.oper_status",
		"net.if.in_octets", "net.if.out_octets",
		"net.if.in_errors", "net.if.out_errors",
		"net.if.in_discards", "net.if.out_discards",
	} {
		if !keys[want] {
			t.Fatalf("policy metrics missing %s: %+v", want, doc.Metrics)
		}
	}

	pub, err := x509.ParsePKIXPublicKey(ca.PolicySigningPublicKeyDER())
	if err != nil {
		t.Fatalf("parse pub: %v", err)
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		t.Fatal("policy key is not Ed25519")
	}
	if !ed25519.Verify(edPub, sp.Document, sp.Signature) {
		t.Fatal("policy signature must verify with targets included")
	}
}

func TestPolicyTargetCeiling(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir(), []string{"localhost"})
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	tooMany := make([]PolicyTarget, MaxPolicyTargets+1)
	if _, err := ca.BuildSignedPolicyWithTargets(1, tooMany); err == nil {
		t.Fatal("over-ceiling target list must fail loudly")
	}
	if len(DefaultPolicyDocument().Targets) != 0 {
		t.Fatal("DefaultPolicyDocument must not invent targets")
	}
}
