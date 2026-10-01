package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func validDocument(t *testing.T, targets []Target) []byte {
	t.Helper()
	doc := Document{
		HeartbeatIntervalSeconds: 30,
		ReportIntervalSeconds:    5,
		BatchMaxSamples:          5000,
		SpoolMaxBytes:            64 << 20,
		Metrics: []Metric{{
			Key: "collector_cpu_percent", Unit: "percent", Source: "collector_cpu",
			IntervalSeconds: 5, Dimensions: map[string]string{"cpu": "total"},
		}},
		Targets: targets,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

func signPolicy(t *testing.T, _ []byte) ([]byte, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	return der, priv
}

func TestVerifyAndValidateWithTargets(t *testing.T) {
	doc := validDocument(t, []Target{{
		DeviceID: "0198d5a3-0000-7000-8000-000000000001",
		MgmtIP:   "192.0.2.10",
		Name:     "edge-1",
		Tier:     "fast",
	}})
	pubDER, priv := signPolicy(t, doc)
	sig := ed25519.Sign(priv, doc)

	got, err := VerifyAndValidate(doc, sig, pubDER)
	if err != nil {
		t.Fatalf("VerifyAndValidate: %v", err)
	}
	if len(got.Targets) != 1 || got.Targets[0].DeviceID != "0198d5a3-0000-7000-8000-000000000001" {
		t.Fatalf("targets = %+v", got.Targets)
	}

	// Tampering must fail signature verification.
	tampered := append([]byte{}, doc...)
	tampered[0] ^= 0xff
	if _, err := VerifyAndValidate(tampered, sig, pubDER); err == nil {
		t.Fatal("tampered document verified")
	}
}

func TestValidateTargetBounds(t *testing.T) {
	valid := []Target{{DeviceID: "0198d5a3-0000-7000-8000-000000000001", MgmtIP: "2001:db8::1", Name: "d", Tier: "slow"}}
	if err := Validate(Document{
		HeartbeatIntervalSeconds: 30, ReportIntervalSeconds: 5, BatchMaxSamples: 5000, SpoolMaxBytes: 1 << 20,
		Metrics: []Metric{{Key: "k", Unit: "u", Source: "s", IntervalSeconds: 1}}, Targets: valid,
	}); err != nil {
		t.Fatalf("valid targets rejected: %v", err)
	}

	cases := map[string][]Target{
		"bad uuid":  {{DeviceID: "not-a-uuid", MgmtIP: "192.0.2.1", Tier: "fast"}},
		"bad ip":    {{DeviceID: "0198d5a3-0000-7000-8000-000000000001", MgmtIP: "nope", Tier: "fast"}},
		"duplicate": {valid[0], valid[0]},
	}
	for name, targets := range cases {
		err := Validate(Document{
			HeartbeatIntervalSeconds: 30, ReportIntervalSeconds: 5, BatchMaxSamples: 5000, SpoolMaxBytes: 1 << 20,
			Metrics: []Metric{{Key: "k", Unit: "u", Source: "s", IntervalSeconds: 1}}, Targets: targets,
		})
		if err == nil {
			t.Fatalf("%s targets accepted", name)
		}
	}

	tooMany := make([]Target, MaxTargets+1)
	err := Validate(Document{
		HeartbeatIntervalSeconds: 30, ReportIntervalSeconds: 5, BatchMaxSamples: 5000, SpoolMaxBytes: 1 << 20,
		Metrics: []Metric{{Key: "k", Unit: "u", Source: "s", IntervalSeconds: 1}}, Targets: tooMany,
	})
	if err == nil {
		t.Fatal("over-limit targets accepted")
	}
}

func TestStoreKeepsLastThreeBundles(t *testing.T) {
	dir := t.TempDir()
	for v := int64(1); v <= 5; v++ {
		if _, err := Store(dir, v, []byte("{}")); err != nil {
			t.Fatalf("store v%d: %v", v, err)
		}
	}
	for _, name := range []string{"policy-v3.json", "policy-v4.json", "policy-v5.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s should be retained: %v", name, err)
		}
	}
	for _, name := range []string{"policy-v1.json", "policy-v2.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s should be pruned (err=%v)", name, err)
		}
	}
	// The newest bundle remains loadable.
	raw, err := os.ReadFile(filepath.Join(dir, "policy-v5.json")) //nolint:gosec // path under t.TempDir()
	if err != nil || string(raw) != "{}" {
		t.Fatalf("load newest: %q err=%v", raw, err)
	}
}
