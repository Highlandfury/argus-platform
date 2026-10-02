package alerts

import (
	"testing"

	"github.com/google/uuid"
)

func TestFingerprintCanonicalAndDistinct(t *testing.T) {
	ruleID := uuid.MustParse("01890000-0000-7000-8000-000000000001")
	deviceID := uuid.MustParse("01890000-0000-7000-8000-000000000002")

	dimsAB := sortedDimensions(map[string]string{"if": "ether1", "site": "hq"})
	dimsBA := sortedDimensions(map[string]string{"site": "hq", "if": "ether1"})
	fp1 := Fingerprint(ruleID, "device", deviceID, dimsAB)
	fp2 := Fingerprint(ruleID, "device", deviceID, dimsBA)
	if fp1 != fp2 {
		t.Fatalf("dimension key order must not change the fingerprint: %s != %s", fp1, fp2)
	}
	if len(fp1) != 64 {
		t.Fatalf("fingerprint length = %d, want 64", len(fp1))
	}

	// Every identity component participates.
	if fp1 == Fingerprint(uuid.MustParse("01890000-0000-7000-8000-000000000003"), "device", deviceID, dimsAB) {
		t.Fatal("rule_id must change the fingerprint")
	}
	if fp1 == Fingerprint(ruleID, "device", uuid.MustParse("01890000-0000-7000-8000-000000000004"), dimsAB) {
		t.Fatal("resource_id must change the fingerprint")
	}
	if fp1 == Fingerprint(ruleID, "device", deviceID, sortedDimensions(map[string]string{"if": "ether2"})) {
		t.Fatal("dimension subset must change the fingerprint")
	}
	if fp1 == Fingerprint(ruleID, "collector", deviceID, dimsAB) {
		t.Fatal("resource_type must change the fingerprint")
	}

	// Empty dimensions are a stable, valid subset.
	if a, b := Fingerprint(ruleID, "device", deviceID, nil), Fingerprint(ruleID, "device", deviceID, []byte("{}")); a != b {
		t.Fatalf("nil and empty dimensions must be identical: %s != %s", a, b)
	}
}
