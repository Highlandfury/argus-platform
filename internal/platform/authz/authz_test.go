package authz

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestRoleCapabilityDerivation(t *testing.T) {
	for _, cap := range InventoryCapabilities {
		if !Allowed("admin", cap) {
			t.Errorf("admin lacks inventory capability %q", cap)
		}
	}
	for _, cap := range ReadCapabilities {
		if !Allowed("viewer", cap) {
			t.Errorf("viewer lacks read capability %q", cap)
		}
	}
	for _, cap := range []string{CapDeviceWrite, CapDeviceMerge, CapDeviceSplit, CapInterfaceWrite, CapDeviceGroupWrite} {
		if Allowed("viewer", cap) {
			t.Errorf("viewer unexpectedly holds write capability %q", cap)
		}
	}
	for _, role := range []string{"", "operator", "auditor"} {
		if Allowed(role, CapDeviceRead) {
			t.Errorf("unknown role %q unexpectedly holds device.read", role)
		}
	}
}

func TestAlertCapabilityDerivation(t *testing.T) {
	for _, cap := range append(append([]string{}, AlertCapabilities...), AlertRuleCapabilities...) {
		if !Allowed("admin", cap) {
			t.Errorf("admin lacks alert capability %q", cap)
		}
	}
	if !Allowed("viewer", CapAlertRead) {
		t.Error("viewer must hold alert.read (docs/04 §6.4: alerts view is granted to read-only)")
	}
	for _, cap := range []string{CapAlertAck, CapAlertSnooze, CapAlertSilence, CapAlertRuleRead, CapAlertRuleWrite} {
		if Allowed("viewer", cap) {
			t.Errorf("viewer unexpectedly holds %q (canonical matrix denies it to read-only)", cap)
		}
	}
	for _, cap := range AlertCapabilities {
		if !IsAlertCapability(cap) {
			t.Errorf("IsAlertCapability(%q) = false", cap)
		}
	}
	for _, cap := range AlertRuleCapabilities {
		if !IsAlertRuleCapability(cap) {
			t.Errorf("IsAlertRuleCapability(%q) = false", cap)
		}
	}
	if IsAlertCapability(CapAlertRuleWrite) || IsAlertRuleCapability(CapAlertAck) {
		t.Error("alert and alert-rule vocabularies must not cross")
	}
}

func TestCapabilityAndScopeVocabulary(t *testing.T) {
	for _, cap := range InventoryCapabilities {
		if !IsInventoryCapability(cap) {
			t.Errorf("IsInventoryCapability(%q) = false", cap)
		}
	}
	if IsInventoryCapability("device.delete") {
		t.Error("device.delete must not be part of the M7-S3 vocabulary (delete collapses under device.write)")
	}
	for _, scope := range []string{ScopeOrg, ScopeSite, ScopeDeviceGroup, ScopeDevice} {
		if !IsScope(scope) {
			t.Errorf("IsScope(%q) = false", scope)
		}
	}
	if IsScope("building") || IsScope("") {
		t.Error("unexpected scope accepted")
	}
}

func TestScopeEvaluation(t *testing.T) {
	siteA, siteB := uuid.New(), uuid.New()
	groupA := uuid.New()

	unrestricted := Scope{Unrestricted: true}
	if !unrestricted.AllowsSite(siteA) || !unrestricted.AllowsDevice(siteB) || !unrestricted.AllowsDeviceGroup(groupA) {
		t.Fatal("unrestricted scope must allow everything")
	}

	restricted := Scope{Sites: []uuid.UUID{siteA}, DeviceGroups: []uuid.UUID{groupA}}
	if !restricted.AllowsSite(siteA) || restricted.AllowsSite(siteB) {
		t.Fatal("site binding must cover exactly the bound site")
	}
	if !restricted.AllowsDevice(siteA) || restricted.AllowsDevice(siteB) {
		t.Fatal("device access must inherit from the device's site binding")
	}
	if !restricted.AllowsDeviceGroup(groupA) || restricted.AllowsDeviceGroup(uuid.New()) {
		t.Fatal("device_group binding must cover exactly the bound group")
	}
	if err := restricted.RequireDevice(siteB); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("RequireDevice(out-of-scope) = %v, want ErrOutOfScope", err)
	}
	if err := restricted.RequireSite(siteA); err != nil {
		t.Fatalf("RequireSite(in-scope) = %v", err)
	}
	if err := restricted.RequireDeviceGroup(groupA); err != nil {
		t.Fatalf("RequireDeviceGroup(in-scope) = %v", err)
	}

	empty := Scope{}
	if empty.AllowsSite(siteA) || empty.AllowsDevice(siteA) || empty.AllowsDeviceGroup(groupA) {
		t.Fatal("zero-value scope must be fail-closed")
	}
}
