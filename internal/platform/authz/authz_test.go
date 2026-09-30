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
