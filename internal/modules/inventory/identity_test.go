package inventory

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func strPtr(s string) *string { return &s }

func TestIdentityTransitionsPresenceAndNullSemantics(t *testing.T) {
	cur := Device{
		Serial:      strPtr("SN-1"),
		SysObjectID: strPtr("1.3.6.1.4.1.9"),
		MgmtIP:      strPtr("10.0.0.1"),
	}

	t.Run("omitted_fields_untouched", func(t *testing.T) {
		tr := identityTransitions(cur, DevicePatch{Name: "renamed", HasName: true})
		if len(tr) != 0 {
			t.Fatalf("omitted identity fields produced transitions: %+v", tr)
		}
	})

	t.Run("same_value_no_transition", func(t *testing.T) {
		tr := identityTransitions(cur, DevicePatch{Serial: NullableString{Set: true, Value: strPtr("SN-1")}})
		if len(tr) != 0 {
			t.Fatalf("same-value PATCH produced transitions: %+v", tr)
		}
	})

	t.Run("changed_serial_closes_and_opens", func(t *testing.T) {
		tr := identityTransitions(cur, DevicePatch{Serial: NullableString{Set: true, Value: strPtr("SN-2")}})
		if len(tr) != 1 {
			t.Fatalf("transitions = %+v, want 1", tr)
		}
		if tr[0].Type != IdentityTypeSerial || tr[0].Close == nil || *tr[0].Close != "SN-1" || tr[0].Open == nil || *tr[0].Open != "SN-2" {
			t.Fatalf("serial transition = %+v", tr[0])
		}
	})

	t.Run("null_closes_without_open", func(t *testing.T) {
		tr := identityTransitions(cur, DevicePatch{MgmtIP: NullableString{Set: true}})
		if len(tr) != 1 || tr[0].Type != IdentityTypeMgmtIP || tr[0].Close == nil || *tr[0].Close != "10.0.0.1" || tr[0].Open != nil {
			t.Fatalf("null transition = %+v", tr)
		}
	})

	t.Run("set_from_nil_opens_without_close", func(t *testing.T) {
		tr := identityTransitions(Device{}, DevicePatch{SysObjectID: NullableString{Set: true, Value: strPtr("1.3.6.1.4.1.9")}})
		if len(tr) != 1 || tr[0].Close != nil || tr[0].Open == nil || *tr[0].Open != "1.3.6.1.4.1.9" {
			t.Fatalf("set-from-nil transition = %+v", tr)
		}
	})

	t.Run("multiple_fields_one_transition_each", func(t *testing.T) {
		tr := identityTransitions(cur, DevicePatch{
			Serial: NullableString{Set: true, Value: strPtr("SN-2")},
			MgmtIP: NullableString{Set: true},
		})
		if len(tr) != 2 {
			t.Fatalf("transitions = %+v, want 2", tr)
		}
	})

	t.Run("mgmt_ip_equality_is_canonical", func(t *testing.T) {
		// host(inet) returns the canonical form; a semantically equal input
		// must not churn history.
		tr := identityTransitions(Device{MgmtIP: strPtr("2001:db8::1")},
			DevicePatch{MgmtIP: NullableString{Set: true, Value: strPtr("2001:DB8::1")}})
		if len(tr) != 0 {
			t.Fatalf("IPv6 case variant produced transitions: %+v", tr)
		}
	})
}

func TestIdentityConflictMapping(t *testing.T) {
	identityErr := &pgconn.PgError{Code: sqlstateUniqueViolation, ConstraintName: identityOpenUniqueIndex}
	if !isIdentityConflict(identityErr) {
		t.Fatal("identity open-window unique violation not mapped")
	}
	if isIdentityConflict(&pgconn.PgError{Code: sqlstateUniqueViolation, ConstraintName: "devices_org_site_name_uniq"}) {
		t.Fatal("device name unique violation misclassified as identity conflict")
	}
	if isIdentityConflict(&pgconn.PgError{Code: "23514", ConstraintName: identityOpenUniqueIndex}) {
		t.Fatal("non-unique SQLSTATE misclassified as identity conflict")
	}
	if isIdentityConflict(errors.New("boom")) {
		t.Fatal("non-pg error misclassified as identity conflict")
	}
	// Wrapped errors must still classify (service paths wrap pg errors).
	if !isIdentityConflict(errors.Join(errors.New("tx failed"), identityErr)) {
		t.Fatal("wrapped identity violation not mapped")
	}
}

func TestCanonicalIdentityValue(t *testing.T) {
	if got := canonicalIdentityValue(IdentityTypeMgmtIP, "2001:DB8::1"); got != "2001:db8::1" {
		t.Fatalf("mgmt_ip canonicalization = %q", got)
	}
	if got := canonicalIdentityValue(IdentityTypeMAC, "AA:BB:CC:00:00:01"); got != "aa:bb:cc:00:00:01" {
		t.Fatalf("mac canonicalization = %q", got)
	}
	if got := canonicalIdentityValue(IdentityTypeSerial, " SN-1 "); got != " SN-1 " {
		t.Fatalf("serial must be kept verbatim, got %q", got)
	}
}
