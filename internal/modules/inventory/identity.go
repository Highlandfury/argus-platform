package inventory

import "net"

// identitySourceManual is the history source for API-driven manual edits
// (matches the create path).
const identitySourceManual = "manual"

// Canonical device-column -> identifier_type mapping for PATCH transitions:
//
//	devices.serial        -> serial
//	devices.sys_object_id -> sys_object_id
//	devices.mgmt_ip       -> mgmt_ip
//
// chassis_id/mac/hostname exist only as explicit identity-history rows (no
// device column), so they never participate in PATCH transitions.

// identityTransition is one open-window transition on a device PATCH: close the
// old window (when there was a value) and open the new one (when the new value
// is not null).
type identityTransition struct {
	Type  string
	Close *string
	Open  *string
}

// identityTransitions computes the history transitions for a device PATCH from
// the current device row. Canonical PATCH semantics:
//
//   - omitted field            -> no transition (history stable)
//   - same-value field         -> no transition (no redundant row)
//   - changed value            -> close old open window, open new window
//   - explicit null            -> close old open window, no new row
//   - value set when old null  -> open new window
func identityTransitions(cur Device, p DevicePatch) []identityTransition {
	var out []identityTransition
	add := func(typ string, curVal *string, patch NullableString) {
		if !patch.Set {
			return
		}
		newVal := patch.Value
		if canonicalIdentityEqual(typ, curVal, newVal) {
			return
		}
		tr := identityTransition{Type: typ}
		if curVal != nil {
			v := canonicalIdentityValue(typ, *curVal)
			tr.Close = &v
		}
		if newVal != nil {
			v := canonicalIdentityValue(typ, *newVal)
			tr.Open = &v
		}
		if tr.Close == nil && tr.Open == nil {
			return
		}
		out = append(out, tr)
	}
	add(IdentityTypeSerial, cur.Serial, p.Serial)
	add(IdentityTypeSysObjectID, cur.SysObjectID, p.SysObjectID)
	add(IdentityTypeMgmtIP, cur.MgmtIP, p.MgmtIP)
	return out
}

// canonicalIdentityValue canonicalizes an identity value for storage and
// comparison. Management IPs are stored as inet (host() normalizes them) and
// MACs are case/format-variable (RFC 2863-style lowercase colon form is the
// canonical text), so both are normalized or close/open lookups and duplicate
// detection would miss equivalent encodings.
func canonicalIdentityValue(typ, value string) string {
	switch typ {
	case IdentityTypeMgmtIP:
		if ip := net.ParseIP(value); ip != nil {
			return ip.String()
		}
	case IdentityTypeMAC:
		if mac, err := net.ParseMAC(value); err == nil {
			return mac.String()
		}
	}
	return value
}

func canonicalIdentityEqual(typ string, a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return canonicalIdentityValue(typ, *a) == canonicalIdentityValue(typ, *b)
}
