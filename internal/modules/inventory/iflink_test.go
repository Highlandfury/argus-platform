package inventory

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func ifRow(name string, alias, mac *string, index int) *Interface {
	return &Interface{
		ID:         uuid.New(),
		IfIndex:    index,
		IfName:     name,
		IfAlias:    alias,
		MAC:        mac,
		OperStatus: strp("up"),
	}
}

func strp(s string) *string { return &s }

// TestChooseInterfaceRowPreference pins the identity preference order: single
// name match; exact MAC; null-safe alias; if_index tie-break; ambiguity is
// never guessed.
func TestChooseInterfaceRowPreference(t *testing.T) {
	uplink := strp("uplink")
	access := strp("access")
	macA := strp("02:00:00:00:00:01")
	macB := strp("02:00:00:00:00:02")

	// Single name match wins regardless of attributes.
	single := []*Interface{ifRow("Gi1/0/1", uplink, macA, 1)}
	o := InterfaceObservation{IfName: "Gi1/0/1", IfIndex: 9}
	if got := chooseInterfaceRow(single, o); got == nil || got.IfIndex != 1 {
		t.Fatalf("single match = %+v", got)
	}

	// Two rows share the name: exact MAC disambiguates.
	rows := []*Interface{
		ifRow("Gi1/0/1", uplink, macA, 1),
		ifRow("Gi1/0/1", access, macB, 2),
	}
	want := rows[1]
	got := chooseInterfaceRow(rows, InterfaceObservation{IfName: "Gi1/0/1", IfIndex: 1, MAC: macB})
	if got != want {
		t.Fatalf("MAC preference = %+v, want row %d", got, want.IfIndex)
	}

	// No MAC: alias disambiguates.
	got = chooseInterfaceRow(rows, InterfaceObservation{IfName: "Gi1/0/1", IfIndex: 1, IfAlias: access})
	if got != want {
		t.Fatalf("alias preference = %+v, want row %d", got, want.IfIndex)
	}

	// Same alias twice: reported if_index breaks the tie.
	rows2 := []*Interface{
		ifRow("Gi1/0/1", uplink, macA, 4),
		ifRow("Gi1/0/1", uplink, macB, 5),
	}
	got = chooseInterfaceRow(rows2, InterfaceObservation{IfName: "Gi1/0/1", IfIndex: 5, IfAlias: uplink})
	if got == nil || got.IfIndex != 5 {
		t.Fatalf("if_index tie-break = %+v, want row index 5", got)
	}

	// Ambiguous: no MAC, alias matches both, no index match -> never guess.
	got = chooseInterfaceRow(rows2, InterfaceObservation{IfName: "Gi1/0/1", IfIndex: 9, IfAlias: uplink})
	if got != nil {
		t.Fatalf("ambiguous match = %+v, want nil", got)
	}

	// No name match at all.
	if got := chooseInterfaceRow(rows, InterfaceObservation{IfName: "Gi2"}); got != nil {
		t.Fatalf("unexpected match = %+v", got)
	}
}

// TestMergeObservationRebindAndPreserve proves a changed if_index rebinds in
// place (same row identity), an occupied index is a documented conflict, and
// operator-set fields survive an observation that omits them.
func TestMergeObservationRebindAndPreserve(t *testing.T) {
	old := time.Date(2026, 10, 1, 11, 0, 0, 0, time.UTC)
	row := ifRow("Gi1/0/1", strp("uplink"), strp("02:00:00:00:00:01"), 1)
	row.MTU = intp(1500)
	row.LastSeenAt = &old
	sibling := ifRow("Gi1/0/2", strp("access"), nil, 4)

	// A rebind to a free index, with an observation that omits alias/MTU.
	newIdx := 7
	speed := int64(10000000000)
	ch := mergeObservation(row, InterfaceObservation{
		IfIndex:    newIdx,
		SpeedBPS:   &speed,
		ObservedAt: old.Add(time.Minute),
	}, []*Interface{sibling})
	if !ch.rebound || ch.oldIndex != 1 || ch.newIndex != newIdx {
		t.Fatalf("changes = %+v, want rebind 1->%d", ch, newIdx)
	}
	if row.IfIndex != newIdx {
		t.Fatalf("if_index = %d, want %d", row.IfIndex, newIdx)
	}
	if row.IfAlias == nil || *row.IfAlias != "uplink" {
		t.Fatalf("alias = %v, empty observation must not clear it", row.IfAlias)
	}
	if row.MTU == nil || *row.MTU != 1500 {
		t.Fatalf("mtu = %v, absent observation must keep the last value", row.MTU)
	}
	if row.SpeedBPS == nil || *row.SpeedBPS != speed {
		t.Fatalf("speed = %v", row.SpeedBPS)
	}
	if row.LastSeenAt == nil || !row.LastSeenAt.After(old) {
		t.Fatalf("last_seen = %v, want advanced", row.LastSeenAt)
	}

	// Out-of-order observation must not move last_seen backwards.
	ch = mergeObservation(row, InterfaceObservation{IfIndex: newIdx, ObservedAt: old}, []*Interface{sibling})
	if ch.rebound {
		t.Fatalf("same-index observation reported a rebind: %+v", ch)
	}
	if !row.LastSeenAt.After(old) {
		t.Fatalf("last_seen regressed to %v", row.LastSeenAt)
	}

	// An occupied index is a conflict: the row keeps its old index.
	ch = mergeObservation(row, InterfaceObservation{IfIndex: sibling.IfIndex, ObservedAt: old.Add(2 * time.Minute)}, []*Interface{sibling})
	if !ch.indexConflict || row.IfIndex == sibling.IfIndex {
		t.Fatalf("occupied index not treated as conflict: %+v row=%d", ch, row.IfIndex)
	}
}

func intp(n int) *int { return &n }

// TestInterfaceStatusAt pins the M10-S2 rollup: fresh + oper up = up; fresh +
// any other known state = down; no observation or stale = unknown.
func TestInterfaceStatusAt(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-time.Minute)
	stale := now.Add(-(InterfaceFreshnessSeconds + 1) * time.Second)

	cases := []struct {
		name string
		row  Interface
		want string
	}{
		{"fresh_up", Interface{OperStatus: strp("up"), LastSeenAt: &fresh}, StatusUp},
		{"fresh_down", Interface{OperStatus: strp("down"), LastSeenAt: &fresh}, StatusDown},
		{"fresh_testing", Interface{OperStatus: strp("testing"), LastSeenAt: &fresh}, StatusDown},
		{"fresh_not_present", Interface{OperStatus: strp("not_present"), LastSeenAt: &fresh}, StatusDown},
		{"stale_up", Interface{OperStatus: strp("up"), LastSeenAt: &stale}, StatusUnknown},
		{"never_observed", Interface{OperStatus: strp("up")}, StatusUnknown},
		{"no_oper", Interface{LastSeenAt: &fresh}, StatusUnknown},
	}
	for _, tc := range cases {
		if got := InterfaceStatusAt(tc.row, now); got != tc.want {
			t.Errorf("%s: status = %q, want %q", tc.name, got, tc.want)
		}
	}
}
