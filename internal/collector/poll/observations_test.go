package poll

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestSNMPProberRendersInterfaceObservations proves one IF-MIB poll produces
// one observation per identity-resolved row with the M10-S2 attributes, and
// that ifIndex is carried in the observation but never in series dimensions.
func TestSNMPProberRendersInterfaceObservations(t *testing.T) {
	clock := newTestClock(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	factory := &fakeFactory{clients: []*fakeSNMPClient{
		newSwitchClient(switchFixture{uptime: 123456789}),
	}}
	p := newSNMPTestProber(t, factory.make, v2cSource(), clock)
	res := p.Probe(context.Background(), snmpTarget("dev-obs", "switch"))
	if !res.SnmpDone {
		t.Fatalf("probe not done: %+v", res)
	}
	if len(res.InterfaceObservations) != 3 {
		t.Fatalf("observations = %d, want 3", len(res.InterfaceObservations))
	}
	byName := map[string]InterfaceObservation{}
	for _, o := range res.InterfaceObservations {
		byName[o.IfName] = o
	}
	o, ok := byName["Gi1/0/1"]
	if !ok {
		t.Fatalf("Gi1/0/1 missing from observations: %+v", res.InterfaceObservations)
	}
	if o.IfIndex != 1 {
		t.Fatalf("if_index = %d, want 1", o.IfIndex)
	}
	if o.IfAlias == nil || *o.IfAlias != "uplink" {
		t.Fatalf("if_alias = %v, want uplink", o.IfAlias)
	}
	if o.AdminStatus == nil || *o.AdminStatus != "up" {
		t.Fatalf("admin_status = %v, want up", o.AdminStatus)
	}
	if o.OperStatus == nil || *o.OperStatus != "up" {
		t.Fatalf("oper_status = %v, want up", o.OperStatus)
	}
	if o.SpeedBPS == nil || *o.SpeedBPS != 1000000000 {
		t.Fatalf("speed_bps = %v, want 1000000000 (ifHighSpeed 1000 Mbit/s)", o.SpeedBPS)
	}
	if o.MTU == nil || *o.MTU != 1500 {
		t.Fatalf("mtu = %v, want 1500", o.MTU)
	}
	if o.MAC == nil || *o.MAC != "02:00:00:00:00:01" {
		t.Fatalf("mac = %v, want 02:00:00:00:00:01", o.MAC)
	}
	if o.IfType == nil || *o.IfType != 6 {
		t.Fatalf("if_type = %v, want 6", o.IfType)
	}
	if o.DeviceID != "dev-obs" || o.ObservedAt.IsZero() {
		t.Fatalf("observation identity/time = %+v", o)
	}
	down := byName["Gi1/0/3"]
	if down.OperStatus == nil || *down.OperStatus != "down" {
		t.Fatalf("Gi1/0/3 oper_status = %v, want down", down.OperStatus)
	}

	// The observation channel never puts ifIndex into a series dimension.
	for _, s := range res.SnmpSamples {
		if _, hasIndex := s.Dimensions["if_index"]; hasIndex {
			t.Fatalf("ifIndex must never be a series dimension: %+v", s)
		}
	}
}

// TestSNMPProberObservationFallbackAndMACFormatting pins the ifSpeed fallback
// (32-bit ifSpeed when ifHighSpeed is absent) and raw-octet MAC rendering.
func TestSNMPProberObservationFallbackAndMACFormatting(t *testing.T) {
	client := newSwitchClient(switchFixture{uptime: 1})
	// Drop ifHighSpeed so the ifSpeed (bit/s) fallback is used.
	ifx := client.walks["1.3.6.1.2.1.31.1.1.1"][:0]
	for _, b := range client.walks["1.3.6.1.2.1.31.1.1.1"] {
		if b.OID != "1.3.6.1.2.1.31.1.1.1.15.1" && b.OID != "1.3.6.1.2.1.31.1.1.1.15.2" && b.OID != "1.3.6.1.2.1.31.1.1.1.15.3" {
			ifx = append(ifx, b)
		}
	}
	client.walks["1.3.6.1.2.1.31.1.1.1"] = ifx

	clock := newTestClock(time.Unix(1000, 0))
	factory := &fakeFactory{clients: []*fakeSNMPClient{client}}
	p := newSNMPTestProber(t, factory.make, v2cSource(), clock)
	res := p.Probe(context.Background(), snmpTarget("dev-fallback", "switch"))
	for _, o := range res.InterfaceObservations {
		if o.SpeedBPS == nil || *o.SpeedBPS != 1000000000 {
			t.Fatalf("%s speed_bps = %v, want the ifSpeed fallback 1000000000", o.IfName, o.SpeedBPS)
		}
	}

	cases := map[string]string{
		"\x02\x00\x00\x00\x00\x01":         "02:00:00:00:00:01",
		"aa:bb:cc:dd:ee:ff":                "aa:bb:cc:dd:ee:ff",
		"AA-BB-CC-DD-EE-FF":                "aa:bb:cc:dd:ee:ff",
		"\x02\x00\x00\x00\x00\x00\x00\x01": "02:00:00:00:00:00:00:01",
		"":                                 "",
		"not-a-mac":                        "",
		"\x01\x02\x03":                     "",
	}
	for raw, want := range cases {
		if got := canonicalMAC(raw); got != want {
			t.Errorf("canonicalMAC(%q) = %q, want %q", raw, got, want)
		}
	}
}

// TestInterfaceBatcherFlushAndRequeue mirrors the health-batcher contract: a
// failed flush requeues at the head and never drops observations.
func TestInterfaceBatcherFlushAndRequeue(t *testing.T) {
	alias := "uplink"
	obs := InterfaceObservation{DeviceID: "d1", IfIndex: 1, IfName: "Gi1/0/1", IfAlias: &alias}
	var flushed [][]InterfaceObservation
	fail := true
	b := NewInterfaceBatcher(
		func() int { return 100 },
		func() time.Duration { return time.Minute },
		func(records []InterfaceObservation) error {
			if fail {
				return errors.New("spool full")
			}
			flushed = append(flushed, records)
			return nil
		}, nil)
	if err := b.Add([]InterfaceObservation{obs}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if b.Len() != 1 {
		t.Fatalf("buffered = %d, want 1", b.Len())
	}
	if err := b.Flush(); err == nil {
		t.Fatal("flush must surface the spool error")
	}
	if b.Len() != 1 {
		t.Fatalf("buffer after failed flush = %d, want the requeued observation", b.Len())
	}
	fail = false
	if err := b.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if len(flushed) != 1 || len(flushed[0]) != 1 || flushed[0][0].IfName != "Gi1/0/1" {
		t.Fatalf("flushed = %+v", flushed)
	}
	if b.Len() != 0 {
		t.Fatalf("buffer after flush = %d, want 0", b.Len())
	}
}

// TestOperStatusNameMapping pins the RFC 2863 enum rendering.
func TestOperStatusNameMapping(t *testing.T) {
	want := []string{"up", "down", "testing", "unknown", "dormant", "not_present", "lower_layer_down"}
	for i, w := range want {
		if got := operStatusName(i + 1); got != w {
			t.Errorf("operStatusName(%d) = %q, want %q", i+1, got, w)
		}
	}
	if got := operStatusName(99); got != "" {
		t.Errorf("operStatusName(99) = %q, want empty", got)
	}
	if got := adminStatusName(2); got != "down" {
		t.Errorf("adminStatusName(2) = %q, want down", got)
	}
}
