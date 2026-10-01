package ingest

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
)

func validObservation(now time.Time) *collectorv1.InterfaceObservation {
	return &collectorv1.InterfaceObservation{
		DeviceId:    "0198d5a3-0000-7000-8000-000000000001",
		IfIndex:     7,
		IfName:      "Gi1/0/7",
		IfAlias:     "uplink",
		IfType:      6,
		AdminStatus: "up",
		OperStatus:  "down",
		SpeedBps:    10000000000,
		Mtu:         9000,
		Mac:         "AA-BB-CC-DD-EE-FF",
		ObservedAt:  timestamppb.New(now),
	}
}

func TestValidateInterfaceObservationsAcceptsAndCanonicalizes(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	out, rej := ValidateInterfaceObservations([]*collectorv1.InterfaceObservation{validObservation(now)}, now)
	if rej != nil {
		t.Fatalf("rejected: %v", rej)
	}
	if len(out) != 1 {
		t.Fatalf("observations = %d, want 1", len(out))
	}
	o := out[0]
	if o.DeviceID.String() != "0198d5a3-0000-7000-8000-000000000001" {
		t.Fatalf("device id = %s", o.DeviceID)
	}
	if o.IfIndex != 7 || o.IfName != "Gi1/0/7" || o.IfAlias == nil || *o.IfAlias != "uplink" {
		t.Fatalf("identity fields = %+v", o)
	}
	if o.AdminStatus == nil || *o.AdminStatus != "up" || o.OperStatus == nil || *o.OperStatus != "down" {
		t.Fatalf("status fields = %+v", o)
	}
	if o.SpeedBPS == nil || *o.SpeedBPS != 10000000000 {
		t.Fatalf("speed = %+v", o.SpeedBPS)
	}
	if o.MTU == nil || *o.MTU != 9000 {
		t.Fatalf("mtu = %+v", o.MTU)
	}
	if o.MAC == nil || *o.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("mac = %v, want canonical lowercase", o.MAC)
	}
	if !o.ObservedAt.Equal(now) {
		t.Fatalf("observed_at = %s, want %s", o.ObservedAt, now)
	}
}

func TestValidateInterfaceObservationsRejections(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		mutate func(*collectorv1.InterfaceObservation)
		want   string
	}{
		{"bad_device", func(o *collectorv1.InterfaceObservation) { o.DeviceId = "nope" }, "validation.interface_device_invalid"},
		{"empty_name", func(o *collectorv1.InterfaceObservation) { o.IfName = "" }, "validation.interface_name_invalid"},
		{"long_name", func(o *collectorv1.InterfaceObservation) { o.IfName = strings.Repeat("x", 201) }, "validation.interface_name_invalid"},
		{"long_alias", func(o *collectorv1.InterfaceObservation) { o.IfAlias = strings.Repeat("x", 201) }, "validation.interface_alias_invalid"},
		{"zero_index", func(o *collectorv1.InterfaceObservation) { o.IfIndex = 0 }, "validation.interface_index_invalid"},
		{"bad_admin", func(o *collectorv1.InterfaceObservation) { o.AdminStatus = "sideways" }, "validation.interface_admin_status_invalid"},
		{"bad_oper", func(o *collectorv1.InterfaceObservation) { o.OperStatus = "flapping" }, "validation.interface_oper_status_invalid"},
		{"negative_speed", func(o *collectorv1.InterfaceObservation) { o.SpeedBps = -1 }, "validation.interface_speed_invalid"},
		{"absurd_speed", func(o *collectorv1.InterfaceObservation) { o.SpeedBps = maxIfSpeedBPS + 1 }, "validation.interface_speed_invalid"},
		{"negative_mtu", func(o *collectorv1.InterfaceObservation) { o.Mtu = -1 }, "validation.interface_mtu_invalid"},
		{"absurd_mtu", func(o *collectorv1.InterfaceObservation) { o.Mtu = maxIfMTU + 1 }, "validation.interface_mtu_invalid"},
		{"missing_ts", func(o *collectorv1.InterfaceObservation) { o.ObservedAt = nil }, "validation.interface_ts_missing"},
		{"stale_ts", func(o *collectorv1.InterfaceObservation) {
			o.ObservedAt = timestamppb.New(now.Add(-30 * 24 * time.Hour))
		}, "validation.interface_ts_out_of_range"},
		{"bad_mac", func(o *collectorv1.InterfaceObservation) { o.Mac = "not-a-mac" }, "validation.interface_mac_invalid"},
	}
	for _, tc := range cases {
		o := validObservation(now)
		tc.mutate(o)
		if _, rej := ValidateInterfaceObservations([]*collectorv1.InterfaceObservation{o}, now); rej == nil || rej.Reason != tc.want {
			t.Errorf("%s: rejection = %v, want %s", tc.name, rej, tc.want)
		}
	}

	tooMany := make([]*collectorv1.InterfaceObservation, MaxBatchInterfaces+1)
	for i := range tooMany {
		tooMany[i] = validObservation(now)
	}
	if _, rej := ValidateInterfaceObservations(tooMany, now); rej == nil || rej.Reason != "validation.interfaces_too_many" {
		t.Fatalf("over-limit rejection = %v", rej)
	}
}

// TestValidateBatchPayloadObservationOnly proves an observations-only batch is
// a valid payload kind (it rides the same claim/ack path).
func TestValidateBatchPayloadObservationOnly(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	batch := &collectorv1.MetricBatch{BatchSeq: 1, Interfaces: []*collectorv1.InterfaceObservation{validObservation(now)}}
	samples, health, rej := ValidateBatchPayload(batch, nil, now)
	if rej != nil {
		t.Fatalf("observation-only batch rejected: %v", rej)
	}
	if len(samples) != 0 || len(health) != 0 {
		t.Fatalf("samples=%d health=%d, want 0/0", len(samples), len(health))
	}
}
