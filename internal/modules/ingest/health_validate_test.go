package ingest

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
)

func healthRecord(now time.Time) *collectorv1.PollHealth {
	return &collectorv1.PollHealth{
		DeviceId:            "0198d5a3-0000-7000-8000-000000000001",
		PollType:            "icmp",
		LatencyMs:           12,
		Outcome:             "success",
		ErrorClass:          "",
		ConsecutiveFailures: 0,
		CheckedAt:           timestamppb.New(now),
	}
}

// TestValidateBatchPayloadHealthOnly proves a health-only batch is accepted
// without a metric allowlist (M9-S1) and that the health bounds are enforced.
func TestValidateBatchPayloadHealthOnly(t *testing.T) {
	now := time.Now().UTC()
	batch := &collectorv1.MetricBatch{BatchSeq: 1, Health: []*collectorv1.PollHealth{healthRecord(now)}}
	samples, health, rej := ValidateBatchPayload(batch, nil, now)
	if rej != nil {
		t.Fatalf("health-only batch rejected: %v", rej)
	}
	if len(samples) != 0 || len(health) != 1 {
		t.Fatalf("samples=%d health=%d", len(samples), len(health))
	}
	if health[0].DeviceID.String() != "0198d5a3-0000-7000-8000-000000000001" || health[0].LatencyMS != 12 {
		t.Fatalf("health = %+v", health[0])
	}
}

func TestValidateBatchPayloadHealthRejections(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name   string
		mutate func(*collectorv1.PollHealth)
		reason string
	}{
		{"bad device", func(h *collectorv1.PollHealth) { h.DeviceId = "nope" }, "validation.health_device_invalid"},
		{"bad poll type", func(h *collectorv1.PollHealth) { h.PollType = "" }, "validation.health_poll_type_invalid"},
		{"bad outcome", func(h *collectorv1.PollHealth) { h.Outcome = "maybe" }, "validation.health_outcome_invalid"},
		{"negative latency", func(h *collectorv1.PollHealth) { h.LatencyMs = -1 }, "validation.health_latency_invalid"},
		{"negative failures", func(h *collectorv1.PollHealth) { h.ConsecutiveFailures = -3 }, "validation.health_failures_invalid"},
		{"missing ts", func(h *collectorv1.PollHealth) { h.CheckedAt = nil }, "validation.health_ts_missing"},
		{"stale ts", func(h *collectorv1.PollHealth) {
			h.CheckedAt = timestamppb.New(now.Add(-8 * 24 * time.Hour))
		}, "validation.health_ts_out_of_range"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := healthRecord(now)
			tc.mutate(h)
			_, _, rej := ValidateBatchPayload(&collectorv1.MetricBatch{BatchSeq: 1, Health: []*collectorv1.PollHealth{h}}, nil, now)
			if rej == nil {
				t.Fatalf("expected rejection %s", tc.reason)
			}
			if rej.Reason != tc.reason {
				t.Fatalf("reason = %q, want %q (%s)", rej.Reason, tc.reason, rej.Detail)
			}
		})
	}
}

func TestValidateBatchPayloadRequiresSomePayload(t *testing.T) {
	_, _, rej := ValidateBatchPayload(&collectorv1.MetricBatch{BatchSeq: 1}, nil, time.Now())
	if rej == nil || rej.Reason != "validation.batch_empty" {
		t.Fatalf("empty batch rej = %+v", rej)
	}
	if _, _, rej := ValidateBatchPayload(nil, nil, time.Now()); rej == nil || rej.Reason != "validation.batch_missing" {
		t.Fatalf("nil batch rej = %+v", rej)
	}
	if _, _, rej := ValidateBatchPayload(&collectorv1.MetricBatch{BatchSeq: 0}, nil, time.Now()); rej == nil || rej.Reason != "validation.batch_seq_invalid" {
		t.Fatalf("seq rej = %+v", rej)
	}
}

// TestValidateSamplesDeviceScope: an additive device_id is parsed; a malformed
// one is a permanent rejection.
func TestValidateSamplesDeviceScope(t *testing.T) {
	now := time.Now().UTC()
	device := "0198d5a3-0000-7000-8000-000000000002"
	batch := &collectorv1.MetricBatch{
		BatchSeq: 1,
		Samples: []*collectorv1.MetricSample{{
			MetricKey: "net.icmp.reachable", Unit: "state", Value: 1,
			DeviceId: device, Ts: timestamppb.New(now),
		}},
	}
	allow := map[string]MetricDef{"net.icmp.reachable": {Key: "net.icmp.reachable", Unit: "state"}}
	samples, _, rej := ValidateBatchPayload(batch, allow, now)
	if rej != nil {
		t.Fatalf("rejected: %v", rej)
	}
	if samples[0].DeviceID.String() != device {
		t.Fatalf("device = %s, want %s", samples[0].DeviceID, device)
	}

	batch.Samples[0].DeviceId = "not-a-uuid"
	if _, _, rej := ValidateBatchPayload(batch, allow, now); rej == nil || rej.Reason != "validation.device_id_invalid" {
		t.Fatalf("bad device id rej = %+v", rej)
	}
}
