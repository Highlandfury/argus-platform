package ingest

import (
	"math"
	"testing"
	"time"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func unitAllowlist() map[string]MetricDef {
	return map[string]MetricDef{"collector_cpu_percent": {Key: "collector_cpu_percent", Unit: "percent"}}
}

func unitSample(value float64, ts time.Time) *collectorv1.MetricSample {
	return &collectorv1.MetricSample{
		MetricKey:  "collector_cpu_percent",
		Value:      value,
		Unit:       "percent",
		Dimensions: map[string]string{"cpu": "total"},
		Ts:         timestamppb.New(ts),
	}
}

func TestValidateBatchHappyPath(t *testing.T) {
	now := time.Now().UTC()
	batch := &collectorv1.MetricBatch{
		BatchSeq: 7,
		Samples:  []*collectorv1.MetricSample{unitSample(12.5, now), unitSample(50, now.Add(-time.Minute))},
	}
	validated, rej := ValidateBatch(batch, unitAllowlist(), now)
	if rej != nil {
		t.Fatalf("rejected: %v", rej)
	}
	if len(validated) != 2 {
		t.Fatalf("validated %d samples", len(validated))
	}
	if string(validated[0].Canonical) != `{"cpu":"total"}` || validated[0].DimHash == 0 {
		t.Fatalf("canonical dims wrong: %s %x", validated[0].Canonical, validated[0].DimHash)
	}
	if validated[0].Unit != "percent" {
		t.Fatalf("unit = %q", validated[0].Unit)
	}
}

func TestValidateBatchRejections(t *testing.T) {
	now := time.Now().UTC()
	bigBatch := make([]*collectorv1.MetricSample, 0, MaxBatchSamples+1)
	for i := 0; i <= MaxBatchSamples; i++ {
		bigBatch = append(bigBatch, unitSample(1, now))
	}
	dims20 := map[string]string{}
	for i := 0; i < 20; i++ {
		dims20[string(rune('a'+i))] = "v"
	}
	tooManyDims := unitSample(1, now)
	tooManyDims.Dimensions = dims20
	unknownKey := unitSample(1, now)
	unknownKey.MetricKey = "not_allowed"
	wrongUnit := unitSample(1, now)
	wrongUnit.Unit = "bytes"

	cases := []struct {
		name   string
		batch  *collectorv1.MetricBatch
		reason string
	}{
		{"nil_batch", nil, "validation.batch_missing"},
		{"bad_seq", &collectorv1.MetricBatch{Samples: []*collectorv1.MetricSample{unitSample(1, now)}}, "validation.batch_seq_invalid"},
		{"empty", &collectorv1.MetricBatch{BatchSeq: 1}, "validation.batch_empty"},
		{"too_large", &collectorv1.MetricBatch{BatchSeq: 1, Samples: bigBatch}, "validation.batch_too_large"},
		{"not_allowed", &collectorv1.MetricBatch{BatchSeq: 1, Samples: []*collectorv1.MetricSample{unknownKey}}, "validation.metric_not_allowed"},
		{"nan", &collectorv1.MetricBatch{BatchSeq: 1, Samples: []*collectorv1.MetricSample{unitSample(math.NaN(), now)}}, "validation.value_not_finite"},
		{"inf", &collectorv1.MetricBatch{BatchSeq: 1, Samples: []*collectorv1.MetricSample{unitSample(math.Inf(1), now)}}, "validation.value_not_finite"},
		{"percent_high", &collectorv1.MetricBatch{BatchSeq: 1, Samples: []*collectorv1.MetricSample{unitSample(101, now)}}, "validation.value_out_of_range"},
		{"percent_low", &collectorv1.MetricBatch{BatchSeq: 1, Samples: []*collectorv1.MetricSample{unitSample(-0.5, now)}}, "validation.value_out_of_range"},
		{"ts_missing", &collectorv1.MetricBatch{BatchSeq: 1, Samples: []*collectorv1.MetricSample{{MetricKey: "collector_cpu_percent", Value: 1}}}, "validation.sample_ts_missing"},
		{"ts_future", &collectorv1.MetricBatch{BatchSeq: 1, Samples: []*collectorv1.MetricSample{unitSample(1, now.Add(30*24*time.Hour))}}, "validation.sample_ts_out_of_range"},
		{"ts_ancient", &collectorv1.MetricBatch{BatchSeq: 1, Samples: []*collectorv1.MetricSample{unitSample(1, now.Add(-30*24*time.Hour))}}, "validation.sample_ts_out_of_range"},
		{"dims_too_many", &collectorv1.MetricBatch{BatchSeq: 1, Samples: []*collectorv1.MetricSample{tooManyDims}}, "validation.dimensions_too_many"},
		{"unit_mismatch", &collectorv1.MetricBatch{BatchSeq: 1, Samples: []*collectorv1.MetricSample{wrongUnit}}, "validation.unit_mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, rej := ValidateBatch(tc.batch, unitAllowlist(), now)
			if rej == nil {
				t.Fatalf("expected rejection %s", tc.reason)
			}
			if rej.Reason != tc.reason {
				t.Fatalf("reason = %q, want %q (%s)", rej.Reason, tc.reason, rej.Detail)
			}
		})
	}
}

func TestAllowlistFromPolicy(t *testing.T) {
	doc := []byte(`{"heartbeat_interval_seconds":30,"report_interval_seconds":5,"batch_max_samples":5000,"spool_max_bytes":67108864,"metrics":[{"key":"collector_cpu_percent","unit":"percent"}]}`)
	allow, err := AllowlistFromPolicy(doc)
	if err != nil {
		t.Fatalf("allowlist: %v", err)
	}
	if _, ok := allow["collector_cpu_percent"]; !ok {
		t.Fatal("allowlist missing collector_cpu_percent")
	}
	if _, err := AllowlistFromPolicy([]byte(`{"metrics":[]}`)); err == nil {
		t.Fatal("empty metrics must be an error")
	}
	if _, err := AllowlistFromPolicy([]byte("not json")); err == nil {
		t.Fatal("invalid JSON must be an error")
	}
}
