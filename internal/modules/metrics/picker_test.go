package metrics

import (
	"testing"
	"time"
)

// TestPickStep pins the canonical resolution picker (docs/08 §13.5):
// ≤ 6 h → 1m; ≤ 7 d → 5m; ≤ 90 d → 1h; beyond → 1d. Boundary values belong
// to the finer tier (inclusive), matching the canonical "≤" wording.
func TestPickStep(t *testing.T) {
	base := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		span time.Duration
		want Step
	}{
		{time.Minute, Step1m},
		{6 * time.Hour, Step1m},
		{6*time.Hour + time.Second, Step5m},
		{7 * 24 * time.Hour, Step5m},
		{7*24*time.Hour + time.Second, Step1h},
		{90 * 24 * time.Hour, Step1h},
		{90*24*time.Hour + time.Second, Step1d},
		{3 * 365 * 24 * time.Hour, Step1d},
	}
	for _, tc := range cases {
		got := PickStep(base, base.Add(tc.span))
		if got != tc.want {
			t.Fatalf("PickStep(span %s) = %s, want %s", tc.span, got, tc.want)
		}
	}
}

func TestResolutionNames(t *testing.T) {
	cases := map[Step]string{
		StepAuto: "raw",
		StepRaw:  "raw",
		Step10s:  "raw",
		Step1m:   "rollup_1m",
		Step5m:   "rollup_5m",
		Step1h:   "rollup_1h",
		Step1d:   "rollup_1d",
	}
	for step, want := range cases {
		if got := ResolutionName(step); got != want {
			t.Fatalf("ResolutionName(%s) = %q, want %q", step, got, want)
		}
	}
}

func TestResolutionWarning(t *testing.T) {
	// Finer-than-recommended explicit steps warn; auto and coarser do not.
	if w := resolutionWarning(Step1m, Step5m); w == "" {
		t.Fatal("1m on a 3-day range must warn")
	}
	if w := resolutionWarning(Step5m, Step1m); w != "" {
		t.Fatalf("coarser explicit step must not warn, got %q", w)
	}
	if w := resolutionWarning(StepAuto, Step1m); w != "" {
		t.Fatalf("auto must not warn, got %q", w)
	}
	if w := resolutionWarning(StepRaw, Step1d); w != "" {
		t.Fatalf("raw must not warn, got %q", w)
	}
}

// TestRollupPolicyTable pins the exact refresh offsets created by migration
// 000012 and consumed by the query fallback boundary.
func TestRollupPolicyTable(t *testing.T) {
	policies := RollupPolicies()
	if len(policies) != 4 {
		t.Fatalf("rollup policies = %d, want 4", len(policies))
	}
	byStep := map[Step]RollupPolicy{}
	for _, p := range policies {
		byStep[p.Step] = p
	}
	one := byStep[Step1m]
	if one.CAGG != "metric_1m" || one.TenantView != "metric_1m_tenant" ||
		one.StartOffset != 7*24*time.Hour || one.EndOffset != 2*time.Minute || one.Schedule != time.Minute {
		t.Fatalf("1m policy diverged from canonical docs/11 §21.2: %+v", one)
	}
	// Coarser levels: documented choice, 2× bucket end offset, bucket schedule.
	if p := byStep[Step5m]; p.StartOffset != 30*24*time.Hour || p.EndOffset != 10*time.Minute || p.Schedule != 5*time.Minute {
		t.Fatalf("5m policy: %+v", p)
	}
	if p := byStep[Step1h]; p.StartOffset != 90*24*time.Hour || p.EndOffset != 2*time.Hour || p.Schedule != time.Hour {
		t.Fatalf("1h policy: %+v", p)
	}
	if p := byStep[Step1d]; p.StartOffset != pgYear+pgMonth || p.EndOffset != 48*time.Hour || p.Schedule != time.Hour {
		t.Fatalf("1d policy: %+v", p)
	}
}

func TestRetentionAndCompressionTables(t *testing.T) {
	ret := RetentionPolicies(30 * 24 * time.Hour)
	if len(ret) != 5 {
		t.Fatalf("retention policies = %d, want 5", len(ret))
	}
	want := map[string]time.Duration{
		"metric_samples": 30 * 24 * time.Hour,
		"metric_1m":      30 * 24 * time.Hour,
		"metric_5m":      90 * 24 * time.Hour,
		"metric_1h":      pgYear + pgMonth,
		"metric_1d":      3 * pgYear,
	}
	for _, rp := range ret {
		if rp.After != want[rp.Relation] {
			t.Fatalf("retention %s = %s, want %s", rp.Relation, rp.After, want[rp.Relation])
		}
	}
	comp := CompressionPolicies()
	if len(comp) != 4 {
		t.Fatalf("compression policies = %d, want 4 (CAGG materializations)", len(comp))
	}
	for _, cp := range comp {
		if cp.After != 7*24*time.Hour || cp.SegmentBy != "series_id" || cp.OrderBy != "bucket DESC" {
			t.Fatalf("compression policy %s: %+v", cp.Relation, cp)
		}
	}
}
