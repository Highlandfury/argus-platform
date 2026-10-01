package metrics

import (
	"testing"
	"time"
)

func TestParseStep(t *testing.T) {
	cases := []struct {
		in      string
		want    Step
		wantErr bool
	}{
		{"", StepAuto, false}, // canonical picker default (docs/12 §22.8)
		{"auto", StepAuto, false},
		{"raw", StepRaw, false},
		{"10s", Step10s, false},
		{"1m", Step1m, false},
		{"5m", Step5m, false},
		{"1h", Step1h, false},
		{"1d", Step1d, false},
		{"2h", "", true},
		{"'; DROP TABLE metric_samples; --", "", true},
		{"raw ", "", true},
	}
	for _, tc := range cases {
		got, err := ParseStep(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("ParseStep(%q): expected error", tc.in)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("ParseStep(%q) = %q, %v", tc.in, got, err)
		}
	}
}

func TestStepIntervals(t *testing.T) {
	if StepAuto.Interval() != 0 || StepRaw.Interval() != 0 || Step10s.Interval() != 10*time.Second ||
		Step1m.Interval() != time.Minute || Step5m.Interval() != 5*time.Minute ||
		Step1h.Interval() != time.Hour || Step1d.Interval() != 24*time.Hour {
		t.Fatal("interval mapping mismatch")
	}
	if Step10s.sqlInterval() != "10 seconds" || Step1m.sqlInterval() != "1 minute" ||
		Step5m.sqlInterval() != "5 minutes" || Step1h.sqlInterval() != "1 hour" || Step1d.sqlInterval() != "1 day" {
		t.Fatal("sql interval mapping mismatch")
	}
}

func TestExpectedBuckets(t *testing.T) {
	base := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		from, to time.Time
		interval time.Duration
		want     int
	}{
		{base, base.Add(2 * time.Minute), time.Minute, 3}, // 12:00, 12:01, 12:02
		{base.Add(10 * time.Second), base.Add(50 * time.Second), 10 * time.Second, 5},
		{base, base.Add(24 * time.Hour), 5 * time.Minute, 289}, // first + last partial bucket
		{base, base, time.Minute, 1},
	}
	for _, tc := range cases {
		if got := expectedBuckets(tc.from, tc.to, tc.interval); got != tc.want {
			t.Fatalf("expectedBuckets(%s..%s, %s) = %d, want %d", tc.from, tc.to, tc.interval, got, tc.want)
		}
	}
}

func TestKnownMetricCatalog(t *testing.T) {
	if !KnownMetricKeys["collector_cpu_percent"] {
		t.Fatal("collector_cpu_percent must be in the Phase-1 catalog")
	}
	if KnownMetricKeys["ifHCInOctets"] || KnownMetricKeys[""] {
		t.Fatal("no other metric keys may be queryable in Phase 1")
	}
}

// TestPointBudgetReconciliation pins the M8 canonical caps: 10k response
// points, a 1M-bucket hard rejection bound, and the 3-year max range.
func TestPointBudgetReconciliation(t *testing.T) {
	if MaxPoints != 10000 || MaxSeries != 100 {
		t.Fatalf("canonical caps changed: MaxPoints=%d MaxSeries=%d", MaxPoints, MaxSeries)
	}
	base := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)

	// 24h @ 10s and 24h @ 1m fit the 10k response cap.
	if points := expectedBuckets(base, base.Add(24*time.Hour), Step10s.Interval()); points > MaxPoints {
		t.Fatalf("24h@10s = %d points, want <= %d", points, MaxPoints)
	}
	if points := expectedBuckets(base, base.Add(24*time.Hour), Step1m.Interval()); points > MaxPoints {
		t.Fatalf("24h@1m = %d points, want <= %d", points, MaxPoints)
	}
	// The full 3-year range at the auto picker fits (1d buckets).
	if points := expectedBuckets(base.Add(-MaxRange), base, PickStep(base.Add(-MaxRange), base).Interval()); points > MaxPoints {
		t.Fatalf("3y@auto = %d points, want <= %d", points, MaxPoints)
	}
	// 3y @ 1m exceeds the hard bucket budget (loud 422, not a silent scan).
	if points := expectedBuckets(base.Add(-MaxRange), base, Step1m.Interval()); points <= maxHardBuckets {
		t.Fatalf("3y@1m = %d buckets, want > hard budget %d", points, maxHardBuckets)
	}
}
