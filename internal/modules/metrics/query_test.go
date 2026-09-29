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
		{"", Step10s, false}, // contract default
		{"raw", StepRaw, false},
		{"10s", Step10s, false},
		{"1m", Step1m, false},
		{"5m", Step5m, false},
		{"1h", "", true},
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
	if StepRaw.Interval() != 0 || Step10s.Interval() != 10*time.Second ||
		Step1m.Interval() != time.Minute || Step5m.Interval() != 5*time.Minute {
		t.Fatal("interval mapping mismatch")
	}
	if Step10s.sqlInterval() != "10 seconds" || Step1m.sqlInterval() != "1 minute" || Step5m.sqlInterval() != "5 minutes" {
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

func TestPointCapRejection(t *testing.T) {
	// 24h at 10s exceeds the 2000-point cap by design (422 upstream).
	base := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	if points := expectedBuckets(base, base.Add(24*time.Hour), Step10s.Interval()); points <= MaxPoints {
		t.Fatalf("expected >%d points for 24h@10s, got %d", MaxPoints, points)
	}
	// 24h at 1m fits (permitted).
	if points := expectedBuckets(base, base.Add(24*time.Hour), Step1m.Interval()); points > MaxPoints {
		t.Fatalf("24h@1m must fit the cap, got %d", points)
	}
}
