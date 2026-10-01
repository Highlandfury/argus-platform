package pollhealth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func statusRow(outcome, class string, ts time.Time, failures int) scheduledRow {
	return scheduledRow{
		DeviceID:            uuid.Nil,
		Ts:                  ts,
		Outcome:             outcome,
		ErrorClass:          class,
		LatencyMS:           10,
		ConsecutiveFailures: failures,
	}
}

func TestClassifyDeviceStatusNoRows(t *testing.T) {
	now := time.Now().UTC()
	st := classifyDeviceStatus(uuid.Nil, nil, now)
	if st.Status != StatusUnknown || st.Since != nil || st.LastCheckedAt != nil || st.LastOutcome != nil {
		t.Fatalf("empty classification = %+v, want unknown with nulls", st)
	}
	if st.DownThreshold != DownThreshold || st.FreshnessSeconds != int(StatusFreshness.Seconds()) {
		t.Fatalf("policy fields = %d/%d", st.DownThreshold, st.FreshnessSeconds)
	}
}

func TestClassifyDeviceStatusTransitions(t *testing.T) {
	now := time.Now().UTC()

	// Fresh success -> up.
	up := classifyDeviceStatus(uuid.Nil, []scheduledRow{statusRow("success", "", now.Add(-30*time.Second), 0)}, now)
	if up.Status != StatusUp || up.Since == nil || !up.Since.Equal(now.Add(-30*time.Second)) {
		t.Fatalf("success -> %+v, want up since the row", up)
	}

	// One and two failures are below the threshold: still up.
	for _, failures := range []int{1, 2} {
		st := classifyDeviceStatus(uuid.Nil, []scheduledRow{statusRow("failure", "timeout", now.Add(-time.Minute), failures)}, now)
		if st.Status != StatusUp {
			t.Fatalf("%d failures -> %q, want up (below threshold)", failures, st.Status)
		}
	}

	// Three consecutive failures -> down; since walks to the first failure.
	rows := []scheduledRow{
		statusRow("failure", "timeout", now.Add(-30*time.Second), 3),
		statusRow("failure", "timeout", now.Add(-90*time.Second), 2),
		statusRow("failure", "timeout", now.Add(-150*time.Second), 1),
		statusRow("success", "", now.Add(-210*time.Second), 0),
	}
	down := classifyDeviceStatus(uuid.Nil, rows, now)
	if down.Status != StatusDown {
		t.Fatalf("3 failures -> %q, want down", down.Status)
	}
	if down.Since == nil || !down.Since.Equal(now.Add(-150*time.Second)) {
		t.Fatalf("down since = %v, want the first failure of the streak", down.Since)
	}
	if down.LastErrorClass == nil || *down.LastErrorClass != "timeout" || down.ConsecutiveFailures == nil || *down.ConsecutiveFailures != 3 {
		t.Fatalf("down last fields = %+v", down)
	}

	// Recovery: newest success -> up since the recovery row (the run restarts).
	recovered := classifyDeviceStatus(uuid.Nil, append([]scheduledRow{
		statusRow("success", "", now.Add(-10*time.Second), 0),
	}, rows...), now)
	if recovered.Status != StatusUp || recovered.Since == nil || !recovered.Since.Equal(now.Add(-10*time.Second)) {
		t.Fatalf("recovery -> %+v, want up since the recovery row", recovered)
	}

	// A long up run longer than the fetched window reports the oldest row.
	long := make([]scheduledRow, 0, 5)
	for i := 0; i < 5; i++ {
		long = append(long, statusRow("success", "", now.Add(-time.Duration(i+1)*time.Minute), 0))
	}
	run := classifyDeviceStatus(uuid.Nil, long, now)
	if run.Since == nil || !run.Since.Equal(now.Add(-5*time.Minute)) {
		t.Fatalf("long run since = %v, want the oldest fetched row", run.Since)
	}
}

func TestClassifyDeviceStatusFreshness(t *testing.T) {
	now := time.Now().UTC()
	stale := now.Add(-StatusFreshness - time.Minute)
	st := classifyDeviceStatus(uuid.Nil, []scheduledRow{statusRow("success", "", stale, 0)}, now)
	if st.Status != StatusUnknown {
		t.Fatalf("stale row -> %q, want unknown", st.Status)
	}
	// Unknown starts when the newest row became stale.
	wantSince := stale.Add(StatusFreshness)
	if st.Since == nil || !st.Since.Equal(wantSince) {
		t.Fatalf("unknown since = %v, want %v", st.Since, wantSince)
	}
	// A stale failure streak is also unknown: the schedule is not reporting.
	st = classifyDeviceStatus(uuid.Nil, []scheduledRow{statusRow("failure", "timeout", stale, 9)}, now)
	if st.Status != StatusUnknown {
		t.Fatalf("stale failures -> %q, want unknown (freshness wins)", st.Status)
	}
	// Exactly at the window boundary the row is still fresh.
	edge := now.Add(-StatusFreshness)
	st = classifyDeviceStatus(uuid.Nil, []scheduledRow{statusRow("success", "", edge, 0)}, now)
	if st.Status != StatusUp {
		t.Fatalf("boundary row -> %q, want up", st.Status)
	}
}
