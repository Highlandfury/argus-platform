package checks

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
)

func TestCheckPayloadShape(t *testing.T) {
	id := uuid.MustParse("0198d5a3-0000-7000-8000-000000000001")
	deviceID := uuid.MustParse("0198d5a3-0000-7000-8000-000000000002")
	collectorID := uuid.MustParse("0198d5a3-0000-7000-8000-000000000003")
	latency := 12
	completed := time.Date(2026, 10, 1, 12, 0, 5, 0, time.UTC)
	c := DeviceCheck{
		ID: id, DeviceID: deviceID, CollectorID: &collectorID, PollType: PollICMP,
		Status: StatusCompleted, Outcome: "success", ErrorClass: "",
		LatencyMS: &latency, CompletedAt: &completed,
		CreatedAt: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
	}
	p := checkPayload(c)
	if p["check_id"] != id.String() || p["device_id"] != deviceID.String() {
		t.Fatalf("payload ids = %+v", p)
	}
	if p["status"] != StatusCompleted || p["outcome"] != "success" || p["latency_ms"] != 12 {
		t.Fatalf("payload terminal fields = %+v", p)
	}
	if p["status_url"] != "/v1/checks/"+id.String() {
		t.Fatalf("status_url = %v", p["status_url"])
	}
	if _, ok := p["completed_at"].(string); !ok {
		t.Fatalf("completed_at = %v, want RFC3339 string", p["completed_at"])
	}

	p = checkPayload(DeviceCheck{ID: id, DeviceID: deviceID, PollType: PollSNMP, Status: StatusPending,
		CreatedAt: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)})
	if p["completed_at"] != nil || p["latency_ms"] != nil || p["collector_id"] != nil {
		t.Fatalf("pending payload must render terminal fields as null: %+v", p)
	}
}

// TestCreateCheckInputValidation pins the pre-database validation so an invalid
// poll type or idempotency key can never reach the store (nil pool is safe for
// these paths by construction).
func TestCreateCheckInputValidation(t *testing.T) {
	svc := New(nil, nil)
	orgID, deviceID := uuid.New(), uuid.New()
	ctx := context.Background()

	cases := []struct {
		name    string
		poll    string
		key     string
		wantErr error
	}{
		{"bad poll type", "tcp", "k1", ErrInvalidPollType},
		{"empty poll type", "", "k1", ErrInvalidPollType},
		{"empty key", PollICMP, "  ", ErrInvalidRequestKey},
		{"oversized key", PollICMP, string(make([]byte, RequestKeyMaxLen+1)), ErrInvalidRequestKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := svc.CreateCheck(ctx, orgID, deviceID, tc.poll, tc.key, Actor{})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestRecordCheckResultValidation pins the result-shape validation (a
// malformed replay is rejected before any state is touched).
func TestRecordCheckResultValidation(t *testing.T) {
	svc := New(nil, nil)
	orgID, collectorID := uuid.New(), uuid.New()
	ctx := context.Background()
	checkID := uuid.New().String()

	if _, err := svc.RecordCheckResult(ctx, orgID, collectorID, nil); err != nil {
		t.Fatalf("nil result must be a no-op, got %v", err)
	}
	if _, err := svc.RecordCheckResult(ctx, orgID, collectorID,
		&collectorv1.CheckResult{CheckId: "not-a-uuid", Outcome: "success"}); !errors.Is(err, ErrInvalidCheckID) {
		t.Fatalf("bad id err = %v, want ErrInvalidCheckID", err)
	}
	if _, err := svc.RecordCheckResult(ctx, orgID, collectorID,
		&collectorv1.CheckResult{CheckId: checkID, Outcome: "maybe"}); !errors.Is(err, ErrInvalidOutcome) {
		t.Fatalf("bad outcome err = %v, want ErrInvalidOutcome", err)
	}
	if _, err := svc.RecordCheckResult(ctx, orgID, collectorID,
		&collectorv1.CheckResult{CheckId: checkID, Outcome: "failure", LatencyMs: -1}); !errors.Is(err, ErrInvalidLatency) {
		t.Fatalf("bad latency err = %v, want ErrInvalidLatency", err)
	}
	if _, err := svc.RecordCheckResult(ctx, orgID, collectorID,
		&collectorv1.CheckResult{CheckId: checkID, Outcome: "failure", ErrorClass: string(make([]byte, 101))}); !errors.Is(err, ErrInvalidErrorClass) {
		t.Fatalf("bad class err = %v, want ErrInvalidErrorClass", err)
	}
}
