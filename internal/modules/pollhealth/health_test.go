package pollhealth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCursorRoundTrip(t *testing.T) {
	ts := time.Date(2026, 10, 1, 12, 0, 0, 123456789, time.UTC)
	id := uuid.MustParse("0198d5a3-0000-7000-8000-000000000001")
	cur := encodeCursor(ts, id)
	gotTs, gotID, err := decodeCursor(cur)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !gotTs.Equal(ts) || gotID != id {
		t.Fatalf("round trip = %s/%s, want %s/%s", gotTs, gotID, ts, id)
	}
}

func TestCursorRejectsMalformed(t *testing.T) {
	for _, cur := range []string{"not-base64!!", "MTIzfG5vdC1hLXV1aWQ"} {
		if _, _, err := decodeCursor(cur); err == nil {
			t.Fatalf("cursor %q accepted", cur)
		}
	}
}
