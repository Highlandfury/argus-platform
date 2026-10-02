package alerts

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

// streamTestTransition builds a committed transition with a fresh UUIDv7
// event id (time-ordered, as the real stream requires).
func streamTestTransition(t *testing.T, orgID uuid.UUID, kind string, ts time.Time) Transition {
	t.Helper()
	eventID, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("new v7: %v", err)
	}
	alertID, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("new v7: %v", err)
	}
	return Transition{
		Alert: Alert{
			ID: alertID, OrgID: orgID, RuleID: uuid.New(), Fingerprint: "ffff",
			ResourceType: "device", ResourceID: uuid.New(), State: StateActive,
			Severity: SeverityCritical, SiteID: uuid.New(), SuppressionReason: "",
		},
		Event: AlertEvent{ID: eventID, AlertID: alertID, Kind: kind, Ts: ts},
	}
}

func TestStreamHubReplayFromBuffer(t *testing.T) {
	orgID := uuid.New()
	now := time.Now().UTC()
	clock := now
	hub := NewStreamHub(StreamOptions{Now: func() time.Time { return clock }})
	sub := hub.Subscribe(orgID)
	defer hub.Unsubscribe(sub)

	var published []Transition
	for i := 0; i < 5; i++ {
		tr := streamTestTransition(t, orgID, EventUpdated, now.Add(time.Duration(i)*time.Second))
		published = append(published, tr)
		hub.Transitioned(context.Background(), tr)
	}
	if hub.Clients() != 1 {
		t.Fatalf("clients = %d, want 1", hub.Clients())
	}
	// Live delivery: all five are buffered for the connection.
	if got := len(sub.ch); got != 5 {
		t.Fatalf("queued live events = %d, want 5", got)
	}

	// Replay after the second event yields the remaining three.
	after := published[1].Event.ID
	replay, found := hub.Replay(orgID, after)
	if !found {
		t.Fatal("Replay: id not found in retained buffer")
	}
	if len(replay) != 3 {
		t.Fatalf("replay = %d events, want 3", len(replay))
	}
	for i, ev := range replay {
		if ev.ID != published[2+i].Event.ID {
			t.Fatalf("replay[%d] = %s, want %s", i, ev.ID, published[2+i].Event.ID)
		}
		if ev.Name != StreamEventUpdated {
			t.Fatalf("replay[%d] name = %q", i, ev.Name)
		}
	}

	// An id never seen in the buffer falls back to PostgreSQL.
	if _, found := hub.Replay(orgID, uuid.New()); found {
		t.Fatal("Replay of an unknown id must report found=false")
	}
}

func TestStreamHubBufferTTLAndBound(t *testing.T) {
	orgID := uuid.New()
	now := time.Now().UTC()
	clock := now
	hub := NewStreamHub(StreamOptions{
		Now:       func() time.Time { return clock },
		BufferTTL: time.Minute,
		BufferMax: 3,
	})
	sub := hub.Subscribe(orgID)
	defer hub.Unsubscribe(sub)

	first := streamTestTransition(t, orgID, EventUpdated, now)
	hub.Transitioned(context.Background(), first)
	// Advance beyond the TTL: the entry is pruned on the next publish.
	clock = now.Add(2 * time.Minute)
	second := streamTestTransition(t, orgID, EventUpdated, clock)
	hub.Transitioned(context.Background(), second)
	if _, found := hub.Replay(orgID, first.Event.ID); found {
		t.Fatal("expired event must not be replayable")
	}

	// Count bound: publish past BufferMax and assert only the newest survive.
	for i := 0; i < 5; i++ {
		hub.Transitioned(context.Background(), streamTestTransition(t, orgID, EventUpdated, clock.Add(time.Duration(i)*time.Second)))
	}
	if _, found := hub.Replay(orgID, second.Event.ID); found {
		t.Fatal("event beyond the count bound must not be replayable")
	}
}

func TestStreamHubSlowClientDropsWithoutBlocking(t *testing.T) {
	orgID := uuid.New()
	now := time.Now().UTC()
	hub := NewStreamHub(StreamOptions{
		Now:          func() time.Time { return now },
		ClientBuffer: 2,
	})
	sub := hub.Subscribe(orgID)
	defer hub.Unsubscribe(sub)

	done := make(chan struct{})
	published := make([]uuid.UUID, 0, 10)
	go func() {
		defer close(done)
		for i := 0; i < 10; i++ {
			tr := streamTestTransition(t, orgID, EventUpdated, now)
			published = append(published, tr.Event.ID)
			hub.Transitioned(context.Background(), tr)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("publish blocked on a slow client")
	}
	if got := len(sub.ch); got != 2 {
		t.Fatalf("queued live events = %d, want the 2-entry bound", got)
	}
	// Dropped events remain replayable from the retained buffer.
	if _, found := hub.Replay(orgID, published[0]); !found {
		t.Fatal("the retained buffer must still hold the events dropped for the slow client")
	}
}

func TestStreamHubUnsubscribeIsIdempotent(t *testing.T) {
	orgID := uuid.New()
	hub := NewStreamHub(StreamOptions{Now: time.Now})
	sub := hub.Subscribe(orgID)
	hub.Unsubscribe(sub)
	hub.Unsubscribe(sub)
	if hub.Clients() != 0 {
		t.Fatalf("clients = %d, want 0", hub.Clients())
	}
}

func TestBuildStreamEventEnvelope(t *testing.T) {
	orgID := uuid.New()
	siteID := uuid.New()
	devID := uuid.New()
	alertID := uuid.New()
	eventID := uuid.New()
	ref := uuid.New()
	tr := Transition{
		Alert: Alert{
			ID: alertID, OrgID: orgID, RuleID: uuid.New(), Fingerprint: "abc",
			ResourceType: "device", ResourceID: devID, State: StateSuppressed,
			Severity: SeverityWarning, SiteID: siteID,
			SuppressionReason: SuppressionMaintenance, SuppressionRef: &ref,
		},
		Event:      AlertEvent{ID: eventID, AlertID: alertID, Kind: EventSuppressed, Ts: time.Now().UTC()},
		Suppressed: true,
	}
	ev := buildStreamEvent(tr)
	if ev == nil {
		t.Fatal("buildStreamEvent returned nil")
	}
	if ev.Name != StreamEventUpdated || ev.ID != eventID || ev.AlertID != alertID {
		t.Fatalf("event identity wrong: %+v", ev)
	}
	var payload map[string]any
	if err := json.Unmarshal(ev.Data, &payload); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if payload["alert_id"] != alertID.String() || payload["device_id"] != devID.String() || payload["site_id"] != siteID.String() {
		t.Fatalf("payload ids = %v", payload)
	}
	if payload["suppressed"] != true || payload["suppression_reason"] != SuppressionMaintenance {
		t.Fatalf("payload suppression = %v", payload)
	}
	if payload["suppression_ref"] != ref.String() {
		t.Fatalf("payload suppression_ref = %v", payload["suppression_ref"])
	}
	if _, ok := payload["incident_id"]; !ok {
		t.Fatal("payload must carry incident_id:null for forward compatibility")
	}
}
