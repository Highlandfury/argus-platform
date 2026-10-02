package notify

// M11-S2 engine unit tests: the pure retry/backoff schedule, dedup identity,
// route matching, token buckets, and the per-channel circuit breaker with an
// injected clock (no sleeps, no database).

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/modules/alerts"
)

func TestRetryScheduleCanonical(t *testing.T) {
	want := []time.Duration{
		1 * time.Minute,
		5 * time.Minute,
		30 * time.Minute,
		2 * time.Hour,
		6 * time.Hour,
	}
	got := RetrySchedule()
	if len(got) != len(want) {
		t.Fatalf("schedule length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("schedule[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestNextRetryAtScheduleAndWindow(t *testing.T) {
	created := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		now      time.Time
		failures int
		want     time.Time
	}{
		{"first", created, 1, created.Add(1 * time.Minute)},
		{"second", created.Add(time.Minute), 2, created.Add(time.Minute + 5*time.Minute)},
		{"third", created.Add(6 * time.Minute), 3, created.Add(36 * time.Minute)},
		{"fourth", created.Add(36 * time.Minute), 4, created.Add(156 * time.Minute)},
		{"fifth", created.Add(156 * time.Minute), 5, created.Add(516 * time.Minute)},
		{"repeats-last", created.Add(516 * time.Minute), 6, created.Add(876 * time.Minute)},
		{"zero-failures-is-first", created, 0, created.Add(1 * time.Minute)},
		{"capped-at-24h", created.Add(23 * time.Hour), 5, created.Add(24 * time.Hour)},
		{"past-window-clamps-to-now", created.Add(25 * time.Hour), 5, created.Add(25 * time.Hour)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NextRetryAt(created, tc.now, tc.failures)
			if !got.Equal(tc.want) {
				t.Fatalf("NextRetryAt = %s, want %s", got, tc.want)
			}
			if got.Location() != time.UTC {
				t.Fatalf("NextRetryAt location = %s, want UTC", got.Location())
			}
			if !tc.now.After(created.Add(MaxRetryWindow)) {
				if limit := created.Add(MaxRetryWindow); got.After(limit) {
					t.Fatalf("NextRetryAt = %s is after the 24h window %s", got, limit)
				}
			}
		})
	}
}

func TestDedupKeyStableAndScoped(t *testing.T) {
	channelID, alertID := uuid.New(), uuid.New()
	base := DedupKey(channelID, alertID, alerts.EventActivated)
	if base != DedupKey(channelID, alertID, alerts.EventActivated) {
		t.Fatal("DedupKey is not stable")
	}
	if len(base) != 64 {
		t.Fatalf("DedupKey length = %d, want 64 hex chars", len(base))
	}
	for _, other := range []string{
		DedupKey(uuid.New(), alertID, alerts.EventActivated),
		DedupKey(channelID, uuid.New(), alerts.EventActivated),
		DedupKey(channelID, alertID, alerts.EventResolved),
	} {
		if other == base {
			t.Fatal("DedupKey collides across channel/alert/event-kind")
		}
	}
}

func TestRouteMatchesSeverityAndScope(t *testing.T) {
	siteA, siteB, deviceA, deviceB := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	alert := alerts.Alert{
		ID: uuid.New(), OrgID: uuid.New(), ResourceID: deviceA, SiteID: siteA,
		Severity: alerts.SeverityCritical,
	}
	cases := []struct {
		name       string
		match      RouteMatch
		deviceKind string
		want       bool
	}{
		{"empty matches all", RouteMatch{}, "switch", true},
		{"severity match", RouteMatch{Severities: []string{"critical"}}, "switch", true},
		{"severity list containing", RouteMatch{Severities: []string{"info", "critical"}}, "switch", true},
		{"severity mismatch", RouteMatch{Severities: []string{"info", "warning"}}, "switch", false},
		{"site match", RouteMatch{Scope: RouteScope{Sites: []uuid.UUID{siteA}}}, "switch", true},
		{"site mismatch", RouteMatch{Scope: RouteScope{Sites: []uuid.UUID{siteB}}}, "switch", false},
		{"device match", RouteMatch{Scope: RouteScope{DeviceIDs: []uuid.UUID{deviceA}}}, "switch", true},
		{"device mismatch", RouteMatch{Scope: RouteScope{DeviceIDs: []uuid.UUID{deviceB}}}, "switch", false},
		{"kind match", RouteMatch{Scope: RouteScope{DeviceKinds: []string{"switch"}}}, "switch", true},
		{"kind mismatch", RouteMatch{Scope: RouteScope{DeviceKinds: []string{"ap"}}}, "switch", false},
		{"site list misses but kind matches (OR)", RouteMatch{Scope: RouteScope{Sites: []uuid.UUID{siteB}, DeviceKinds: []string{"switch"}}}, "switch", true},
		{"severity and scope must both hold", RouteMatch{Severities: []string{"warning"}, Scope: RouteScope{Sites: []uuid.UUID{siteA}}}, "switch", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := routeMatches(tc.match, alert, tc.deviceKind); got != tc.want {
				t.Fatalf("routeMatches = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRouteScopeIsEmpty(t *testing.T) {
	if !(RouteScope{}).IsEmpty() {
		t.Fatal("zero scope must be empty")
	}
	if (RouteScope{DeviceKinds: []string{"switch"}}).IsEmpty() {
		t.Fatal("kind scope must not be empty")
	}
}

func TestSeverityBucketRate(t *testing.T) {
	cases := map[string]float64{
		SeverityCritical: BucketCritical,
		SeverityWarning:  BucketWarning,
		SeverityInfo:     BucketInfo,
		"bogus":          BucketInfo, // fail closed to the smallest budget
	}
	for severity, want := range cases {
		if got := SeverityBucketRate(severity); got != want {
			t.Fatalf("SeverityBucketRate(%q) = %v, want %v", severity, got, want)
		}
	}
}

func TestBucketSetAllowsRefillsAndCaps(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	b := newBucketSet()
	for i := 0; i < int(BucketInfo); i++ {
		if !b.allow("route-a:info", BucketInfo, now) {
			t.Fatalf("token %d denied inside the hourly budget", i)
		}
	}
	if b.allow("route-a:info", BucketInfo, now) {
		t.Fatal("token allowed past the hourly budget")
	}
	// 6 minutes at 5/h refills 0.5 tokens: still denied.
	if b.allow("route-a:info", BucketInfo, now.Add(6*time.Minute)) {
		t.Fatal("half a refilled token was allowed")
	}
	// At 12 minutes one full token is available again.
	if !b.allow("route-a:info", BucketInfo, now.Add(12*time.Minute)) {
		t.Fatal("refilled token denied")
	}
	// Independent keys do not share budgets.
	if !b.allow("route-b:info", BucketInfo, now) {
		t.Fatal("independent bucket denied")
	}
	// A long idle period never refills past the rate (burst): after 24 h at
	// 5/h the bucket holds 5 tokens, not 120.
	burst := now.Add(24 * time.Hour)
	for i := 0; i < int(BucketInfo); i++ {
		if !b.allow("route-c:info", BucketInfo, burst) {
			t.Fatalf("burst token %d denied after idle", i+1)
		}
	}
	if b.allow("route-c:info", BucketInfo, burst) {
		t.Fatal("bucket burst exceeded its hourly rate after idle")
	}
}

func TestBucketSetDisabledAndNil(t *testing.T) {
	now := time.Now()
	if newBucketSet().allow("k", 0, now) {
		t.Fatal("zero-rate bucket allowed a token")
	}
	var nilSet *bucketSet
	if nilSet.allow("k", 5, now) {
		t.Fatal("nil bucket set allowed a token")
	}
}

func TestBreakerOpenHalfOpenProbeAndReset(t *testing.T) {
	b := newBreakerSet()
	id := uuid.New()
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

	if allowed, _ := b.allow(id, now); !allowed {
		t.Fatal("fresh breaker denied an attempt")
	}
	for i := 1; i < BreakerThreshold; i++ {
		if opened := b.failure(id, now); opened {
			t.Fatalf("breaker opened after %d failures", i)
		}
	}
	// Exactly the threshold-th consecutive failure opens the breaker once.
	if opened := b.failure(id, now); !opened {
		t.Fatal("breaker did not open at the threshold")
	}
	if opened := b.failure(id, now); opened {
		t.Fatal("already-open breaker reported a second transition")
	}
	allowed, openUntil := b.allow(id, now)
	if allowed {
		t.Fatal("open breaker allowed an attempt")
	}
	if !openUntil.Equal(now.Add(BreakerHalfOpen)) {
		t.Fatalf("openUntil = %s, want %s", openUntil, now.Add(BreakerHalfOpen))
	}
	// Half-open: exactly one probe is admitted at a time.
	probeAt := now.Add(BreakerHalfOpen)
	if allowed, _ := b.allow(id, probeAt); !allowed {
		t.Fatal("half-open breaker denied the probe")
	}
	if allowed, _ := b.allow(id, probeAt); allowed {
		t.Fatal("half-open breaker admitted a second concurrent probe")
	}
	// A failed probe re-opens for another half-open interval.
	if opened := b.failure(id, probeAt); opened {
		t.Fatal("failed probe reported an open transition on an already-open breaker")
	}
	allowed, openUntil = b.allow(id, probeAt)
	if allowed || !openUntil.Equal(probeAt.Add(BreakerHalfOpen)) {
		t.Fatalf("probe failure did not re-open: allowed=%v until=%s", allowed, openUntil)
	}
	// A successful probe closes the breaker and clears the failure streak.
	secondProbe := probeAt.Add(BreakerHalfOpen)
	if allowed, _ := b.allow(id, secondProbe); !allowed {
		t.Fatal("second half-open probe denied")
	}
	b.success(id)
	if allowed, _ := b.allow(id, secondProbe); !allowed {
		t.Fatal("closed breaker denied an attempt")
	}
	// The streak is cleared: four more failures must not open it.
	for i := 0; i < BreakerThreshold-1; i++ {
		if opened := b.failure(id, secondProbe); opened {
			t.Fatalf("stale failure streak opened the breaker on failure %d", i+1)
		}
	}
}

func TestBreakerNilSafety(t *testing.T) {
	var b *breakerSet
	id := uuid.New()
	if allowed, _ := b.allow(id, time.Now()); !allowed {
		t.Fatal("nil breaker denied")
	}
	b.success(id) // must not panic
	if b.failure(id, time.Now()) {
		t.Fatal("nil breaker reported an open transition")
	}
}

func TestRecipientCapAndRouteReason(t *testing.T) {
	e := NewEngine(nil, nil, EngineOptions{})
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	ch := Channel{ID: uuid.New(), Kind: KindWebhook, Config: []byte("{}")}

	if reason := e.throttleReason(false, SeverityCritical, ch, now); reason == "" {
		t.Fatal("exhausted route bucket must report a reason")
	}
	for i := 0; i < RecipientHourlyCap; i++ {
		if reason := e.throttleReason(true, SeverityInfo, ch, now); reason != "" {
			t.Fatalf("recipient token %d denied inside the cap: %s", i+1, reason)
		}
	}
	if reason := e.throttleReason(true, SeverityInfo, ch, now); reason == "" {
		t.Fatal("recipient cap did not deny past the limit")
	}
	if reason := e.throttleReason(true, SeverityInfo, ch, now.Add(time.Hour)); reason != "" {
		t.Fatalf("recipient cap did not refill: %s", reason)
	}
}

func TestSMTPPerRecipientCapIsPerAddress(t *testing.T) {
	e := NewEngine(nil, nil, EngineOptions{})
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	cfg, _ := json.Marshal(SMTPConfig{To: []string{"a@example.test", "b@example.test"}})
	ch := Channel{ID: uuid.New(), Kind: KindSMTP, Config: cfg}
	for i := 0; i < RecipientHourlyCap; i++ {
		if reason := e.throttleReason(true, SeverityInfo, ch, now); reason != "" {
			t.Fatalf("token %d denied inside both recipient caps: %s", i+1, reason)
		}
	}
	if reason := e.throttleReason(true, SeverityInfo, ch, now); reason == "" {
		t.Fatal("recipient caps did not deny past the limit")
	}
}

func TestRouteBucketKeyIsPerRouteNotPerChannel(t *testing.T) {
	routeID := uuid.New()
	if got, want := routeBucketKey(routeID, SeverityInfo), "route:"+routeID.String()+":info"; got != want {
		t.Fatalf("routeBucketKey = %q, want %q", got, want)
	}
	// A second route of the same severity has an independent budget.
	if routeBucketKey(routeID, SeverityInfo) == routeBucketKey(uuid.New(), SeverityInfo) {
		t.Fatal("route bucket key does not include the route id")
	}
}

func TestTransitionedIgnoresNonNotifyKinds(t *testing.T) {
	e := NewEngine(nil, nil, EngineOptions{})
	// With a nil pool this would panic if the event tried to enqueue; the
	// alerts->notify contract is that only fired/reactivated/resolved notify.
	e.Transitioned(context.Background(), alerts.Transition{
		Event: alerts.AlertEvent{Kind: alerts.EventUpdated},
	})
	if len(alerts.NotifyKinds) != 4 ||
		!alerts.NotifyKinds[alerts.EventActivated] ||
		!alerts.NotifyKinds[alerts.EventReactivated] ||
		!alerts.NotifyKinds[alerts.EventResolved] ||
		!alerts.NotifyKinds[alerts.EventManualResolved] {
		t.Fatalf("NotifyKinds contract drifted: %v", alerts.NotifyKinds)
	}
}

func TestEventConstantsAreStable(t *testing.T) {
	if EventFired != "alert.fired" || EventResolved != "alert.resolved" {
		t.Fatalf("event vocabulary drifted: %q %q", EventFired, EventResolved)
	}
	if StatusPending != "pending" || StatusDelivered != "delivered" ||
		StatusFailed != "failed" || StatusDeadLetter != "dead_letter" {
		t.Fatal("delivery status vocabulary drifted")
	}
	if MaxAttempts != 12 || DedupWindow != 5*time.Minute || BreakerThreshold != 5 || BreakerHalfOpen != 5*time.Minute {
		t.Fatal("canonical engine constants drifted")
	}
}
