package poll

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestRequestsPerMinutePerProfile(t *testing.T) {
	cases := map[string]int{
		TierFast:      RequestsPerMinuteFast,
		TierStandard:  RequestsPerMinuteStandard,
		TierSlow:      RequestsPerMinuteSlow,
		TierInventory: RequestsPerMinuteInventory,
		"unknown":     RequestsPerMinuteStandard,
		"":            RequestsPerMinuteStandard,
	}
	for tier, want := range cases {
		if got := RequestsPerMinute(tier); got != want {
			t.Fatalf("RequestsPerMinute(%q) = %d, want %d", tier, got, want)
		}
	}
	if RequestsPerMinuteStandard != 300 {
		t.Fatalf("canonical standard budget = %d, want 300", RequestsPerMinuteStandard)
	}
}

func TestRequestLimiterSlidingWindow(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	lim := NewRequestLimiter(3, func() time.Time { return now })
	for i := 0; i < 3; i++ {
		if !lim.Allow() {
			t.Fatalf("request %d denied under budget", i+1)
		}
	}
	if lim.Allow() {
		t.Fatal("fourth request allowed over budget")
	}
	if lim.Count() != 3 {
		t.Fatalf("count = %d, want 3", lim.Count())
	}
	// Denied requests are not recorded: a saturated device cannot grow state.
	for i := 0; i < 10; i++ {
		_ = lim.Allow()
	}
	if lim.Count() != 3 {
		t.Fatalf("count after denials = %d, want 3", lim.Count())
	}
	// The window slides.
	now = now.Add(RequestBudgetWindow + time.Second)
	if !lim.Allow() {
		t.Fatal("request denied after the window slid")
	}
	if lim.Count() != 1 {
		t.Fatalf("count after slide = %d, want 1", lim.Count())
	}
	if lim.Max() != 3 {
		t.Fatalf("max = %d, want 3", lim.Max())
	}
}

func TestTierSessionCaps(t *testing.T) {
	cases := map[string]int{
		TierFast:      1,
		TierStandard:  2,
		TierSlow:      2,
		TierInventory: 1,
		"":            2,
	}
	for tier, want := range cases {
		if got := TierSessionCap(tier); got != want {
			t.Fatalf("TierSessionCap(%q) = %d, want %d", tier, got, want)
		}
	}
}

func TestSessionLimiterPerDeviceAndGlobal(t *testing.T) {
	lim := NewSessionLimiter(2)

	// Standard device: 2 concurrent sessions, the third is denied.
	rel1, ok := lim.Acquire("dev-a", TierStandard)
	if !ok {
		t.Fatal("first standard session denied")
	}
	if _, ok := lim.Acquire("dev-a", TierStandard); !ok {
		t.Fatal("second standard session denied")
	}
	if _, ok := lim.Acquire("dev-a", TierStandard); ok {
		t.Fatal("third standard session allowed over the tier cap")
	}
	// The global cap (2) is now reached even for a fresh device.
	if _, ok := lim.Acquire("dev-b", TierSlow); ok {
		t.Fatal("third global session allowed over the global cap")
	}
	rel1()
	if got := lim.DeviceInUse("dev-a"); got != 1 {
		t.Fatalf("dev-a sessions = %d, want 1", got)
	}
	if got := lim.GlobalInUse(); got != 1 {
		t.Fatalf("global sessions = %d, want 1", got)
	}
	if _, ok := lim.Acquire("dev-b", TierSlow); !ok {
		t.Fatal("session denied after a release")
	}
	if got := lim.GlobalMax(); got != 2 {
		t.Fatalf("global max = %d, want 2", got)
	}

	// Fast device cap is 1.
	fast := NewSessionLimiter(10)
	rel, ok := fast.Acquire("dev-fast", TierFast)
	if !ok {
		t.Fatal("fast session denied")
	}
	if _, ok := fast.Acquire("dev-fast", TierFast); ok {
		t.Fatal("second fast session allowed over the tier cap")
	}
	rel()
	if fast.DeviceInUse("dev-fast") != 0 {
		t.Fatal("release did not free the fast session")
	}
	// Double release is a no-op (idempotent).
	rel()
	if fast.GlobalInUse() != 0 {
		t.Fatalf("global usage after double release = %d, want 0", fast.GlobalInUse())
	}
}

// TestWalkBudgetExceeded proves the per-device request budget gates every walk
// RPC, aborts with the stable sentinel and maps to the rate_limited class.
func TestWalkBudgetExceeded(t *testing.T) {
	calls := 0
	s := &fakeSession{bulkFn: func(_ []string, _ int) ([]SNMPVarBind, error) {
		calls++
		return []SNMPVarBind{bind("1.3.6.1.2.1.2.2.1.2."+fmt.Sprint(calls), ValueString, 0)}, nil
	}}
	lim := NewRequestLimiter(2, nil)
	vars, err := walkOIDBudget(s, "1.3.6.1.2.1.2.2.1", 25, lim)
	if !errors.Is(err, ErrSNMPBudgetExceeded) {
		t.Fatalf("err = %v, want ErrSNMPBudgetExceeded", err)
	}
	if calls != 2 || len(vars) != 2 {
		t.Fatalf("calls=%d vars=%d, want 2/2 (two requests allowed)", calls, len(vars))
	}
	if got := classifySNMPErrorClass(err); got != ErrorRateLimited {
		t.Fatalf("class = %q, want %q", got, ErrorRateLimited)
	}
	if lim.Allow() {
		t.Fatal("budget refilled within the same window")
	}
}

// TestWalkOneInFlightPerDevice proves the client serializes walks per device
// (canonical docs/07 §12.3 "no more than one walk in flight per device").
func TestWalkOneInFlightPerDevice(t *testing.T) {
	var mu sync.Mutex
	active, maxActive := 0, 0
	release := make(chan struct{})
	entered := make(chan struct{}, 2)
	s := &fakeSession{bulkFn: func(_ []string, _ int) ([]SNMPVarBind, error) {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()
		entered <- struct{}{}
		<-release
		mu.Lock()
		active--
		mu.Unlock()
		return []SNMPVarBind{{OID: "1.3.6.1.2.1.2.2.1.2.1", Kind: ValueEndOfMib}}, nil
	}}
	c := &snmpClient{session: s, maxRepetitions: 25}
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.Walk("1.3.6.1.2.1.2.2.1")
		}()
	}
	<-entered
	// The second walk must still be blocked on the client mutex.
	select {
	case <-entered:
		t.Fatal("two walks entered concurrently for one device")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	<-entered
	wg.Wait()
	if maxActive != 1 {
		t.Fatalf("max concurrent walks = %d, want 1", maxActive)
	}
}
