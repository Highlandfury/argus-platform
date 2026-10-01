package poll

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// TestSNMPProberCPUGuardFlag proves the hrProcessorLoad guard: a device
// answering with any CPU at/above the threshold sets CPULoadHigh on a healthy
// poll (docs/07 §12.7), and the threshold is honored exactly.
func TestSNMPProberCPUGuardFlag(t *testing.T) {
	clock := newTestClock(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	creds := v2cSource()

	calm := newHostClient()
	prober := newSNMPTestProber(t, (&fakeFactory{clients: []*fakeSNMPClient{calm}}).make, creds, clock)
	res := prober.Probe(context.Background(), snmpTarget("dev-calm", "host"))
	if !res.Reachable() || res.CPULoadHigh {
		t.Fatalf("calm host: reachable=%v high=%v, want true/false", res.Reachable(), res.CPULoadHigh)
	}

	hot := newHostClient()
	hot.walks["1.3.6.1.2.1.25.3.3.1"][1].Uint = 80 // exactly at the threshold
	prober = newSNMPTestProber(t, (&fakeFactory{clients: []*fakeSNMPClient{hot}}).make, creds, clock)
	res = prober.Probe(context.Background(), snmpTarget("dev-hot", "host"))
	if !res.Reachable() || !res.CPULoadHigh {
		t.Fatalf("hot host: reachable=%v high=%v, want true/true", res.Reachable(), res.CPULoadHigh)
	}

	// A stricter configured threshold does not fire on the same data.
	prober = NewSNMPProber(SNMPProberConfig{
		Credentials:     creds,
		ClientFactory:   (&fakeFactory{clients: []*fakeSNMPClient{hot}}).make,
		Logger:          slog.New(slog.NewTextHandler(discardWriter{}, nil)),
		Now:             clock.Now,
		CPUGuardPercent: 90,
	})
	res = prober.Probe(context.Background(), snmpTarget("dev-hot", "host"))
	if res.CPULoadHigh {
		t.Fatal("guard fired under a stricter threshold")
	}
}

// TestSNMPProberSessionCeilingSkips proves the global session ceiling skips
// and accounts a probe (rate_limited) instead of queueing it, and releases the
// slot when the in-flight session ends.
func TestSNMPProberSessionCeilingSkips(t *testing.T) {
	clock := newTestClock(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	creds := v2cSource()
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	blocking := &fakeSNMPClient{
		getBinds: []SNMPVarBind{
			stringBind("1.3.6.1.1.0", "x"),
			stringBind("1.3.6.1.2.0", "1.3"),
			tickBind("1.3.6.1.3.0", 1),
		},
		walks: map[string][]SNMPVarBind{},
	}
	slowFactory := func(_ netip.Addr, _ SNMPCredentials, _ ClientConfig) (SNMPClient, error) {
		return &blockingGetClient{fakeSNMPClient: blocking, entered: entered, release: release}, nil
	}
	prober := NewSNMPProber(SNMPProberConfig{
		Credentials:   creds,
		ClientFactory: slowFactory,
		Sessions:      NewSessionLimiter(1),
		Logger:        slog.New(slog.NewTextHandler(discardWriter{}, nil)),
		Now:           clock.Now,
	})

	var wg sync.WaitGroup
	var first Result
	wg.Add(1)
	go func() {
		defer wg.Done()
		first = prober.Probe(context.Background(), snmpTarget("dev-a", "host"))
	}()
	<-entered

	// The global slot is taken: a second device is skipped and accounted.
	second := prober.Probe(context.Background(), snmpTarget("dev-b", "host"))
	if second.ErrorClass != ErrorRateLimited || second.Reachable() {
		t.Fatalf("second probe = %+v, want rate_limited", second)
	}
	if prober.sessions.GlobalInUse() != 1 {
		t.Fatalf("global sessions = %d, want 1", prober.sessions.GlobalInUse())
	}

	close(release)
	wg.Wait()
	if !first.Reachable() {
		t.Fatalf("first probe = %+v, want success", first)
	}
	if prober.sessions.GlobalInUse() != 0 {
		t.Fatalf("global sessions after release = %d, want 0", prober.sessions.GlobalInUse())
	}
}

// blockingGetClient wraps a fake client and blocks the scalar GET until the
// test releases it.
type blockingGetClient struct {
	*fakeSNMPClient
	entered chan struct{}
	release chan struct{}
}

func (c *blockingGetClient) Get(_ []string) ([]SNMPVarBind, error) {
	c.entered <- struct{}{}
	<-c.release
	return c.getBinds, nil
}

// budgetedClient enforces ClientConfig.Limiter for fake clients the way the
// real snmpClient does: every Get and every Walk consumes one slot.
type budgetedClient struct {
	SNMPClient
	limiter *RequestLimiter
}

func (c *budgetedClient) Get(oids []string) ([]SNMPVarBind, error) {
	if !c.limiter.Allow() {
		return nil, ErrSNMPBudgetExceeded
	}
	return c.SNMPClient.Get(oids)
}

func (c *budgetedClient) Walk(rootOID string) ([]SNMPVarBind, error) {
	if !c.limiter.Allow() {
		return nil, ErrSNMPBudgetExceeded
	}
	return c.SNMPClient.Walk(rootOID)
}

// budgetedFactory wraps a factory so its clients honor cfg.Limiter.
func budgetedFactory(inner ClientFactory) ClientFactory {
	return func(addr netip.Addr, creds SNMPCredentials, cfg ClientConfig) (SNMPClient, error) {
		client, err := inner(addr, creds, cfg)
		if err != nil {
			return nil, err
		}
		return &budgetedClient{SNMPClient: client, limiter: cfg.Limiter}, nil
	}
}

// TestSNMPProberRequestBudgetPerDevice proves the request budget is per device
// and per profile: one saturated device reports rate_limited while another
// target on the same prober keeps polling.
func TestSNMPProberRequestBudgetPerDevice(t *testing.T) {
	clock := newTestClock(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	creds := v2cSource()
	factory := &fakeFactory{clients: []*fakeSNMPClient{newSwitchClient(switchFixture{uptime: 1000}), newSwitchClient(switchFixture{uptime: 1000})}}
	prober := NewSNMPProber(SNMPProberConfig{
		Credentials:   creds,
		ClientFactory: budgetedFactory(factory.make),
		Logger:        slog.New(slog.NewTextHandler(discardWriter{}, nil)),
		Now:           clock.Now,
		RequestBudget: func(tier string) int {
			if tier == TierFast {
				return 10
			}
			return 1 // allow the scalar GET only: the first walk is denied
		},
	})

	saturated := prober.Probe(context.Background(), snmpTarget("dev-sat", "switch")) // standard tier
	if saturated.ErrorClass != ErrorRateLimited {
		t.Fatalf("saturated probe = %+v, want rate_limited", saturated)
	}
	healthy := prober.Probe(context.Background(), Target{
		DeviceID: "dev-ok", MgmtIP: netip.MustParseAddr("192.0.2.11"),
		Name: "dev-ok", Tier: TierFast, PollType: PollSNMP, Kind: "switch",
	})
	if !healthy.Reachable() || healthy.ErrorClass != "" {
		t.Fatalf("healthy probe = %+v, want success (other target must not starve)", healthy)
	}
	if got := prober.devices["dev-sat"].limiter.Count(); got != 1 {
		t.Fatalf("saturated device budget count = %d, want 1", got)
	}
}

// TestSNMPProberBudgetWindowRecovers proves a device recovers once the sliding
// window passes.
func TestSNMPProberBudgetWindowRecovers(t *testing.T) {
	clock := newTestClock(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	creds := v2cSource()
	factory := &fakeFactory{clients: []*fakeSNMPClient{
		newSwitchClient(switchFixture{uptime: 1000}),
		newSwitchClient(switchFixture{uptime: 1000}),
		newSwitchClient(switchFixture{uptime: 1000}),
	}}
	prober := NewSNMPProber(SNMPProberConfig{
		Credentials:   creds,
		ClientFactory: budgetedFactory(factory.make),
		Logger:        slog.New(slog.NewTextHandler(discardWriter{}, nil)),
		Now:           clock.Now,
		RequestBudget: func(string) int { return 10 },
	})
	target := snmpTarget("dev", "switch")
	if res := prober.Probe(context.Background(), target); !res.Reachable() {
		t.Fatalf("first poll = %+v", res)
	}
	// Exhaust the rest of the window through the limiter directly.
	for prober.devices["dev"].limiter.Allow() {
	}
	if res := prober.Probe(context.Background(), target); res.ErrorClass != ErrorRateLimited {
		t.Fatalf("saturated poll = %+v, want rate_limited", res)
	}
	clock.Advance(RequestBudgetWindow + time.Second)
	if res := prober.Probe(context.Background(), target); !res.Reachable() {
		t.Fatalf("poll after window slide = %+v, want success", res)
	}
}
