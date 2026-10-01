package poll

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// fakePinger is the injectable Pinger seam: scripted RTTs or error.
type fakePinger struct {
	rtts  []time.Duration
	err   error
	calls int
	addr  netip.Addr
	count int
}

func (f *fakePinger) Ping(_ context.Context, addr netip.Addr, count int, _, _ time.Duration) ([]time.Duration, error) {
	f.calls++
	f.addr = addr
	f.count = count
	return f.rtts, f.err
}

func (f *fakePinger) Close() error { return nil }

func v4Target() Target {
	return Target{DeviceID: "11111111-1111-4111-8111-111111111111", MgmtIP: netip.MustParseAddr("192.0.2.5"), Name: "edge", Tier: TierFast}
}

func TestProberFullSuccess(t *testing.T) {
	fp := &fakePinger{rtts: []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond}}
	p := NewICMPProber(ICMPConfig{Pinger: fp})
	res := p.Probe(context.Background(), v4Target())

	if !res.Reachable() || res.Outcome() != OutcomeSuccess || res.ErrorClass != ErrorNone {
		t.Fatalf("result = %+v", res)
	}
	if res.Sent != 3 || res.Received != 3 || res.LossPercent != 0 {
		t.Fatalf("counters = %+v", res)
	}
	if res.RTTAvg != 20*time.Millisecond || res.RTTMin != 10*time.Millisecond || res.RTTMax != 30*time.Millisecond {
		t.Fatalf("rtt = %+v", res)
	}
	samples := res.Samples(v4Target(), time.Now())
	if len(samples) != 3 {
		t.Fatalf("samples = %d, want 3", len(samples))
	}
	byKey := map[string]Sample{}
	for _, s := range samples {
		byKey[s.MetricKey] = s
	}
	if byKey[MetricReachable].Value != 1 || byKey[MetricLossPct].Value != 0 || byKey[MetricRTT].Value != 20 {
		t.Fatalf("sample values = %+v", byKey)
	}
	if byKey[MetricReachable].Unit != UnitState || byKey[MetricRTT].Unit != UnitMS || byKey[MetricLossPct].Unit != UnitPercent {
		t.Fatalf("sample units = %+v", byKey)
	}
}

func TestProberPartialLossIsSuccessWithClass(t *testing.T) {
	fp := &fakePinger{rtts: []time.Duration{5 * time.Millisecond, 7 * time.Millisecond}}
	p := NewICMPProber(ICMPConfig{Pinger: fp})
	res := p.Probe(context.Background(), v4Target())

	if res.Sent != 3 || res.Received != 2 {
		t.Fatalf("counters = %+v", res)
	}
	if res.Outcome() != OutcomeSuccess || res.ErrorClass != ErrorLoss {
		t.Fatalf("outcome/class = %s/%s", res.Outcome(), res.ErrorClass)
	}
	wantLoss := 100.0 / 3.0
	if diff := res.LossPercent - wantLoss; diff > 1e-9 || diff < -1e-9 {
		t.Fatalf("loss = %v, want %v", res.LossPercent, wantLoss)
	}
	if len(res.Samples(v4Target(), time.Now())) != 3 {
		t.Fatal("partial loss must still emit reachable/loss/rtt")
	}
}

func TestProberTotalLossOmitsRTT(t *testing.T) {
	fp := &fakePinger{}
	p := NewICMPProber(ICMPConfig{Pinger: fp})
	res := p.Probe(context.Background(), v4Target())

	if res.Reachable() || res.Outcome() != OutcomeFailure || res.ErrorClass != ErrorTimeout {
		t.Fatalf("result = %+v", res)
	}
	if res.LossPercent != 100 {
		t.Fatalf("loss = %v, want 100", res.LossPercent)
	}
	samples := res.Samples(v4Target(), time.Now())
	if len(samples) != 2 {
		t.Fatalf("samples = %d, want 2 (no fake RTT zero)", len(samples))
	}
	for _, s := range samples {
		if s.MetricKey == MetricRTT {
			t.Fatal("outage must not emit an RTT sample")
		}
	}
}

func TestProberTransportErrorProducesNoSamples(t *testing.T) {
	fp := &fakePinger{err: errors.New("network is unreachable")}
	p := NewICMPProber(ICMPConfig{Pinger: fp})
	res := p.Probe(context.Background(), v4Target())

	if res.Sent != 0 || res.Outcome() != OutcomeFailure || res.ErrorClass != ErrorUnreachable {
		t.Fatalf("result = %+v", res)
	}
	if samples := res.Samples(v4Target(), time.Now()); len(samples) != 0 {
		t.Fatalf("untried probe emitted %d samples", len(samples))
	}
}

func TestProberUnsupportedPlatform(t *testing.T) {
	p := &ICMPProber{pingerErr: ErrUnsupportedPlatform}
	res := p.Probe(context.Background(), v4Target())
	if res.ErrorClass != ErrorUnsupported || res.Outcome() != OutcomeFailure {
		t.Fatalf("result = %+v", res)
	}
	if samples := res.Samples(v4Target(), time.Now()); len(samples) != 0 {
		t.Fatalf("unsupported probe emitted %d samples", len(samples))
	}
}

func TestProberIPv6UnsupportedInM9S1(t *testing.T) {
	fp := &fakePinger{rtts: []time.Duration{time.Millisecond}}
	p := NewICMPProber(ICMPConfig{Pinger: fp})
	target := Target{DeviceID: "dev", MgmtIP: netip.MustParseAddr("2001:db8::1"), Tier: TierFast}
	res := p.Probe(context.Background(), target)
	if res.ErrorClass != ErrorUnsupported {
		t.Fatalf("IPv6 class = %q, want unsupported (ICMPv6 is V2)", res.ErrorClass)
	}
	if fp.calls != 0 {
		t.Fatal("IPv6 target must not reach the IPv4 pinger")
	}
}

func TestProberDefaultsBoundTheWindow(t *testing.T) {
	fp := &fakePinger{}
	p := NewICMPProber(ICMPConfig{Pinger: fp, Count: 999})
	if p.count != DefaultPingCount || p.interval != DefaultPingInterval || p.timeout != DefaultPingTimeout {
		t.Fatalf("defaults not applied: count=%d interval=%s timeout=%s", p.count, p.interval, p.timeout)
	}
}
