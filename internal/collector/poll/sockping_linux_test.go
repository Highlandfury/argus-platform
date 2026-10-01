//go:build linux

package poll

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

// TestSocketPingerLoopback is the real-socket integration test for the Linux
// ICMP implementation. CI runners need CAP_NET_RAW or an unprivileged ping
// socket (net.ipv4.ping_group_range covering the process GID); when neither
// capability is available the test skips with the reason instead of failing
// (the capability statement is recorded in M9_EVIDENCE.md).
func TestSocketPingerLoopback(t *testing.T) {
	p, err := newSocketPinger()
	if err != nil {
		t.Skipf("ICMP capability unavailable on this runner (NET_RAW / unprivileged ping): %v", err)
	}
	defer func() { _ = p.Close() }()

	rtts, err := p.Ping(context.Background(), netip.MustParseAddr("127.0.0.1"), 2, 10*time.Millisecond, time.Second)
	if err != nil {
		t.Fatalf("loopback ping: %v", err)
	}
	if len(rtts) == 0 {
		t.Fatal("loopback ping returned no replies")
	}
	for _, rtt := range rtts {
		if rtt <= 0 || rtt > time.Second {
			t.Fatalf("rtt out of range: %s", rtt)
		}
	}
}

func TestICMPProberLoopback(t *testing.T) {
	prober := NewICMPProber(ICMPConfig{})
	defer func() { _ = prober.Close() }()
	res := prober.Probe(context.Background(), Target{
		DeviceID: "loopback", MgmtIP: netip.MustParseAddr("127.0.0.1"), Name: "loopback", Tier: TierFast,
	})
	if res.ErrorClass == ErrorUnsupported {
		t.Skip("ICMP capability unavailable on this runner (NET_RAW / unprivileged ping)")
	}
	if !res.Reachable() {
		t.Fatalf("loopback probe not reachable: %+v", res)
	}
	if len(res.Samples(Target{DeviceID: "loopback"}, time.Now())) != 3 {
		t.Fatal("reachable probe must emit reachable/loss/rtt")
	}
}
