package poll

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSNMPClient is a scripted SNMPClient.
type fakeSNMPClient struct {
	getBinds  []SNMPVarBind
	getErr    error
	walks     map[string][]SNMPVarBind
	walkErrs  map[string]error
	walkCalls []string
	closed    bool
}

func (c *fakeSNMPClient) Get(_ []string) ([]SNMPVarBind, error) {
	if c.getErr != nil {
		return nil, c.getErr
	}
	return c.getBinds, nil
}

func (c *fakeSNMPClient) Walk(root string) ([]SNMPVarBind, error) {
	c.walkCalls = append(c.walkCalls, root)
	if err, ok := c.walkErrs[root]; ok && err != nil {
		return nil, err
	}
	return c.walks[root], nil
}

func (c *fakeSNMPClient) Close() error {
	c.closed = true
	return nil
}

// fakeFactory hands out scripted clients in order (one per Probe).
type fakeFactory struct {
	clients  []*fakeSNMPClient
	buildErr error
	built    []*fakeSNMPClient
}

func (f *fakeFactory) make(_ netip.Addr, _ SNMPCredentials, _ ClientConfig) (SNMPClient, error) {
	if f.buildErr != nil {
		return nil, f.buildErr
	}
	if len(f.clients) == 0 {
		return nil, errors.New("fakeFactory: no client scripted")
	}
	c := f.clients[0]
	f.clients = f.clients[1:]
	f.built = append(f.built, c)
	return c, nil
}

func stringBind(oid, s string) SNMPVarBind {
	return SNMPVarBind{OID: oid, Kind: ValueString, Str: s}
}

func counter32Bind(oid string, v uint64) SNMPVarBind {
	return SNMPVarBind{OID: oid, Kind: ValueUnsigned, Uint: v}
}

func counter64Bind(oid string, v uint64) SNMPVarBind {
	return SNMPVarBind{OID: oid, Kind: ValueCounter64, Uint: v}
}

func tickBind(oid string, v uint64) SNMPVarBind {
	return SNMPVarBind{OID: oid, Kind: ValueUnsigned, Uint: v}
}

type switchFixture struct {
	uptime        uint64
	in1           uint64
	out1          uint64
	inErr1        uint64
	discontinuity uint64
}

func newSwitchClient(f switchFixture) *fakeSNMPClient {
	c := &fakeSNMPClient{
		getBinds: []SNMPVarBind{
			stringBind("1.3.6.1.2.1.1.1.0", "Argus Simulated Switch"),
			stringBind("1.3.6.1.2.1.1.2.0", "1.3.6.1.4.1.8072.3.2.10"),
			tickBind("1.3.6.1.2.1.1.3.0", f.uptime),
			stringBind("1.3.6.1.2.1.1.5.0", "sim-switch-1"),
		},
		walks: make(map[string][]SNMPVarBind),
	}
	ifc := []SNMPVarBind{
		stringBind("1.3.6.1.2.1.2.2.1.2.1", "Gi1/0/1"),
		stringBind("1.3.6.1.2.1.2.2.1.2.2", "Gi1/0/2"),
		stringBind("1.3.6.1.2.1.2.2.1.2.3", "Gi1/0/3"),
		counter32Bind("1.3.6.1.2.1.2.2.1.8.1", 1),
		counter32Bind("1.3.6.1.2.1.2.2.1.8.2", 1),
		counter32Bind("1.3.6.1.2.1.2.2.1.8.3", 2),
		counter32Bind("1.3.6.1.2.1.2.2.1.13.1", 5),
		counter32Bind("1.3.6.1.2.1.2.2.1.13.2", 0),
		counter32Bind("1.3.6.1.2.1.2.2.1.13.3", 3),
		counter32Bind("1.3.6.1.2.1.2.2.1.14.1", f.inErr1),
		counter32Bind("1.3.6.1.2.1.2.2.1.14.2", 0),
		counter32Bind("1.3.6.1.2.1.2.2.1.14.3", 3),
		counter32Bind("1.3.6.1.2.1.2.2.1.19.1", 2),
		counter32Bind("1.3.6.1.2.1.2.2.1.19.2", 0),
		counter32Bind("1.3.6.1.2.1.2.2.1.19.3", 0),
		counter32Bind("1.3.6.1.2.1.2.2.1.20.1", 4),
		counter32Bind("1.3.6.1.2.1.2.2.1.20.2", 0),
		counter32Bind("1.3.6.1.2.1.2.2.1.20.3", 0),
	}
	ifx := []SNMPVarBind{
		stringBind("1.3.6.1.2.1.31.1.1.1.1.1", "Gi1/0/1"),
		stringBind("1.3.6.1.2.1.31.1.1.1.1.2", "Gi1/0/2"),
		stringBind("1.3.6.1.2.1.31.1.1.1.1.3", "Gi1/0/3"),
		counter64Bind("1.3.6.1.2.1.31.1.1.1.6.1", f.in1),
		counter64Bind("1.3.6.1.2.1.31.1.1.1.6.2", 5000000000),
		counter64Bind("1.3.6.1.2.1.31.1.1.1.6.3", 1000),
		counter64Bind("1.3.6.1.2.1.31.1.1.1.10.1", f.out1),
		counter64Bind("1.3.6.1.2.1.31.1.1.1.10.2", 100),
		counter64Bind("1.3.6.1.2.1.31.1.1.1.10.3", 300),
		stringBind("1.3.6.1.2.1.31.1.1.1.18.1", "uplink"),
		stringBind("1.3.6.1.2.1.31.1.1.1.18.2", "access"),
		stringBind("1.3.6.1.2.1.31.1.1.1.18.3", "spare"),
		tickBind("1.3.6.1.2.1.31.1.1.1.19.1", f.discontinuity),
		tickBind("1.3.6.1.2.1.31.1.1.1.19.2", f.discontinuity),
		tickBind("1.3.6.1.2.1.31.1.1.1.19.3", f.discontinuity),
	}
	c.walks["1.3.6.1.2.1.2.2.1"] = ifc
	c.walks["1.3.6.1.2.1.31.1.1.1"] = ifx
	return c
}

func newHostClient() *fakeSNMPClient {
	return &fakeSNMPClient{
		getBinds: []SNMPVarBind{
			stringBind("1.3.6.1.2.1.1.1.0", "Argus Simulated Host"),
			tickBind("1.3.6.1.2.1.1.3.0", 222222222),
		},
		walks: map[string][]SNMPVarBind{
			"1.3.6.1.2.1.25.3.3.1": {
				counter32Bind("1.3.6.1.2.1.25.3.3.1.2.1", 17),
				counter32Bind("1.3.6.1.2.1.25.3.3.1.2.2", 42),
			},
		},
	}
}

func newSNMPTestProber(t *testing.T, factory ClientFactory, creds CredentialSource, clock *testClock) *SNMPProber {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(discardWriter{}, nil))
	return NewSNMPProber(SNMPProberConfig{
		Credentials:   creds,
		ClientFactory: factory,
		Logger:        logger,
		Now:           clock.Now,
	})
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func snmpTarget(id, kind string) Target {
	return Target{
		DeviceID: id,
		MgmtIP:   netip.MustParseAddr("192.0.2.10"),
		Name:     id,
		Tier:     TierStandard,
		PollType: PollSNMP,
		Kind:     kind,
	}
}

func v2cSource() *StaticCredentialSource {
	src := NewStaticCredentialSource()
	src.SetDefault(SNMPCredentials{Version: SNMPVersionV2c, Community: "public"})
	return src
}

func sampleByKey(samples []Sample, key string, dims map[string]string) (Sample, bool) {
	for _, s := range samples {
		if s.MetricKey != key || len(s.Dimensions) != len(dims) {
			continue
		}
		ok := true
		for k, v := range dims {
			if s.Dimensions[k] != v {
				ok = false
				break
			}
		}
		if ok {
			return s, true
		}
	}
	return Sample{}, false
}

func TestSNMPProberSwitchSamplesAndCounterRates(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	clock := newTestClock(t0)
	factory := &fakeFactory{clients: []*fakeSNMPClient{
		newSwitchClient(switchFixture{uptime: 123456789, in1: 1<<64 - 50, out1: 1<<64 - 1616, inErr1: 1<<32 - 5}),
		newSwitchClient(switchFixture{uptime: 123456789, in1: 25, out1: 3, inErr1: 2}),
	}}
	p := newSNMPTestProber(t, factory.make, v2cSource(), clock)
	target := snmpTarget("dev-1", "switch")

	first := p.Probe(context.Background(), target)
	if !first.SnmpDone || first.Outcome() != OutcomeSuccess {
		t.Fatalf("first probe = %+v", first)
	}
	if up, ok := sampleByKey(first.SnmpSamples, "sys.uptime_s", nil); !ok || math.Abs(up.Value-1234567.89) > 0.001 {
		t.Fatalf("uptime sample = %+v ok=%v", up, ok)
	}
	if op, ok := sampleByKey(first.SnmpSamples, "net.if.oper_status", map[string]string{"if_name": "Gi1/0/2", "if_alias": "access"}); !ok || op.Value != 1 {
		t.Fatalf("oper status sample = %+v ok=%v", op, ok)
	}
	if _, ok := sampleByKey(first.SnmpSamples, "net.if.in_octets", map[string]string{"if_name": "Gi1/0/1", "if_alias": "uplink"}); ok {
		t.Fatal("counter must not emit on the seeding poll")
	}

	clock.Advance(time.Second)
	second := p.Probe(context.Background(), target)
	if !second.SnmpDone || second.Outcome() != OutcomeSuccess {
		t.Fatalf("second probe = %+v", second)
	}
	dims := map[string]string{"if_name": "Gi1/0/1", "if_alias": "uplink"}
	if s, ok := sampleByKey(second.SnmpSamples, "net.if.in_octets", dims); !ok || s.Value != 75 {
		t.Fatalf("64-bit wrapped in_octets = %+v ok=%v, want 75 B/s", s, ok)
	}
	if s, ok := sampleByKey(second.SnmpSamples, "net.if.out_octets", dims); !ok || s.Value != 1619 {
		t.Fatalf("64-bit wrapped out_octets = %+v ok=%v, want 1619 B/s", s, ok)
	}
	if s, ok := sampleByKey(second.SnmpSamples, "net.if.in_errors", dims); !ok || s.Value != 7 {
		t.Fatalf("32-bit wrapped in_errors = %+v ok=%v, want 7/s", s, ok)
	}
	for _, s := range second.SnmpSamples {
		if _, hasIndex := s.Dimensions["if_index"]; hasIndex {
			t.Fatalf("ifIndex must never be a series dimension: %+v", s)
		}
	}
}

func TestSNMPProberRebootReseedsWithoutSpike(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	clock := newTestClock(t0)
	factory := &fakeFactory{clients: []*fakeSNMPClient{
		newSwitchClient(switchFixture{uptime: 123456789, in1: 1 << 40, out1: 1 << 40, inErr1: 1000}),
		newSwitchClient(switchFixture{uptime: 100, in1: 5, out1: 7, inErr1: 1}),
		newSwitchClient(switchFixture{uptime: 100, in1: 5, out1: 7, inErr1: 1}),
	}}
	p := newSNMPTestProber(t, factory.make, v2cSource(), clock)
	target := snmpTarget("dev-reboot", "switch")

	p.Probe(context.Background(), target)
	clock.Advance(time.Second)

	reboot := p.Probe(context.Background(), target)
	if !reboot.SnmpDone || reboot.Outcome() != OutcomeSuccess {
		t.Fatalf("reboot probe = %+v", reboot)
	}
	for _, key := range []string{"net.if.in_octets", "net.if.out_octets", "net.if.in_errors"} {
		if s, ok := sampleByKey(reboot.SnmpSamples, key, map[string]string{"if_name": "Gi1/0/1", "if_alias": "uplink"}); ok {
			t.Fatalf("%s emitted after reboot: %+v (false spike)", key, s)
		}
	}

	clock.Advance(time.Second)
	after := p.Probe(context.Background(), target)
	dims := map[string]string{"if_name": "Gi1/0/1", "if_alias": "uplink"}
	if s, ok := sampleByKey(after.SnmpSamples, "net.if.in_octets", dims); !ok || s.Value != 0 {
		t.Fatalf("post-reboot in_octets = %+v ok=%v, want 0 B/s from the new baseline", s, ok)
	}
}

func TestSNMPProberDiscontinuityReseeds(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	clock := newTestClock(t0)
	factory := &fakeFactory{clients: []*fakeSNMPClient{
		newSwitchClient(switchFixture{uptime: 123456789, in1: 1000, out1: 1000, inErr1: 10, discontinuity: 0}),
		newSwitchClient(switchFixture{uptime: 123456789, in1: 2000, out1: 2000, inErr1: 20, discontinuity: 77}),
		newSwitchClient(switchFixture{uptime: 123456789, in1: 2100, out1: 2100, inErr1: 21, discontinuity: 77}),
	}}
	p := newSNMPTestProber(t, factory.make, v2cSource(), clock)
	target := snmpTarget("dev-disc", "switch")
	dims := map[string]string{"if_name": "Gi1/0/1", "if_alias": "uplink"}

	p.Probe(context.Background(), target)
	clock.Advance(time.Second)
	changed := p.Probe(context.Background(), target)
	if s, ok := sampleByKey(changed.SnmpSamples, "net.if.in_octets", dims); ok {
		t.Fatalf("in_octets emitted across an ifCounterDiscontinuityTime change: %+v", s)
	}
	clock.Advance(time.Second)
	next := p.Probe(context.Background(), target)
	if s, ok := sampleByKey(next.SnmpSamples, "net.if.in_octets", dims); !ok || s.Value != 100 {
		t.Fatalf("post-discontinuity in_octets = %+v ok=%v, want 100 B/s", s, ok)
	}
}

func TestSNMPProberTemplateDrift(t *testing.T) {
	clock := newTestClock(time.Unix(1000, 0))
	client := newSwitchClient(switchFixture{uptime: 1000})
	client.walks = map[string][]SNMPVarBind{} // agent answers the system GET but no tables
	factory := &fakeFactory{clients: []*fakeSNMPClient{client}}
	p := newSNMPTestProber(t, factory.make, v2cSource(), clock)

	res := p.Probe(context.Background(), snmpTarget("dev-drift", "switch"))
	if !res.SnmpDone || res.Outcome() != OutcomeSuccess {
		t.Fatalf("drift probe = %+v", res)
	}
	if res.ErrorClass != ErrorTemplateDrift {
		t.Fatalf("error class = %q, want %q", res.ErrorClass, ErrorTemplateDrift)
	}
}

func TestSNMPProberWalkTruncation(t *testing.T) {
	clock := newTestClock(time.Unix(1000, 0))
	client := newSwitchClient(switchFixture{uptime: 1000})
	client.walkErrs = map[string]error{"1.3.6.1.2.1.2.2.1": ErrSNMPTruncated}
	factory := &fakeFactory{clients: []*fakeSNMPClient{client}}
	p := newSNMPTestProber(t, factory.make, v2cSource(), clock)

	res := p.Probe(context.Background(), snmpTarget("dev-trunc", "switch"))
	if res.SnmpDone || res.Outcome() != OutcomeFailure {
		t.Fatalf("truncation probe = %+v, want failure", res)
	}
	if res.ErrorClass != ErrorWalkTruncation {
		t.Fatalf("error class = %q, want %q", res.ErrorClass, ErrorWalkTruncation)
	}
}

func TestSNMPProberClientErrorClasses(t *testing.T) {
	clock := newTestClock(time.Unix(1000, 0))
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"timeout", ErrSNMPTimeout, ErrorTimeout},
		{"auth", ErrSNMPAuthFailure, ErrorAuthFailure},
	}
	for _, tc := range cases {
		factory := &fakeFactory{buildErr: tc.err}
		p := newSNMPTestProber(t, factory.make, v2cSource(), clock)
		res := p.Probe(context.Background(), snmpTarget("dev-"+tc.name, "switch"))
		if res.ErrorClass != tc.want || res.SnmpDone || res.Outcome() != OutcomeFailure {
			t.Fatalf("%s probe = %+v, want class %q failure", tc.name, res, tc.want)
		}
	}
}

func TestSNMPProberCredentialStates(t *testing.T) {
	clock := newTestClock(time.Unix(1000, 0))
	factory := &fakeFactory{}
	p := newSNMPTestProber(t, factory.make, NewStaticCredentialSource(), clock)
	if res := p.Probe(context.Background(), snmpTarget("dev-none", "switch")); res.ErrorClass != ErrorCredentialMissing {
		t.Fatalf("missing credential class = %q", res.ErrorClass)
	}
	bad := NewStaticCredentialSource()
	bad.SetDefault(SNMPCredentials{Version: "v1", Community: "public"})
	p = newSNMPTestProber(t, factory.make, bad, clock)
	if res := p.Probe(context.Background(), snmpTarget("dev-bad", "switch")); res.ErrorClass != ErrorCredentialInvalid {
		t.Fatalf("invalid credential class = %q", res.ErrorClass)
	}
}

func TestSNMPProberHostKindSelectsHostResources(t *testing.T) {
	clock := newTestClock(time.Unix(1000, 0))
	client := newHostClient()
	factory := &fakeFactory{clients: []*fakeSNMPClient{client}}
	p := newSNMPTestProber(t, factory.make, v2cSource(), clock)

	res := p.Probe(context.Background(), snmpTarget("dev-host", "host"))
	if !res.SnmpDone || res.ErrorClass != ErrorNone {
		t.Fatalf("host probe = %+v", res)
	}
	if s, ok := sampleByKey(res.SnmpSamples, "sys.cpu.util", map[string]string{"cpu": "2"}); !ok || s.Value != 42 {
		t.Fatalf("sys.cpu.util = %+v ok=%v, want 42 for cpu 2", s, ok)
	}
	for _, call := range client.walkCalls {
		if call == "1.3.6.1.2.1.2.2.1" || call == "1.3.6.1.2.1.31.1.1.1" {
			t.Fatalf("host kind must not walk IF-MIB (called %s)", call)
		}
	}
}

func TestSNMPProberUptimeWrapReseeds(t *testing.T) {
	// A sysUpTime decrease is treated as a reboot (a 497-day TimeTicks wrap is
	// indistinguishable within one interval and must reseed, never spike).
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	clock := newTestClock(t0)
	factory := &fakeFactory{clients: []*fakeSNMPClient{
		newSwitchClient(switchFixture{uptime: 4294967000, in1: 1 << 40, out1: 1 << 40, inErr1: 1000}),
		newSwitchClient(switchFixture{uptime: 100, in1: 50, out1: 70, inErr1: 1}),
	}}
	p := newSNMPTestProber(t, factory.make, v2cSource(), clock)
	target := snmpTarget("dev-uptime-wrap", "switch")
	p.Probe(context.Background(), target)
	clock.Advance(time.Second)
	wrapped := p.Probe(context.Background(), target)
	dims := map[string]string{"if_name": "Gi1/0/1", "if_alias": "uplink"}
	if s, ok := sampleByKey(wrapped.SnmpSamples, "net.if.in_octets", dims); ok {
		t.Fatalf("in_octets emitted across a sysUpTime decrease: %+v", s)
	}
}

func TestSNMPProberTargetRemovedDropsState(t *testing.T) {
	clock := newTestClock(time.Unix(1000, 0))
	factory := &fakeFactory{clients: []*fakeSNMPClient{newSwitchClient(switchFixture{uptime: 1000})}}
	p := newSNMPTestProber(t, factory.make, v2cSource(), clock)
	p.Probe(context.Background(), snmpTarget("dev-drop", "switch"))
	p.mu.Lock()
	n := len(p.devices)
	p.mu.Unlock()
	if n != 1 {
		t.Fatalf("device state rows = %d, want 1", n)
	}
	p.TargetRemoved("dev-drop", PollSNMP)
	p.mu.Lock()
	n = len(p.devices)
	p.mu.Unlock()
	if n != 0 {
		t.Fatalf("device state after removal = %d, want 0", n)
	}
}

func TestMultiProberDispatchesAndEngineEmitsBothPollTypes(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	clock := newTestClock(t0)
	snmpFactory := &fakeFactory{clients: []*fakeSNMPClient{newSwitchClient(switchFixture{uptime: 123456789})}}
	snmp := newSNMPTestProber(t, snmpFactory.make, v2cSource(), clock)
	icmp := &fakeProber{script: []Result{{PollType: PollICMP, Sent: 3, Received: 3, LossPercent: 0}}}
	multi := NewMultiProber(map[string]Prober{PollICMP: icmp, PollSNMP: snmp})

	var mu sync.Mutex
	var samples []Sample
	var health []Health
	eng := NewEngine(Config{
		Prober: multi,
		Clock:  clock,
		OnSample: func(s Sample) {
			mu.Lock()
			samples = append(samples, s)
			mu.Unlock()
		},
		OnHealth: func(h Health) {
			mu.Lock()
			health = append(health, h)
			mu.Unlock()
		},
	})
	base := target("dev-both", TierFast)
	base.PollType = PollICMP
	snmpT := base
	snmpT.PollType = PollSNMP
	snmpT.Kind = "switch"
	eng.ApplyTargets([]Target{base, snmpT})

	if n := eng.Step(context.Background(), clock.Now()); n != 2 {
		t.Fatalf("step probed %d, want 2 (icmp + snmp)", n)
	}
	mu.Lock()
	defer mu.Unlock()
	types := map[string]bool{}
	for _, h := range health {
		types[h.PollType] = true
	}
	if !types[PollICMP] || !types[PollSNMP] {
		t.Fatalf("health poll types = %v, want icmp+snmp", types)
	}
	var haveICMP, haveSNMP bool
	for _, s := range samples {
		switch s.MetricKey {
		case MetricReachable:
			haveICMP = true
		case "sys.uptime_s":
			haveSNMP = true
		}
	}
	if !haveICMP || !haveSNMP {
		t.Fatalf("samples icmp=%v snmp=%v; want both", haveICMP, haveSNMP)
	}
	// Removing the SNMP target releases prober state; the ICMP target stays.
	eng.ApplyTargets([]Target{base})
	snmp.mu.Lock()
	n := len(snmp.devices)
	snmp.mu.Unlock()
	if n != 0 {
		t.Fatalf("snmp device state after removing only the snmp target = %d, want 0", n)
	}
}

func TestSNMPProberWarnsOnceForV2c(t *testing.T) {
	clock := newTestClock(time.Unix(1000, 0))
	var buf strings.Builder
	factory := &fakeFactory{clients: []*fakeSNMPClient{
		newSwitchClient(switchFixture{uptime: 1}),
		newSwitchClient(switchFixture{uptime: 2}),
	}}
	p := NewSNMPProber(SNMPProberConfig{
		Credentials:   v2cSource(),
		ClientFactory: factory.make,
		Logger:        slog.New(slog.NewTextHandler(&buf, nil)),
		Now:           clock.Now,
	})
	target := snmpTarget("dev-warn", "switch")
	p.Probe(context.Background(), target)
	clock.Advance(time.Minute)
	p.Probe(context.Background(), target)
	if got := strings.Count(buf.String(), "SNMP v2c in use"); got != 1 {
		t.Fatalf("v2c warnings = %d, want exactly 1 for the device", got)
	}
}
