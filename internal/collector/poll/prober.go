package poll

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// Ping defaults. The diagnostic bound in docs/10 §"icmp" is count <= 50 and
// interval <= 200 ms; polling uses a small fixed window (3 echoes) so a slow
// target cannot occupy a poll worker for long.
const (
	DefaultPingCount    = 3
	DefaultPingInterval = 200 * time.Millisecond
	DefaultPingTimeout  = 2 * time.Second
	MaxPingCount        = 50
)

// ErrUnsupportedPlatform is returned when the host has neither raw-socket nor
// unprivileged-ICMP capability (the collector targets Linux; other platforms
// keep the build green and report `unsupported` poll health).
var ErrUnsupportedPlatform = errors.New("poll: ICMP not supported on this platform")

// Pinger executes a bounded echo sequence against one address. It is the
// injectable seam for unit tests; the production implementation uses raw
// sockets (CAP_NET_RAW) with an unprivileged ping-socket fallback (Linux).
type Pinger interface {
	// Ping sends up to count echo requests separated by interval and returns
	// the RTT of every reply received before each packet's timeout. A missing
	// reply is data (loss), not an error: only transport-level failures are
	// returned as errors.
	Ping(ctx context.Context, addr netip.Addr, count int, interval, timeout time.Duration) ([]time.Duration, error)
	// Close releases the socket.
	Close() error
}

// Result is the normalized outcome of one poll (errors are data, docs/06 §).
type Result struct {
	PollType    string
	Sent        int
	Received    int
	RTTMin      time.Duration
	RTTAvg      time.Duration
	RTTMax      time.Duration
	LossPercent float64
	Latency     time.Duration // whole-probe duration (poll_health.latency_ms)
	ErrorClass  string

	// SNMP fields (M9-S2). SnmpDone reports that every SNMP step of the probe
	// completed (a table walk that timed out leaves it false even when some
	// samples were produced). SnmpSamples carries already-rendered series, so
	// Result.Samples returns them verbatim.
	SnmpDone          bool
	SnmpSamples       []Sample
	SnmpMetricsSeen   int
	SnmpMetricsExpect int
	// InterfaceObservations carries the per-row IF-MIB attributes (M10-S2)
	// rendered by the prober for the server-side interfaces association. Rows
	// observed before a failed later walk are real data and are kept, like
	// samples.
	InterfaceObservations []InterfaceObservation
	// CPULoadHigh reports that the device answered while one of its
	// hrProcessorLoad values crossed the M9-S4 guard threshold (docs/07
	// §12.7): healthy poll, but the scheduler steps the cadence down.
	CPULoadHigh bool
}

// Reachable reports whether the poll produced a completed, usable result. For
// ICMP that is at least one echo reply; for SNMP it is a fully completed
// probe (a respond-but-truncated walk is a failure, P2-AC-20).
func (r Result) Reachable() bool {
	if r.PollType == PollSNMP {
		return r.SnmpDone
	}
	return r.Received > 0
}

// Outcome returns the poll-health outcome string.
func (r Result) Outcome() string {
	if r.Reachable() {
		return OutcomeSuccess
	}
	return OutcomeFailure
}

// Samples renders the series for one poll window. SNMP samples are rendered by
// the SNMP prober (they carry counter math and dimensions) and returned as-is.
// When no packet was actually sent (unsupported platform / transport failure
// before send) no samples are produced: an untried probe must not fabricate
// loss data. A failed attempt produces reachable=0 and loss=100; the RTT
// series is omitted for windows without replies so the outage is a gap, not a
// fake zero.
func (r Result) Samples(target Target, ts time.Time) []Sample {
	if r.PollType == PollSNMP {
		return r.SnmpSamples
	}
	if r.Sent == 0 {
		return nil
	}
	reachable := 0.0
	if r.Reachable() {
		reachable = 1
	}
	out := []Sample{
		{MetricKey: MetricReachable, Unit: UnitState, Value: reachable, Ts: ts, DeviceID: target.DeviceID},
		{MetricKey: MetricLossPct, Unit: UnitPercent, Value: r.LossPercent, Ts: ts, DeviceID: target.DeviceID},
	}
	if r.Reachable() {
		out = append(out, Sample{
			MetricKey: MetricRTT, Unit: UnitMS,
			Value: float64(r.RTTAvg.Microseconds()) / 1000.0,
			Ts:    ts, DeviceID: target.DeviceID,
		})
	}
	return out
}

// Prober executes one poll against one target.
type Prober interface {
	Probe(ctx context.Context, target Target) Result
}

// ICMPProber is the ICMP echo prober. It composes a Pinger (socket I/O) so the
// normalization logic is unit-testable with an injectable fake.
type ICMPProber struct {
	pinger   Pinger
	count    int
	interval time.Duration
	timeout  time.Duration
	// pingerErr is set when socket creation failed; every probe then reports
	// `unsupported` (no samples, health only).
	pingerErr error
}

// ICMPConfig configures the prober. Zero values take the documented defaults.
type ICMPConfig struct {
	Pinger   Pinger // nil: the platform socket pinger is created
	Count    int
	Interval time.Duration
	Timeout  time.Duration
}

// NewICMPProber builds the production prober. On Linux the socket pinger tries
// a raw socket first (CAP_NET_RAW) and falls back to an unprivileged ICMP
// ping socket (net.ipv4.ping_group_range); on other platforms construction
// succeeds but every probe reports `unsupported` so the collector still runs
// and the health path is exercised.
func NewICMPProber(cfg ICMPConfig) *ICMPProber {
	p := &ICMPProber{pinger: cfg.Pinger, count: cfg.Count, interval: cfg.Interval, timeout: cfg.Timeout}
	if p.count <= 0 || p.count > MaxPingCount {
		p.count = DefaultPingCount
	}
	if p.interval <= 0 {
		p.interval = DefaultPingInterval
	}
	if p.timeout <= 0 {
		p.timeout = DefaultPingTimeout
	}
	if p.pinger == nil {
		sock, err := newSocketPinger()
		if err != nil {
			p.pingerErr = err
		} else {
			p.pinger = sock
		}
	}
	return p
}

// Probe implements Prober. ICMPv6 is not implemented in this slice (canonical
// docs/07 §: IPv6/ICMPv6 is V2); IPv6 targets report `unsupported`.
func (p *ICMPProber) Probe(ctx context.Context, target Target) Result {
	start := time.Now()
	res := Result{PollType: PollICMP, LossPercent: 100}
	if p.pingerErr != nil || p.pinger == nil {
		res.ErrorClass = ErrorUnsupported
		res.Latency = time.Since(start)
		return res
	}
	if !target.MgmtIP.Is4() {
		res.ErrorClass = ErrorUnsupported
		res.Latency = time.Since(start)
		return res
	}
	rtts, err := p.pinger.Ping(ctx, target.MgmtIP, p.count, p.interval, p.timeout)
	if err != nil {
		res.ErrorClass = classifyPingError(err)
		res.Latency = time.Since(start)
		return res
	}
	res.Sent = p.count
	res.Received = len(rtts)
	if res.Received > 0 {
		var sum time.Duration
		res.RTTMin, res.RTTMax = rtts[0], rtts[0]
		for _, rtt := range rtts {
			sum += rtt
			if rtt < res.RTTMin {
				res.RTTMin = rtt
			}
			if rtt > res.RTTMax {
				res.RTTMax = rtt
			}
		}
		res.RTTAvg = sum / time.Duration(res.Received)
	}
	res.LossPercent = float64(res.Sent-res.Received) / float64(res.Sent) * 100
	if !res.Reachable() {
		res.ErrorClass = ErrorTimeout
	} else if res.LossPercent > 0 {
		// Partial loss is degraded but reachable: success with a non-empty
		// class so consumers can distinguish a lossy window (P2-AC-20).
		res.ErrorClass = ErrorLoss
	}
	res.Latency = time.Since(start)
	return res
}

// Close releases the underlying socket.
func (p *ICMPProber) Close() error {
	if p.pinger == nil {
		return nil
	}
	return p.pinger.Close()
}

func classifyPingError(err error) string {
	switch {
	case errors.Is(err, ErrUnsupportedPlatform):
		return ErrorUnsupported
	case errors.Is(err, context.DeadlineExceeded):
		return ErrorTimeout
	default:
		return ErrorUnreachable
	}
}

// PingError carries a machine-readable class for transport-level ping
// failures (e.g. "network is unreachable").
type PingError struct {
	Class string
	Err   error
}

func (e *PingError) Error() string { return fmt.Sprintf("poll: ping %s: %v", e.Class, e.Err) }
func (e *PingError) Unwrap() error { return e.Err }
