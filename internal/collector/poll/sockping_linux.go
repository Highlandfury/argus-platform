//go:build linux

package poll

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// socketPinger is the Linux ICMP echo implementation. One socket is opened per
// probe window: concurrent probes never share a receive queue (which would
// cross-deliver replies), and the per-window socket overhead is negligible at
// poll cadences.
//
// Capability requirements (canonical docs/06 §C1 / docs/15 §):
//   - raw mode ("ip4:icmp") needs CAP_NET_RAW or root;
//   - unprivileged mode ("udp4", Linux ping sockets) needs the process's GID
//     inside net.ipv4.ping_group_range (the distroless nonroot image ships a
//     helper that widens it, or the unit grants CAP_NET_RAW).
//
// The prober documents which mode it selected through the health error class
// (`unsupported` when neither is available).
type socketPinger struct {
	network string // "ip4:icmp" (raw, privileged) or "udp4" (ping socket)
}

// newSocketPinger selects the best available ICMP socket mode once at startup.
func newSocketPinger() (Pinger, error) {
	if c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0"); err == nil {
		_ = c.Close()
		return &socketPinger{network: "ip4:icmp"}, nil
	}
	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("%w: raw and unprivileged ICMP sockets unavailable: %w", ErrUnsupportedPlatform, err)
	}
	_ = c.Close()
	return &socketPinger{network: "udp4"}, nil
}

// Ping implements Pinger.
func (p *socketPinger) Ping(ctx context.Context, addr netip.Addr, count int, interval, timeout time.Duration) ([]time.Duration, error) {
	if !addr.Is4() {
		// ICMPv6 is V2 (canonical docs/03); the prober reports it unsupported.
		return nil, ErrUnsupportedPlatform
	}
	conn, err := icmp.ListenPacket(p.network, "0.0.0.0")
	if err != nil {
		return nil, &PingError{Class: ErrorUnsupported, Err: err}
	}
	defer func() { _ = conn.Close() }()

	udp := p.network == "udp4"
	dst := net.Addr(&net.IPAddr{IP: addr.AsSlice()})
	if udp {
		dst = &net.UDPAddr{IP: addr.AsSlice()}
	}
	// The identifier distinguishes our echo stream from stale packets; ping
	// sockets rewrite it on the wire, so replies are matched by sequence and
	// peer address instead.
	id := int(time.Now().UnixNano() & 0xffff)
	payload := make([]byte, 24)

	rtts := make([]time.Duration, 0, count)
	for seq := 1; seq <= count; seq++ {
		if err := ctx.Err(); err != nil {
			return rtts, err
		}
		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{ID: id, Seq: seq, Data: payload},
		}
		wire, err := msg.Marshal(nil)
		if err != nil {
			return rtts, fmt.Errorf("poll: marshal echo: %w", err)
		}
		start := time.Now()
		if _, err := conn.WriteTo(wire, dst); err != nil {
			return rtts, &PingError{Class: ErrorUnreachable, Err: err}
		}
		if rtt, ok, err := awaitEchoReply(ctx, conn, udp, addr, seq, start, start.Add(timeout)); err != nil {
			return rtts, err
		} else if ok {
			rtts = append(rtts, rtt)
		}
		if seq < count {
			wait := interval - time.Since(start)
			if wait > 0 {
				timer := time.NewTimer(wait)
				select {
				case <-ctx.Done():
					timer.Stop()
					return rtts, ctx.Err()
				case <-timer.C:
				}
			}
		}
	}
	return rtts, nil
}

// awaitEchoReply waits until deadline for the echo reply of seq from addr.
// A deadline with no matching reply is packet loss (ok=false, nil error).
func awaitEchoReply(ctx context.Context, conn *icmp.PacketConn, udp bool, addr netip.Addr, seq int, start, deadline time.Time) (time.Duration, bool, error) {
	buf := make([]byte, 1500)
	for {
		if err := ctx.Err(); err != nil {
			return 0, false, err
		}
		if err := conn.SetReadDeadline(deadline); err != nil {
			return 0, false, err
		}
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return 0, false, nil
			}
			return 0, false, &PingError{Class: ErrorUnreachable, Err: err}
		}
		if !peerMatches(peer, udp, addr) {
			continue
		}
		parsed, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}
		if parsed.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		echo, ok := parsed.Body.(*icmp.Echo)
		if !ok || echo.Seq != seq {
			continue
		}
		return time.Since(start), true, nil
	}
}

func peerMatches(peer net.Addr, udp bool, addr netip.Addr) bool {
	switch a := peer.(type) {
	case *net.UDPAddr:
		got, ok := netip.AddrFromSlice(a.IP)
		return ok && got.Unmap() == addr
	case *net.IPAddr:
		got, ok := netip.AddrFromSlice(a.IP)
		return ok && got.Unmap() == addr
	default:
		return !udp // raw sockets with an unparsable peer keep trying
	}
}

// Close implements Pinger (sockets are per probe; nothing persists).
func (p *socketPinger) Close() error { return nil }
