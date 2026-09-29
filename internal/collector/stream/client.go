// Package stream implements the collector-side mTLS control stream: connect,
// hello, policy apply+ack, heartbeats, reconnect with backoff, and terminal
// handling of server disconnects (REVOKED must stop retrying).
package stream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
	"github.com/argus-platform/argus/internal/collector"
	"github.com/argus-platform/argus/internal/collector/policy"
)

const protocolVersion = 1

// DisconnectError carries a server-ordered disconnect code.
type DisconnectError struct {
	Code   collectorv1.Disconnect_Code
	Reason string
}

func (e *DisconnectError) Error() string {
	return fmt.Sprintf("collector stream disconnected: %s (%s)", e.Code, e.Reason)
}

// Config is the stream client input.
type Config struct {
	StreamAddr     string
	CAFile         string
	CertFile       string
	KeyFile        string
	CollectorID    string
	AgentVersion   string
	PolicyDir      string
	Log            *slog.Logger
	AppliedVersion int64
	PolicyKeyDER   []byte
	// OnPolicyApplied is invoked after a new policy version is verified and
	// persisted (used to persist the applied version in collector.json).
	OnPolicyApplied func(version int64)
	// OnDisconnect is invoked for every server-ordered disconnect (test/logging
	// observability; the caller never has to parse error strings).
	OnDisconnect func(code collectorv1.Disconnect_Code, reason string)
}

// Client runs the control stream lifecycle.
type Client struct {
	cfg     Config
	machine *collector.Machine
}

// New creates a stream client bound to a state machine.
func New(cfg Config, machine *collector.Machine) *Client {
	return &Client{cfg: cfg, machine: machine}
}

func (c *Client) log() *slog.Logger {
	if c.cfg.Log != nil {
		return c.cfg.Log
	}
	return slog.Default()
}

// disconnectErr centralizes server-ordered disconnect creation + the
// observability hook.
func (c *Client) disconnectErr(code collectorv1.Disconnect_Code, reason string) *DisconnectError {
	if c.cfg.OnDisconnect != nil {
		c.cfg.OnDisconnect(code, reason)
	}
	return &DisconnectError{Code: code, Reason: reason}
}

// Run drives connect -> active -> reconnect until ctx ends or the identity is
// revoked (terminal). It returns nil for clean shutdown and revocation.
func (c *Client) Run(ctx context.Context) error {
	backoff := time.Second
	for {
		err := c.runOnce(ctx)
		if ctx.Err() != nil {
			return nil
		}

		var dErr *DisconnectError
		if errors.As(err, &dErr) {
			switch dErr.Code {
			case collectorv1.Disconnect_CODE_REVOKED:
				c.log().Error("collector revoked by server; stopping permanently", "reason", dErr.Reason)
				_ = c.machine.Transition(collector.StateRevoked)
				return nil
			case collectorv1.Disconnect_CODE_PROTOCOL_ERROR:
				c.log().Error("protocol error; stopping", "reason", dErr.Reason)
				_ = c.machine.Transition(collector.StateFailed)
				return fmt.Errorf("stream: %w", dErr)
			}
		}
		c.log().Warn("stream lost; will reconnect", "error", err, "backoff", backoff)
		if c.machine.State() == collector.StateActive {
			_ = c.machine.Transition(collector.StateDisconnected)
		}
		if c.machine.State() != collector.StateReconnecting {
			if err := c.machine.Transition(collector.StateReconnecting); err != nil {
				c.log().Error("state transition", "error", err)
			}
		}

		jitter := time.Duration(rand.Int63n(int64(backoff) / 2)) //nolint:gosec // jitter, not security material
		select {
		case <-time.After(backoff + jitter):
		case <-ctx.Done():
			return nil
		}
		if backoff < 30*time.Second {
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
}

func (c *Client) runOnce(ctx context.Context) error {
	caPEM, err := os.ReadFile(c.cfg.CAFile)
	if err != nil {
		return fmt.Errorf("stream: read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return errors.New("stream: pinned CA contains no certificates")
	}
	cert, err := tls.LoadX509KeyPair(c.cfg.CertFile, c.cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("stream: load client identity: %w", err)
	}
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	})
	conn, err := grpc.NewClient(c.cfg.StreamAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("stream: dial: %w", err)
	}
	defer func() { _ = conn.Close() }()

	client := collectorv1.NewCollectorServiceClient(conn)
	gstream, err := client.Stream(ctx)
	if err != nil {
		return fmt.Errorf("stream: open: %w", err)
	}
	send := func(m *collectorv1.ClientMessage) error { return gstream.Send(m) }

	if err := send(&collectorv1.ClientMessage{
		Msg: &collectorv1.ClientMessage_Hello{Hello: &collectorv1.ClientHello{
			CollectorId:     c.cfg.CollectorID,
			AgentVersion:    c.cfg.AgentVersion,
			ProtocolVersion: protocolVersion,
		}},
	}); err != nil {
		return fmt.Errorf("stream: hello: %w", err)
	}

	recvCh := make(chan *collectorv1.ServerMessage, 16)
	recvErr := make(chan error, 1)
	go func() {
		for {
			msg, err := gstream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case recvCh <- msg:
			case <-ctx.Done():
				return
			}
		}
	}()

	var hello *collectorv1.ServerHello
	select {
	case msg := <-recvCh:
		switch {
		case msg.GetHello() != nil:
			hello = msg.GetHello()
		case msg.GetDisconnect() != nil:
			// Revoked (or otherwise terminated) between auth and hello.
			d := msg.GetDisconnect()
			return c.disconnectErr(d.GetCode(), d.GetReason())
		default:
			return c.disconnectErr(collectorv1.Disconnect_CODE_PROTOCOL_ERROR, "expected ServerHello")
		}
	case err := <-recvErr:
		return normalize(err)
	case <-ctx.Done():
		return nil
	}

	if err := c.handlePolicy(send, hello.GetPolicy()); err != nil {
		c.log().Error("initial policy rejected", "error", err)
	}
	if c.machine.State() != collector.StateActive {
		if err := c.machine.Transition(collector.StateActive); err != nil {
			return err
		}
	}

	heartbeatEvery := time.Duration(hello.GetHeartbeatIntervalSeconds()) * time.Second
	if heartbeatEvery <= 0 {
		heartbeatEvery = 30 * time.Second
	}
	ticker := time.NewTicker(heartbeatEvery)
	defer ticker.Stop()
	started := time.Now()
	var skewMillis int64
	if st := hello.GetServerTime(); st != nil {
		skewMillis = time.Since(st.AsTime()).Milliseconds()
	}

	for {
		select {
		case msg := <-recvCh:
			switch {
			case msg.GetPolicyUpdate() != nil:
				if err := c.handlePolicy(send, msg.GetPolicyUpdate().GetPolicy()); err != nil {
					c.log().Error("policy update rejected", "error", err)
				}
			case msg.GetPing() != nil:
				if st := msg.GetPing().GetServerTime(); st != nil {
					skewMillis = time.Since(st.AsTime()).Milliseconds()
				}
			case msg.GetBatchResult() != nil:
				// Batch acknowledgements are M4 functionality; nothing to do.
			case msg.GetHello() != nil:
				return c.disconnectErr(collectorv1.Disconnect_CODE_PROTOCOL_ERROR, "duplicate ServerHello")
			case msg.GetDisconnect() != nil:
				d := msg.GetDisconnect()
				return c.disconnectErr(d.GetCode(), d.GetReason())
			}
		case <-ticker.C:
			if err := send(&collectorv1.ClientMessage{
				Msg: &collectorv1.ClientMessage_Heartbeat{Heartbeat: &collectorv1.Heartbeat{
					SentAt:        timestamppb.Now(),
					ClockSkewMs:   skewMillis,
					AgentVersion:  c.cfg.AgentVersion,
					UptimeSeconds: int64(time.Since(started).Seconds()),
				}},
			}); err != nil {
				return normalize(err)
			}
		case err := <-recvErr:
			return normalize(err)
		case <-ctx.Done():
			return nil
		}
	}
}

// handlePolicy verifies, validates, stores, and acks a policy. Invalid policy
// is rejected with applied=false while the previous good state is kept.
func (c *Client) handlePolicy(send func(*collectorv1.ClientMessage) error, p *collectorv1.Policy) error {
	ack := func(version int64, applied bool, reason string) {
		_ = send(&collectorv1.ClientMessage{
			Msg: &collectorv1.ClientMessage_PolicyAck{PolicyAck: &collectorv1.PolicyAck{
				PolicyVersion: version,
				Applied:       applied,
				Error:         reason,
			}},
		})
	}
	if p == nil {
		return nil
	}
	version := p.GetVersion()
	if _, err := policy.VerifyAndValidate(p.GetDocument(), p.GetSignature(), c.cfg.PolicyKeyDER); err != nil {
		ack(version, false, err.Error())
		return err
	}
	if version <= c.cfg.AppliedVersion {
		ack(version, true, "") // idempotent re-delivery
		return nil
	}
	if _, err := policy.Store(c.cfg.PolicyDir, version, p.GetDocument()); err != nil {
		ack(version, false, "store failed")
		return err
	}
	c.cfg.AppliedVersion = version
	if c.cfg.OnPolicyApplied != nil {
		c.cfg.OnPolicyApplied(version)
	}
	ack(version, true, "")
	c.log().Info("policy applied", "version", version)
	return nil
}

// normalize maps a clean client close (EOF) to a normal disconnect signal.
func normalize(err error) error {
	if errors.Is(err, io.EOF) {
		return &DisconnectError{Code: collectorv1.Disconnect_CODE_SERVER_SHUTDOWN, Reason: "server closed the stream"}
	}
	return err
}
