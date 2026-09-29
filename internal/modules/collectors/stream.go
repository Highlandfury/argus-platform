package collectors

import (
	"errors"
	"io"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
	"github.com/argus-platform/argus/internal/modules/ingest"
	"github.com/argus-platform/argus/internal/platform/grpcx"
)

const (
	maxInflightBatches = 8
	maxBatchSamples    = 5000
)

// StreamServer implements collectorv1.CollectorService (port 8443, mTLS).
// It owns the server-side session lifecycle: identity resolution, hello
// validation, policy delivery, heartbeat/ack handling, deterministic duplicate
// handling, revocation/shutdown disconnects, and delivery of metric batches to
// the ingest pipeline (M4).
type StreamServer struct {
	collectorv1.UnimplementedCollectorServiceServer
	Svc      *Service
	Registry *SessionRegistry
	Ingest   ingest.Ingester
	Log      *slog.Logger
}

// NewStreamServer wires the collector stream service. ingester may be nil in
// degraded configurations (batches are then explicitly rejected, never
// silently dropped).
func NewStreamServer(svc *Service, registry *SessionRegistry, ingester ingest.Ingester, log *slog.Logger) *StreamServer {
	return &StreamServer{Svc: svc, Registry: registry, Ingest: ingester, Log: log}
}

// Stream is the single bidirectional control/telemetry stream per collector.
func (s *StreamServer) Stream(gstream collectorv1.CollectorService_StreamServer) error {
	ctx := gstream.Context()
	metrics := s.Svc.metrics

	fingerprint, err := grpcx.PeerCertificateFingerprint(ctx)
	if err != nil {
		metrics.connects.WithLabelValues("no_certificate").Inc()
		return status.Error(codes.Unauthenticated, "client certificate required")
	}
	ident, err := s.Svc.ResolveCertificate(ctx, fingerprint)
	if err != nil {
		metrics.connects.WithLabelValues("unknown_identity").Inc()
		return status.Error(codes.Unauthenticated, "unknown collector identity")
	}
	if ident.RevokedAt != nil || ident.Status == "revoked" {
		metrics.connects.WithLabelValues("revoked").Inc()
		_ = gstream.Send(disconnectMsg(collectorv1.Disconnect_CODE_REVOKED, "collector revoked"))
		return nil
	}

	recvCh := make(chan *collectorv1.ClientMessage, 16)
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

	// First message must be the hello, and it must match the certificate.
	var first *collectorv1.ClientMessage
	select {
	case first = <-recvCh:
	case err := <-recvErr:
		return normalizeStreamErr(err)
	case <-ctx.Done():
		return nil
	}
	hello := first.GetHello()
	if hello == nil {
		return s.protocolError(gstream, "first message must be ClientHello")
	}
	if hello.GetCollectorId() != ident.CollectorID.String() {
		metrics.connects.WithLabelValues("identity_mismatch").Inc()
		return s.protocolError(gstream, "hello collector_id does not match certificate identity")
	}
	if hello.GetProtocolVersion() != ProtocolVersion {
		return s.protocolError(gstream, "unsupported protocol version")
	}

	agentVersion := strPtr(hello.GetAgentVersion())
	if err := s.Svc.MarkConnected(ctx, ident.OrgID, ident.CollectorID, agentVersion); err != nil && s.Log != nil {
		s.Log.Error("mark collector connected", "collector_id", ident.CollectorID, "error", err)
	}

	session, superseded := s.Registry.Register(ident.CollectorID)
	defer s.Registry.Unregister(ident.CollectorID, session)
	metrics.streamsActive.Inc()
	defer metrics.streamsActive.Dec()
	switch {
	case superseded:
		metrics.connects.WithLabelValues("superseded_previous").Inc()
	default:
		metrics.connects.WithLabelValues("ok").Inc()
	}

	// ServerHello: latest signed policy is always included; the collector
	// applies it only when the version is newer and acks either way (the ack
	// is the server's source of truth for applied version).
	latest, err := s.Svc.LatestPolicy(ctx, ident.OrgID, ident.CollectorID)
	if err != nil && s.Log != nil {
		s.Log.Error("load latest policy", "collector_id", ident.CollectorID, "error", err)
	}
	// Ingest authorization: the batch allowlist tracks the signed policy
	// currently in effect (refreshed on push and on acks of newer versions).
	allowlist, allowlistVersion := policyAllowlist(latest)
	refreshAllowlist := func() {
		current, err := s.Svc.LatestPolicy(ctx, ident.OrgID, ident.CollectorID)
		if err != nil || current == nil {
			return
		}
		if m, v := policyAllowlist(current); m != nil {
			allowlist, allowlistVersion = m, v
		}
	}
	if err := gstream.Send(&collectorv1.ServerMessage{
		Msg: &collectorv1.ServerMessage_Hello{Hello: &collectorv1.ServerHello{
			ServerTime:               timestamppb.Now(),
			ProtocolVersion:          ProtocolVersion,
			MaxInflightBatches:       maxInflightBatches,
			MaxBatchSamples:          maxBatchSamples,
			HeartbeatIntervalSeconds: uint32(DefaultHeartbeatInterval / time.Second),
			Policy:                   policyToProto(latest),
		}},
	}); err != nil {
		return normalizeStreamErr(err)
	}

	for {
		select {
		case msg := <-recvCh:
			switch {
			case msg.GetHeartbeat() != nil:
				hb := msg.GetHeartbeat()
				stats := HeartbeatStats{
					SpoolBytes:          hb.GetSpoolBytes(),
					SpoolRecords:        hb.GetSpoolRecords(),
					HighestSeq:          hb.GetHighestSeq(),
					AckedSeq:            hb.GetAckedSeq(),
					DroppedRecordsTotal: hb.GetDroppedRecordsTotal(),
					CorruptRecordsTotal: hb.GetCorruptRecordsTotal(),
					ClockSkewMillis:     hb.GetClockSkewMs(),
					UptimeSeconds:       hb.GetUptimeSeconds(),
				}
				if err := s.Svc.RecordHeartbeat(ctx, ident.OrgID, ident.CollectorID, stats); err != nil && s.Log != nil {
					s.Log.Error("record heartbeat", "collector_id", ident.CollectorID, "error", err)
				}
			case msg.GetPolicyAck() != nil:
				ack := msg.GetPolicyAck()
				if ack.GetApplied() && ack.GetPolicyVersion() > allowlistVersion {
					refreshAllowlist()
				}
				if err := s.Svc.RecordPolicyAck(ctx, ident.OrgID, ident.CollectorID, ack.GetPolicyVersion(), ack.GetApplied()); err != nil && s.Log != nil {
					s.Log.Error("record policy ack", "collector_id", ident.CollectorID, "error", err)
				}
			case msg.GetBatch() != nil:
				batch := msg.GetBatch()
				outcome := ingest.BatchOutcome{
					Status: collectorv1.BatchResult_STATUS_REJECTED,
					Reason: "ingest.unavailable",
				}
				switch {
				case s.Ingest == nil:
					// Degraded: explicit rejection; never a silent drop.
				case allowlist == nil:
					samples := 0
					if batch != nil {
						samples = len(batch.GetSamples())
					}
					outcome = ingest.BatchOutcome{
						Status:   collectorv1.BatchResult_STATUS_REJECTED,
						Reason:   "validation.policy_unavailable",
						Rejected: uint32(samples), //nolint:gosec // bounded by maxBatchSamples
					}
				default:
					outcome = s.Ingest.IngestBatch(ctx, ident.OrgID, ident.CollectorID, allowlist, batch)
				}
				if err := gstream.Send(batchResultMsg(batch.GetBatchSeq(), outcome)); err != nil {
					return normalizeStreamErr(err)
				}
			case msg.GetHello() != nil:
				return s.protocolError(gstream, "duplicate hello")
			default:
				return s.protocolError(gstream, "unsupported message")
			}
		case dm := <-session.Notify():
			_ = gstream.Send(disconnectMsg(dm.Code, dm.Reason))
			return nil
		case sp := <-session.Policy():
			metrics.policyPushes.Inc()
			if m, v := policyAllowlist(sp); m != nil {
				allowlist, allowlistVersion = m, v
			}
			_ = gstream.Send(&collectorv1.ServerMessage{
				Msg: &collectorv1.ServerMessage_PolicyUpdate{PolicyUpdate: &collectorv1.PolicyUpdate{Policy: policyToProto(sp)}},
			})
		case err := <-recvErr:
			return normalizeStreamErr(err)
		case <-ctx.Done():
			return nil
		}
	}
}

func disconnectMsg(code collectorv1.Disconnect_Code, reason string) *collectorv1.ServerMessage {
	return &collectorv1.ServerMessage{
		Msg: &collectorv1.ServerMessage_Disconnect{Disconnect: &collectorv1.Disconnect{Code: code, Reason: reason}},
	}
}

// policyAllowlist parses a signed policy document into the ingest allowlist.
// A nil or unparsable policy yields a nil allowlist (ingest then rejects with
// validation.policy_unavailable rather than guessing).
func policyAllowlist(sp *SignedPolicy) (map[string]ingest.MetricDef, int64) {
	if sp == nil {
		return nil, 0
	}
	allowlist, err := ingest.AllowlistFromPolicy(sp.Document)
	if err != nil {
		return nil, 0
	}
	return allowlist, sp.Version
}

// batchResultMsg converts a pipeline outcome into the wire BatchResult.
func batchResultMsg(seq int64, outcome ingest.BatchOutcome) *collectorv1.ServerMessage {
	result := &collectorv1.BatchResult{
		BatchSeq:        seq,
		Status:          outcome.Status,
		Reason:          outcome.Reason,
		AcceptedSamples: outcome.Accepted,
		RejectedSamples: outcome.Rejected,
	}
	if !outcome.IngestedAt.IsZero() {
		result.IngestedAt = timestamppb.New(outcome.IngestedAt)
	}
	return &collectorv1.ServerMessage{
		Msg: &collectorv1.ServerMessage_BatchResult{BatchResult: result},
	}
}

func (s *StreamServer) protocolError(gstream collectorv1.CollectorService_StreamServer, reason string) error {
	s.Svc.metrics.connects.WithLabelValues("protocol_error").Inc()
	_ = gstream.Send(disconnectMsg(collectorv1.Disconnect_CODE_PROTOCOL_ERROR, reason))
	return status.Error(codes.InvalidArgument, reason)
}

// normalizeStreamErr maps transport-level failures: a clean client close (EOF)
// is success; everything else keeps its gRPC status.
func normalizeStreamErr(err error) error {
	if errors.Is(err, io.EOF) {
		return nil
	}
	if status.Code(err) != codes.Unknown {
		return err
	}
	return status.Error(codes.Unavailable, err.Error())
}
