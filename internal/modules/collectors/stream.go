package collectors

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
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

	// streamIngestConcurrency is the process-wide budget of concurrent batch
	// transactions. One stream may use the whole budget (measured: a single
	// stream needs ~6-8 concurrent transactions to move from ~9k to ~19k
	// samples/s); a fleet shares it. Without the process-wide bound, 200
	// collectors × 6 in-flight batches queue 1,200 transactions against the
	// 10-connection pool, per-batch latency crosses the collector ack timeout,
	// and streams cancel their own in-flight work (measured during L-02;
	// ADR-016). Acquisition happens in the stream's receive loop, so a stream
	// never builds an internal queue: backpressure reaches the collector
	// through gRPC flow control instead.
	streamIngestConcurrency = 8
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

	// ingestGlobal is the process-wide batch-transaction budget (see
	// streamIngestConcurrency). Initialized by NewStreamServer.
	ingestGlobal chan struct{}
}

// NewStreamServer wires the collector stream service. ingester may be nil in
// degraded configurations (batches are then explicitly rejected, never
// silently dropped).
func NewStreamServer(svc *Service, registry *SessionRegistry, ingester ingest.Ingester, log *slog.Logger) *StreamServer {
	return &StreamServer{
		Svc:          svc,
		Registry:     registry,
		Ingest:       ingester,
		Log:          log,
		ingestGlobal: make(chan struct{}, streamIngestConcurrency),
	}
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
	reqID := grpcx.RequestIDFrom(ctx)
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
		s.countStreamError(err)
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
		s.Log.Error("mark collector connected", "request_id", reqID, "collector_id", ident.CollectorID, "error", err)
	}
	if s.Log != nil {
		s.Log.Info("collector stream connected",
			"request_id", reqID,
			"collector_id", ident.CollectorID,
			"agent_version", hello.GetAgentVersion(),
			"protocol_version", hello.GetProtocolVersion())
	}

	session, superseded := s.Registry.RegisterWithSessionKey(ident.CollectorID, hello.GetSessionPublicKey())
	defer s.Registry.Unregister(ident.CollectorID, session)
	metrics.streamsActive.Inc()
	defer metrics.streamsActive.Dec()
	switch {
	case superseded:
		metrics.connects.WithLabelValues("superseded_previous").Inc()
	default:
		metrics.connects.WithLabelValues("ok").Inc()
	}

	// ServerHello: latest signed policy is always included; when the collector
	// presented an ephemeral session key (M9-S3) the document additionally
	// carries credentials materialized to that key. The collector acks every
	// delivery and (re)applies credential material at version >= its applied
	// version (a reconnect re-keys the material), so the ack is the server's
	// source of truth for the applied version.
	latest, err := s.Svc.PolicyForSession(ctx, ident.OrgID, ident.CollectorID, hello.GetSessionPublicKey())
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

	// Batch pipelining (ADR-016, M8-S2a): the client may keep up to
	// maxInflightBatches batches in flight. Processing them strictly serially
	// capped one stream at a single commit at a time (measured ~9k samples/s
	// on the dev node); a process-wide worker budget lets a stream run several
	// batch transactions concurrently (WAL group commit + CPU parallelism)
	// while preserving every guarantee: each batch claims its own ledger row
	// (duplicate/concurrent batches stay idempotent, original wins), a
	// BatchResult is emitted only after IngestBatch returns
	// (ack-after-commit), ordering is not required by the protocol (the
	// collector advances its watermark on contiguous acks), and there are no
	// drops: with the budget exhausted the receive loop stops reading, so
	// backpressure reaches the collector and unacked batches are replayed.
	ingestResults := make(chan *collectorv1.ServerMessage, 2*streamIngestConcurrency)
	var ingestWG sync.WaitGroup
	defer ingestWG.Wait()

	dispatchBatch := func(batch *collectorv1.MetricBatch, allow map[string]ingest.MetricDef) {
		select {
		case s.ingestGlobal <- struct{}{}:
		case <-ctx.Done():
			return
		}
		ingestWG.Add(1)
		seq := batch.GetBatchSeq()
		go func() {
			defer ingestWG.Done()
			outcome := ingest.BatchOutcome{
				Status: collectorv1.BatchResult_STATUS_REJECTED,
				Reason: "ingest.unavailable",
			}
			switch {
			case s.Ingest == nil:
				// Degraded: explicit rejection; never a silent drop.
			case allow == nil && len(batch.GetSamples()) > 0:
				// Health-only batches need no metric allowlist: poll health
				// carries its own validated fields and persists under the same
				// batch claim (M9-S1).
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
				outcome = s.Ingest.IngestBatch(ctx, ident.OrgID, ident.CollectorID, allow, batch)
			}
			<-s.ingestGlobal // release before the (bounded) result send: no dispatch deadlock
			select {
			case ingestResults <- batchResultMsg(seq, outcome):
			case <-ctx.Done():
			}
		}()
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
					s.Log.Error("record heartbeat", "request_id", reqID, "collector_id", ident.CollectorID, "error", err)
				}
			case msg.GetPolicyAck() != nil:
				ack := msg.GetPolicyAck()
				if ack.GetApplied() && ack.GetPolicyVersion() > allowlistVersion {
					refreshAllowlist()
				}
				if err := s.Svc.RecordPolicyAck(ctx, ident.OrgID, ident.CollectorID, ack.GetPolicyVersion(), ack.GetApplied()); err != nil && s.Log != nil {
					s.Log.Error("record policy ack", "request_id", reqID, "collector_id", ident.CollectorID, "error", err)
				}
			case msg.GetBatch() != nil:
				dispatchBatch(msg.GetBatch(), allowlist)
			case msg.GetHello() != nil:
				return s.protocolError(gstream, "duplicate hello")
			default:
				return s.protocolError(gstream, "unsupported message")
			}
		case out := <-ingestResults:
			if err := gstream.Send(out); err != nil {
				return normalizeStreamErr(err)
			}
		case dm := <-session.Notify():
			if s.Log != nil {
				s.Log.Info("collector stream disconnected by server",
					"request_id", reqID,
					"collector_id", ident.CollectorID,
					"code", dm.Code.String(),
					"reason", dm.Reason)
			}
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
			s.countStreamError(err)
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
	if s.Log != nil {
		s.Log.Error("collector stream protocol error",
			"request_id", grpcx.RequestIDFrom(gstream.Context()),
			"reason", reason)
	}
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

// countStreamError increments argus_grpc_malformed_total for decode/size
// failures (Internal "failed to unmarshal" or ResourceExhausted). Ordinary
// disconnects (EOF, cancellation, transport unavailability) are not malformed.
func (s *StreamServer) countStreamError(err error) {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return
	}
	code := status.Code(err)
	if code == codes.Internal || code == codes.ResourceExhausted || strings.Contains(err.Error(), "failed to unmarshal") {
		s.Svc.metrics.malformed.Inc()
	}
}
