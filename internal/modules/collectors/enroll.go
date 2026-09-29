package collectors

import (
	"context"
	"errors"
	"log/slog"
	"net"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
	"github.com/argus-platform/argus/internal/platform/ratelimit"
)

// ProtocolVersion is the collector wire protocol major version.
const ProtocolVersion = 1

// EnrollmentServer implements collectorv1.EnrollmentService (port 8444,
// server-authenticated TLS only; the token is the pre-auth credential).
type EnrollmentServer struct {
	collectorv1.UnimplementedEnrollmentServiceServer
	Svc     *Service
	Limiter *ratelimit.Limiter
	Log     *slog.Logger
}

// NewEnrollmentServer wires the enrollment RPC.
func NewEnrollmentServer(svc *Service, limiter *ratelimit.Limiter, log *slog.Logger) *EnrollmentServer {
	return &EnrollmentServer{Svc: svc, Limiter: limiter, Log: log}
}

// Enroll handles the one-time token + CSR exchange. Failure modes are uniform
// where the spec requires no oracle (bad/expired/used token), distinct where
// the spec requires actionable errors (malformed CSR, name collision).
func (s *EnrollmentServer) Enroll(ctx context.Context, req *collectorv1.EnrollRequest) (*collectorv1.EnrollResponse, error) {
	if s.Limiter != nil {
		if ok, retry := s.Limiter.Allow(peerIP(ctx)); !ok {
			s.Svc.metrics.enrollments.WithLabelValues("rate_limited").Inc()
			return nil, status.Errorf(codes.ResourceExhausted, "too many enrollment attempts; retry after %s", retry)
		}
	}
	if req.GetEnrollmentToken() == "" || len(req.GetEnrollmentToken()) > 128 {
		return nil, status.Error(codes.InvalidArgument, "enrollment failed")
	}
	if req.GetCsrPem() == "" || len(req.GetCsrPem()) > 16*1024 {
		return nil, status.Error(codes.InvalidArgument, "invalid certificate request")
	}
	if req.GetCollectorName() == "" || len(req.GetCollectorName()) > 128 {
		return nil, status.Error(codes.InvalidArgument, "collector name is required (max 128 chars)")
	}

	res, err := s.Svc.Enroll(ctx, EnrollRequest{
		Token:        req.GetEnrollmentToken(),
		CSR:          req.GetCsrPem(),
		Name:         req.GetCollectorName(),
		AgentVersion: req.GetAgentVersion(),
		Hostname:     req.GetHostname(),
		OS:           req.GetOs(),
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrEnrollDenied), errors.Is(err, ErrSiteRequired):
			// Uniform: callers cannot distinguish unknown/expired/used/scope.
			return nil, status.Error(codes.PermissionDenied, "enrollment failed")
		case errors.Is(err, ErrInvalidCSR):
			return nil, status.Error(codes.InvalidArgument, "invalid certificate request")
		case errors.Is(err, ErrNameTaken):
			return nil, status.Error(codes.AlreadyExists, "collector name already enrolled")
		default:
			if s.Log != nil {
				s.Log.Error("enrollment failed", "error", err)
			}
			return nil, status.Error(codes.Internal, "enrollment failed")
		}
	}

	return &collectorv1.EnrollResponse{
		CollectorId:            res.CollectorID.String(),
		ClientCertPem:          string(res.CertPEM),
		CaChainPem:             string(res.ChainPEM),
		CertNotAfter:           timestamppb.New(res.CertNotAfter),
		Policy:                 policyToProto(res.Policy),
		ServerTime:             timestamppb.New(res.ServerTime),
		PolicySigningPublicKey: res.PolicyPubDER,
	}, nil
}

// policyToProto converts a signed policy into its wire form.
func policyToProto(sp *SignedPolicy) *collectorv1.Policy {
	if sp == nil {
		return nil
	}
	return &collectorv1.Policy{
		Version:      sp.Version,
		Document:     sp.Document,
		Signature:    sp.Signature,
		SigningKeyId: sp.KeyID,
		JitterSalt:   sp.JitterSalt,
	}
}

func peerIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return p.Addr.String()
	}
	return host
}
