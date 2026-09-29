// Request-ID propagation (SPEC §15): every RPC/stream receives a correlation
// ID (from x-request-id metadata when valid, otherwise generated), which is
// stored in the handler context for structured logs and echoed in the response
// headers. The interceptors are pure observability: they never fail an RPC.

package grpcx

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/argus-platform/argus/internal/platform/httpx"
)

// MetadataRequestID is the correlation-ID metadata key.
const MetadataRequestID = "x-request-id"

type requestIDKey struct{}

// RequestIDFrom extracts the correlation ID established by the interceptors.
func RequestIDFrom(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey{}).(string); ok {
		return v
	}
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := md.Get(MetadataRequestID); len(vals) > 0 {
			return httpx.SanitizeRequestID(vals[0])
		}
	}
	return ""
}

func incomingRequestID(ctx context.Context) string {
	id := ""
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := md.Get(MetadataRequestID); len(vals) > 0 {
			id = vals[0]
		}
	}
	return httpx.SanitizeRequestID(id)
}

// UnaryServerInterceptor establishes and echoes the correlation ID for unary
// RPCs (e.g. enrollment).
func UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		id := incomingRequestID(ctx)
		_ = grpc.SetHeader(ctx, metadata.Pairs(MetadataRequestID, id))
		return handler(context.WithValue(ctx, requestIDKey{}, id), req)
	}
}

// StreamServerInterceptor establishes and echoes the correlation ID for
// streams (collector control/telemetry). One ID per stream session; individual
// messages are not treated as new requests.
func StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		id := incomingRequestID(ss.Context())
		_ = ss.SetHeader(metadata.Pairs(MetadataRequestID, id))
		return handler(srv, &serverStream{ServerStream: ss, ctx: context.WithValue(ss.Context(), requestIDKey{}, id)})
	}
}

type serverStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *serverStream) Context() context.Context { return s.ctx }
