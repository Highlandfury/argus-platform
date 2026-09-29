package grpcx

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestUnaryInterceptorGeneratesAndEchoes(t *testing.T) {
	interceptor := UnaryServerInterceptor()
	var seen string
	handler := func(ctx context.Context, _ any) (any, error) {
		seen = RequestIDFrom(ctx)
		return "ok", nil
	}
	// No incoming metadata: a fresh ID is generated.
	if _, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{}, handler); err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	if seen == "" || !strings.HasPrefix(seen, "") {
		t.Fatalf("missing generated id: %q", seen)
	}

	// Caller-provided valid metadata is preserved.
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(MetadataRequestID, "collector-session-1"))
	if _, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, handler); err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	if seen != "collector-session-1" {
		t.Fatalf("id not preserved: %q", seen)
	}

	// Hostile metadata is replaced, never propagated into logs.
	ctx = metadata.NewIncomingContext(context.Background(), metadata.Pairs(MetadataRequestID, "bad\nvalue"))
	if _, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, handler); err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	if seen == "bad\nvalue" || strings.ContainsAny(seen, "\n\r") {
		t.Fatalf("unsafe id propagated: %q", seen)
	}
}

func TestStreamInterceptorEstablishesOneIDPerSession(t *testing.T) {
	interceptor := StreamServerInterceptor()
	var seen string
	handler := func(_ any, ss grpc.ServerStream) error {
		seen = RequestIDFrom(ss.Context())
		// Same context for every message in the session.
		if again := RequestIDFrom(ss.Context()); again != seen {
			return context.Canceled
		}
		return nil
	}
	ss := &fakeStream{ctx: metadata.NewIncomingContext(context.Background(), metadata.Pairs(MetadataRequestID, "stream-42"))}
	if err := interceptor(nil, ss, &grpc.StreamServerInfo{}, handler); err != nil {
		t.Fatalf("stream interceptor: %v", err)
	}
	if seen != "stream-42" {
		t.Fatalf("stream id: %q", seen)
	}
	if v := ss.header.Get(MetadataRequestID); len(v) != 1 || v[0] != "stream-42" {
		t.Fatalf("id not echoed in stream headers: %v", v)
	}
}

type fakeStream struct {
	grpc.ServerStream
	ctx    context.Context
	header metadata.MD
}

func (f *fakeStream) Context() context.Context { return f.ctx }
func (f *fakeStream) SetHeader(md metadata.MD) error {
	f.header = md
	return nil
}
