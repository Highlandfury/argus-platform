// Package grpcx holds gRPC server helpers shared by the collector control plane.
package grpcx

import (
	"context"
	"crypto/sha256"
	"errors"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// ErrNoPeerCertificate is returned when the request carries no verified client
// certificate chain (misconfigured listener or non-mTLS caller).
var ErrNoPeerCertificate = errors.New("grpcx: no verified peer certificate")

// PeerCertificateFingerprint returns SHA-256 over the DER of the leaf client
// certificate — the collector identity map key (SPEC §8.2).
func PeerCertificateFingerprint(ctx context.Context) ([]byte, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, ErrNoPeerCertificate
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, ErrNoPeerCertificate
	}
	chains := tlsInfo.State.VerifiedChains
	if len(chains) == 0 || len(chains[0]) == 0 {
		return nil, ErrNoPeerCertificate
	}
	sum := sha256.Sum256(chains[0][0].Raw)
	return sum[:], nil
}
