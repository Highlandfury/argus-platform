package httpx

import (
	"context"

	"github.com/google/uuid"
)

// Principal is the authenticated session context attached by the session
// middleware. Modules read it instead of knowing about cookies or sessions.
type Principal struct {
	UserID    uuid.UUID
	OrgID     uuid.UUID
	SessionID uuid.UUID
	Email     string
	Role      string
	// CSRFHash is the session's stored CSRF fingerprint (never serialized).
	CSRFHash []byte
}

type principalKey struct{}

// WithPrincipal stores the principal in the request context.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom extracts the principal; false when unauthenticated.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}
