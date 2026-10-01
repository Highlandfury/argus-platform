package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/modules/identity"
	"github.com/argus-platform/argus/internal/platform/security"
)

// TestM8S2bAuthLookupAndTouchThrottle pins the M8-S2b L-03 remediation:
//
//  1. Authenticate resolves the session and user in one auth transaction, so a
//     valid token works and an unknown token / revoked session / disabled user
//     are uniformly rejected.
//  2. last_seen_at is refreshed at most once per identity.SessionTouchInterval:
//     a fresh session is left untouched by a burst of requests (no per-request
//     row write / WAL commit), and a stale session is touched exactly once on
//     the next request.
func TestM8S2bAuthLookupAndTouchThrottle(t *testing.T) {
	ctx := context.Background()
	tn := seedTenant(t, "m8s2b-auth")

	svc, err := identity.New(appPool, authPool, nil)
	must(t, err)

	rawToken := "m8s2b-raw-session-token" //nolint:gosec // test fixture value, not a credential
	tokenHash := security.HashToken(rawToken)
	sessionID := uuid.New()
	_, err = ownerPool.Exec(ctx,
		`INSERT INTO sessions (id, org_id, user_id, token_hash, csrf_hash, expires_at)
		 VALUES ($1, $2, $3, $4, $5, now() + interval '1 hour')`,
		sessionID, tn.OrgID, tn.UserID, tokenHash, []byte("m8s2b-csrf"))
	must(t, err)

	readLastSeen := func() time.Time {
		t.Helper()
		var ts time.Time
		must(t, ownerPool.QueryRow(ctx,
			`SELECT last_seen_at FROM sessions WHERE id = $1`, sessionID).Scan(&ts))
		return ts
	}

	// A valid token authenticates and returns the joined identity context.
	auth, err := svc.Authenticate(ctx, rawToken)
	must(t, err)
	if auth.User.ID.String() != tn.UserID || auth.Session.ID != sessionID {
		t.Fatalf("authenticate returned wrong identity: user=%s session=%s", auth.User.ID, auth.Session.ID)
	}

	// The session was just created (last_seen_at = now()), so the first request
	// must not write it.
	afterFirst := readLastSeen()

	// A second immediate request must not write either: the touch is throttled.
	if _, err := svc.Authenticate(ctx, rawToken); err != nil {
		t.Fatalf("second authenticate: %v", err)
	}
	if got := readLastSeen(); !got.Equal(afterFirst) {
		t.Fatalf("throttle violated: last_seen_at changed within the interval: %v -> %v", afterFirst, got)
	}

	// Backdate the session beyond the touch interval: the next request must
	// refresh it exactly once, and the following request must not write again.
	stale := time.Now().Add(-2 * identity.SessionTouchInterval)
	must(t, func() error {
		_, err := ownerPool.Exec(ctx, `UPDATE sessions SET last_seen_at = $2 WHERE id = $1`, sessionID, stale)
		return err
	}())
	if _, err := svc.Authenticate(ctx, rawToken); err != nil {
		t.Fatalf("authenticate after backdate: %v", err)
	}
	touched := readLastSeen()
	if !touched.After(stale) || time.Since(touched) > time.Minute {
		t.Fatalf("stale session was not touched: stale=%v now=%v", stale, touched)
	}
	if _, err := svc.Authenticate(ctx, rawToken); err != nil {
		t.Fatalf("authenticate after touch: %v", err)
	}
	if got := readLastSeen(); !got.Equal(touched) {
		t.Fatalf("throttle violated after refresh: %v -> %v", touched, got)
	}

	// Unknown token, revoked session and disabled user are all invalid.
	if _, err := svc.Authenticate(ctx, "not-a-session"); !errors.Is(err, identity.ErrSessionInvalid) {
		t.Fatalf("unknown token: want ErrSessionInvalid, got %v", err)
	}
	must(t, func() error {
		_, err := ownerPool.Exec(ctx, `UPDATE sessions SET revoked_at = now() WHERE id = $1`, sessionID)
		return err
	}())
	if _, err := svc.Authenticate(ctx, rawToken); !errors.Is(err, identity.ErrSessionInvalid) {
		t.Fatalf("revoked session: want ErrSessionInvalid, got %v", err)
	}
	must(t, func() error {
		_, err := ownerPool.Exec(ctx, `UPDATE sessions SET revoked_at = NULL WHERE id = $1`, sessionID)
		return err
	}())
	must(t, func() error {
		_, err := ownerPool.Exec(ctx, `UPDATE users SET disabled_at = now() WHERE id = $1`, tn.UserID)
		return err
	}())
	if _, err := svc.Authenticate(ctx, rawToken); !errors.Is(err, identity.ErrSessionInvalid) {
		t.Fatalf("disabled user: want ErrSessionInvalid, got %v", err)
	}

	// The auth role still cannot read tenant tables beyond its grants: a
	// direct collectors read through the auth pool must fail.
	var exists bool
	err = authPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM collectors WHERE id = $1)`, tn.CollectorID).Scan(&exists)
	if err == nil || pgErrCode(err) != sqlstateInsufficientPrivilege {
		t.Fatalf("auth role read collectors: want 42501, got %v", err)
	}
}
