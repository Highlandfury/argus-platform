package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/argus-platform/argus/internal/modules/tenancy"
	"github.com/argus-platform/argus/internal/platform/database"
	"github.com/argus-platform/argus/internal/platform/security"
)

// SessionTTL is the absolute session lifetime (SPEC §24.3: 12 hours).
const SessionTTL = 12 * time.Hour

var (
	// ErrInvalidCredentials is deliberately uniform for unknown org, unknown
	// email, wrong password, and disabled accounts (no enumeration oracle).
	ErrInvalidCredentials = errors.New("identity: invalid credentials")
	// ErrSessionInvalid covers unknown, expired, and revoked sessions.
	ErrSessionInvalid = errors.New("identity: session invalid")
)

// Service implements authentication and session management.
type Service struct {
	app     *pgxpool.Pool
	auth    *pgxpool.Pool
	tenancy *tenancy.Service
	// dummyHash equalizes verification work when the account does not exist,
	// so response timing cannot distinguish enumeration cases (S-16).
	dummyHash string
}

// New wires the identity service. The constructor prepares the timing-
// equalization hash once.
func New(app, auth *pgxpool.Pool, tenancySvc *tenancy.Service) (*Service, error) {
	dummy, err := security.HashPassword("argus-not-a-real-password")
	if err != nil {
		return nil, fmt.Errorf("identity: prepare timing hash: %w", err)
	}
	return &Service{app: app, auth: auth, tenancy: tenancySvc, dummyHash: dummy}, nil
}

// LoginResult carries the freshly minted secrets and identity context.
type LoginResult struct {
	RawToken  string
	RawCSRF   string
	ExpiresAt time.Time
	User      User
	Org       tenancy.Org
}

// Authenticated is what the session middleware receives.
type Authenticated struct {
	User    User
	Session Session
}

// Login verifies credentials and creates a session. All failure modes return
// ErrInvalidCredentials (uniform error and comparable timing).
func (s *Service) Login(ctx context.Context, orgSlug, email, password string) (LoginResult, error) {
	org, err := s.tenancy.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		if errors.Is(err, tenancy.ErrOrgNotFound) {
			s.dummyVerify(password)
			return LoginResult{}, ErrInvalidCredentials
		}
		return LoginResult{}, err
	}
	orgID, err := uuid.Parse(org.ID)
	if err != nil {
		return LoginResult{}, fmt.Errorf("identity: org id: %w", err)
	}

	var user User
	err = database.WithAuthTx(ctx, s.auth, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		user, err = findUserByOrgEmail(ctx, tx, orgID, email)
		return err
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			s.dummyVerify(password)
			return LoginResult{}, ErrInvalidCredentials
		}
		return LoginResult{}, err
	}

	ok, verr := security.VerifyPassword(user.PasswordHash, password)
	if verr != nil || !ok {
		return LoginResult{}, ErrInvalidCredentials
	}
	if user.Disabled {
		return LoginResult{}, ErrInvalidCredentials
	}

	rawToken, tokenHash, err := security.NewToken()
	if err != nil {
		return LoginResult{}, err
	}
	rawCSRF, csrfHash, err := security.NewToken()
	if err != nil {
		return LoginResult{}, err
	}
	expiresAt := time.Now().Add(SessionTTL)
	sessionID, err := uuid.NewV7()
	if err != nil {
		return LoginResult{}, err
	}

	err = database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		return insertSession(ctx, tx, sessionID, orgID, user.ID, tokenHash, csrfHash, expiresAt)
	})
	if err != nil {
		return LoginResult{}, err
	}

	return LoginResult{RawToken: rawToken, RawCSRF: rawCSRF, ExpiresAt: expiresAt, User: user, Org: org}, nil
}

// SessionTouchInterval bounds how often an authenticated request writes the
// session's last_seen_at. Touching every request serialized all traffic of one
// session on the session row lock and its WAL commit (measured: L-03 50 VUs,
// pg_locks transactionid waits); last_seen_at is observability metadata, so a
// throttle preserves its meaning without the herd.
const SessionTouchInterval = 30 * time.Second

// Authenticate resolves a raw session token, enforces validity, and refreshes
// last_seen_at (throttled, best-effort), returning the identity context for
// the middleware. The session and user are read in one transaction/query.
func (s *Service) Authenticate(ctx context.Context, rawToken string) (Authenticated, error) {
	if rawToken == "" {
		return Authenticated{}, ErrSessionInvalid
	}
	tokenHash := security.HashToken(rawToken)

	var (
		sess Session
		user User
	)
	err := database.WithAuthTx(ctx, s.auth, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		sess, user, err = getSessionUserByTokenHash(ctx, tx, tokenHash)
		return err
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Authenticated{}, ErrSessionInvalid
		}
		return Authenticated{}, err
	}
	now := time.Now()
	if sess.RevokedAt != nil || now.After(sess.ExpiresAt) || user.Disabled {
		return Authenticated{}, ErrSessionInvalid
	}

	// Best-effort touch: a failed refresh must not fail the request, and the
	// conditional UPDATE runs at most once per SessionTouchInterval per session.
	cutoff := now.Add(-SessionTouchInterval)
	if sess.LastSeenAt == nil || sess.LastSeenAt.Before(cutoff) {
		_ = database.WithAuthTx(ctx, s.auth, func(ctx context.Context, tx pgx.Tx) error {
			return touchSession(ctx, tx, sess.ID, cutoff)
		})
	}

	return Authenticated{User: user, Session: sess}, nil
}

// Logout revokes one session (idempotent).
func (s *Service) Logout(ctx context.Context, sessionID uuid.UUID) error {
	return database.WithAuthTx(ctx, s.auth, func(ctx context.Context, tx pgx.Tx) error {
		return revokeSession(ctx, tx, sessionID)
	})
}

func (s *Service) dummyVerify(password string) {
	_, _ = security.VerifyPassword(s.dummyHash, password)
}
