// Package identity owns users, sessions, and the login/logout flows.
package identity

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// User is the minimal user projection used by authentication.
type User struct {
	ID           uuid.UUID
	OrgID        uuid.UUID
	Email        string
	Role         string
	PasswordHash string
	Disabled     bool
}

// Session is a session row (token material is stored hashed).
type Session struct {
	ID         uuid.UUID
	OrgID      uuid.UUID
	UserID     uuid.UUID
	CSRFHash   []byte
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	LastSeenAt *time.Time
}

func findUserByOrgEmail(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, email string) (User, error) {
	var u User
	var disabledAt *time.Time
	err := tx.QueryRow(ctx, `
		SELECT id, org_id, email, role, password_hash, disabled_at
		FROM users
		WHERE org_id = $1 AND lower(email) = lower($2)`, orgID, email).
		Scan(&u.ID, &u.OrgID, &u.Email, &u.Role, &u.PasswordHash, &disabledAt)
	if err != nil {
		return User{}, err
	}
	u.Disabled = disabledAt != nil
	return u, nil
}

// getSessionUserByTokenHash resolves a session and its user in one query so one
// authenticated request costs one auth lookup instead of two sequential ones.
// The join is safe: sessions.user_id is an FK to users.id and both tables are
// granted to argus_auth.
func getSessionUserByTokenHash(ctx context.Context, tx pgx.Tx, tokenHash []byte) (Session, User, error) {
	var (
		s          Session
		u          User
		disabledAt *time.Time
	)
	err := tx.QueryRow(ctx, `
		SELECT s.id, s.org_id, s.user_id, s.csrf_hash, s.expires_at, s.revoked_at, s.last_seen_at,
		       u.id, u.org_id, u.email, u.role, u.disabled_at
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1`, tokenHash).
		Scan(&s.ID, &s.OrgID, &s.UserID, &s.CSRFHash, &s.ExpiresAt, &s.RevokedAt, &s.LastSeenAt,
			&u.ID, &u.OrgID, &u.Email, &u.Role, &disabledAt)
	if err != nil {
		return Session{}, User{}, err
	}
	u.Disabled = disabledAt != nil
	return s, u, nil
}

func insertSession(ctx context.Context, tx pgx.Tx, id, orgID, userID uuid.UUID, tokenHash, csrfHash []byte, expiresAt time.Time) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO sessions (id, org_id, user_id, token_hash, csrf_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, id, orgID, userID, tokenHash, csrfHash, expiresAt)
	return err
}

// touchSession refreshes last_seen_at only when it is older than the cutoff.
// The condition makes concurrent touches of one session collapse to a single
// row write instead of queueing every request on the session row lock; the
// touch is observability metadata, not security state.
func touchSession(ctx context.Context, tx pgx.Tx, id uuid.UUID, cutoff time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE sessions SET last_seen_at = now() WHERE id = $1 AND (last_seen_at IS NULL OR last_seen_at < $2)`, id, cutoff)
	return err
}

func revokeSession(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	_, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id)
	return err
}
