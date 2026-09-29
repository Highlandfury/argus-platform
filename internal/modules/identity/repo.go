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
	ID        uuid.UUID
	OrgID     uuid.UUID
	UserID    uuid.UUID
	CSRFHash  []byte
	ExpiresAt time.Time
	RevokedAt *time.Time
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

func getUserByID(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (User, error) {
	var u User
	var disabledAt *time.Time
	err := tx.QueryRow(ctx, `
		SELECT id, org_id, email, role, password_hash, disabled_at
		FROM users WHERE id = $1`, userID).
		Scan(&u.ID, &u.OrgID, &u.Email, &u.Role, &u.PasswordHash, &disabledAt)
	if err != nil {
		return User{}, err
	}
	u.Disabled = disabledAt != nil
	return u, nil
}

func insertSession(ctx context.Context, tx pgx.Tx, id, orgID, userID uuid.UUID, tokenHash, csrfHash []byte, expiresAt time.Time) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO sessions (id, org_id, user_id, token_hash, csrf_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, id, orgID, userID, tokenHash, csrfHash, expiresAt)
	return err
}

func getSessionByTokenHash(ctx context.Context, tx pgx.Tx, tokenHash []byte) (Session, error) {
	var s Session
	err := tx.QueryRow(ctx, `
		SELECT id, org_id, user_id, csrf_hash, expires_at, revoked_at
		FROM sessions WHERE token_hash = $1`, tokenHash).
		Scan(&s.ID, &s.OrgID, &s.UserID, &s.CSRFHash, &s.ExpiresAt, &s.RevokedAt)
	return s, err
}

func touchSession(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	_, err := tx.Exec(ctx, `UPDATE sessions SET last_seen_at = now() WHERE id = $1`, id)
	return err
}

func revokeSession(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	_, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id)
	return err
}
