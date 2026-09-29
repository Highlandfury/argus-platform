package database

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNoTenant is returned when a tenant-scoped operation is attempted with a
// zero organization ID. Every tenant query MUST go through WithTenant, so this
// is a programming-error guard, not a user-facing condition.
var ErrNoTenant = errors.New("database: tenant organization ID is required")

// WithTenant runs fn inside a transaction with the tenant context set via
// set_config('app.current_org', $1, is_local => true) — the parameterized
// equivalent of SET LOCAL. Because the setting is transaction-scoped it reverts
// at COMMIT/ROLLBACK and never leaks across pooled connections, which keeps the
// design PgBouncer transaction-pooling safe (docs/phase-1/PHASE_1_SPEC.md §7.2).
//
// The callback error is returned unwrapped so callers can use errors.Is.
func WithTenant(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, fn func(ctx context.Context, tx pgx.Tx) error) error {
	if orgID == uuid.Nil {
		return ErrNoTenant
	}
	if pool == nil {
		return errors.New("database: nil pool")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("database: begin tenant tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful commit
	if _, err := tx.Exec(ctx, "SELECT set_config('app.current_org', $1, true)", orgID.String()); err != nil {
		return fmt.Errorf("database: set tenant context: %w", err)
	}
	if err := fn(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("database: commit tenant tx: %w", err)
	}
	return nil
}

// WithAuthTx runs fn inside a transaction under the argus_auth role
// (SET LOCAL ROLE argus_auth). It is used exclusively for pre-authentication
// lookups: organizations, users, sessions. The role holds BYPASSRLS (so those
// lookups work before a tenant is known) but its grants are restricted to
// exactly those three tables — it cannot read collector or metric data.
//
// The role name is a compile-time constant; no user input reaches this SQL.
func WithAuthTx(ctx context.Context, authPool *pgxpool.Pool, fn func(ctx context.Context, tx pgx.Tx) error) error {
	if authPool == nil {
		return errors.New("database: nil auth pool")
	}
	tx, err := authPool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("database: begin auth tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE argus_auth"); err != nil {
		return fmt.Errorf("database: set auth role: %w", err)
	}
	if err := fn(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("database: commit auth tx: %w", err)
	}
	return nil
}
