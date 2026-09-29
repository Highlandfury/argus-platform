// Package database owns the PostgreSQL connections and the tenant-context
// discipline that every module must follow (docs/phase-1/PHASE_1_SPEC.md §7).
//
// Two roles, two pools:
//   - app pool  (argus_app_login → argus_app): RLS-enforced; every tenant query
//     must run inside WithTenant.
//   - auth pool (argus_auth_login → argus_auth): pre-authentication lookups only
//     (organizations/users/sessions); no grants on collector or metric tables.
package database

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres" // database driver
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/argus-platform/argus/migrations"
)

// CheckSchema verifies database reachability and that the schema is current and
// clean. Used by readiness; the app role has SELECT on schema_migrations.
func CheckSchema(ctx context.Context, pool *pgxpool.Pool) error {
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("database ping: %w", err)
	}
	var version uint
	var dirty bool
	if err := pool.QueryRow(ctx, `SELECT version, dirty FROM schema_migrations`).Scan(&version, &dirty); err != nil {
		return fmt.Errorf("schema state unreadable: %w", err)
	}
	if dirty {
		return errors.New("schema is dirty (interrupted migration)")
	}
	if version != migrations.Latest {
		return fmt.Errorf("schema version %d, expected %d (run migrations)", version, migrations.Latest)
	}
	return nil
}

// MigrateUp applies all pending migrations. Already-current schema is not an error.
// Returns the schema version in effect afterwards.
func MigrateUp(dsn string) (uint, error) {
	m, err := newMigrator(dsn)
	if err != nil {
		return 0, err
	}
	upErr := m.Up()
	if upErr != nil && !errors.Is(upErr, migrate.ErrNoChange) {
		_, _ = m.Close()
		return 0, fmt.Errorf("migrate up: %w", upErr)
	}
	version, dirty, err := m.Version()
	_ = closeMigrator(m)
	if err != nil {
		return 0, fmt.Errorf("migrate version: %w", err)
	}
	if dirty {
		return version, errors.New("migration state is dirty; manual intervention required")
	}
	return version, nil
}

// MigrateDown steps down by n migrations (n > 0). Stepping below zero is treated
// as already-at-base, matching dev/test usage.
func MigrateDown(dsn string, n int) error {
	if n <= 0 {
		return errors.New("migrate down: n must be positive")
	}
	m, err := newMigrator(dsn)
	if err != nil {
		return err
	}
	downErr := m.Steps(-n)
	if downErr != nil && !errors.Is(downErr, migrate.ErrNoChange) && !errors.Is(downErr, migrate.ErrNilVersion) {
		_, _ = m.Close()
		return fmt.Errorf("migrate down: %w", downErr)
	}
	return closeMigrator(m)
}

func newMigrator(dsn string) (*migrate.Migrate, error) {
	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return nil, fmt.Errorf("migration source: %w", err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, dsn)
	if err != nil {
		return nil, fmt.Errorf("migration driver: %w", err)
	}
	m.Log = migrateLogger{}
	return m, nil
}

func closeMigrator(m *migrate.Migrate) error {
	srcErr, dbErr := m.Close()
	if srcErr != nil {
		return fmt.Errorf("close migration source: %w", srcErr)
	}
	if dbErr != nil {
		return fmt.Errorf("close migration database: %w", dbErr)
	}
	return nil
}

// migrateLogger adapts golang-migrate's verbose logger to slog at debug level.
type migrateLogger struct{}

func (migrateLogger) Printf(format string, v ...any) {
	slog.Debug(fmt.Sprintf(format, v...), "component", "migrate")
}

func (migrateLogger) Verbose() bool { return false }
