// Package integration runs M1 database/security tests against a real
// TimescaleDB container (the same digest-pinned image as the dev stack).
//
// The suite is the M1 acceptance evidence: migrations, schema shape, role
// boundaries, tenant isolation, and transaction-scoped context. It is NOT
// optional for acceptance; environments without Docker must set
// ARGUS_SKIP_DOCKER_TESTS=1 explicitly, which is invalid for an M1 acceptance
// run and is recorded as such in ACCEPTANCE_RUN.md.
package integration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/argus-platform/argus/internal/platform/database"
)

const timescaleImage = "timescale/timescaledb:2.30.1-pg18@sha256:9dede0e3ccc071cf71935b17f76bf243331df0b1575338c8ac294640fcf12a36"

const (
	sqlstateInsufficientPrivilege = "42501"
	sqlstateCheckViolation        = "23514"
)

var (
	ownerDSN string
	appDSN   string
	authDSN  string

	ownerPool *pgxpool.Pool
	appPool   *pgxpool.Pool
	authPool  *pgxpool.Pool
)

func TestMain(m *testing.M) {
	if os.Getenv("ARGUS_SKIP_DOCKER_TESTS") == "1" {
		fmt.Fprintln(os.Stderr, "integration: SKIPPED by ARGUS_SKIP_DOCKER_TESTS=1 (invalid for M1 acceptance)")
		os.Exit(0)
	}
	code, err := runSuite(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "integration harness:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func runSuite(m *testing.M) (int, error) {
	ctx := context.Background()

	c, base, err := startTimescaleContainer(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = testcontainers.TerminateContainer(c) }()

	ownerDSN = base
	appDSN = appDSNFor(base)
	authDSN = authDSNFor(base)

	if err := waitStable(ctx, base); err != nil {
		return 0, err
	}
	if _, err := database.MigrateUp(base); err != nil {
		return 0, fmt.Errorf("migrate up: %w", err)
	}
	if err := applyDevRolesScript(ctx, base); err != nil {
		return 0, err
	}

	if ownerPool, err = database.NewPool(ctx, ownerDSN, "it-owner", database.DefaultPoolConfig()); err != nil {
		return 0, fmt.Errorf("owner pool: %w", err)
	}
	defer ownerPool.Close()
	if appPool, err = database.NewPool(ctx, appDSN, "it-app", database.DefaultPoolConfig()); err != nil {
		return 0, fmt.Errorf("app pool: %w", err)
	}
	defer appPool.Close()
	if authPool, err = database.NewPool(ctx, authDSN, "it-auth", database.DefaultPoolConfig()); err != nil {
		return 0, fmt.Errorf("auth pool: %w", err)
	}
	defer authPool.Close()

	code := m.Run()
	terminateSNMPSimFixture()
	return code, nil
}

// waitStable waits until the database answers two canary queries three seconds
// apart. The TimescaleDB image restarts the server once during first-boot
// initialization (extension install + tune), so plain port readiness races.
func waitStable(ctx context.Context, dsn string) error {
	return waitStableFor(ctx, dsn, 4*time.Minute)
}

func waitStableFor(ctx context.Context, dsn string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var firstOK time.Time
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := pgx.Connect(ctx, dsn)
		if err == nil {
			var one int
			err = conn.QueryRow(ctx, "SELECT 1").Scan(&one)
			_ = conn.Close(ctx)
			if err == nil && one == 1 {
				if firstOK.IsZero() {
					firstOK = time.Now()
				} else if time.Since(firstOK) >= 3*time.Second {
					return nil
				}
			} else {
				firstOK = time.Time{}
				lastErr = err
			}
		} else {
			lastErr = err
		}
		time.Sleep(2 * time.Second)
	}
	if lastErr == nil {
		lastErr = errors.New("no connection attempt succeeded")
	}
	return fmt.Errorf("database not stably ready within %s: last error: %w", timeout, lastErr)
}

// applyDevRolesScript executes the SQL embedded in the dev bootstrap script
// (scripts/db-init/01-roles.sh) so tests exercise the real artifact, not a
// copy. The psql variable :'pw' is substituted with the testcontainer password.
func applyDevRolesScript(ctx context.Context, dsn string) error {
	path := filepath.Join("..", "..", "scripts", "db-init", "01-roles.sh")
	raw, err := os.ReadFile(path) //nolint:gosec // fixed repository-relative constant path
	if err != nil {
		return fmt.Errorf("read roles script: %w", err)
	}
	script := string(raw)
	start := strings.Index(script, "<<'SQL'")
	end := strings.LastIndex(script, "\nSQL")
	if start < 0 || end < 0 || end <= start {
		return errors.New("roles script: SQL heredoc not found")
	}
	sql := script[start+len("<<'SQL'") : end]
	// Must match the POSTGRES_PASSWORD of the test container below.
	const containerPassword = "dev-db-change-me" //nolint:gosec // testcontainer placeholder value
	sql = strings.ReplaceAll(sql, ":'pw'", "'"+strings.ReplaceAll(containerPassword, "'", "''")+"'")

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect for roles: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	// Simple protocol: the script contains DO blocks with semicolons.
	if _, err := conn.PgConn().Exec(ctx, sql).ReadAll(); err != nil {
		return fmt.Errorf("apply roles script: %w", err)
	}
	return nil
}

// startTimescaleContainer launches the digest-pinned TimescaleDB image and
// returns the container plus the owner DSN. Used by TestMain and by tests that
// need their own isolated database (e.g., restart recovery).
func startTimescaleContainer(ctx context.Context) (testcontainers.Container, string, error) {
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: timescaleImage,
			Env: map[string]string{ //nolint:gosec // testcontainer placeholder values
				"POSTGRES_DB":       "argus",
				"POSTGRES_USER":     "argus_owner",
				"POSTGRES_PASSWORD": "dev-db-change-me", //nolint:gosec // testcontainer placeholder value
			},
			ExposedPorts: []string{"5432/tcp"},
			WaitingFor:   wait.ForListeningPort("5432/tcp").WithStartupTimeout(5 * time.Minute),
		},
		Started: true,
	})
	if err != nil {
		return nil, "", fmt.Errorf("start timescaledb container (is Docker running?): %w", err)
	}
	host, err := c.Host(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("container host: %w", err)
	}
	port, err := c.MappedPort(ctx, "5432/tcp")
	if err != nil {
		return nil, "", fmt.Errorf("container port: %w", err)
	}
	return c, fmt.Sprintf("postgres://argus_owner:dev-db-change-me@%s:%s/argus?sslmode=disable", host, port.Port()), nil //nolint:gosec // testcontainer placeholder value
}

func appDSNFor(base string) string {
	return strings.Replace(base, "argus_owner:dev-db-change-me", "argus_app_login:dev-db-change-me", 1) //nolint:gosec // testcontainer placeholder value
}

func authDSNFor(base string) string {
	return strings.Replace(base, "argus_owner:dev-db-change-me", "argus_auth_login:dev-db-change-me", 1) //nolint:gosec // testcontainer placeholder value
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
}

func newUUID() string { return uuid.New().String() }

func mustUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatalf("parse uuid %q: %v", s, err)
	}
	return id
}

// pgErrCode extracts the PostgreSQL error code from an error chain.
func pgErrCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// tenant is a fully seeded organization fixture for isolation tests.
type tenant struct {
	Slug        string
	OrgID       string
	SiteID      string
	UserID      string
	SessionID   string
	CollectorID string
	SeriesID    int64
	SampleTS    time.Time
}

// seedTenant creates one organization with the full M1 chain:
// org -> site -> user/session -> collector -> certificate -> series -> sample -> batch.
// Organization/site/user/session rows are inserted by the owner (setup role);
// collector/series/sample/batch are inserted through the app pool inside
// WithTenant, proving that the sanctioned application write path works.
func seedTenant(t *testing.T, slug string) tenant {
	t.Helper()
	ctx := context.Background()

	tn := tenant{
		Slug:        slug,
		OrgID:       newUUID(),
		SiteID:      newUUID(),
		UserID:      newUUID(),
		SessionID:   newUUID(),
		CollectorID: newUUID(),
		SampleTS:    time.Now().UTC().Truncate(time.Second),
	}

	_, err := ownerPool.Exec(ctx,
		`INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $3)`,
		tn.OrgID, "Org "+slug, slug)
	must(t, err)

	_, err = ownerPool.Exec(ctx,
		`INSERT INTO sites (id, org_id, name) VALUES ($1, $2, 'HQ')`,
		tn.SiteID, tn.OrgID)
	must(t, err)

	_, err = ownerPool.Exec(ctx,
		`INSERT INTO users (id, org_id, email, password_hash, role) VALUES ($1, $2, $3, 'it-not-used', 'admin')`,
		tn.UserID, tn.OrgID, slug+"@dev.local")
	must(t, err)

	_, err = ownerPool.Exec(ctx,
		`INSERT INTO sessions (id, org_id, user_id, token_hash, csrf_hash, expires_at)
		 VALUES ($1, $2, $3, $4, $5, now() + interval '1 hour')`,
		tn.SessionID, tn.OrgID, tn.UserID, []byte(slug+"-token-hash"), []byte(slug+"-csrf-hash"))
	must(t, err)

	err = database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO collectors (id, org_id, site_id, name, status) VALUES ($1, $2, $3, $4, 'active')`,
			tn.CollectorID, tn.OrgID, tn.SiteID, "collector-"+slug); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO collector_certificates (id, org_id, collector_id, serial, fingerprint_sha256, not_before, not_after)
			 VALUES ($1, $2, $3, $4, $5, now(), now() + interval '90 days')`,
			newUUID(), tn.OrgID, tn.CollectorID, "serial-"+slug, []byte("fp-"+slug)); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx,
			`INSERT INTO metric_series (org_id, collector_id, metric_key, dimensions, dim_hash, unit)
			 VALUES ($1, $2, 'collector_cpu_percent', '{}'::jsonb, 1, 'percent') RETURNING id`,
			tn.OrgID, tn.CollectorID).Scan(&tn.SeriesID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO metric_samples (org_id, series_id, ts, value) VALUES ($1, $2, $3, 42)`,
			tn.OrgID, tn.SeriesID, tn.SampleTS); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO ingested_batches (collector_id, batch_seq, org_id, sample_count, first_ts, last_ts)
			 VALUES ($1, 1, $2, 1, $3, $3)`,
			tn.CollectorID, tn.OrgID, tn.SampleTS); err != nil {
			return err
		}
		return nil
	})
	must(t, err)

	return tn
}

var tenantTables = []string{
	"sites",
	"users",
	"sessions",
	"collectors",
	"collector_certificates",
	"metric_series",
	"metric_samples",
	"ingested_batches",
}

func countRows(t *testing.T, asOrg string, filterOrg string) map[string]int {
	t.Helper()
	return countRowsOn(t, appPool, asOrg, filterOrg)
}

func countRowsOn(t *testing.T, pool *pgxpool.Pool, asOrg string, filterOrg string) map[string]int {
	t.Helper()
	ctx := context.Background()
	out := make(map[string]int, len(tenantTables))
	must(t, database.WithTenant(ctx, pool, mustUUID(t, asOrg), func(ctx context.Context, tx pgx.Tx) error {
		for _, tbl := range tenantTables {
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM `+tbl+` WHERE org_id = $1`, filterOrg).Scan(&n); err != nil {
				return fmt.Errorf("count %s: %w", tbl, err)
			}
			out[tbl] = n
		}
		return nil
	}))
	return out
}
