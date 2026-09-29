package integration

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/argus-platform/argus/internal/platform/database"
)

// assertIsolation verifies, in both directions, that the tenant sees exactly its
// own rows (1 per table) and zero foreign rows. Application-layer filtering is
// not involved: every query runs as argus_app inside WithTenant (RLS only).
func assertIsolation(t *testing.T, tn tenant, other tenant) {
	t.Helper()
	t.Run(tn.Slug+"-own-rows", func(t *testing.T) {
		own := countRows(t, tn.OrgID, tn.OrgID)
		for tbl, n := range own {
			if n != 1 {
				t.Fatalf("%s: sees %d own rows in %s, want 1", tn.Slug, n, tbl)
			}
		}
	})
	t.Run(tn.Slug+"-foreign-rows", func(t *testing.T) {
		foreign := countRows(t, tn.OrgID, other.OrgID)
		for tbl, n := range foreign {
			if n != 0 {
				t.Fatalf("%s: sees %d foreign rows in %s, want 0", tn.Slug, n, tbl)
			}
		}
	})
}

func TestTenantIsolationReads(t *testing.T) {
	// Unique slugs so the scenario is re-runnable (it is also executed inside
	// TestFailureSuite/T8 in the same process).
	a := seedTenant(t, "iso-reads-a-"+newUUID()[:8])
	b := seedTenant(t, "iso-reads-b-"+newUUID()[:8])

	assertIsolation(t, a, b)
	assertIsolation(t, b, a)

	// Point query for a foreign collector ID must yield zero rows, not an error.
	var n int
	must(t, database.WithTenant(context.Background(), appPool, mustUUID(t, a.OrgID), func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM collectors WHERE id = $1`, b.CollectorID).Scan(&n)
	}))
	if n != 0 {
		t.Fatalf("tenant A can see tenant B's collector by ID")
	}
}

func TestCrossTenantWritesDenied(t *testing.T) {
	ctx := context.Background()
	a := seedTenant(t, "iso-writes-a-"+newUUID()[:8])
	b := seedTenant(t, "iso-writes-b-"+newUUID()[:8])
	orgA := mustUUID(t, a.OrgID)

	// INSERT with a foreign org_id violates RLS WITH CHECK.
	inserts := []struct {
		name string
		sql  string
		args []any
	}{
		{"metric_samples", `INSERT INTO metric_samples (org_id, series_id, ts, value) VALUES ($1, $2, now(), 1)`, []any{b.OrgID, b.SeriesID}},
		{"collectors", `INSERT INTO collectors (id, org_id, site_id, name) VALUES ($1, $2, $3, 'intruder')`, []any{newUUID(), b.OrgID, b.SiteID}},
		{"ingested_batches", `INSERT INTO ingested_batches (collector_id, batch_seq, org_id, sample_count) VALUES ($1, 999, $2, 1)`, []any{b.CollectorID, b.OrgID}},
	}
	for _, tc := range inserts {
		t.Run("insert-"+tc.name, func(t *testing.T) {
			err := database.WithTenant(ctx, appPool, orgA, func(ctx context.Context, tx pgx.Tx) error {
				_, err := tx.Exec(ctx, tc.sql, tc.args...)
				return err
			})
			if got := pgErrCode(err); got != sqlstateInsufficientPrivilege {
				t.Fatalf("insert %s: want SQLSTATE %s (RLS violation), got %q (%v)", tc.name, sqlstateInsufficientPrivilege, got, err)
			}
		})
	}

	// UPDATE and DELETE against foreign rows affect zero rows (rows are invisible).
	err := database.WithTenant(ctx, appPool, orgA, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE collectors SET name = 'hacked' WHERE id = $1`, b.CollectorID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 0 {
			return fmt.Errorf("UPDATE reached a foreign row (%d affected)", tag.RowsAffected())
		}
		tag, err = tx.Exec(ctx, `DELETE FROM metric_series WHERE id = $1`, b.SeriesID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 0 {
			return fmt.Errorf("DELETE reached a foreign row (%d affected)", tag.RowsAffected())
		}
		return nil
	})
	must(t, err)

	// Tenant B's data is intact.
	var name string
	must(t, database.WithTenant(ctx, appPool, mustUUID(t, b.OrgID), func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT name FROM collectors WHERE id = $1`, b.CollectorID).Scan(&name)
	}))
	if name != "collector-"+b.Slug {
		t.Fatalf("tenant B collector was modified: name=%q", name)
	}
	own := countRows(t, b.OrgID, b.OrgID)
	for tbl, n := range own {
		if n != 1 {
			t.Fatalf("tenant B lost data in %s: %d rows", tbl, n)
		}
	}
}

func TestUnscopedAccessSeesNothing(t *testing.T) {
	ctx := context.Background()
	seedTenant(t, "iso-unscoped-"+newUUID()[:8])

	tables := []string{
		"organizations", "sites", "users", "sessions", "collectors",
		"enrollment_tokens", "collector_certificates", "collector_policies",
		"metric_series", "metric_samples", "ingested_batches",
	}
	for _, tbl := range tables {
		var n int
		must(t, appPool.QueryRow(ctx, `SELECT count(*) FROM `+tbl).Scan(&n))
		if n != 0 {
			t.Fatalf("unscoped query on %s returned %d rows (must be 0 under default-deny RLS)", tbl, n)
		}
	}

	// Unscoped INSERT fails WITH CHECK, not silently.
	_, err := appPool.Exec(ctx,
		`INSERT INTO organizations (id, name, slug) VALUES ($1, 'sneaky', $2)`,
		newUUID(), "sneaky-"+newUUID())
	if got := pgErrCode(err); got != sqlstateInsufficientPrivilege {
		t.Fatalf("unscoped insert: want SQLSTATE %s, got %q (%v)", sqlstateInsufficientPrivilege, got, err)
	}
}

// TestTenantContextPoolingDoesNotLeak proves the PgBouncer-style requirement:
// tenant context is transaction-scoped and cannot leak across pooled reuse.
func TestTenantContextPoolingDoesNotLeak(t *testing.T) {
	ctx := context.Background()
	a := seedTenant(t, "iso-leak-a")
	b := seedTenant(t, "iso-leak-b")
	orgA := mustUUID(t, a.OrgID)

	// MaxConns=1 guarantees consecutive transactions reuse the same backend.
	pool, err := database.NewPool(ctx, appDSN, "it-leak", database.PoolConfig{
		MaxConns:          1,
		MinConns:          1,
		MaxConnLifetime:   time.Minute,
		MaxConnIdleTime:   time.Minute,
		HealthCheckPeriod: time.Second,
	})
	must(t, err)
	defer pool.Close()

	var pidBefore, pidAfter int
	must(t, pool.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pidBefore))

	for i := 0; i < 3; i++ {
		ownA := countRowsOn(t, pool, a.OrgID, a.OrgID)
		fgnA := countRowsOn(t, pool, a.OrgID, b.OrgID)
		if ownA["collectors"] != 1 || fgnA["collectors"] != 0 {
			t.Fatalf("iteration %d: A context wrong (own=%d foreign=%d)", i, ownA["collectors"], fgnA["collectors"])
		}
		ownB := countRowsOn(t, pool, b.OrgID, b.OrgID)
		fgnB := countRowsOn(t, pool, b.OrgID, a.OrgID)
		if ownB["collectors"] != 1 || fgnB["collectors"] != 0 {
			t.Fatalf("iteration %d: B context wrong (own=%d foreign=%d)", i, ownB["collectors"], fgnB["collectors"])
		}
	}

	must(t, pool.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pidAfter))
	if pidBefore != pidAfter {
		t.Fatalf("test premise invalid: backend changed (%d -> %d) despite MaxConns=1", pidBefore, pidAfter)
	}

	// No tenant setting remains on the reused session.
	assertNoTenantSetting(t, pool)

	// A failed transaction must not leak context either, and the connection
	// stays usable for the next tenant.
	sentinel := errors.New("intentional callback failure")
	err = database.WithTenant(ctx, pool, orgA, func(context.Context, pgx.Tx) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("callback error not preserved: %v", err)
	}
	assertNoTenantSetting(t, pool)

	ownB := countRowsOn(t, pool, b.OrgID, b.OrgID)
	if ownB["collectors"] != 1 {
		t.Fatalf("pool unusable or mis-scoped after failed tx: %+v", ownB)
	}
}

func assertNoTenantSetting(t *testing.T, pool interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}) {
	t.Helper()
	var leaked *string
	must(t, pool.QueryRow(context.Background(),
		"SELECT nullif(current_setting('app.current_org', true), '')").Scan(&leaked))
	if leaked != nil {
		t.Fatalf("tenant setting leaked across pooled transactions: %q", *leaked)
	}
}

// runJob invokes a TimescaleDB background job synchronously.
// (In TimescaleDB 2.30 run_job is a procedure, hence CALL.)
func runJob(ctx context.Context, jobID int) error {
	_, err := ownerPool.Exec(ctx, `CALL run_job($1)`, jobID)
	return err
}

// TestAuthRoleBoundaries proves the argus_auth contract: pre-authentication
// lookups on three tables, nothing else — even though the role holds BYPASSRLS.
func TestAuthRoleBoundaries(t *testing.T) {
	ctx := context.Background()
	seedTenant(t, "iso-auth-a-"+newUUID()[:8])
	seedTenant(t, "iso-auth-b-"+newUUID()[:8])

	t.Run("allowed-reads", func(t *testing.T) {
		var orgs, users, sessions, tokens int
		must(t, database.WithAuthTx(ctx, authPool, func(ctx context.Context, tx pgx.Tx) error {
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM organizations`).Scan(&orgs); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&users); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM sessions`).Scan(&sessions); err != nil {
				return err
			}
			// M3 amendment: enrollment token resolution is a pre-auth lookup.
			return tx.QueryRow(ctx, `SELECT count(*) FROM enrollment_tokens`).Scan(&tokens)
		}))
		if orgs < 2 || users < 2 || sessions < 2 {
			t.Fatalf("auth role pre-auth visibility too small: orgs=%d users=%d sessions=%d", orgs, users, sessions)
		}
	})

	t.Run("denied-tables", func(t *testing.T) {
		denied := []string{
			"collectors", "collector_certificates", "collector_policies",
			"metric_series", "metric_samples", "ingested_batches", "sites",
		}
		for _, tbl := range denied {
			err := database.WithAuthTx(ctx, authPool, func(ctx context.Context, tx pgx.Tx) error {
				var n int
				return tx.QueryRow(ctx, `SELECT count(*) FROM `+tbl).Scan(&n)
			})
			if got := pgErrCode(err); got != sqlstateInsufficientPrivilege {
				t.Fatalf("auth role read %s: want SQLSTATE %s, got %q (%v)", tbl, sqlstateInsufficientPrivilege, got, err)
			}
		}
	})

	t.Run("denied-writes", func(t *testing.T) {
		err := database.WithAuthTx(ctx, authPool, func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO users (id, org_id, email, password_hash) SELECT $1, id, $2, 'x' FROM organizations LIMIT 1`, newUUID(), "intruder@dev.local")
			return err
		})
		if got := pgErrCode(err); got != sqlstateInsufficientPrivilege {
			t.Fatalf("auth role insert users: want SQLSTATE %s, got %q (%v)", sqlstateInsufficientPrivilege, got, err)
		}

		err = database.WithAuthTx(ctx, authPool, func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE users SET role = 'viewer'`)
			return err
		})
		if got := pgErrCode(err); got != sqlstateInsufficientPrivilege {
			t.Fatalf("auth role update users: want SQLSTATE %s, got %q (%v)", sqlstateInsufficientPrivilege, got, err)
		}
	})

	t.Run("sessions-column-scope", func(t *testing.T) {
		var sessionID string
		_ = sessionID
		must(t, database.WithAuthTx(ctx, authPool, func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT id FROM sessions LIMIT 1`).Scan(&sessionID)
		}))

		// last_seen_at is granted...
		must(t, database.WithAuthTx(ctx, authPool, func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE sessions SET last_seen_at = now() WHERE id = $1`, sessionID)
			return err
		}))
		// ...token_hash is not.
		err := database.WithAuthTx(ctx, authPool, func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE sessions SET token_hash = $1 WHERE id = $2`, []byte("stolen"), sessionID)
			return err
		})
		if got := pgErrCode(err); got != sqlstateInsufficientPrivilege {
			t.Fatalf("auth role update sessions.token_hash: want SQLSTATE %s, got %q (%v)", sqlstateInsufficientPrivilege, got, err)
		}
	})

	t.Run("enrollment-token-select-only", func(t *testing.T) {
		tn := seedTenant(t, "iso-token-a-"+newUUID()[:8])
		tokenID := newUUID()
		_, err := ownerPool.Exec(ctx,
			`INSERT INTO enrollment_tokens (id, org_id, site_id, token_hash, expires_at)
			 VALUES ($1, $2, $3, $4, now() + interval '1 hour')`,
			tokenID, tn.OrgID, tn.SiteID, []byte("token-hash-"+tn.Slug))
		must(t, err)

		// SELECT is the whole grant: claiming (UPDATE) stays on the app role.
		err = database.WithAuthTx(ctx, authPool, func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE enrollment_tokens SET used_at = now() WHERE id = $1`, tokenID)
			return err
		})
		if got := pgErrCode(err); got != sqlstateInsufficientPrivilege {
			t.Fatalf("auth role update enrollment_tokens: want SQLSTATE %s, got %q (%v)", sqlstateInsufficientPrivilege, got, err)
		}
	})

	t.Run("certificate-resolver-function", func(t *testing.T) {
		tn := seedTenant(t, "iso-resolver-a-"+newUUID()[:8])
		fp := []byte("fp-" + tn.Slug)

		// The auth role may execute the fixed resolver...
		var resolvedID, resolvedStatus string
		must(t, database.WithAuthTx(ctx, authPool, func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx,
				`SELECT collector_id::text, status FROM public.argus_resolve_collector_certificate($1)`, fp).
				Scan(&resolvedID, &resolvedStatus)
		}))
		if resolvedID != tn.CollectorID || resolvedStatus != "active" {
			t.Fatalf("resolver returned (%s,%s), want (%s,active)", resolvedID, resolvedStatus, tn.CollectorID)
		}

		// ...the app role may not.
		err := database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
			var n int
			return tx.QueryRow(ctx, `SELECT count(*) FROM public.argus_resolve_collector_certificate($1)`, fp).Scan(&n)
		})
		if got := pgErrCode(err); got != sqlstateInsufficientPrivilege {
			t.Fatalf("app role resolver execution: want SQLSTATE %s, got %q (%v)", sqlstateInsufficientPrivilege, got, err)
		}
	})
}

// TestAppCannotEscalateRole proves the app pool cannot assume the owner (or
// anything else) via SET ROLE.
func TestAppCannotEscalateRole(t *testing.T) {
	ctx := context.Background()
	err := database.WithTenant(ctx, appPool, mustUUID(t, seedTenant(t, "iso-escalate-"+newUUID()[:8]).OrgID), func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "SET LOCAL ROLE argus_owner")
		return err
	})
	if got := pgErrCode(err); got != sqlstateInsufficientPrivilege {
		t.Fatalf("SET ROLE argus_owner from app: want SQLSTATE %s, got %q (%v)", sqlstateInsufficientPrivilege, got, err)
	}
}

// TestChunkAccessIsRLSProtected proves the chunk boundary of tenant isolation:
// chunks carry the same RLS policy as the parent (applied synchronously at
// creation by the migration 000006 event trigger). TimescaleDB propagates
// hypertable privileges to chunks and the app role needs them for parent
// queries, so denying internal access is not viable — direct chunk reads are
// row-filtered by app.current_org instead.
func TestChunkAccessIsRLSProtected(t *testing.T) {
	ctx := context.Background()
	a := seedTenant(t, "iso-chunk-a-"+newUUID()[:8])
	b := seedTenant(t, "iso-chunk-b-"+newUUID()[:8])

	// Production mechanism: the backstop job (1-minute cadence) runs the sweep.
	// Force one run now so the assertion is deterministic instead of timing-based.
	var jobID int
	must(t, ownerPool.QueryRow(ctx,
		`SELECT job_id FROM timescaledb_information.jobs WHERE proc_name = 'argus_secure_chunk_job'`).Scan(&jobID))
	must(t, runJob(ctx, jobID))

	// The app role may also invoke the sweep itself (M4 ingest calls it in-tx);
	// with everything secured it is a cheap no-op.
	var securedByApp int
	must(t, appPool.QueryRow(ctx, `SELECT public.argus_ensure_chunk_rls()`).Scan(&securedByApp))

	var chunkSchema, chunkName string
	var rlsEnabled bool
	must(t, ownerPool.QueryRow(ctx, `
		SELECT ch.chunk_schema, ch.chunk_name, cls.relrowsecurity
		FROM timescaledb_information.chunks ch
		JOIN pg_namespace ns ON ns.nspname = ch.chunk_schema
		JOIN pg_class cls ON cls.relnamespace = ns.oid AND cls.relname = ch.chunk_name
		WHERE ch.hypertable_name = 'metric_samples'
		  AND ch.range_start <= now() AND ch.range_end > now()
		LIMIT 1`).Scan(&chunkSchema, &chunkName, &rlsEnabled))
	if !rlsEnabled {
		t.Fatal("current chunk has RLS disabled after run_job — chunk guard failed")
	}
	ident := pgx.Identifier{chunkSchema, chunkName}.Sanitize()

	// The chunk demonstrably contains more than one tenant's rows.
	var ownerCount int
	must(t, ownerPool.QueryRow(ctx, `SELECT count(*) FROM `+ident).Scan(&ownerCount))
	if ownerCount < 2 {
		t.Fatalf("chunk should contain multiple tenants' rows, has %d", ownerCount)
	}

	// Unscoped app access sees nothing.
	var unscoped int
	must(t, appPool.QueryRow(ctx, `SELECT count(*) FROM `+ident).Scan(&unscoped))
	if unscoped != 0 {
		t.Fatalf("unscoped direct chunk read returned %d rows (RLS bypass!)", unscoped)
	}

	// Scoped access sees exactly this tenant's rows inside the chunk.
	for _, tn := range []tenant{a, b} {
		var expected int
		must(t, ownerPool.QueryRow(ctx, `SELECT count(*) FROM `+ident+` WHERE org_id = $1`, tn.OrgID).Scan(&expected))
		var got int
		must(t, database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM `+ident).Scan(&got)
		}))
		if got != expected || got == 0 {
			t.Fatalf("%s: chunk read returned %d rows, want %d", tn.Slug, got, expected)
		}
		if got >= ownerCount {
			t.Fatalf("%s: chunk read returned %d rows of %d total (not filtered)", tn.Slug, got, ownerCount)
		}
	}
}
