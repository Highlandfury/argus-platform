package integration

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/argus-platform/argus/internal/platform/database"
	"github.com/argus-platform/argus/migrations"
)

// TestLatestVersionMatchesFiles enforces the migrations.Latest governance rule:
// the constant must always equal the highest numbered migration file.
func TestLatestVersionMatchesFiles(t *testing.T) {
	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		t.Fatalf("read embedded migrations: %v", err)
	}
	var maxVersion uint
	count := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		count++
		prefix, _, ok := strings.Cut(name, "_")
		if !ok {
			t.Fatalf("migration %q has no numeric prefix", name)
		}
		v, err := strconv.ParseUint(prefix, 10, 32)
		if err != nil {
			t.Fatalf("migration %q prefix: %v", name, err)
		}
		if uint(v) > maxVersion {
			maxVersion = uint(v)
		}
	}
	if count == 0 {
		t.Fatal("no migration files found in embed FS")
	}
	if maxVersion != migrations.Latest {
		t.Fatalf("migrations.Latest=%d but highest file version is %d", migrations.Latest, maxVersion)
	}
}

// TestMigrationsDownAndUpOnFreshDatabase proves down migrations work and that
// re-applying from base succeeds — on a throwaway database so the shared
// schema used by other tests is untouched.
func TestMigrationsDownAndUpOnFreshDatabase(t *testing.T) {
	ctx := context.Background()
	dbName := "argus_mtest"

	if _, err := ownerPool.Exec(ctx, "DROP DATABASE IF EXISTS "+dbName+" WITH (FORCE)"); err != nil {
		t.Fatalf("drop pre-existing test db: %v", err)
	}
	if _, err := ownerPool.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		t.Fatalf("create test db: %v", err)
	}
	t.Cleanup(func() {
		_, _ = ownerPool.Exec(ctx, "DROP DATABASE IF EXISTS "+dbName+" WITH (FORCE)")
	})

	dsn := replaceDatabase(t, ownerDSN, dbName)

	version, err := database.MigrateUp(dsn)
	if err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	if version != migrations.Latest {
		t.Fatalf("version after up = %d, want %d", version, migrations.Latest)
	}
	if !tableExists(t, dsn, "public.collectors") {
		t.Fatal("collectors table missing after up")
	}

	if err := database.MigrateDown(dsn, int(migrations.Latest)); err != nil {
		t.Fatalf("migrate down: %v", err)
	}
	if tableExists(t, dsn, "public.collectors") {
		t.Fatal("collectors table still present after full down")
	}

	version, err = database.MigrateUp(dsn)
	if err != nil {
		t.Fatalf("migrate re-up: %v", err)
	}
	if version != migrations.Latest {
		t.Fatalf("version after re-up = %d, want %d", version, migrations.Latest)
	}

	// Idempotent replay on the shared database.
	if v, err := database.MigrateUp(ownerDSN); err != nil || v != migrations.Latest {
		t.Fatalf("idempotent replay: version=%d err=%v", v, err)
	}
}

// TestSchemaMatchesSpec asserts the structural contract of PHASE_1_SPEC §7.1.
func TestSchemaMatchesSpec(t *testing.T) {
	ctx := context.Background()

	t.Run("tables", func(t *testing.T) {
		want := []string{
			"organizations", "sites", "users", "sessions",
			"enrollment_tokens", "collectors", "collector_certificates", "collector_policies",
			"metric_series", "metric_samples", "ingested_batches", "schema_migrations",
		}
		for _, tbl := range want {
			var exists bool
			must(t, ownerPool.QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", "public."+tbl).Scan(&exists))
			if !exists {
				t.Fatalf("table %s missing", tbl)
			}
		}
	})

	t.Run("hypertable", func(t *testing.T) {
		var dims int
		must(t, ownerPool.QueryRow(ctx,
			`SELECT num_dimensions FROM timescaledb_information.hypertables WHERE hypertable_name = 'metric_samples'`).Scan(&dims))
		if dims != 1 {
			t.Fatalf("metric_samples num_dimensions = %d, want 1", dims)
		}
		var interval string
		must(t, ownerPool.QueryRow(ctx,
			`SELECT time_interval::text FROM timescaledb_information.dimensions WHERE hypertable_name = 'metric_samples'`).Scan(&interval))
		if interval != "1 day" {
			t.Fatalf("metric_samples chunk interval = %q, want \"1 day\"", interval)
		}
	})

	t.Run("rls_enabled_and_forced", func(t *testing.T) {
		var n int
		must(t, ownerPool.QueryRow(ctx,
			`SELECT count(*) FROM pg_class c
			 JOIN pg_namespace ns ON ns.oid = c.relnamespace
			 WHERE ns.nspname = 'public' AND c.relkind = 'r'
			   AND c.relrowsecurity AND c.relforcerowsecurity`).Scan(&n))
		if n != 11 {
			t.Fatalf("RLS-enabled+forced tables = %d, want 11", n)
		}
		var policies int
		must(t, ownerPool.QueryRow(ctx, `SELECT count(*) FROM pg_policies WHERE schemaname = 'public'`).Scan(&policies))
		if policies != 11 {
			t.Fatalf("tenant policies = %d, want 11", policies)
		}
	})

	t.Run("partial_unique_series_index", func(t *testing.T) {
		var def string
		must(t, ownerPool.QueryRow(ctx,
			`SELECT indexdef FROM pg_indexes WHERE schemaname='public' AND indexname='metric_series_collector_identity'`).Scan(&def))
		if !strings.Contains(def, "UNIQUE") || !strings.Contains(def, "WHERE (device_id IS NULL)") {
			t.Fatalf("unexpected metric_series_collector_identity definition: %s", def)
		}
	})

	t.Run("metric_samples_fk_contract", func(t *testing.T) {
		// Exactly one FK (org_id); series_id deliberately has no FK (hot ingest path).
		var n int
		must(t, ownerPool.QueryRow(ctx,
			`SELECT count(*) FROM pg_constraint WHERE conrelid = 'public.metric_samples'::regclass AND contype = 'f'`).Scan(&n))
		if n != 1 {
			t.Fatalf("metric_samples FK count = %d, want 1 (org only)", n)
		}
		var checkExists bool
		must(t, ownerPool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='public.metric_samples'::regclass AND conname='metric_samples_value_finite')`).Scan(&checkExists))
		if !checkExists {
			t.Fatal("metric_samples_value_finite check missing")
		}
	})

	t.Run("collectors_status_check", func(t *testing.T) {
		var exists bool
		must(t, ownerPool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='public.collectors'::regclass AND conname='collectors_status_check')`).Scan(&exists))
		if !exists {
			t.Fatal("collectors_status_check missing")
		}
	})

	t.Run("schema_migrations_state", func(t *testing.T) {
		var version uint
		var dirty bool
		must(t, ownerPool.QueryRow(ctx, `SELECT version, dirty FROM schema_migrations`).Scan(&version, &dirty))
		if dirty {
			t.Fatal("schema_migrations dirty")
		}
		if version != migrations.Latest {
			t.Fatalf("schema_migrations version = %d, want %d", version, migrations.Latest)
		}
	})
}

func replaceDatabase(t *testing.T, dsn, name string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	u.Path = "/" + name
	return u.String()
}

func tableExists(t *testing.T, dsn, qualifiedName string) bool {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	var exists bool
	if err := conn.QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", qualifiedName).Scan(&exists); err != nil {
		t.Fatalf("to_regclass: %v", err)
	}
	return exists
}
