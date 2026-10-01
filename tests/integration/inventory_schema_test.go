package integration

// M7-S1 (Phase 2): inventory + credential schema acceptance on the real
// TimescaleDB harness — migrations 000008/000009 apply cleanly, RLS isolates
// all six new tables across two orgs, and the canonical constraints
// (UQ(device_id, if_index), UQ(credential_id, scope_type, scope_id)) hold.
// The down/up round-trip follows TestMigrationsDownAndUpOnFreshDatabase.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/argus-platform/argus/internal/platform/database"
	"github.com/argus-platform/argus/migrations"
)

// inventoryTables is the seven-table M7-S1/S3 tenant surface.
var inventoryTables = []string{
	"devices",
	"interfaces",
	"device_identity_history",
	"device_groups",
	"device_credentials",
	"credential_bindings",
	"user_scope_bindings",
}

const sqlstateUniqueViolation = "23505"

// inventoryFixture holds one tenant's M7 rows (one per table).
type inventoryFixture struct {
	DeviceID       string
	InterfaceID    string
	IdentityID     string
	GroupID        string
	CredentialID   string
	BindingID      string
	ScopeBindingID string
}

// seedInventoryFixture writes one row into each M7 table through the sanctioned
// app path (WithTenant), proving RLS WITH CHECK accepts the tenant's own writes.
func seedInventoryFixture(t *testing.T, tn tenant) inventoryFixture {
	t.Helper()
	ctx := context.Background()
	fx := inventoryFixture{
		DeviceID:       newUUID(),
		InterfaceID:    newUUID(),
		IdentityID:     newUUID(),
		GroupID:        newUUID(),
		CredentialID:   newUUID(),
		BindingID:      newUUID(),
		ScopeBindingID: newUUID(),
	}
	err := database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO devices (id, org_id, site_id, name, kind, mgmt_ip, serial, sys_object_id)
			 VALUES ($1, $2, $3, $4, 'switch', '10.0.0.10', $5, '1.3.6.1.4.1.9')`,
			fx.DeviceID, tn.OrgID, tn.SiteID, "dev-"+tn.Slug, "SN-"+tn.Slug); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO interfaces (id, org_id, device_id, if_index, if_name, if_alias, role)
			 VALUES ($1, $2, $3, 1, 'Gi1/0/1', 'uplink', 'uplink')`,
			fx.InterfaceID, tn.OrgID, fx.DeviceID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO device_identity_history (id, org_id, device_id, identifier_type, identifier_value, source)
			 VALUES ($1, $2, $3, 'serial', $4, 'manual')`,
			fx.IdentityID, tn.OrgID, fx.DeviceID, "SN-"+tn.Slug); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO device_groups (id, org_id, name, selector) VALUES ($1, $2, $3, $4::jsonb)`,
			fx.GroupID, tn.OrgID, "grp-"+tn.Slug, `{"kinds":["switch"]}`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO device_credentials (id, org_id, name, kind, data_enc, kms_key_id, key_version, encryption_context)
			 VALUES ($1, $2, $3, 'snmp_v2c', $4, 'dev-master-key', 1, $5::jsonb)`,
			fx.CredentialID, tn.OrgID, "cred-"+tn.Slug, []byte("envelope-"+tn.Slug), `{"secret_type":"snmp_v2c"}`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO credential_bindings (id, org_id, credential_id, scope_type, scope_id, priority)
			 VALUES ($1, $2, $3, 'device', $4, 10)`,
			fx.BindingID, tn.OrgID, fx.CredentialID, fx.DeviceID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO user_scope_bindings (id, org_id, user_id, scope_type, scope_id)
			 VALUES ($1, $2, $3, 'site', $4)`,
			fx.ScopeBindingID, tn.OrgID, tn.UserID, tn.SiteID); err != nil {
			return err
		}
		return nil
	})
	must(t, err)
	return fx
}

// countInventoryRows counts rows per M7 table as seen by asOrg while filtering
// for filterOrg — RLS only, no application-layer filter (mirrors countRowsOn).
func countInventoryRows(t *testing.T, asOrg string, filterOrg string) map[string]int {
	t.Helper()
	ctx := context.Background()
	out := make(map[string]int, len(inventoryTables))
	must(t, database.WithTenant(ctx, appPool, mustUUID(t, asOrg), func(ctx context.Context, tx pgx.Tx) error {
		for _, tbl := range inventoryTables {
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

// TestInventorySchemaMigrated asserts the M7-S1/S3 structural contract on the
// harness database: schema version, the seven tables, forced RLS + tenant
// policy on each, and the named canonical constraints/indexes.
func TestInventorySchemaMigrated(t *testing.T) {
	ctx := context.Background()

	var version uint
	var dirty bool
	must(t, ownerPool.QueryRow(ctx, `SELECT version, dirty FROM schema_migrations`).Scan(&version, &dirty))
	if dirty {
		t.Fatal("schema_migrations dirty")
	}
	if version != migrations.Latest {
		t.Fatalf("schema version = %d, want %d (migrations 000008..000011)", version, migrations.Latest)
	}

	for _, tbl := range inventoryTables {
		var exists bool
		must(t, ownerPool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, "public."+tbl).Scan(&exists))
		if !exists {
			t.Fatalf("table %s missing (migrations 000008..000011)", tbl)
		}
		var rls, forced bool
		must(t, ownerPool.QueryRow(ctx,
			`SELECT c.relrowsecurity, c.relforcerowsecurity
			 FROM pg_class c JOIN pg_namespace ns ON ns.oid = c.relnamespace
			 WHERE ns.nspname = 'public' AND c.relname = $1`, tbl).Scan(&rls, &forced))
		if !rls || !forced {
			t.Fatalf("%s: RLS enabled=%v forced=%v, want both true", tbl, rls, forced)
		}
		var policies int
		must(t, ownerPool.QueryRow(ctx,
			`SELECT count(*) FROM pg_policies WHERE schemaname = 'public' AND tablename = $1 AND policyname = $2`,
			tbl, tbl+"_tenant").Scan(&policies))
		if policies != 1 {
			t.Fatalf("%s: %s policies = %d, want 1", tbl, tbl+"_tenant", policies)
		}
	}

	t.Run("constraints", func(t *testing.T) {
		for _, con := range []struct{ table, name string }{
			{"interfaces", "interfaces_device_if_index_key"},
			{"credential_bindings", "credential_bindings_scope_key"},
		} {
			var exists bool
			must(t, ownerPool.QueryRow(ctx,
				`SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = $1::regclass AND conname = $2)`,
				"public."+con.table, con.name).Scan(&exists))
			if !exists {
				t.Fatalf("%s.%s missing", con.table, con.name)
			}
		}
		var def string
		must(t, ownerPool.QueryRow(ctx,
			`SELECT indexdef FROM pg_indexes WHERE schemaname = 'public' AND indexname = 'devices_org_site_name_uniq'`).Scan(&def))
		if !strings.Contains(def, "UNIQUE") || !strings.Contains(def, "WHERE (deleted_at IS NULL)") {
			t.Fatalf("unexpected devices_org_site_name_uniq definition: %s", def)
		}
		// Open identity windows are unique per (org, identifier_type,
		// identifier_value); closed history rows may repeat (migration 000011).
		var openUniq string
		must(t, ownerPool.QueryRow(ctx,
			`SELECT indexdef FROM pg_indexes WHERE schemaname = 'public' AND indexname = 'device_identity_history_open_uniq'`).Scan(&openUniq))
		if !strings.Contains(openUniq, "UNIQUE") || !strings.Contains(openUniq, "WHERE (last_seen_at IS NULL)") {
			t.Fatalf("unexpected device_identity_history_open_uniq definition: %s", openUniq)
		}
	})
}

// TestInventorySchemaRLSIsolation proves cross-tenant isolation for all six
// tables with the existing mechanics: own rows visible, foreign rows invisible,
// cross-tenant inserts denied (WITH CHECK), foreign updates/deletes inert, and
// unscoped access default-deny.
func TestInventorySchemaRLSIsolation(t *testing.T) {
	ctx := context.Background()
	a := seedTenant(t, "m7-iso-a-"+newUUID()[:8])
	b := seedTenant(t, "m7-iso-b-"+newUUID()[:8])
	seedInventoryFixture(t, a)
	fxOther := seedInventoryFixture(t, b)

	for _, tc := range []struct {
		name string
		as   tenant
		fil  tenant
		want int
	}{
		{"a-own", a, a, 1},
		{"a-foreign", a, b, 0},
		{"b-own", b, b, 1},
		{"b-foreign", b, a, 0},
	} {
		t.Run(tc.name+"-rows", func(t *testing.T) {
			for tbl, n := range countInventoryRows(t, tc.as.OrgID, tc.fil.OrgID) {
				if n != tc.want {
					t.Fatalf("org %s sees %d rows in %s filtered for %s, want %d", tc.as.Slug, n, tbl, tc.fil.Slug, tc.want)
				}
			}
		})
	}

	// Point query for a foreign device ID yields zero rows, not an error.
	var n int
	must(t, database.WithTenant(ctx, appPool, mustUUID(t, a.OrgID), func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM devices WHERE id = $1`, fxOther.DeviceID).Scan(&n)
	}))
	if n != 0 {
		t.Fatalf("tenant A can see tenant B's device by ID")
	}

	// Unscoped reads (no app.current_org) see nothing.
	for _, tbl := range inventoryTables {
		var unscoped int
		must(t, appPool.QueryRow(ctx, `SELECT count(*) FROM `+tbl).Scan(&unscoped))
		if unscoped != 0 {
			t.Fatalf("unscoped query on %s returned %d rows (must be 0 under default-deny RLS)", tbl, unscoped)
		}
	}

	// Foreign-org INSERTs fail RLS WITH CHECK for every table.
	foreignInserts := []struct {
		name string
		sql  string
		args []any
	}{
		{"devices", `INSERT INTO devices (id, org_id, site_id, name, kind) VALUES ($1, $2, $3, 'intruder', 'switch')`,
			[]any{newUUID(), b.OrgID, b.SiteID}},
		{"interfaces", `INSERT INTO interfaces (id, org_id, device_id, if_index, if_name) VALUES ($1, $2, $3, 4242, 'intruder0')`,
			[]any{newUUID(), b.OrgID, fxOther.DeviceID}},
		{"device_identity_history", `INSERT INTO device_identity_history (id, org_id, device_id, identifier_type, identifier_value, source) VALUES ($1, $2, $3, 'serial', 'SN-INTRUDER', 'manual')`,
			[]any{newUUID(), b.OrgID, fxOther.DeviceID}},
		{"device_groups", `INSERT INTO device_groups (id, org_id, name) VALUES ($1, $2, 'intruder-group')`,
			[]any{newUUID(), b.OrgID}},
		{"device_credentials", `INSERT INTO device_credentials (id, org_id, name, kind, data_enc, kms_key_id, key_version) VALUES ($1, $2, 'intruder-cred', 'snmp_v2c', $3, 'dev-master-key', 1)`,
			[]any{newUUID(), b.OrgID, []byte("intruder-envelope")}},
		{"credential_bindings", `INSERT INTO credential_bindings (id, org_id, credential_id, scope_type, scope_id) VALUES ($1, $2, $3, 'device', $4)`,
			[]any{newUUID(), b.OrgID, fxOther.CredentialID, fxOther.DeviceID}},
		{"user_scope_bindings", `INSERT INTO user_scope_bindings (id, org_id, user_id, scope_type, scope_id) VALUES ($1, $2, $3, 'site', $4)`,
			[]any{newUUID(), b.OrgID, b.UserID, b.SiteID}},
	}
	for _, tc := range foreignInserts {
		t.Run("insert-"+tc.name, func(t *testing.T) {
			err := database.WithTenant(ctx, appPool, mustUUID(t, a.OrgID), func(ctx context.Context, tx pgx.Tx) error {
				_, err := tx.Exec(ctx, tc.sql, tc.args...)
				return err
			})
			if got := pgErrCode(err); got != sqlstateInsufficientPrivilege {
				t.Fatalf("insert %s with foreign org_id: want SQLSTATE %s (RLS violation), got %q (%v)",
					tc.name, sqlstateInsufficientPrivilege, got, err)
			}
		})
	}

	// Foreign UPDATE/DELETE affect zero rows (rows are invisible under RLS).
	must(t, database.WithTenant(ctx, appPool, mustUUID(t, a.OrgID), func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE devices SET name = 'hacked' WHERE id = $1`, fxOther.DeviceID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 0 {
			return fmt.Errorf("UPDATE reached a foreign device row (%d affected)", tag.RowsAffected())
		}
		tag, err = tx.Exec(ctx, `DELETE FROM credential_bindings WHERE id = $1`, fxOther.BindingID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 0 {
			return fmt.Errorf("DELETE reached a foreign binding row (%d affected)", tag.RowsAffected())
		}
		return nil
	}))

	// Tenant B's data is intact.
	for tbl, n := range countInventoryRows(t, b.OrgID, b.OrgID) {
		if n != 1 {
			t.Fatalf("tenant B lost data in %s: %d rows, want 1", tbl, n)
		}
	}
}

// TestInventorySchemaConstraints proves the canonical uniqueness rules reject
// duplicates while still allowing legitimate multi-device / rotation cases.
func TestInventorySchemaConstraints(t *testing.T) {
	ctx := context.Background()
	tn := seedTenant(t, "m7-cons-"+newUUID()[:8])
	fx := seedInventoryFixture(t, tn)

	t.Run("duplicate_device_if_index_rejected", func(t *testing.T) {
		err := database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx,
				`INSERT INTO interfaces (id, org_id, device_id, if_index, if_name) VALUES ($1, $2, $3, 1, 'dup0')`,
				newUUID(), tn.OrgID, fx.DeviceID)
			return err
		})
		if got := pgErrCode(err); got != sqlstateUniqueViolation {
			t.Fatalf("duplicate (device_id, if_index): want SQLSTATE %s, got %q (%v)", sqlstateUniqueViolation, got, err)
		}
	})

	t.Run("same_if_index_other_device_allowed", func(t *testing.T) {
		device2 := newUUID()
		must(t, database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
			if _, err := tx.Exec(ctx,
				`INSERT INTO devices (id, org_id, site_id, name, kind) VALUES ($1, $2, $3, $4, 'switch')`,
				device2, tn.OrgID, tn.SiteID, "dev2-"+tn.Slug); err != nil {
				return err
			}
			_, err := tx.Exec(ctx,
				`INSERT INTO interfaces (id, org_id, device_id, if_index, if_name) VALUES ($1, $2, $3, 1, 'Gi1/0/1')`,
				newUUID(), tn.OrgID, device2)
			return err
		}))
	})

	t.Run("duplicate_binding_per_scope_rejected", func(t *testing.T) {
		err := database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx,
				`INSERT INTO credential_bindings (id, org_id, credential_id, scope_type, scope_id, priority) VALUES ($1, $2, $3, 'device', $4, 20)`,
				newUUID(), tn.OrgID, fx.CredentialID, fx.DeviceID)
			return err
		})
		if got := pgErrCode(err); got != sqlstateUniqueViolation {
			t.Fatalf("duplicate (credential_id, scope_type, scope_id): want SQLSTATE %s, got %q (%v)", sqlstateUniqueViolation, got, err)
		}
	})

	t.Run("same_scope_other_credential_allowed", func(t *testing.T) {
		cred2 := newUUID()
		must(t, database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
			if _, err := tx.Exec(ctx,
				`INSERT INTO device_credentials (id, org_id, name, kind, data_enc, kms_key_id, key_version)
				 VALUES ($1, $2, $3, 'snmp_v3', $4, 'dev-master-key', 1)`,
				cred2, tn.OrgID, "cred2-"+tn.Slug, []byte("envelope2-"+tn.Slug)); err != nil {
				return err
			}
			// Rotation case: a second credential may target the same device scope;
			// priority orders them at dispatch.
			_, err := tx.Exec(ctx,
				`INSERT INTO credential_bindings (id, org_id, credential_id, scope_type, scope_id, priority)
				 VALUES ($1, $2, $3, 'device', $4, 5)`,
				newUUID(), tn.OrgID, cred2, fx.DeviceID)
			return err
		}))
	})

	t.Run("device_name_unique_per_site_live_only", func(t *testing.T) {
		dupName := "dev-dup-" + tn.Slug
		deviceA, deviceB := newUUID(), newUUID()
		insertNamed := func(id, name string) error {
			return database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
				_, err := tx.Exec(ctx,
					`INSERT INTO devices (id, org_id, site_id, name, kind) VALUES ($1, $2, $3, $4, 'switch')`,
					id, tn.OrgID, tn.SiteID, name)
				return err
			})
		}
		must(t, insertNamed(deviceA, dupName))
		if got := pgErrCode(insertNamed(deviceB, dupName)); got != sqlstateUniqueViolation {
			t.Fatalf("duplicate live device name in site: want SQLSTATE %s, got %q", sqlstateUniqueViolation, got)
		}
		// Soft delete frees the name (partial unique index on deleted_at IS NULL).
		must(t, database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE devices SET deleted_at = now() WHERE id = $1`, deviceA)
			return err
		}))
		must(t, insertNamed(deviceB, dupName))
	})

	t.Run("open_identity_unique_history_repeats_and_reuse", func(t *testing.T) {
		value := "SN-" + tn.Slug // the fixture's open serial on fx.DeviceID
		device2, device3 := newUUID(), newUUID()
		must(t, database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
			for _, d := range []struct{ id, name string }{
				{device2, "uniq2-" + tn.Slug},
				{device3, "uniq3-" + tn.Slug},
			} {
				if _, err := tx.Exec(ctx,
					`INSERT INTO devices (id, org_id, site_id, name, kind) VALUES ($1, $2, $3, $4, 'switch')`,
					d.id, tn.OrgID, tn.SiteID, d.name); err != nil {
					return err
				}
			}
			return nil
		}))

		openIdentity := func(deviceID, value string) error {
			return database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
				_, err := tx.Exec(ctx,
					`INSERT INTO device_identity_history (id, org_id, device_id, identifier_type, identifier_value, source)
					 VALUES ($1, $2, $3, 'serial', $4, 'manual')`,
					newUUID(), tn.OrgID, deviceID, value)
				return err
			})
		}

		// A second OPEN window for the same serial in the same org is rejected.
		if got := pgErrCode(openIdentity(device2, value)); got != sqlstateUniqueViolation {
			t.Fatalf("duplicate open identity: want SQLSTATE %s, got %q", sqlstateUniqueViolation, got)
		}

		// Close the old window: the serial is re-claimable.
		must(t, database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx,
				`UPDATE device_identity_history SET last_seen_at = now()
				 WHERE device_id = $1 AND identifier_type = 'serial' AND identifier_value = $2 AND last_seen_at IS NULL`,
				fx.DeviceID, value)
			return err
		}))
		must(t, openIdentity(device2, value))

		// Historical (closed) rows may repeat — even while the value is open.
		must(t, database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx,
				`INSERT INTO device_identity_history (id, org_id, device_id, identifier_type, identifier_value, source, first_seen_at, last_seen_at)
				 VALUES ($1, $2, $3, 'serial', $4, 'manual', now() - interval '2 days', now() - interval '1 day')`,
				newUUID(), tn.OrgID, device3, value)
			return err
		}))

		// Cross-tenant: another org may hold the same serial open concurrently
		// (the uniqueness scope is org-wide).
		other := seedTenant(t, "m7-uniq-"+newUUID()[:8])
		otherDevice := newUUID()
		must(t, database.WithTenant(ctx, appPool, mustUUID(t, other.OrgID), func(ctx context.Context, tx pgx.Tx) error {
			if _, err := tx.Exec(ctx,
				`INSERT INTO devices (id, org_id, site_id, name, kind) VALUES ($1, $2, $3, 'uniq-other', 'switch')`,
				otherDevice, other.OrgID, other.SiteID); err != nil {
				return err
			}
			_, err := tx.Exec(ctx,
				`INSERT INTO device_identity_history (id, org_id, device_id, identifier_type, identifier_value, source)
				 VALUES ($1, $2, $3, 'serial', $4, 'manual')`,
				newUUID(), other.OrgID, otherDevice, value)
			return err
		}))
	})
}

// TestInventorySchemaDownUpRoundTrip steps migrations down to version 7 on a
// throwaway database: the seven M7 tables (and the open-identity unique index)
// disappear, the Phase-1 schema stays, and re-applying up restores everything
// (including the M8 metrics migrations). The step count follows
// migrations.Latest so later milestones extend the round trip automatically.
func TestInventorySchemaDownUpRoundTrip(t *testing.T) {
	ctx := context.Background()
	dbName := "argus_m7test"

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
	for _, tbl := range inventoryTables {
		if !tableExists(t, dsn, "public."+tbl) {
			t.Fatalf("%s missing after up", tbl)
		}
	}
	if !indexExists(t, dsn, "device_identity_history_open_uniq") {
		t.Fatal("device_identity_history_open_uniq missing after up")
	}

	if err := database.MigrateDown(dsn, int(migrations.Latest)-7); err != nil {
		t.Fatalf("migrate down to version 7: %v", err)
	}
	for _, tbl := range inventoryTables {
		if tableExists(t, dsn, "public."+tbl) {
			t.Fatalf("%s still present after down", tbl)
		}
	}
	if indexExists(t, dsn, "device_identity_history_open_uniq") {
		t.Fatal("device_identity_history_open_uniq still present after down")
	}
	if !tableExists(t, dsn, "public.collectors") {
		t.Fatal("Phase-1 collectors table lost on M7 down")
	}

	version, err = database.MigrateUp(dsn)
	if err != nil {
		t.Fatalf("migrate re-up: %v", err)
	}
	if version != migrations.Latest {
		t.Fatalf("version after re-up = %d, want %d", version, migrations.Latest)
	}
	for _, tbl := range inventoryTables {
		if !tableExists(t, dsn, "public."+tbl) {
			t.Fatalf("%s missing after re-up", tbl)
		}
	}
}
