package integration

import (
	"context"
	"errors"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/moby/moby/client"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/argus-platform/argus/internal/platform/database"
	"github.com/argus-platform/argus/migrations"
)

// TestFailedTransactionRollsBackAllSteps proves tenant transactions are atomic:
// a mid-transaction failure (CHECK violation) discards earlier statements and
// leaves no tenant context behind.
func TestFailedTransactionRollsBackAllSteps(t *testing.T) {
	ctx := context.Background()
	tn := seedTenant(t, "fail-rollback")
	collectorID := newUUID()

	err := database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO collectors (id, org_id, site_id, name) VALUES ($1, $2, $3, 'will-rollback')`,
			collectorID, tn.OrgID, tn.SiteID); err != nil {
			return err
		}
		// NaN violates metric_samples_value_finite -> aborts the transaction.
		_, err := tx.Exec(ctx,
			`INSERT INTO metric_samples (org_id, series_id, ts, value) VALUES ($1, $2, now(), $3)`,
			tn.OrgID, tn.SeriesID, math.NaN())
		return err
	})
	if got := pgErrCode(err); got != sqlstateCheckViolation {
		t.Fatalf("want SQLSTATE %s, got %q (%v)", sqlstateCheckViolation, got, err)
	}

	own := countRows(t, tn.OrgID, tn.OrgID)
	if own["collectors"] != 1 {
		t.Fatalf("collectors = %d, want 1 (the rolled-back insert must not survive)", own["collectors"])
	}
	assertNoTenantSetting(t, appPool)

	// The same connection/tenant remains usable for a clean unit of work.
	must(t, database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO collectors (id, org_id, site_id, name) VALUES ($1, $2, $3, 'after-rollback')`,
			collectorID, tn.OrgID, tn.SiteID)
		return err
	}))
	own = countRows(t, tn.OrgID, tn.OrgID)
	if own["collectors"] != 2 {
		t.Fatalf("collectors = %d, want 2 after clean retry", own["collectors"])
	}
}

// TestPartialBatchIsAtomicAndReplayable proves the ingest unit of work is
// all-or-nothing: a failed sample write must also discard the idempotency
// claim, and a retry of the same logical batch then lands exactly once.
func TestPartialBatchIsAtomicAndReplayable(t *testing.T) {
	ctx := context.Background()
	tn := seedTenant(t, "fail-partial")
	ts := time.Now().UTC().Truncate(time.Second).Add(2 * time.Minute)
	seq := int64(3001)

	// Attempt 1: claim succeeds, then the sample write fails (NaN).
	err := database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
		if _, err := claimBatch(ctx, tx, tn.CollectorID, tn.OrgID, seq, 1, ts); err != nil {
			return err
		}
		sid, err := insertSeries(ctx, tx, tn.OrgID, tn.CollectorID, "collector_cpu_percent", 1)
		if err != nil {
			return err
		}
		return insertSample(ctx, tx, tn.OrgID, sid, ts, math.NaN())
	})
	if got := pgErrCode(err); got != sqlstateCheckViolation {
		t.Fatalf("want SQLSTATE %s, got %q (%v)", sqlstateCheckViolation, got, err)
	}

	// The claim must have rolled back with the rest of the unit.
	var claims int
	must(t, database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM ingested_batches WHERE collector_id = $1 AND batch_seq = $2`,
			tn.CollectorID, seq).Scan(&claims)
	}))
	if claims != 0 {
		t.Fatalf("phantom claim survived rollback: %d rows for seq %d", claims, seq)
	}

	// Retry succeeds; replay is short-circuited by the claim.
	must(t, database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
		inserted, err := claimBatch(ctx, tx, tn.CollectorID, tn.OrgID, seq, 1, ts)
		if err != nil {
			return err
		}
		if !inserted {
			return errors.New("claim should succeed after rollback")
		}
		sid, err := insertSeries(ctx, tx, tn.OrgID, tn.CollectorID, "collector_cpu_percent", 1)
		if err != nil {
			return err
		}
		return insertSample(ctx, tx, tn.OrgID, sid, ts, 21)
	}))
	must(t, database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
		inserted, err := claimBatch(ctx, tx, tn.CollectorID, tn.OrgID, seq, 1, ts)
		if err != nil {
			return err
		}
		if inserted {
			return errors.New("replay accepted as new")
		}
		return nil
	}))

	var samples int
	must(t, database.WithTenant(ctx, appPool, mustUUID(t, tn.OrgID), func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM metric_samples WHERE series_id = $1 AND ts = $2`,
			tn.SeriesID, ts).Scan(&samples)
	}))
	if samples != 1 {
		t.Fatalf("samples = %d, want exactly 1", samples)
	}
}

// TestDatabaseRestartRecovery proves the platform survives a database restart:
// schema and data persist, migrations replay cleanly, and fresh clients connect.
//
// Restart mechanics: the container is recreated on the same named volume
// (equivalent to compose down/up or container replacement). An in-place restart
// of a container created with an EPHEMERAL host port is unreliable on Docker
// Desktop 4.93: the published-port proxy is not re-established after `start`
// (observed empirically; containers with explicit bindings — which is what the
// dev compose stack uses — are unaffected). The recreate variant is also the
// stronger test: the data must survive a brand-new container.
func TestDatabaseRestartRecovery(t *testing.T) {
	ctx := context.Background()
	volumeName := "argus-it-restart-" + newUUID()[:8]

	if dc, err := testcontainers.NewDockerClientWithOpts(ctx); err == nil {
		defer func() {
			_, _ = dc.VolumeRemove(context.Background(), volumeName, client.VolumeRemoveOptions{Force: true})
			_ = dc.Close()
		}()
	}

	startReplica := func() (testcontainers.Container, string, error) {
		c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image: timescaleImage,
				Env: map[string]string{
					"POSTGRES_DB":       "argus",
					"POSTGRES_USER":     "argus_owner",
					"POSTGRES_PASSWORD": "devpass",
				},
				ExposedPorts: []string{"5432/tcp"},
				// PostgreSQL 18 image layout: the data lives under /var/lib/postgresql.
				Mounts: testcontainers.ContainerMounts{{
					Source: testcontainers.GenericVolumeMountSource{Name: volumeName},
					Target: "/var/lib/postgresql",
				}},
				WaitingFor: wait.ForListeningPort("5432/tcp").WithStartupTimeout(5 * time.Minute),
			},
			Started: true,
		})
		if err != nil {
			return nil, "", err
		}
		host, err := c.Host(ctx)
		if err != nil {
			return nil, "", err
		}
		port, err := c.MappedPort(ctx, "5432/tcp")
		if err != nil {
			return nil, "", err
		}
		return c, fmt.Sprintf("postgres://argus_owner:devpass@%s:%s/argus?sslmode=disable", host, port.Port()), nil
	}

	// Boot #1: initialize schema and write tenant data.
	c1, base1, err := startReplica()
	must(t, err)
	must(t, waitStable(ctx, base1))
	version, err := database.MigrateUp(base1)
	if err != nil || version != migrations.Latest {
		t.Fatalf("migrate: version=%d err=%v", version, err)
	}
	must(t, applyDevRolesScript(ctx, base1))

	ownerP, err := database.NewPool(ctx, base1, "restart-owner", database.DefaultPoolConfig())
	must(t, err)
	appP, err := database.NewPool(ctx, appDSNFor(base1), "restart-app", database.DefaultPoolConfig())
	must(t, err)

	orgID, siteID, collectorID := newUUID(), newUUID(), newUUID()
	_, err = ownerP.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1, 'Restart Org', $2)`, orgID, "restart-"+orgID[:8])
	must(t, err)
	_, err = ownerP.Exec(ctx, `INSERT INTO sites (id, org_id, name) VALUES ($1, $2, 'HQ')`, siteID, orgID)
	must(t, err)
	must(t, database.WithTenant(ctx, appP, mustUUID(t, orgID), func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO collectors (id, org_id, site_id, name) VALUES ($1, $2, $3, 'restart-collector')`,
			collectorID, orgID, siteID)
		return err
	}))
	ownerP.Close()
	appP.Close()

	// Replace the container; the named volume keeps the data.
	must(t, testcontainers.TerminateContainer(c1))

	// Boot #2: fresh container, same volume.
	c2, base2, err := startReplica()
	must(t, err)
	defer func() { _ = testcontainers.TerminateContainer(c2) }()
	must(t, waitStable(ctx, base2))

	// Migrations are idempotent across the replacement and the schema is current.
	version, err = database.MigrateUp(base2)
	if err != nil || version != migrations.Latest {
		t.Fatalf("migrate after restart: version=%d err=%v", version, err)
	}

	// Data persisted and fresh clients see it.
	appP2, err := database.NewPool(ctx, appDSNFor(base2), "restart-app-2", database.DefaultPoolConfig())
	must(t, err)
	defer appP2.Close()
	var count int
	must(t, database.WithTenant(ctx, appP2, mustUUID(t, orgID), func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM collectors`).Scan(&count)
	}))
	if count != 1 {
		t.Fatalf("fresh client sees %d collectors after restart, want 1", count)
	}
}
