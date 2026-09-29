package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/argus-platform/argus/internal/modules/tenancy"
	"github.com/argus-platform/argus/internal/platform/database"
	"github.com/argus-platform/argus/internal/platform/security"
)

// TestSeedDevIdempotentAndIsolated proves the development seed contract:
// converge-on-rerun with stable ids, per-org email uniqueness, and no
// cross-tenant leakage through the seeded data paths.
func TestSeedDevIdempotentAndIsolated(t *testing.T) {
	ctx := context.Background()
	slug := "seedtest-" + newUUID()[:8]

	passwordHash, err := security.HashPassword("it-password")
	must(t, err)
	params := tenancy.SeedParams{
		Slug:              slug,
		OrgName:           "Seed Org",
		SiteName:          "HQ",
		AdminEmail:        slug + "@dev.local",
		AdminPasswordHash: passwordHash,
	}

	first, err := tenancy.SeedDev(ctx, appPool, authPool, params)
	must(t, err)
	if !first.CreatedOrg || !first.CreatedSite || !first.CreatedUser {
		t.Fatalf("first run must create everything: %+v", first)
	}

	second, err := tenancy.SeedDev(ctx, appPool, authPool, params)
	must(t, err)
	if second.CreatedOrg || second.CreatedSite || second.CreatedUser {
		t.Fatalf("second run must converge without creating: %+v", second)
	}
	if second.OrgID != first.OrgID || second.SiteID != first.SiteID || second.UserID != first.UserID {
		t.Fatalf("ids must be stable across runs:\nfirst=%+v\nsecond=%+v", first, second)
	}

	// Exactly one site and one user; the converged hash verifies the password.
	orgUUID := mustUUID(t, first.OrgID)
	var sites, users int
	var storedHash string
	must(t, database.WithTenant(ctx, appPool, orgUUID, func(ctx context.Context, tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM sites`).Scan(&sites); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&users); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT password_hash FROM users WHERE id = $1`, first.UserID).Scan(&storedHash)
	}))
	if sites != 1 || users != 1 {
		t.Fatalf("sites=%d users=%d, want 1/1", sites, users)
	}
	ok, err := security.VerifyPassword(storedHash, "it-password")
	must(t, err)
	if !ok {
		t.Fatal("stored hash does not verify the seeded password")
	}

	// The same admin email in a different organization is allowed (email is
	// unique per org, not globally) and the two tenants stay isolated.
	other, err := tenancy.SeedDev(ctx, appPool, authPool, tenancy.SeedParams{
		Slug:              slug + "-b",
		OrgName:           "Seed Org B",
		SiteName:          "HQ",
		AdminEmail:        params.AdminEmail,
		AdminPasswordHash: passwordHash,
	})
	must(t, err)
	if other.OrgID == first.OrgID {
		t.Fatal("distinct slugs must produce distinct organizations")
	}
	var foreign int
	must(t, database.WithTenant(ctx, appPool, orgUUID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM users WHERE org_id = $1`, other.OrgID).Scan(&foreign)
	}))
	if foreign != 0 {
		t.Fatalf("tenant A sees %d of tenant B's seeded users", foreign)
	}

	// Pre-authentication slug resolution works through the restricted auth role.
	svc := tenancy.New(nil, authPool)
	got, err := svc.ResolveOrgBySlug(ctx, slug)
	must(t, err)
	if got.ID != first.OrgID {
		t.Fatalf("slug resolution returned %s, want %s", got.ID, first.OrgID)
	}
	if _, err := svc.ResolveOrgBySlug(ctx, slug+"-missing"); !errors.Is(err, tenancy.ErrOrgNotFound) {
		t.Fatalf("want ErrOrgNotFound for a missing slug, got %v", err)
	}
}
