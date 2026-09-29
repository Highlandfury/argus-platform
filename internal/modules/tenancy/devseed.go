package tenancy

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/argus-platform/argus/internal/platform/database"
)

// SeedParams describes the development seed (all values non-secret except the
// pre-hashed admin password).
type SeedParams struct {
	Slug              string
	OrgName           string
	SiteName          string
	AdminEmail        string
	AdminPasswordHash string
}

// SeedResult reports what the seed converged (ids are stable across runs).
type SeedResult struct {
	OrgID       string
	SiteID      string
	UserID      string
	Email       string
	CreatedOrg  bool
	CreatedSite bool
	CreatedUser bool
}

// SeedDev idempotently converges the development organization, site, and admin
// user. The org lookup uses the restricted auth role (pre-auth style); all
// writes run through the RLS-enforced app pool inside the tenant transaction.
// Re-running refreshes the admin password hash (dev predictability).
func SeedDev(ctx context.Context, app, auth *pgxpool.Pool, p SeedParams) (SeedResult, error) {
	res := SeedResult{Email: p.AdminEmail}

	var org Org
	err := database.WithAuthTx(ctx, auth, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		org, err = getOrgBySlug(ctx, tx, p.Slug)
		if errors.Is(err, ErrOrgNotFound) {
			org = Org{}
			return nil
		}
		return err
	})
	if err != nil {
		return res, err
	}

	if org.ID == "" {
		id, err := newID()
		if err != nil {
			return res, err
		}
		org.ID, org.Slug, org.Name = id, p.Slug, p.OrgName
		res.CreatedOrg = true
	}
	res.OrgID = org.ID

	orgUUID, err := parseUUID(org.ID)
	if err != nil {
		return res, err
	}

	err = database.WithTenant(ctx, app, orgUUID, func(ctx context.Context, tx pgx.Tx) error {
		if res.CreatedOrg {
			if err := insertOrg(ctx, tx, org.ID, p.Slug, p.OrgName); err != nil {
				return err
			}
		}
		siteID, siteInserted, err := upsertSite(ctx, tx, org.ID, p.SiteName)
		if err != nil {
			return err
		}
		res.SiteID, res.CreatedSite = siteID, siteInserted

		userID, userInserted, err := upsertAdminUser(ctx, tx, org.ID, p.AdminEmail, p.AdminPasswordHash)
		if err != nil {
			return err
		}
		res.UserID, res.CreatedUser = userID, userInserted
		return nil
	})
	if err != nil {
		return res, err
	}
	return res, nil
}
