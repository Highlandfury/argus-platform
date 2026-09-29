package tenancy

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/argus-platform/argus/internal/platform/database"
)

// ctxType keeps the repo SQL helpers signature-compatible with pgx functions.
type ctxType = context.Context

// Service exposes tenancy reads. Writes (beyond the dev seed) arrive with the
// admin API in M2.
type Service struct {
	app  *pgxpool.Pool // RLS-enforced runtime role
	auth *pgxpool.Pool // pre-authentication lookup role
}

// New wires the tenancy service to its two pools.
func New(app, auth *pgxpool.Pool) *Service {
	return &Service{app: app, auth: auth}
}

// ListSites returns the sites of one organization (tenant-scoped read).
func (s *Service) ListSites(ctx context.Context, orgID uuid.UUID) ([]Site, error) {
	var sites []Site
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		sites, err = listSites(ctx, tx)
		return err
	})
	return sites, err
}

// GetOrg returns one organization by id (tenant-scoped read).
func (s *Service) GetOrg(ctx context.Context, orgID uuid.UUID) (Org, error) {
	var org Org
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		org, err = getOrgByID(ctx, tx, orgID)
		return err
	})
	return org, err
}

// ResolveOrgBySlug performs the pre-authentication lookup used by the login
// flow (M2) through the restricted argus_auth role.
func (s *Service) ResolveOrgBySlug(ctx context.Context, slug string) (Org, error) {
	var org Org
	err := database.WithAuthTx(ctx, s.auth, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		org, err = getOrgBySlug(ctx, tx, slug)
		return err
	})
	return org, err
}
