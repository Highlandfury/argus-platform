package tenancy

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/argus-platform/argus/internal/platform/database"
)

// ctxType keeps the repo SQL helper signatures pgx-compatible.
type ctxType = context.Context

// ErrInvalidCursor is returned for a malformed pagination cursor.
var ErrInvalidCursor = errors.New("tenancy: invalid cursor")

// SitePage is one page of sites with its continuation cursor.
type SitePage struct {
	Sites      []Site
	NextCursor string
}

// Service exposes tenancy reads. Writes (beyond the dev seed) arrive with the
// admin API later.
type Service struct {
	app  *pgxpool.Pool // RLS-enforced runtime role
	auth *pgxpool.Pool // pre-authentication lookup role
}

// New wires the tenancy service to its two pools.
func New(app, auth *pgxpool.Pool) *Service {
	return &Service{app: app, auth: auth}
}

// ListSitesPage returns sites ordered by id, limited, with an opaque
// continuation cursor (the last returned id).
func (s *Service) ListSitesPage(ctx context.Context, orgID uuid.UUID, limit int, cursor string) (SitePage, error) {
	if limit <= 0 || limit > 100 {
		return SitePage{}, ErrInvalidCursor
	}
	var after *uuid.UUID
	if cursor != "" {
		id, err := uuid.Parse(cursor)
		if err != nil {
			return SitePage{}, ErrInvalidCursor
		}
		after = &id
	}

	var page SitePage
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		sites, err := listSitesPage(ctx, tx, orgID, after, limit+1)
		if err != nil {
			return err
		}
		if len(sites) > limit {
			page.NextCursor = sites[limit-1].ID
			sites = sites[:limit]
		}
		page.Sites = sites
		return nil
	})
	return page, err
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
// flow through the restricted argus_auth role.
func (s *Service) ResolveOrgBySlug(ctx context.Context, slug string) (Org, error) {
	var org Org
	err := database.WithAuthTx(ctx, s.auth, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		org, err = getOrgBySlug(ctx, tx, slug)
		return err
	})
	return org, err
}
