// Package tenancy owns organizations, sites, and the development seed.
// HTTP handlers arrive in M2 with the authenticated API surface (no
// unauthenticated endpoints exist in M1).
package tenancy

import (
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrOrgNotFound is returned when a slug lookup finds no organization.
var ErrOrgNotFound = errors.New("tenancy: organization not found")

// Org is an organization record (minimal M1 projection).
type Org struct {
	ID   string
	Slug string
	Name string
}

// Site is a site record (minimal M1 projection).
type Site struct {
	ID   string
	Name string
}

func getOrgBySlug(ctx ctxType, tx pgx.Tx, slug string) (Org, error) {
	var org Org
	err := tx.QueryRow(ctx,
		`SELECT id, slug, name FROM organizations WHERE slug = $1`, slug).
		Scan(&org.ID, &org.Slug, &org.Name)
	if errors.Is(err, pgx.ErrNoRows) {
		return Org{}, ErrOrgNotFound
	}
	return org, err
}

func getOrgByID(ctx ctxType, tx pgx.Tx, orgID uuid.UUID) (Org, error) {
	var org Org
	err := tx.QueryRow(ctx,
		`SELECT id, slug, name FROM organizations WHERE id = $1`, orgID).
		Scan(&org.ID, &org.Slug, &org.Name)
	if errors.Is(err, pgx.ErrNoRows) {
		return Org{}, ErrOrgNotFound
	}
	return org, err
}

func insertOrg(ctx ctxType, tx pgx.Tx, id, slug, name string) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO organizations (id, slug, name) VALUES ($1, $2, $3)
		 ON CONFLICT (slug) DO NOTHING`, id, slug, name)
	return err
}

// upsertSite returns the site id and whether the row was newly inserted
// (xmax = 0 distinguishes insert from conflict-update).
func upsertSite(ctx ctxType, tx pgx.Tx, orgID, name string) (string, bool, error) {
	id, err := newID()
	if err != nil {
		return "", false, err
	}
	var outID string
	var inserted bool
	err = tx.QueryRow(ctx,
		`INSERT INTO sites (id, org_id, name) VALUES ($1, $2, $3)
		 ON CONFLICT (org_id, name) DO UPDATE SET updated_at = now()
		 RETURNING id, (xmax = 0) AS inserted`, id, orgID, name).Scan(&outID, &inserted)
	return outID, inserted, err
}

// upsertAdminUser converges the admin account (password hash refreshed on each
// seed run so dev environments are predictable).
func upsertAdminUser(ctx ctxType, tx pgx.Tx, orgID, email, passwordHash string) (string, bool, error) {
	id, err := newID()
	if err != nil {
		return "", false, err
	}
	var outID string
	var inserted bool
	err = tx.QueryRow(ctx,
		`INSERT INTO users (id, org_id, email, password_hash, role) VALUES ($1, $2, $3, $4, 'admin')
		 ON CONFLICT (org_id, lower(email)) DO UPDATE
		   SET password_hash = EXCLUDED.password_hash, role = 'admin', disabled_at = NULL, updated_at = now()
		 RETURNING id, (xmax = 0) AS inserted`, id, orgID, email, passwordHash).Scan(&outID, &inserted)
	return outID, inserted, err
}

func listSitesPage(ctx ctxType, tx pgx.Tx, orgID uuid.UUID, after *uuid.UUID, limit int) ([]Site, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, name FROM sites
		WHERE org_id = $1 AND ($2::uuid IS NULL OR id > $2)
		ORDER BY id
		LIMIT $3`, orgID, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sites := make([]Site, 0, limit)
	for rows.Next() {
		var s Site
		if err := rows.Scan(&s.ID, &s.Name); err != nil {
			return nil, err
		}
		sites = append(sites, s)
	}
	return sites, rows.Err()
}

func newID() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}
