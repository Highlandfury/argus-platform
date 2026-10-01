package credentials

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/argus-platform/argus/internal/platform/database"
	"github.com/argus-platform/argus/internal/platform/secrets"
)

// Resolver is the M9 use-hook boundary: it answers "which credential applies
// to this device?" and (internally only) materializes its plaintext. It is NOT
// wired to any HTTP route — the API is write-only; dispatch-time use happens in
// the future collector policy path (M9), which will call this resolver.
//
// Resolution runs org-scoped (database.WithTenant → RLS), so a device or
// binding of another tenant is invisible: cross-tenant probes fail closed with
// ErrDeviceNotFound and never resolve to a credential.
type Resolver struct {
	app   *pgxpool.Pool
	vault secrets.SecretsVault
	// groupMembership resolves dynamic device_group membership. It is nil
	// until the selector grammar lands (M9): dynamic group membership is not
	// resolvable from the current schema, so the device_group tier is a
	// documented extension point (see M7_EVIDENCE.md).
	groupMembership GroupMembershipFunc
}

// GroupMembershipFunc resolves the device_group ids a device belongs to. M9
// plugs selector evaluation in here without changing the resolver.
type GroupMembershipFunc func(ctx context.Context, tx pgx.Tx, deviceID uuid.UUID) ([]uuid.UUID, error)

// Option configures a Resolver (extension point for M9).
type Option func(*Resolver)

// WithGroupMembership supplies the device→device_group membership resolver.
func WithGroupMembership(fn GroupMembershipFunc) Option {
	return func(r *Resolver) { r.groupMembership = fn }
}

// NewResolver wires the resolver to the app pool (RLS-enforced) and the
// SecretsVault.
func NewResolver(app *pgxpool.Pool, vault secrets.SecretsVault, opts ...Option) *Resolver {
	r := &Resolver{app: app, vault: vault}
	for _, o := range opts {
		o(r)
	}
	return r
}

// ResolveForDevice returns the effective credential for a live device using
// the canonical precedence (docs/14 §24.5, docs/11 §21.1): direct device
// binding > device_group binding > site binding > org binding; within one scope
// level the higher priority wins; same priority is broken deterministically by
// the lowest (oldest) credential id. Unbound devices fail with
// ErrNoCredential; unknown/foreign devices with ErrDeviceNotFound.
func (r *Resolver) ResolveForDevice(ctx context.Context, orgID, deviceID uuid.UUID) (EffectiveCredential, error) {
	if r == nil || r.app == nil {
		return EffectiveCredential{}, errors.New("credentials: resolver not configured")
	}
	var eff EffectiveCredential
	err := database.WithTenant(ctx, r.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		eff, err = r.resolveForDeviceTx(ctx, tx, deviceID)
		return err
	})
	return eff, err
}

// Materialize resolves the effective credential and decrypts its envelope
// through the SecretsVault. It is the ONLY path that returns plaintext, it is
// internal-only (never wired to HTTP), and callers must treat the returned
// bytes as sensitive: no logging, no persistence beyond the collector session
// for which it was materialized. Crypto-shredding (deleted key material) fails
// Opener with a vault error.
func (r *Resolver) Materialize(ctx context.Context, orgID, deviceID uuid.UUID) ([]byte, EffectiveCredential, error) {
	if r == nil || r.app == nil {
		return nil, EffectiveCredential{}, errors.New("credentials: resolver not configured")
	}
	if r.vault == nil {
		return nil, EffectiveCredential{}, ErrVaultUnavailable
	}
	var (
		env secrets.Envelope
		eff EffectiveCredential
	)
	err := database.WithTenant(ctx, r.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		eff, err = r.resolveForDeviceTx(ctx, tx, deviceID)
		if err != nil {
			return err
		}
		row, err := findCredential(ctx, tx, eff.CredentialID)
		if err != nil {
			return err
		}
		env, err = row.Envelope()
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, EffectiveCredential{}, err
	}
	// Decrypt outside the transaction: the envelope was loaded in tenant scope
	// and its encryption context binds it to {org, kind, id, version}.
	plaintext, err := r.vault.Open(env)
	if err != nil {
		return nil, EffectiveCredential{}, err
	}
	return plaintext, eff, nil
}

// resolveForDeviceTx resolves within an existing tenant transaction: the
// device's site anchors the site/org tiers, and the (currently empty)
// membership list anchors the device_group tier.
func (r *Resolver) resolveForDeviceTx(ctx context.Context, tx pgx.Tx, deviceID uuid.UUID) (EffectiveCredential, error) {
	var siteID uuid.UUID
	err := tx.QueryRow(ctx,
		`SELECT site_id FROM devices WHERE id = $1 AND deleted_at IS NULL`, deviceID).Scan(&siteID)
	if errors.Is(err, pgx.ErrNoRows) {
		return EffectiveCredential{}, ErrDeviceNotFound
	}
	if err != nil {
		return EffectiveCredential{}, err
	}

	groupIDs, err := r.deviceGroupIDs(ctx, tx, deviceID)
	if err != nil {
		return EffectiveCredential{}, err
	}
	candidates, err := candidateBindings(ctx, tx, deviceID, siteID, groupIDs)
	if err != nil {
		return EffectiveCredential{}, err
	}
	eff, ok := selectEffective(candidates)
	if !ok {
		return EffectiveCredential{}, ErrNoCredential
	}
	return eff, nil
}

func (r *Resolver) deviceGroupIDs(ctx context.Context, tx pgx.Tx, deviceID uuid.UUID) ([]uuid.UUID, error) {
	if r.groupMembership == nil {
		// Documented limitation: dynamic selector membership is not resolvable
		// from the current schema; M9 plugs WithGroupMembership in.
		return nil, nil
	}
	return r.groupMembership(ctx, tx, deviceID)
}

// candidateBindings loads every binding that applies to the device (direct,
// group-tier memberships, site, org) with its credential metadata. The safe
// column list is used: resolution needs identity, not key material.
func candidateBindings(ctx context.Context, tx pgx.Tx, deviceID, siteID uuid.UUID, groupIDs []uuid.UUID) ([]candidate, error) {
	// key_version is selected alongside the metadata projection: dispatch
	// materialization binds the envelope generation into the authenticated
	// context (M9-S3) without exposing envelope bytes to the resolver result.
	rows, err := tx.Query(ctx, `
		SELECT `+credentialMetaColumns+`, c.key_version,
		       b.id, b.org_id, b.credential_id, b.scope_type, b.scope_id, b.priority, b.created_at
		FROM credential_bindings b
		JOIN device_credentials c ON c.id = b.credential_id
		WHERE (b.scope_type = 'device' AND b.scope_id = $1)
		   OR (b.scope_type = 'device_group' AND b.scope_id = ANY($2))
		   OR (b.scope_type = 'site' AND b.scope_id = $3)
		   OR (b.scope_type = 'org')
		ORDER BY b.id`, deviceID, groupIDs, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]candidate, 0, 8)
	for rows.Next() {
		var (
			c Credential
			b Binding
		)
		if err := rows.Scan(&c.ID, &c.OrgID, &c.Name, &c.Kind, &c.Metadata,
			&c.RotatedAt, &c.CreatedAt, &c.UpdatedAt, &c.KeyVersion,
			&b.ID, &b.OrgID, &b.CredentialID, &b.ScopeType, &b.ScopeID, &b.Priority, &b.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, candidate{Credential: c, Binding: b})
	}
	return out, rows.Err()
}
