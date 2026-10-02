package credentials

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/argus-platform/argus/internal/platform/secrets"
)

// Sentinel errors are mapped to HTTP problems at the edge. Not-found covers
// out-of-scope resources too (RLS makes foreign rows invisible), so responses
// expose no existence oracle.
var (
	ErrNotFound          = errors.New("credentials: credential not found")
	ErrBindingNotFound   = errors.New("credentials: binding not found")
	ErrBindingConflict   = errors.New("credentials: binding already exists")
	ErrNameConflict      = errors.New("credentials: name already in use")
	ErrTargetNotFound    = errors.New("credentials: binding target not found")
	ErrNoCredential      = errors.New("credentials: no credential applies to the device")
	ErrDeviceNotFound    = errors.New("credentials: device not found")
	ErrInvalidCursor     = errors.New("credentials: invalid cursor")
	ErrInvalidScope      = errors.New("credentials: invalid scope type")
	ErrValidation        = errors.New("credentials: validation failed")
	ErrVaultUnavailable  = errors.New("credentials: secrets vault not configured")
	ErrEnvelopeMalformed = errors.New("credentials: stored envelope is unreadable")
)

// PostgreSQL SQLSTATE and constraint names used to map conflicts to their
// deterministic sentinels.
const (
	sqlstateUniqueViolation  = "23505"
	credentialNameConstraint = "device_credentials_org_name_key" //nolint:gosec // constraint name, not a credential
	bindingScopeConstraint   = "credential_bindings_scope_key"   //nolint:gosec // constraint name, not a credential
)

// isUniqueViolation reports whether err is a 23505 conflict on constraint.
func isUniqueViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) &&
		pgErr.Code == sqlstateUniqueViolation &&
		pgErr.ConstraintName == constraint
}

// credentialColumns / credentialMetaColumns are explicitly listed and shared by
// SELECT/RETURNING paths. The metadata column list deliberately omits the
// envelope columns; list endpoints never read secret material from the
// database.
//
//nolint:gosec // column list, not a credential
const credentialColumns = `c.id, c.org_id, c.name, c.kind, c.data_enc, c.kms_key_id, c.key_version,
	c.encryption_context, c.metadata, c.rotated_at, c.created_at, c.updated_at`

//nolint:gosec // column list, not a credential
const credentialMetaColumns = `c.id, c.org_id, c.name, c.kind, c.metadata,
	c.rotated_at, c.created_at, c.updated_at`

const bindingColumns = `b.id, b.org_id, b.credential_id, b.scope_type, b.scope_id, b.priority, b.created_at`

func scanCredential(row pgx.Row) (Credential, error) {
	var c Credential
	err := row.Scan(&c.ID, &c.OrgID, &c.Name, &c.Kind, &c.DataEnc, &c.KMSKeyID, &c.KeyVersion,
		&c.EncryptionContext, &c.Metadata, &c.RotatedAt, &c.CreatedAt, &c.UpdatedAt)
	return c, err
}

func scanCredentialMeta(row pgx.Row) (Credential, error) {
	var c Credential
	err := row.Scan(&c.ID, &c.OrgID, &c.Name, &c.Kind, &c.Metadata,
		&c.RotatedAt, &c.CreatedAt, &c.UpdatedAt)
	return c, err
}

func scanBinding(row pgx.Row) (Binding, error) {
	var b Binding
	err := row.Scan(&b.ID, &b.OrgID, &b.CredentialID, &b.ScopeType, &b.ScopeID, &b.Priority, &b.CreatedAt)
	return b, err
}

// findCredential returns one credential row including its sealed envelope.
// RLS scopes the lookup to the transaction's org.
func findCredential(ctx context.Context, tx pgx.Tx, id uuid.UUID) (Credential, error) {
	c, err := scanCredential(tx.QueryRow(ctx,
		`SELECT `+credentialColumns+` FROM device_credentials c WHERE c.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Credential{}, ErrNotFound
	}
	return c, err
}

// findCredentialMeta returns one credential row without the envelope columns.
func findCredentialMeta(ctx context.Context, tx pgx.Tx, id uuid.UUID) (Credential, error) {
	c, err := scanCredentialMeta(tx.QueryRow(ctx,
		`SELECT `+credentialMetaColumns+` FROM device_credentials c WHERE c.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Credential{}, ErrNotFound
	}
	return c, err
}

func listCredentials(ctx context.Context, tx pgx.Tx, limit int, after *uuid.UUID, desc bool) ([]Credential, error) {
	// Newest-first walks descending ids (UUIDv7 is time-sorted); the cursor
	// comparison flips with the direction so pages stay stable.
	cmp, dir := ">", ""
	if desc {
		cmp, dir = "<", " DESC"
	}
	rows, err := tx.Query(ctx, `SELECT `+credentialMetaColumns+` FROM device_credentials c
		WHERE ($1::uuid IS NULL OR c.id `+cmp+` $1)
		ORDER BY c.id`+dir+`
		LIMIT $2`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Credential, 0, limit)
	for rows.Next() {
		c, err := scanCredentialMeta(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// insertCredential stores one sealed credential. The envelope columns come
// straight from SecretsVault.Seal; plaintext never reaches this layer.
func insertCredential(ctx context.Context, tx pgx.Tx, c Credential) (Credential, error) {
	metadata := c.Metadata
	if len(metadata) == 0 {
		metadata = json.RawMessage(`{}`)
	}
	row := tx.QueryRow(ctx, `
		INSERT INTO device_credentials AS c
			(id, org_id, name, kind, data_enc, kms_key_id, key_version, encryption_context, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb)
		RETURNING `+credentialMetaColumns,
		c.ID, c.OrgID, c.Name, c.Kind, c.DataEnc, c.KMSKeyID, c.KeyVersion,
		string(c.EncryptionContext), metadata)
	return scanCredentialMeta(row)
}

// updateCredentialEnvelope atomically replaces the sealed envelope (rotation)
// and stamps rotated_at/updated_at with the transaction's server now().
func updateCredentialEnvelope(ctx context.Context, tx pgx.Tx, id uuid.UUID, env secrets.Envelope) (Credential, error) {
	contextJSON, err := json.Marshal(env.EncryptionContext)
	if err != nil {
		return Credential{}, err
	}
	row := tx.QueryRow(ctx, `
		UPDATE device_credentials c SET
			data_enc           = $2,
			kms_key_id         = $3,
			key_version        = $4,
			encryption_context = $5::jsonb,
			rotated_at         = now(),
			updated_at         = now()
		WHERE c.id = $1
		RETURNING `+credentialMetaColumns,
		id, env.DataEnc, env.KMSKeyID, env.KeyVersion, string(contextJSON))
	c, err := scanCredentialMeta(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Credential{}, ErrNotFound
	}
	return c, err
}

// listBindings returns the bindings of the given credentials ordered by
// credential and scope for deterministic payloads.
func listBindings(ctx context.Context, tx pgx.Tx, credentialIDs []uuid.UUID) ([]Binding, error) {
	if len(credentialIDs) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `SELECT `+bindingColumns+` FROM credential_bindings b
		WHERE b.credential_id = ANY($1)
		ORDER BY b.credential_id, b.scope_type, b.scope_id`, credentialIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Binding, 0, len(credentialIDs))
	for rows.Next() {
		b, err := scanBinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func insertBinding(ctx context.Context, tx pgx.Tx, b Binding) (Binding, error) {
	row := tx.QueryRow(ctx, `
		INSERT INTO credential_bindings AS b
			(id, org_id, credential_id, scope_type, scope_id, priority)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING `+bindingColumns,
		b.ID, b.OrgID, b.CredentialID, b.ScopeType, b.ScopeID, b.Priority)
	return scanBinding(row)
}

func deleteBinding(ctx context.Context, tx pgx.Tx, credentialID uuid.UUID, scopeType string, scopeID uuid.UUID) (bool, error) {
	tag, err := tx.Exec(ctx, `
		DELETE FROM credential_bindings b
		WHERE b.credential_id = $1 AND b.scope_type = $2 AND b.scope_id = $3`,
		credentialID, scopeType, scopeID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// siteExists / groupExists / deviceExists resolve binding targets inside the
// caller's tenant transaction. RLS scopes every lookup, so a foreign target is
// indistinguishable from a missing one (both false).
func siteExists(ctx context.Context, tx pgx.Tx, id uuid.UUID) (bool, error) {
	var ok bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM sites WHERE id = $1)`, id).Scan(&ok)
	return ok, err
}

func groupExists(ctx context.Context, tx pgx.Tx, id uuid.UUID) (bool, error) {
	var ok bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM device_groups WHERE id = $1)`, id).Scan(&ok)
	return ok, err
}

// deviceExists checks a LIVE device (soft-deleted devices are not bindable).
func deviceExists(ctx context.Context, tx pgx.Tx, id uuid.UUID) (bool, error) {
	var ok bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM devices WHERE id = $1 AND deleted_at IS NULL)`, id).Scan(&ok)
	return ok, err
}
