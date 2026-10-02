package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/argus-platform/argus/internal/platform/authz"
	"github.com/argus-platform/argus/internal/platform/database"
	"github.com/argus-platform/argus/internal/platform/secrets"
)

// Service implements the credential lifecycle over the database and the
// SecretsVault. Every method is org-scoped: it opens a database.WithTenant
// transaction (RLS as the isolation floor) and secrets are sealed before any
// row is written. Plaintext is never stored, logged, or returned.
type Service struct {
	app   *pgxpool.Pool
	vault secrets.SecretsVault
	audit AuditSink
	authz *authz.Authorizer
}

// New wires the credentials service. vault must be the process SecretsVault
// (nil disables mutations with ErrVaultUnavailable); audit may be nil in unit
// contexts; the server passes SlogAudit so mutations always leave structured
// evidence.
func New(app *pgxpool.Pool, vault secrets.SecretsVault, audit AuditSink) *Service {
	return &Service{app: app, vault: vault, audit: audit, authz: authz.New(app)}
}

// ScopeFor resolves the caller's scope bindings inside a tenant transaction
// (shared with the inventory surface).
func (s *Service) ScopeFor(ctx context.Context, orgID, userID uuid.UUID) (authz.Scope, error) {
	return s.authz.ScopeFor(ctx, orgID, userID)
}

// CreateInput is the validated input for a credential create; Secret is the
// only place plaintext enters the module and it is sealed immediately.
type CreateInput struct {
	Name     string
	Kind     string
	Secret   []byte
	Metadata json.RawMessage
}

func newID() (uuid.UUID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, fmt.Errorf("credentials: generate id: %w", err)
	}
	return id, nil
}

// record writes one audit event through the configured sink (nil = disabled).
// Data must never contain secret material.
func (s *Service) record(orgID uuid.UUID, actor Actor, action string, resourceID uuid.UUID, data map[string]any) {
	if s.audit == nil {
		return
	}
	s.audit.Record(AuditEvent{
		Action:       action,
		ActorType:    "user",
		ActorID:      actor.UserID,
		OrgID:        orgID,
		ResourceType: "credential",
		ResourceID:   resourceID,
		Data:         data,
		RequestID:    actor.RequestID,
		ClientIP:     actor.ClientIP,
		At:           time.Now().UTC(),
	})
}

func (s *Service) ready() error {
	if s == nil || s.app == nil {
		return errors.New("credentials: service not configured")
	}
	if s.vault == nil {
		return ErrVaultUnavailable
	}
	return nil
}

// validateCreate double-checks the service boundary (HTTP validates first and
// returns field errors; this guards direct callers and future dispatch code).
func validateCreate(in CreateInput) error {
	switch {
	case strings.TrimSpace(in.Name) == "" || len(in.Name) > 200:
		return fmt.Errorf("%w: name is required (max 200 chars)", ErrValidation)
	case strings.TrimSpace(in.Kind) == "":
		return fmt.Errorf("%w: kind is required", ErrValidation)
	case len(in.Secret) == 0:
		return fmt.Errorf("%w: secret is required", ErrValidation)
	}
	if len(in.Metadata) > 0 {
		var m map[string]any
		if err := json.Unmarshal(in.Metadata, &m); err != nil || m == nil {
			return fmt.Errorf("%w: metadata must be a JSON object", ErrValidation)
		}
	}
	return nil
}

// Create seals the secret with a fresh per-secret DEK and stores the envelope.
// The returned metadata is the API-safe projection; the plaintext is dropped
// as soon as Seal returns.
func (s *Service) Create(ctx context.Context, orgID uuid.UUID, in CreateInput, actor Actor) (CredentialMetadata, error) {
	if err := s.ready(); err != nil {
		return CredentialMetadata{}, err
	}
	if err := validateCreate(in); err != nil {
		return CredentialMetadata{}, err
	}
	id, err := newID()
	if err != nil {
		return CredentialMetadata{}, err
	}
	env, err := s.vault.Seal(orgID, in.Kind, id, in.Secret)
	if err != nil {
		return CredentialMetadata{}, fmt.Errorf("credentials: seal secret: %w", err)
	}
	contextJSON, err := json.Marshal(env.EncryptionContext)
	if err != nil {
		return CredentialMetadata{}, fmt.Errorf("credentials: encode context: %w", err)
	}
	row := Credential{
		ID:                id,
		OrgID:             orgID,
		Name:              in.Name,
		Kind:              in.Kind,
		DataEnc:           env.DataEnc,
		KMSKeyID:          env.KMSKeyID,
		KeyVersion:        env.KeyVersion,
		EncryptionContext: contextJSON,
		Metadata:          in.Metadata,
	}
	var created Credential
	err = database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		created, err = insertCredential(ctx, tx, row)
		return err
	})
	if err != nil {
		if isUniqueViolation(err, credentialNameConstraint) {
			return CredentialMetadata{}, ErrNameConflict
		}
		return CredentialMetadata{}, err
	}
	s.record(orgID, actor, ActionCredentialCreate, created.ID, map[string]any{
		"name": created.Name,
		"kind": created.Kind,
	})
	return ProjectCredential(created, nil), nil
}

// Get returns one credential's metadata plus its binding summaries.
func (s *Service) Get(ctx context.Context, orgID, id uuid.UUID) (CredentialMetadata, error) {
	if s == nil || s.app == nil {
		return CredentialMetadata{}, errors.New("credentials: service not configured")
	}
	var out CredentialMetadata
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		c, err := findCredentialMeta(ctx, tx, id)
		if err != nil {
			return err
		}
		bindings, err := listBindings(ctx, tx, []uuid.UUID{id})
		if err != nil {
			return err
		}
		out = ProjectCredential(c, bindings)
		return nil
	})
	return out, err
}

// List returns one cursor page of credential metadata ordered by id (UUIDv7,
// time-sortable), each with its binding summaries. desc = newest first.
func (s *Service) List(ctx context.Context, orgID uuid.UUID, limit int, cursor string, desc bool) ([]CredentialMetadata, string, bool, error) {
	if s == nil || s.app == nil {
		return nil, "", false, errors.New("credentials: service not configured")
	}
	var after *uuid.UUID
	if cursor != "" {
		id, err := uuid.Parse(cursor)
		if err != nil {
			return nil, "", false, ErrInvalidCursor
		}
		after = &id
	}
	var (
		rows       []Credential
		bindings   []Binding
		hasMore    bool
		nextCursor string
	)
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		rows, err = listCredentials(ctx, tx, limit+1, after, desc)
		if err != nil {
			return err
		}
		if len(rows) > limit {
			nextCursor = rows[limit-1].ID.String()
			hasMore = true
			rows = rows[:limit]
		}
		ids := make([]uuid.UUID, 0, len(rows))
		for _, c := range rows {
			ids = append(ids, c.ID)
		}
		bindings, err = listBindings(ctx, tx, ids)
		return err
	})
	if err != nil {
		return nil, "", false, err
	}
	byCredential := make(map[uuid.UUID][]Binding, len(rows))
	for _, b := range bindings {
		byCredential[b.CredentialID] = append(byCredential[b.CredentialID], b)
	}
	out := make([]CredentialMetadata, 0, len(rows))
	for _, c := range rows {
		out = append(out, ProjectCredential(c, byCredential[c.ID]))
	}
	return out, nextCursor, hasMore, nil
}

// Rotate re-seals the credential under a fresh per-secret DEK in one
// transaction: data_enc/kms_key_id/key_version/encryption_context and
// rotated_at are replaced atomically, and the old envelope bytes are gone.
// When the KEK key ring advances to a new current version, the stored
// key_version follows the vault (unit-tested with a version-bumping vault).
func (s *Service) Rotate(ctx context.Context, orgID, id uuid.UUID, newSecret []byte, actor Actor) (CredentialMetadata, error) {
	if err := s.ready(); err != nil {
		return CredentialMetadata{}, err
	}
	if len(newSecret) == 0 {
		return CredentialMetadata{}, fmt.Errorf("%w: secret is required", ErrValidation)
	}
	var updated Credential
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		cur, err := findCredential(ctx, tx, id)
		if err != nil {
			return err
		}
		// The encryption context binds ciphertext to {org, kind, id, version};
		// re-sealing keeps type and id so the context stays truthful.
		env, err := s.vault.Seal(orgID, cur.Kind, cur.ID, newSecret)
		if err != nil {
			return fmt.Errorf("credentials: seal rotated secret: %w", err)
		}
		updated, err = updateCredentialEnvelope(ctx, tx, id, env)
		return err
	})
	if err != nil {
		return CredentialMetadata{}, err
	}
	bindings, err := s.bindingsFor(ctx, orgID, id)
	if err != nil {
		return CredentialMetadata{}, err
	}
	s.record(orgID, actor, ActionCredentialRotate, id, map[string]any{
		"name": updated.Name,
		"kind": updated.Kind,
	})
	return ProjectCredential(updated, bindings), nil
}

// bindingsFor loads one credential's bindings in its own tenant transaction.
func (s *Service) bindingsFor(ctx context.Context, orgID, id uuid.UUID) ([]Binding, error) {
	var bindings []Binding
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		bindings, err = listBindings(ctx, tx, []uuid.UUID{id})
		return err
	})
	return bindings, err
}

// Bind attaches a credential to a scope target. The target is resolved
// server-side inside the caller's tenant transaction (sites / device_groups /
// devices table, or the caller's own org), never trusted from the request:
// existing target → binding; foreign or unknown target → ErrTargetNotFound
// (uniform 404, no existence oracle); duplicate → ErrBindingConflict.
func (s *Service) Bind(ctx context.Context, orgID, credentialID uuid.UUID, scopeType string, scopeID uuid.UUID, priority int, actor Actor) (Binding, error) {
	if s == nil || s.app == nil {
		return Binding{}, errors.New("credentials: service not configured")
	}
	if !IsScopeType(scopeType) {
		return Binding{}, ErrInvalidScope
	}
	id, err := newID()
	if err != nil {
		return Binding{}, err
	}
	var created Binding
	err = database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := findCredentialMeta(ctx, tx, credentialID); err != nil {
			return err
		}
		if err := resolveTarget(ctx, tx, orgID, scopeType, scopeID); err != nil {
			return err
		}
		created, err = insertBinding(ctx, tx, Binding{
			ID:           id,
			OrgID:        orgID,
			CredentialID: credentialID,
			ScopeType:    scopeType,
			ScopeID:      scopeID,
			Priority:     priority,
		})
		return err
	})
	if err != nil {
		if isUniqueViolation(err, bindingScopeConstraint) {
			return Binding{}, ErrBindingConflict
		}
		return Binding{}, err
	}
	s.record(orgID, actor, ActionCredentialBind, credentialID, map[string]any{
		"scope_type": created.ScopeType,
		"scope_id":   created.ScopeID.String(),
		"priority":   created.Priority,
	})
	return created, nil
}

// resolveTarget validates a binding target for a scope type. org targets must
// be the caller's own org (the migration CHECK enforces the same invariant at
// the database); every other type resolves a live tenant row.
func resolveTarget(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, scopeType string, scopeID uuid.UUID) error {
	switch scopeType {
	case "org":
		if scopeID != orgID {
			return ErrTargetNotFound
		}
		return nil
	case "site":
		ok, err := siteExists(ctx, tx, scopeID)
		if err != nil {
			return err
		}
		if !ok {
			return ErrTargetNotFound
		}
		return nil
	case "device_group":
		ok, err := groupExists(ctx, tx, scopeID)
		if err != nil {
			return err
		}
		if !ok {
			return ErrTargetNotFound
		}
		return nil
	case "device":
		ok, err := deviceExists(ctx, tx, scopeID)
		if err != nil {
			return err
		}
		if !ok {
			return ErrTargetNotFound
		}
		return nil
	default:
		return ErrInvalidScope
	}
}

// Unbind removes the binding identified by (credential, scope_type, scope_id).
// Unlike Bind it deliberately does NOT resolve the target: a binding stays
// addressable so operators can clean up after a target was deleted.
func (s *Service) Unbind(ctx context.Context, orgID, credentialID uuid.UUID, scopeType string, scopeID uuid.UUID, actor Actor) error {
	if s == nil || s.app == nil {
		return errors.New("credentials: service not configured")
	}
	if !IsScopeType(scopeType) {
		return ErrInvalidScope
	}
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := findCredentialMeta(ctx, tx, credentialID); err != nil {
			return err
		}
		deleted, err := deleteBinding(ctx, tx, credentialID, scopeType, scopeID)
		if err != nil {
			return err
		}
		if !deleted {
			return ErrBindingNotFound
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.record(orgID, actor, ActionCredentialUnbind, credentialID, map[string]any{
		"scope_type": scopeType,
		"scope_id":   scopeID.String(),
	})
	return nil
}
