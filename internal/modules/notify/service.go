package notify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/argus-platform/argus/internal/platform/authz"
	"github.com/argus-platform/argus/internal/platform/database"
	"github.com/argus-platform/argus/internal/platform/secrets"
)

// secretType is the SecretsVault secret_type for notification channel
// secrets (part of the envelope encryption context).
const secretType = "notification_channel"

// Service implements channel/route CRUD and the delivery log over the
// database. Every method runs inside one database.WithTenant transaction (RLS
// is the isolation floor).
type Service struct {
	app   *pgxpool.Pool
	vault secrets.SecretsVault
	az    *authz.Authorizer
	// Now is the clock seam for deterministic tests.
	Now func() time.Time
}

// New wires the service. vault may be nil: channels without secrets still
// work, secret-bearing writes/tests fail closed with ErrVaultUnavailable.
func New(app *pgxpool.Pool, vault secrets.SecretsVault) *Service {
	return &Service{app: app, vault: vault, Now: time.Now}
}

// SetAuthorizer wires the server-side scope resolver (P2-D5). Handlers fail
// closed when it is missing, so production wiring must call this.
func (s *Service) SetAuthorizer(az *authz.Authorizer) { s.az = az }

// ScopeFor resolves the caller's bindings for the org-wide notification
// surface; it fails closed when no authorizer is configured.
func (s *Service) ScopeFor(ctx context.Context, orgID, userID uuid.UUID) (authz.Scope, error) {
	if s == nil || s.az == nil {
		return authz.Scope{}, errors.New("notify: authorizer not configured")
	}
	return s.az.ScopeFor(ctx, orgID, userID)
}

const channelMetaColumns = `c.id, c.org_id, c.kind, c.name, c.enabled, c.config,
	(c.secret_enc IS NOT NULL) AS secret_set, c.created_by, c.created_at, c.updated_at`

const channelEnvelopeColumns = `c.id, c.org_id, c.kind, c.name, c.enabled, c.config,
	c.secret_enc, c.kms_key_id, c.key_version, c.encryption_context, c.created_by, c.created_at, c.updated_at`

const routeColumns = `r.id, r.org_id, r.name, r.match, r.channel_ids, r.template_overrides,
	r.enabled, r.created_by, r.created_at, r.updated_at`

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func scanChannelMeta(row pgx.Row) (Channel, error) {
	var c Channel
	err := row.Scan(&c.ID, &c.OrgID, &c.Kind, &c.Name, &c.Enabled, &c.Config,
		&c.SecretSet, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt)
	return c, err
}

func scanChannelSecret(row pgx.Row) (Channel, error) {
	var (
		c         Channel
		secretEnc []byte
		kmsKeyID  *string
		keyVer    *int
		ctxRaw    []byte
	)
	err := row.Scan(&c.ID, &c.OrgID, &c.Kind, &c.Name, &c.Enabled, &c.Config,
		&secretEnc, &kmsKeyID, &keyVer, &ctxRaw, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return Channel{}, err
	}
	if len(secretEnc) > 0 {
		env, err := buildEnvelope(secretEnc, kmsKeyID, keyVer, ctxRaw)
		if err != nil {
			return Channel{}, err
		}
		c.Envelope = env
		c.SecretSet = true
	}
	return c, nil
}

func buildEnvelope(secretEnc []byte, kmsKeyID *string, keyVer *int, ctxRaw []byte) (*secrets.Envelope, error) {
	if kmsKeyID == nil || keyVer == nil {
		return nil, errors.New("notify: stored channel secret is malformed")
	}
	encCtx, err := secrets.ParseContext(ctxRaw)
	if err != nil {
		return nil, fmt.Errorf("notify: stored channel secret context: %w", err)
	}
	return &secrets.Envelope{
		DataEnc:           secretEnc,
		KMSKeyID:          *kmsKeyID,
		KeyVersion:        *keyVer,
		EncryptionContext: encCtx,
	}, nil
}

func scanRoute(row pgx.Row) (Route, error) {
	var (
		r        Route
		matchRaw []byte
		tplRaw   []byte
	)
	err := row.Scan(&r.ID, &r.OrgID, &r.Name, &matchRaw, &r.ChannelIDs, &tplRaw,
		&r.Enabled, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return Route{}, err
	}
	match, canonical, verrs := ParseRouteMatch(matchRaw)
	if len(verrs) > 0 {
		return Route{}, fmt.Errorf("notify: stored route match invalid: %w", verrs)
	}
	r.Match, r.MatchJSON, r.TemplateOverrides = match, canonical, tplRaw
	return r, nil
}

// sealSecret seals one channel secret JSON through the vault.
func (s *Service) sealSecret(orgID uuid.UUID, channelID uuid.UUID, plaintext []byte) (*secrets.Envelope, error) {
	if s.vault == nil {
		return nil, ErrVaultUnavailable
	}
	env, err := s.vault.Seal(orgID, secretType, channelID, plaintext)
	if err != nil {
		return nil, err
	}
	return &env, nil
}

// CreateChannel validates and inserts one channel; secrets are sealed
// immediately and never stored or echoed in clear.
func (s *Service) CreateChannel(ctx context.Context, orgID uuid.UUID, actor Actor, in ChannelCreateInput) (Channel, error) {
	configOut, secretOut, errs := ValidateChannel(in.Kind, in.Name, in.Config, in.Secret)
	if len(errs) > 0 {
		return Channel{}, errs
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Channel{}, err
	}
	var env *secrets.Envelope
	if len(secretOut) > 0 {
		env, err = s.sealSecret(orgID, id, secretOut)
		if err != nil {
			return Channel{}, err
		}
	}
	var createdBy *uuid.UUID
	if actor.UserID != uuid.Nil {
		uid := actor.UserID
		createdBy = &uid
	}
	var out Channel
	err = database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			INSERT INTO notification_channels AS c
				(id, org_id, kind, name, enabled, config, secret_enc, kms_key_id, key_version, encryption_context, created_by)
			VALUES ($1, $2, $3, $4, true, $5::jsonb, $6, $7, $8, $9::jsonb, $10)
			RETURNING `+channelMetaColumns,
			id, orgID, in.Kind, strings.TrimSpace(in.Name), configOut,
			envelopeBytes(env), envelopeKeyID(env), envelopeKeyVersion(env), envelopeContext(env), createdBy)
		var err error
		out, err = scanChannelMeta(row)
		if err != nil && isUniqueViolation(err) {
			return ErrNameConflict
		}
		return err
	})
	if err != nil {
		return Channel{}, err
	}
	return out, nil
}

func envelopeBytes(env *secrets.Envelope) []byte {
	if env == nil {
		return nil
	}
	return env.DataEnc
}

func envelopeKeyID(env *secrets.Envelope) *string {
	if env == nil {
		return nil
	}
	id := env.KMSKeyID
	return &id
}

func envelopeKeyVersion(env *secrets.Envelope) *int {
	if env == nil {
		return nil
	}
	v := env.KeyVersion
	return &v
}

func envelopeContext(env *secrets.Envelope) any {
	if env == nil {
		return nil
	}
	out, _ := json.Marshal(env.EncryptionContext)
	return out
}

// GetChannel returns the metadata projection of one channel (no secret
// material is read from the database).
func (s *Service) GetChannel(ctx context.Context, orgID, channelID uuid.UUID) (Channel, error) {
	var out Channel
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = scanChannelMeta(tx.QueryRow(ctx,
			`SELECT `+channelMetaColumns+` FROM notification_channels c WHERE c.id = $1`, channelID))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrChannelNotFound
		}
		return err
	})
	if err != nil {
		return Channel{}, err
	}
	return out, nil
}

// ListChannels returns one cursor page (newest id first).
func (s *Service) ListChannels(ctx context.Context, orgID uuid.UUID, limit int, cursor string) (ChannelPage, error) {
	if limit <= 0 || limit > MaxPageSize {
		limit = 25
	}
	var after *uuid.UUID
	if cursor != "" {
		id, err := uuid.Parse(cursor)
		if err != nil {
			return ChannelPage{}, ErrInvalidCursor
		}
		after = &id
	}
	var page ChannelPage
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+channelMetaColumns+` FROM notification_channels c
			WHERE ($1::uuid IS NULL OR c.id < $1)
			ORDER BY c.id DESC LIMIT $2`, after, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			ch, err := scanChannelMeta(rows)
			if err != nil {
				return err
			}
			page.Channels = append(page.Channels, ch)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(page.Channels) > limit {
			page.NextCursor = page.Channels[limit-1].ID.String()
			page.HasMore = true
			page.Channels = page.Channels[:limit]
		}
		return nil
	})
	if err != nil {
		return ChannelPage{}, err
	}
	return page, nil
}

// UpdateChannel applies a partial patch. A new secret replaces the sealed
// envelope; `secret: null` clears it; omitted keeps it. The kind is immutable
// (a webhook channel cannot silently become an SMTP channel).
func (s *Service) UpdateChannel(ctx context.Context, orgID, channelID uuid.UUID, patch ChannelPatchInput) (Channel, error) {
	var out Channel
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		current, err := scanChannelSecret(tx.QueryRow(ctx,
			`SELECT `+channelEnvelopeColumns+` FROM notification_channels c WHERE c.id = $1 FOR UPDATE`, channelID))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrChannelNotFound
		}
		if err != nil {
			return err
		}
		name := current.Name
		if patch.Name != nil {
			name = strings.TrimSpace(*patch.Name)
		}
		config := patch.Config
		if len(config) == 0 {
			config = current.Config
		}
		var env = current.Envelope
		var newSecret []byte
		switch {
		case len(patch.Secret) > 0:
			_, validated, errs := ValidateChannel(current.Kind, name, config, patch.Secret)
			if len(errs) > 0 {
				return errs
			}
			newSecret = validated
		case patch.ClearSecret:
			_, errs := ValidateChannelConfig(current.Kind, name, config)
			if len(errs) > 0 {
				return errs
			}
			env = nil
		default:
			_, errs := ValidateChannelConfig(current.Kind, name, config)
			if len(errs) > 0 {
				return errs
			}
		}
		if len(newSecret) > 0 {
			env, err = s.sealSecret(orgID, channelID, newSecret)
			if err != nil {
				return err
			}
		}
		enabled := current.Enabled
		if patch.Enabled != nil {
			enabled = *patch.Enabled
		}
		row := tx.QueryRow(ctx, `
			UPDATE notification_channels c SET
				name = $2, enabled = $3, config = $4::jsonb,
				secret_enc = $5, kms_key_id = $6, key_version = $7, encryption_context = $8::jsonb,
				updated_at = now()
			WHERE c.id = $1
			RETURNING `+channelMetaColumns,
			channelID, name, enabled, config,
			envelopeBytes(env), envelopeKeyID(env), envelopeKeyVersion(env), envelopeContext(env))
		out, err = scanChannelMeta(row)
		if err != nil && isUniqueViolation(err) {
			return ErrNameConflict
		}
		return err
	})
	if err != nil {
		return Channel{}, err
	}
	return out, nil
}

// DeleteChannel soft-disables a channel: the delivery log's channel FK would
// otherwise cascade-delete audit history.
func (s *Service) DeleteChannel(ctx context.Context, orgID, channelID uuid.UUID) (Channel, error) {
	enabled := false
	return s.UpdateChannel(ctx, orgID, channelID, ChannelPatchInput{Enabled: &enabled})
}

// CreateRoute validates and inserts one route. Channel ids must exist in the
// same tenant (RLS-scoped lookup), so a foreign id is indistinguishable from
// a missing one.
func (s *Service) CreateRoute(ctx context.Context, orgID uuid.UUID, actor Actor, in RouteCreateInput) (Route, error) {
	name := strings.TrimSpace(in.Name)
	var errs ValidationErrors
	switch {
	case name == "":
		errs = append(errs, ValidationError{Field: "name", Code: "required", Message: "name is required"})
	case len(name) > MaxNameLen:
		errs = append(errs, ValidationError{Field: "name", Code: "too_long", Message: fmt.Sprintf("name must be at most %d characters", MaxNameLen)})
	}
	_, matchJSON, matchErrs := ParseRouteMatch(in.MatchJSON)
	errs = append(errs, matchErrs...)
	tpl, tplErrs := ParseTemplateOverrides(in.TemplateOverrides)
	errs = append(errs, tplErrs...)
	errs = append(errs, ValidateChannelIDs(in.ChannelIDs)...)
	if len(errs) > 0 {
		return Route{}, errs
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Route{}, err
	}
	var createdBy *uuid.UUID
	if actor.UserID != uuid.Nil {
		uid := actor.UserID
		createdBy = &uid
	}
	var out Route
	err = database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		if err := requireChannels(ctx, tx, in.ChannelIDs); err != nil {
			return err
		}
		row := tx.QueryRow(ctx, `
			INSERT INTO notification_routes AS r
				(id, org_id, name, match, channel_ids, template_overrides, enabled, created_by)
			VALUES ($1, $2, $3, $4::jsonb, $5, $6::jsonb, true, $7)
			RETURNING `+routeColumns,
			id, orgID, name, matchJSON, in.ChannelIDs, tpl, createdBy)
		var err error
		out, err = scanRoute(row)
		if err != nil && isUniqueViolation(err) {
			return ErrNameConflict
		}
		return err
	})
	if err != nil {
		return Route{}, err
	}
	return out, nil
}

func requireChannels(ctx context.Context, tx pgx.Tx, ids []uuid.UUID) error {
	var found int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM notification_channels WHERE id = ANY($1::uuid[])`, ids).Scan(&found); err != nil {
		return err
	}
	if found != len(ids) {
		return ValidationErrors{{Field: "channel_ids", Code: "not_found", Message: "one or more channels do not exist in this organization"}}
	}
	return nil
}

// GetRoute returns one route.
func (s *Service) GetRoute(ctx context.Context, orgID, routeID uuid.UUID) (Route, error) {
	var out Route
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = scanRoute(tx.QueryRow(ctx, `SELECT `+routeColumns+` FROM notification_routes r WHERE r.id = $1`, routeID))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRouteNotFound
		}
		return err
	})
	if err != nil {
		return Route{}, err
	}
	return out, nil
}

// ListRoutes returns one cursor page (newest id first).
func (s *Service) ListRoutes(ctx context.Context, orgID uuid.UUID, limit int, cursor string) (RoutePage, error) {
	if limit <= 0 || limit > MaxPageSize {
		limit = 25
	}
	var after *uuid.UUID
	if cursor != "" {
		id, err := uuid.Parse(cursor)
		if err != nil {
			return RoutePage{}, ErrInvalidCursor
		}
		after = &id
	}
	var page RoutePage
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+routeColumns+` FROM notification_routes r
			WHERE ($1::uuid IS NULL OR r.id < $1)
			ORDER BY r.id DESC LIMIT $2`, after, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			rt, err := scanRoute(rows)
			if err != nil {
				return err
			}
			page.Routes = append(page.Routes, rt)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(page.Routes) > limit {
			page.NextCursor = page.Routes[limit-1].ID.String()
			page.HasMore = true
			page.Routes = page.Routes[:limit]
		}
		return nil
	})
	if err != nil {
		return RoutePage{}, err
	}
	return page, nil
}

// UpdateRoute applies a partial patch; omitted fields keep their value.
func (s *Service) UpdateRoute(ctx context.Context, orgID, routeID uuid.UUID, patch RoutePatchInput) (Route, error) {
	var out Route
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		current, err := scanRoute(tx.QueryRow(ctx,
			`SELECT `+routeColumns+` FROM notification_routes r WHERE r.id = $1 FOR UPDATE`, routeID))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRouteNotFound
		}
		if err != nil {
			return err
		}
		name := current.Name
		if patch.Name != nil {
			name = strings.TrimSpace(*patch.Name)
		}
		var errs ValidationErrors
		if name == "" || len(name) > MaxNameLen {
			errs = append(errs, ValidationError{Field: "name", Code: "invalid", Message: "name must be 1..200 characters"})
		}
		matchJSON := current.MatchJSON
		if len(patch.MatchJSON) > 0 {
			_, matchJSON, errs = appendMatchErrs(errs, patch.MatchJSON)
		}
		tpl := current.TemplateOverrides
		if len(patch.TemplateOverrides) > 0 {
			var tplErrs ValidationErrors
			tpl, tplErrs = ParseTemplateOverrides(patch.TemplateOverrides)
			errs = append(errs, tplErrs...)
		}
		channelIDs := current.ChannelIDs
		if patch.ChannelIDs != nil {
			channelIDs = patch.ChannelIDs
			errs = append(errs, ValidateChannelIDs(channelIDs)...)
		}
		if len(errs) > 0 {
			return errs
		}
		if err := requireChannels(ctx, tx, channelIDs); err != nil {
			return err
		}
		enabled := current.Enabled
		if patch.Enabled != nil {
			enabled = *patch.Enabled
		}
		row := tx.QueryRow(ctx, `
			UPDATE notification_routes r SET
				name = $2, match = $3::jsonb, channel_ids = $4, template_overrides = $5::jsonb,
				enabled = $6, updated_at = now()
			WHERE r.id = $1
			RETURNING `+routeColumns,
			routeID, name, matchJSON, channelIDs, tpl, enabled)
		out, err = scanRoute(row)
		if err != nil && isUniqueViolation(err) {
			return ErrNameConflict
		}
		return err
	})
	if err != nil {
		return Route{}, err
	}
	return out, nil
}

func appendMatchErrs(errs ValidationErrors, raw []byte) (RouteMatch, []byte, ValidationErrors) {
	m, canonical, matchErrs := ParseRouteMatch(raw)
	return m, canonical, append(errs, matchErrs...)
}

// DeleteRoute hard-deletes a route (deliveries keep route_id = NULL).
func (s *Service) DeleteRoute(ctx context.Context, orgID, routeID uuid.UUID) error {
	return database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM notification_routes WHERE id = $1`, routeID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrRouteNotFound
		}
		return nil
	})
}

const deliveryColumns = `d.id, d.org_id, d.alert_id, d.event_id, d.event_kind, d.severity,
	d.route_id, d.channel_id, d.status, d.attempts, d.next_attempt_at, d.response_code,
	d.response_excerpt, d.dedup_key, d.subject, d.body, d.payload, d.created_at, d.updated_at, d.delivered_at`

func scanDelivery(row interface{ Scan(...any) error }) (Delivery, error) {
	var d Delivery
	err := row.Scan(&d.ID, &d.OrgID, &d.AlertID, &d.EventID, &d.EventKind, &d.Severity,
		&d.RouteID, &d.ChannelID, &d.Status, &d.Attempts, &d.NextAttemptAt, &d.ResponseCode,
		&d.ResponseExcerpt, &d.DedupKey, &d.Subject, &d.Body, &d.Payload, &d.CreatedAt, &d.UpdatedAt, &d.DeliveredAt)
	return d, err
}

// ListDeliveries returns one cursor page of the delivery log, newest first
// (created_at, id keyset), optionally filtered by channel/status/alert.
func (s *Service) ListDeliveries(ctx context.Context, orgID uuid.UUID, f DeliveryFilter, limit int, cursor string) (DeliveryPage, error) {
	if limit <= 0 || limit > MaxPageSize {
		limit = 25
	}
	var (
		afterTs *time.Time
		afterID *uuid.UUID
	)
	if cursor != "" {
		ts, id, err := decodeDeliveryCursor(cursor)
		if err != nil {
			return DeliveryPage{}, ErrInvalidCursor
		}
		afterTs, afterID = &ts, &id
	}
	var page DeliveryPage
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+deliveryColumns+` FROM notification_deliveries d
			WHERE ($1::timestamptz IS NULL OR (d.created_at, d.id) < ($1::timestamptz, $2::uuid))
			  AND ($3::uuid IS NULL OR d.channel_id = $3)
			  AND ($4::text IS NULL OR d.status = $4)
			  AND ($5::uuid IS NULL OR d.alert_id = $5)
			ORDER BY d.created_at DESC, d.id DESC
			LIMIT $6`,
			afterTs, afterID, f.ChannelID, f.Status, f.AlertID, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			d, err := scanDelivery(rows)
			if err != nil {
				return err
			}
			page.Deliveries = append(page.Deliveries, d)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(page.Deliveries) > limit {
			last := page.Deliveries[limit-1]
			page.NextCursor = encodeDeliveryCursor(last.CreatedAt, last.ID)
			page.HasMore = true
			page.Deliveries = page.Deliveries[:limit]
		}
		return nil
	})
	if err != nil {
		return DeliveryPage{}, err
	}
	return page, nil
}

// encodeDeliveryCursor is an opaque base64("unix_nano|uuid") keyset cursor.
func encodeDeliveryCursor(ts time.Time, id uuid.UUID) string {
	raw := strconv.FormatInt(ts.UTC().UnixNano(), 10) + "|" + id.String()
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeDeliveryCursor(cursor string) (time.Time, uuid.UUID, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, uuid.Nil, err
	}
	parts := strings.SplitN(string(raw), "|", 2)
	if len(parts) != 2 {
		return time.Time{}, uuid.Nil, errors.New("notify: malformed cursor")
	}
	nanos, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return time.Time{}, uuid.Nil, err
	}
	id, err := uuid.Parse(parts[1])
	if err != nil {
		return time.Time{}, uuid.Nil, err
	}
	return time.Unix(0, nanos).UTC(), id, nil
}
