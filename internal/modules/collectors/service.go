package collectors

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/argus-platform/argus/internal/modules/credentials"
	"github.com/argus-platform/argus/internal/platform/database"
	"github.com/argus-platform/argus/internal/platform/sessioncrypto"
	"github.com/argus-platform/argus/internal/platform/telemetry"
)

const (
	minTokenTTL = time.Minute
	tokenTTLMax = 7 * 24 * time.Hour
	// StaleAfterMultiplier defines when a connected collector with no recent
	// heartbeat is reported as stale (3x the policy interval, SPEC §4.1).
	StaleAfterMultiplier = 3
	// DefaultHeartbeatInterval is the Phase-1 policy heartbeat cadence.
	DefaultHeartbeatInterval = 30 * time.Second
)

// Service implements the collector identity lifecycle over the database.
type Service struct {
	app     *pgxpool.Pool
	auth    *pgxpool.Pool
	ca      *CA
	metrics *metrics
	// creds is the M7-S4 credentials resolver boundary used to materialize
	// effective SNMP credentials into policy bundles (M9-S3). Nil (or a typed
	// nil *credentials.Resolver) disables materialization: bundles are then
	// delivered without a session block.
	creds CredentialResolver
	// log is optional; materialization failures are logged without any secret
	// material.
	log *slog.Logger
}

// CredentialResolver is the M9-S3 dispatch boundary: it resolves the effective
// credential for a device (bindings enforced server-side, RLS-scoped) and
// returns its decrypted plaintext plus identity metadata. It is implemented by
// *credentials.Resolver; the interface keeps the policy path testable without
// a database.
type CredentialResolver interface {
	Materialize(ctx context.Context, orgID, deviceID uuid.UUID) ([]byte, credentials.EffectiveCredential, error)
}

// Option configures the collectors service.
type Option func(*Service)

// WithCredentialResolver wires the M9-S3 materialization resolver.
func WithCredentialResolver(r CredentialResolver) Option {
	return func(s *Service) { s.creds = r }
}

// WithLogger wires the optional service logger (errors never carry secrets).
func WithLogger(log *slog.Logger) Option {
	return func(s *Service) { s.log = log }
}

// New wires the collectors service (tel may be nil in unit contexts).
func New(app, auth *pgxpool.Pool, ca *CA, tel *telemetry.Registry, opts ...Option) *Service {
	s := &Service{app: app, auth: auth, ca: ca, metrics: newMetrics(tel)}
	for _, o := range opts {
		o(s)
	}
	return s
}

// EnrollRequest mirrors the gRPC enrollment input.
type EnrollRequest struct {
	Token        string
	CSR          string
	Name         string
	AgentVersion string
	Hostname     string
	OS           string
}

// EnrollResult carries everything the collector needs to persist identity.
type EnrollResult struct {
	CollectorID  uuid.UUID
	OrgID        uuid.UUID
	CertPEM      []byte
	ChainPEM     []byte
	CertNotAfter time.Time
	Policy       *SignedPolicy
	PolicyPubDER []byte
	ServerTime   time.Time
}

// Enroll executes the one-time enrollment: token resolution (pre-auth), CSR
// issuance, registry + certificate inserts, and initial signed policy — all
// inside one tenant transaction whose rollback also un-consumes the token.
func (s *Service) Enroll(ctx context.Context, req EnrollRequest) (EnrollResult, error) {
	hash := HashEnrollmentToken(req.Token)

	var token TokenRow
	err := database.WithAuthTx(ctx, s.auth, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		token, err = findTokenByHash(ctx, tx, hash)
		return err
	})
	if err != nil {
		s.metrics.enrollments.WithLabelValues("invalid").Inc()
		return EnrollResult{}, ErrEnrollDenied
	}
	if token.UsedAt != nil {
		s.metrics.enrollments.WithLabelValues("used").Inc()
		return EnrollResult{}, ErrEnrollDenied
	}
	if time.Now().After(token.ExpiresAt) {
		s.metrics.enrollments.WithLabelValues("expired").Inc()
		return EnrollResult{}, ErrEnrollDenied
	}
	if token.SiteID == nil {
		s.metrics.enrollments.WithLabelValues("invalid").Inc()
		return EnrollResult{}, ErrSiteRequired
	}

	collectorID, err := uuid.NewV7()
	if err != nil {
		return EnrollResult{}, err
	}

	var result EnrollResult
	err = database.WithTenant(ctx, s.app, token.OrgID, func(ctx context.Context, tx pgx.Tx) error {
		orgSlug, err := getOrgSlug(ctx, tx, token.OrgID)
		if err != nil {
			return err
		}
		leaf, err := s.ca.IssueLeaf([]byte(req.CSR), collectorID, orgSlug)
		if err != nil {
			return err
		}

		row := CollectorRow{
			ID:           collectorID,
			OrgID:        token.OrgID,
			SiteID:       *token.SiteID,
			Name:         req.Name,
			AgentVersion: strPtr(req.AgentVersion),
			Hostname:     strPtr(req.Hostname),
			OS:           strPtr(req.OS),
		}
		if err := insertCollector(ctx, tx, row); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return ErrNameTaken
			}
			return err
		}
		claimed, err := claimToken(ctx, tx, token.ID, collectorID)
		if err != nil {
			return err
		}
		if !claimed {
			return ErrEnrollDenied
		}
		certID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		if err := insertCertificate(ctx, tx, certID, token.OrgID, collectorID,
			leaf.Serial, leaf.Fingerprint, leaf.NotBefore, leaf.NotAfter); err != nil {
			return err
		}
		targets, err := listPolicyTargets(ctx, tx)
		if err != nil {
			return err
		}
		sp, err := s.ca.BuildSignedPolicyWithTargets(1, targets)
		if err != nil {
			return err
		}
		policyID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		if err := insertPolicy(ctx, tx, policyID, token.OrgID, collectorID, sp); err != nil {
			return err
		}
		result = EnrollResult{
			CollectorID:  collectorID,
			OrgID:        token.OrgID,
			CertPEM:      leaf.CertPEM,
			ChainPEM:     leaf.ChainPEM,
			CertNotAfter: leaf.NotAfter,
			Policy:       sp,
			PolicyPubDER: s.ca.PolicySigningPublicKeyDER(),
			ServerTime:   time.Now(),
		}
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrEnrollDenied):
			// A token that slips past the pre-check and loses the atomic claim
			// race is a used token (no oracle is exposed to the caller).
			s.metrics.enrollments.WithLabelValues("used").Inc()
		case errors.Is(err, ErrNameTaken):
			s.metrics.enrollments.WithLabelValues("name_taken").Inc()
		case errors.Is(err, ErrInvalidCSR):
			s.metrics.enrollments.WithLabelValues("invalid_csr").Inc()
		default:
			s.metrics.enrollments.WithLabelValues("error").Inc()
		}
		return EnrollResult{}, err
	}
	s.metrics.enrollments.WithLabelValues("ok").Inc()
	return result, nil
}

// CreateEnrollmentToken mints a one-time, site-bound credential (raw returned
// once; SHA-256 stored).
func (s *Service) CreateEnrollmentToken(ctx context.Context, orgID, siteID uuid.UUID, ttl time.Duration, createdBy *uuid.UUID) (raw string, id uuid.UUID, expiresAt time.Time, err error) {
	if ttl < minTokenTTL || ttl > tokenTTLMax {
		return "", uuid.Nil, time.Time{}, fmt.Errorf("collectors: ttl must be between %s and %s", minTokenTTL, tokenTTLMax)
	}
	raw, hash, err := MintEnrollmentToken()
	if err != nil {
		return "", uuid.Nil, time.Time{}, err
	}
	id, err = uuid.NewV7()
	if err != nil {
		return "", uuid.Nil, time.Time{}, err
	}
	expiresAt = time.Now().Add(ttl)
	err = database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		return insertToken(ctx, tx, id, orgID, &siteID, hash, expiresAt, createdBy)
	})
	if err != nil {
		return "", uuid.Nil, time.Time{}, err
	}
	return raw, id, expiresAt, nil
}

// TokenPage lists enrollment token metadata (never raw values).
type TokenPage struct {
	Tokens     []TokenRow
	NextCursor string
}

// ListTokens returns the org's enrollment tokens ordered by id.
func (s *Service) ListTokens(ctx context.Context, orgID uuid.UUID, limit int, cursor string) (TokenPage, error) {
	var after *uuid.UUID
	if cursor != "" {
		id, err := uuid.Parse(cursor)
		if err != nil {
			return TokenPage{}, ErrInvalidCursor
		}
		after = &id
	}
	var page TokenPage
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := listTokens(ctx, tx, limit, after)
		if err != nil {
			return err
		}
		if len(rows) > limit {
			page.NextCursor = rows[limit-1].ID.String()
			rows = rows[:limit]
		}
		page.Tokens = rows
		return nil
	})
	return page, err
}

// ErrInvalidCursor is returned for malformed pagination cursors.
var ErrInvalidCursor = fmt.Errorf("collectors: invalid cursor")

// CollectorPage is one page of the registry.
type CollectorPage struct {
	Collectors []CollectorRow
	NextCursor string
}

// ListFilter narrows the registry listing.
type ListFilter struct {
	SiteID *uuid.UUID
	Status *string
}

// ListCollectors returns the org's collectors ordered by id.
func (s *Service) ListCollectors(ctx context.Context, orgID uuid.UUID, f ListFilter, limit int, cursor string) (CollectorPage, error) {
	var after *uuid.UUID
	if cursor != "" {
		id, err := uuid.Parse(cursor)
		if err != nil {
			return CollectorPage{}, ErrInvalidCursor
		}
		after = &id
	}
	var page CollectorPage
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := listCollectors(ctx, tx, limit, after, f.SiteID, f.Status)
		if err != nil {
			return err
		}
		if len(rows) > limit {
			page.NextCursor = rows[limit-1].ID.String()
			rows = rows[:limit]
		}
		page.Collectors = rows
		return nil
	})
	return page, err
}

// GetCollector returns one registry entry.
func (s *Service) GetCollector(ctx context.Context, orgID, id uuid.UUID) (CollectorRow, error) {
	var row CollectorRow
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		row, err = findCollectorByID(ctx, tx, id)
		return err
	})
	return row, err
}

// CollectorExists reports whether the collector exists in the org (RLS-scoped).
// Used by the metrics query path for 404-without-oracle semantics.
func (s *Service) CollectorExists(ctx context.Context, orgID, collectorID uuid.UUID) (bool, error) {
	var exists bool
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM collectors WHERE id = $1)`, collectorID).Scan(&exists)
	})
	return exists, err
}

// RevokeCollector marks a collector and its certificates revoked. changed=false
// when it was already revoked (idempotent).
func (s *Service) RevokeCollector(ctx context.Context, orgID, id uuid.UUID) (bool, error) {
	var changed bool
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := findCollectorByID(ctx, tx, id); err != nil {
			return err
		}
		var err error
		changed, err = revokeCollectorTx(ctx, tx, id)
		return err
	})
	return changed, err
}

// ResyncPolicy issues the next policy version for a collector.
func (s *Service) ResyncPolicy(ctx context.Context, orgID, collectorID uuid.UUID) (int64, error) {
	var version int64
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		current, err := maxPolicyVersion(ctx, tx, collectorID)
		if err != nil {
			return err
		}
		targets, err := listPolicyTargets(ctx, tx)
		if err != nil {
			return err
		}
		sp, err := s.ca.BuildSignedPolicyWithTargets(current+1, targets)
		if err != nil {
			return err
		}
		policyID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		if err := insertPolicy(ctx, tx, policyID, orgID, collectorID, sp); err != nil {
			return err
		}
		version = sp.Version
		return nil
	})
	return version, err
}

// LatestPolicy returns the newest signed policy for a collector (nil if none).
func (s *Service) LatestPolicy(ctx context.Context, orgID, collectorID uuid.UUID) (*SignedPolicy, error) {
	var sp *SignedPolicy
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		sp, err = latestPolicy(ctx, tx, collectorID)
		return err
	})
	return sp, err
}

// PolicyForSession returns the newest signed policy for a collector with M9-S3
// per-session credential materialization attached when the collector presented
// an ephemeral session public key and SNMP credentials resolve for its poll
// targets. The stored base bundle is never modified or persisted with the
// material: the returned SignedPolicy is a per-request, per-session document
// signed by the same Ed25519 key.
//
// Materialization is best-effort per device (a credential that cannot be
// opened is skipped, and that device reports credential_missing; it can never
// make the bundle undeliverable). Bindings are enforced by the resolver:
// ErrNoCredential / ErrDeviceNotFound simply produce no record.
func (s *Service) PolicyForSession(ctx context.Context, orgID, collectorID uuid.UUID, collectorSessionPublicKey []byte) (*SignedPolicy, error) {
	base, err := s.LatestPolicy(ctx, orgID, collectorID)
	if err != nil || base == nil {
		return base, err
	}
	return s.materializePolicy(ctx, orgID, collectorID, base, collectorSessionPublicKey), nil
}

// materializePolicy attaches credential material to a copy of the stored base
// bundle. It never returns an error: the base bundle is always deliverable, and
// materialization failures are fail-closed per device.
func (s *Service) materializePolicy(ctx context.Context, orgID, collectorID uuid.UUID, base *SignedPolicy, collectorSessionPublicKey []byte) *SignedPolicy {
	if s.creds == nil || len(collectorSessionPublicKey) == 0 {
		return base
	}
	var doc PolicyDocument
	if err := json.Unmarshal(base.Document, &doc); err != nil {
		// A stored document always unmarshals (it was built here); if that
		// invariant ever breaks, deliver the base bundle rather than failing
		// the stream.
		s.warn("materialize: stored policy unreadable", "collector_id", collectorID, "error", err)
		return base
	}

	creds := make([]sessioncrypto.PlainCredential, 0, 8)
	for _, t := range doc.Targets {
		if !strings.EqualFold(strings.TrimSpace(t.PollType), "snmp") {
			continue
		}
		deviceID, err := uuid.Parse(t.DeviceID)
		if err != nil {
			continue
		}
		plaintext, eff, err := s.creds.Materialize(ctx, orgID, deviceID)
		if err != nil {
			if !errors.Is(err, credentials.ErrNoCredential) && !errors.Is(err, credentials.ErrDeviceNotFound) {
				// Unexpected (vault/resolver) failure: skip this device only.
				s.warn("materialize: credential resolution failed", "device_id", deviceID, "error", err)
			}
			continue
		}
		if !isSNMPCredentialKind(eff.Kind) {
			clear(plaintext)
			continue
		}
		creds = append(creds, sessioncrypto.PlainCredential{
			DeviceID:     t.DeviceID,
			CredentialID: eff.CredentialID.String(),
			Kind:         eff.Kind,
			Version:      eff.Version,
			Plaintext:    plaintext,
		})
	}
	defer func() {
		for i := range creds {
			clear(creds[i].Plaintext)
		}
	}()
	if len(creds) == 0 {
		return base
	}

	orgIDStr := orgID.String()
	collectorIDStr := collectorID.String()
	session, err := sessioncrypto.Seal(collectorSessionPublicKey, orgIDStr, collectorIDStr, base.Version, creds)
	if err != nil {
		s.warn("materialize: seal failed", "collector_id", collectorID, "error", err)
		return base
	}
	materialized, err := s.ca.SignMaterializedPolicy(base.Version, doc, session)
	if err != nil {
		s.warn("materialize: sign failed", "collector_id", collectorID, "error", err)
		return base
	}
	materialized.JitterSalt = base.JitterSalt
	return materialized
}

// isSNMPCredentialKind reports whether the effective credential kind is SNMP
// material the collector can consume. Non-SNMP credentials bound to a device
// never become SNMP poll material.
func isSNMPCredentialKind(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "snmp_v2c", "snmp_v3":
		return true
	default:
		return false
	}
}

func (s *Service) warn(msg string, args ...any) {
	if s.log != nil {
		s.log.Warn(msg, args...)
	}
}

// ResolveCertificate maps an mTLS fingerprint to its collector identity.
func (s *Service) ResolveCertificate(ctx context.Context, fingerprint []byte) (ResolvedCert, error) {
	var rc ResolvedCert
	err := database.WithAuthTx(ctx, s.auth, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		rc, err = resolveCertificateTx(ctx, tx, fingerprint)
		return err
	})
	return rc, err
}

// MarkConnected records stream establishment (status pending -> active).
func (s *Service) MarkConnected(ctx context.Context, orgID, collectorID uuid.UUID, agentVersion *string) error {
	return database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		return markStreamConnected(ctx, tx, collectorID, agentVersion)
	})
}

// HeartbeatStats is the reported collector-side accounting (SPEC heartbeat).
type HeartbeatStats struct {
	SpoolBytes          uint64 `json:"spool_bytes"`
	SpoolRecords        uint64 `json:"spool_records"`
	HighestSeq          int64  `json:"highest_seq"`
	AckedSeq            int64  `json:"acked_seq"`
	DroppedRecordsTotal uint64 `json:"dropped_records_total"`
	CorruptRecordsTotal uint64 `json:"corrupt_records_total"`
	ClockSkewMillis     int64  `json:"clock_skew_ms"`
	UptimeSeconds       int64  `json:"uptime_seconds"`
}

// RecordHeartbeat persists last_heartbeat_at + reported stats.
func (s *Service) RecordHeartbeat(ctx context.Context, orgID, collectorID uuid.UUID, stats HeartbeatStats) error {
	raw, err := json.Marshal(stats)
	if err != nil {
		return err
	}
	s.metrics.heartbeats.Inc()
	return database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		return recordHeartbeat(ctx, tx, collectorID, raw)
	})
}

// RecordPolicyAck advances the collector's acknowledged policy version.
func (s *Service) RecordPolicyAck(ctx context.Context, orgID, collectorID uuid.UUID, version int64, applied bool) error {
	if applied {
		s.metrics.policyAcks.WithLabelValues("applied").Inc()
	} else {
		s.metrics.policyAcks.WithLabelValues("rejected").Inc()
	}
	return database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		return recordPolicyAck(ctx, tx, collectorID, version)
	})
}

// EffectiveStatus derives the reported status (stored status + heartbeat age).
func EffectiveStatus(c CollectorRow, now time.Time) string {
	if c.Status == "active" && c.LastHeartbeatAt != nil {
		if now.Sub(*c.LastHeartbeatAt) > StaleAfterMultiplier*DefaultHeartbeatInterval {
			return "stale"
		}
	}
	return c.Status
}

// NewSaltHex generates jitter salts for policy deliveries.
func NewSaltHex() string {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
