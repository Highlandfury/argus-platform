package collectors

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Sentinel errors mapped to transport-specific responses at the edges.
var (
	ErrEnrollDenied      = errors.New("collectors: enrollment denied")
	ErrNameTaken         = errors.New("collectors: collector name already enrolled")
	ErrCollectorNotFound = errors.New("collectors: collector not found")
	ErrUnknownIdentity   = errors.New("collectors: unknown certificate identity")
	ErrSiteRequired      = errors.New("collectors: enrollment token must be site-bound")
)

// CollectorRow is a collector registry row joined with its latest certificate.
type CollectorRow struct {
	ID              uuid.UUID
	OrgID           uuid.UUID
	SiteID          uuid.UUID
	Name            string
	Status          string
	AgentVersion    *string
	Hostname        *string
	OS              *string
	PolicyVersion   int64
	LastHeartbeatAt *time.Time
	LastStreamAt    *time.Time
	EnrolledAt      *time.Time
	ReportedStats   []byte
	CertFingerprint []byte
	CertNotAfter    *time.Time
	CertRevokedAt   *time.Time
}

// TokenRow is an enrollment token (metadata; the raw value is never stored).
type TokenRow struct {
	ID        uuid.UUID
	OrgID     uuid.UUID
	SiteID    *uuid.UUID
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// ResolvedCert is the certificate-to-collector mapping used by the mTLS layer.
type ResolvedCert struct {
	CollectorID uuid.UUID
	OrgID       uuid.UUID
	SiteID      uuid.UUID
	Name        string
	Status      string
	CertID      uuid.UUID
	RevokedAt   *time.Time
	NotAfter    time.Time
}

const collectorColumns = `c.id, c.org_id, c.site_id, c.name, c.status, c.agent_version, c.hostname, c.os,
	c.policy_version, c.last_heartbeat_at, c.last_stream_at, c.enrolled_at, c.reported_stats,
	cc.fingerprint_sha256, cc.not_after, cc.revoked_at`

const collectorFrom = `FROM collectors c
	LEFT JOIN LATERAL (
		SELECT fingerprint_sha256, not_after, revoked_at
		FROM collector_certificates
		WHERE collector_id = c.id
		ORDER BY created_at DESC
		LIMIT 1
	) cc ON true`

func scanCollector(row pgx.Row) (CollectorRow, error) {
	var c CollectorRow
	err := row.Scan(&c.ID, &c.OrgID, &c.SiteID, &c.Name, &c.Status, &c.AgentVersion, &c.Hostname, &c.OS,
		&c.PolicyVersion, &c.LastHeartbeatAt, &c.LastStreamAt, &c.EnrolledAt, &c.ReportedStats,
		&c.CertFingerprint, &c.CertNotAfter, &c.CertRevokedAt)
	return c, err
}

func findCollectorByID(ctx context.Context, tx pgx.Tx, id uuid.UUID) (CollectorRow, error) {
	c, err := scanCollector(tx.QueryRow(ctx, `SELECT `+collectorColumns+` `+collectorFrom+` WHERE c.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return CollectorRow{}, ErrCollectorNotFound
	}
	return c, err
}

func listCollectors(ctx context.Context, tx pgx.Tx, limit int, cursor *uuid.UUID, siteID *uuid.UUID, status *string) ([]CollectorRow, error) {
	rows, err := tx.Query(ctx, `SELECT `+collectorColumns+` `+collectorFrom+`
		WHERE ($1::uuid IS NULL OR c.id > $1)
		  AND ($2::uuid IS NULL OR c.site_id = $2)
		  AND ($3::text IS NULL OR c.status = $3)
		ORDER BY c.id
		LIMIT $4`, cursor, siteID, status, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]CollectorRow, 0, limit)
	for rows.Next() {
		c, err := scanCollector(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func insertCollector(ctx context.Context, tx pgx.Tx, c CollectorRow) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO collectors (id, org_id, site_id, name, status, agent_version, hostname, os, enrolled_at, policy_version)
		VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7, now(), 0)`,
		c.ID, c.OrgID, c.SiteID, c.Name, c.AgentVersion, c.Hostname, c.OS)
	return err
}

func insertCertificate(ctx context.Context, tx pgx.Tx, id, orgID, collectorID uuid.UUID, serial string, fingerprint []byte, notBefore, notAfter time.Time) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO collector_certificates (id, org_id, collector_id, serial, fingerprint_sha256, not_before, not_after)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`, id, orgID, collectorID, serial, fingerprint, notBefore, notAfter)
	return err
}

func insertPolicy(ctx context.Context, tx pgx.Tx, id, orgID, collectorID uuid.UUID, sp *SignedPolicy) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO collector_policies (id, org_id, collector_id, version, document, signature, signing_key_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		id, orgID, collectorID, sp.Version, sp.Document, sp.Signature, sp.KeyID)
	return err
}

func latestPolicy(ctx context.Context, tx pgx.Tx, collectorID uuid.UUID) (*SignedPolicy, error) {
	sp := &SignedPolicy{}
	err := tx.QueryRow(ctx, `
		SELECT version, document, signature, signing_key_id
		FROM collector_policies WHERE collector_id = $1
		ORDER BY version DESC LIMIT 1`, collectorID).
		Scan(&sp.Version, &sp.Document, &sp.Signature, &sp.KeyID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sp.JitterSalt = NewSaltHex()
	return sp, nil
}

func maxPolicyVersion(ctx context.Context, tx pgx.Tx, collectorID uuid.UUID) (int64, error) {
	var v int64
	err := tx.QueryRow(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM collector_policies WHERE collector_id = $1`, collectorID).Scan(&v)
	return v, err
}

// listPolicyTargets returns the org's poll targets for the signed policy
// bundle (M9-S1; extended in M9-S2). Live devices (not soft-deleted, not
// retired) with a management IP get an ICMP target for liveness and, when an
// applicable SNMP credential binding exists (device/site/org scope;
// group-scope selector resolution is not available before S3's dispatch
// resolution), an additional SNMP target carrying the device kind for
// template selection. Must run inside a tenant transaction. host() strips any
// /32 suffix an operator may have stored so the collector always receives a
// bare address.
func listPolicyTargets(ctx context.Context, tx pgx.Tx) ([]PolicyTarget, error) {
	rows, err := tx.Query(ctx, `
		SELECT d.id, host(d.mgmt_ip), d.name, d.poll_profile, d.kind,
		       EXISTS (
		           SELECT 1
		           FROM credential_bindings b
		           JOIN device_credentials c
		             ON c.id = b.credential_id AND c.org_id = b.org_id
		           WHERE b.org_id = d.org_id
		             AND c.kind IN ('snmp_v2c', 'snmp_v3')
		             AND (
		                 (b.scope_type = 'device' AND b.scope_id = d.id)
		                 OR (b.scope_type = 'site' AND b.scope_id = d.site_id)
		                 OR (b.scope_type = 'org' AND b.scope_id = d.org_id)
		             )
		       ) AS snmp_bound
		FROM devices d
		WHERE d.deleted_at IS NULL AND d.status <> 'retired' AND d.mgmt_ip IS NOT NULL
		ORDER BY d.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]PolicyTarget, 0)
	for rows.Next() {
		var id uuid.UUID
		var t PolicyTarget
		var snmpBound bool
		if err := rows.Scan(&id, &t.MgmtIP, &t.Name, &t.Tier, &t.Kind, &snmpBound); err != nil {
			return nil, err
		}
		t.DeviceID = id.String()
		t.PollType = "icmp"
		out = append(out, t)
		if snmpBound {
			snmp := t
			snmp.PollType = "snmp"
			out = append(out, snmp)
		}
	}
	return out, rows.Err()
}

func findTokenByHash(ctx context.Context, tx pgx.Tx, hash []byte) (TokenRow, error) {
	var t TokenRow
	err := tx.QueryRow(ctx, `
		SELECT id, org_id, site_id, expires_at, used_at, created_at
		FROM enrollment_tokens WHERE token_hash = $1`, hash).
		Scan(&t.ID, &t.OrgID, &t.SiteID, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return TokenRow{}, ErrEnrollDenied
	}
	return t, err
}

func insertToken(ctx context.Context, tx pgx.Tx, id, orgID uuid.UUID, siteID *uuid.UUID, hash []byte, expiresAt time.Time, createdBy *uuid.UUID) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO enrollment_tokens (id, org_id, site_id, token_hash, expires_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)`, id, orgID, siteID, hash, expiresAt, createdBy)
	return err
}

func listTokens(ctx context.Context, tx pgx.Tx, limit int, cursor *uuid.UUID) ([]TokenRow, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, org_id, site_id, expires_at, used_at, created_at
		FROM enrollment_tokens
		WHERE ($1::uuid IS NULL OR id > $1)
		ORDER BY id
		LIMIT $2`, cursor, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]TokenRow, 0, limit)
	for rows.Next() {
		var t TokenRow
		if err := rows.Scan(&t.ID, &t.OrgID, &t.SiteID, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// claimToken atomically marks a token used. False => already used or expired.
func claimToken(ctx context.Context, tx pgx.Tx, tokenID, collectorID uuid.UUID) (bool, error) {
	var id uuid.UUID
	err := tx.QueryRow(ctx, `
		UPDATE enrollment_tokens
		SET used_at = now(), used_by_collector_id = $2
		WHERE id = $1 AND used_at IS NULL AND expires_at > now()
		RETURNING id`, tokenID, collectorID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func markStreamConnected(ctx context.Context, tx pgx.Tx, id uuid.UUID, agentVersion *string) error {
	_, err := tx.Exec(ctx, `
		UPDATE collectors
		SET last_stream_at = now(),
		    agent_version = COALESCE($2, agent_version),
		    status = CASE WHEN status = 'pending' THEN 'active' ELSE status END
		WHERE id = $1`, id, agentVersion)
	return err
}

func recordHeartbeat(ctx context.Context, tx pgx.Tx, id uuid.UUID, stats []byte) error {
	_, err := tx.Exec(ctx, `
		UPDATE collectors
		SET last_heartbeat_at = now(),
		    reported_stats = $2,
		    status = CASE WHEN status = 'pending' THEN 'active' ELSE status END
		WHERE id = $1`, id, stats)
	return err
}

func recordPolicyAck(ctx context.Context, tx pgx.Tx, id uuid.UUID, version int64) error {
	_, err := tx.Exec(ctx, `
		UPDATE collectors SET policy_version = GREATEST(policy_version, $2) WHERE id = $1`, id, version)
	return err
}

// revokeCollectorTx returns changed=false when it was already revoked.
func revokeCollectorTx(ctx context.Context, tx pgx.Tx, id uuid.UUID) (bool, error) {
	var out uuid.UUID
	err := tx.QueryRow(ctx, `
		UPDATE collectors SET status = 'revoked'
		WHERE id = $1 AND status <> 'revoked'
		RETURNING id`, id).Scan(&out)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_, err = tx.Exec(ctx, `
		UPDATE collector_certificates SET revoked_at = now()
		WHERE collector_id = $1 AND revoked_at IS NULL`, id)
	return true, err
}

func getOrgSlug(ctx context.Context, tx pgx.Tx, orgID uuid.UUID) (string, error) {
	var slug string
	err := tx.QueryRow(ctx, `SELECT slug FROM organizations WHERE id = $1`, orgID).Scan(&slug)
	if err != nil {
		return "", fmt.Errorf("collectors: org slug: %w", err)
	}
	return slug, nil
}

func resolveCertificateTx(ctx context.Context, tx pgx.Tx, fingerprint []byte) (ResolvedCert, error) {
	var rc ResolvedCert
	err := tx.QueryRow(ctx, `
		SELECT collector_id, org_id, site_id, collector_name, status, cert_id, revoked_at, not_after
		FROM public.argus_resolve_collector_certificate($1)`, fingerprint).
		Scan(&rc.CollectorID, &rc.OrgID, &rc.SiteID, &rc.Name, &rc.Status, &rc.CertID, &rc.RevokedAt, &rc.NotAfter)
	if errors.Is(err, pgx.ErrNoRows) {
		return ResolvedCert{}, ErrUnknownIdentity
	}
	return rc, err
}
