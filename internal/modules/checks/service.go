package checks

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
	"github.com/argus-platform/argus/internal/platform/database"
)

// CheckPusher delivers a check order to a live collector session (implemented
// by *collectors.SessionRegistry). False means offline or buffer-full: the row
// stays pending for reconnect redelivery / TTL expiry.
type CheckPusher interface {
	PushCheck(collectorID uuid.UUID, req *collectorv1.CheckRequest) bool
}

// Service implements the on-demand check lifecycle over the database. Every
// method runs inside one database.WithTenant transaction (RLS is the isolation
// floor); the collector push happens outside the transaction, best-effort.
type Service struct {
	app    *pgxpool.Pool
	pusher CheckPusher
}

// New wires the checks service. pusher may be nil (checks then always wait for
// reconnect redelivery / TTL).
func New(app *pgxpool.Pool, pusher CheckPusher) *Service {
	return &Service{app: app, pusher: pusher}
}

const checkColumns = `c.id, c.org_id, c.device_id, c.collector_id, c.poll_type, c.status,
	c.requested_by, c.request_key, c.created_at, c.completed_at, c.outcome, c.error_class, c.latency_ms`

func scanCheck(row pgx.Row) (DeviceCheck, error) {
	var c DeviceCheck
	err := row.Scan(&c.ID, &c.OrgID, &c.DeviceID, &c.CollectorID, &c.PollType, &c.Status,
		&c.RequestedBy, &c.RequestKey, &c.CreatedAt, &c.CompletedAt, &c.Outcome, &c.ErrorClass, &c.LatencyMS)
	return c, err
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// CreateCheck resolves the device, enforces the pending ceiling, selects the
// site's collector and inserts the check row. The second return value reports
// an idempotent replay (same org + request key + device returned the original
// row). The collector push is best-effort: an offline collector leaves the
// check pending.
func (s *Service) CreateCheck(ctx context.Context, orgID, deviceID uuid.UUID, pollType, requestKey string, actor Actor) (DeviceCheck, bool, error) {
	pollType = strings.ToLower(strings.TrimSpace(pollType))
	if pollType != PollICMP && pollType != PollSNMP {
		return DeviceCheck{}, false, ErrInvalidPollType
	}
	requestKey = strings.TrimSpace(requestKey)
	if requestKey == "" || len(requestKey) > RequestKeyMaxLen {
		return DeviceCheck{}, false, ErrInvalidRequestKey
	}

	var out DeviceCheck
	replayed := false
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		// Expire stale pending rows for this device first so the ceiling counts
		// only bounded, still-deliverable work.
		if err := expirePending(ctx, tx, deviceID); err != nil {
			return err
		}

		// Idempotent replay: the same key for the same device returns the
		// original row. Scoping the lookup to the requested device keeps the
		// response inside the caller's scope (no cross-device key oracle).
		existing, err := findCheckByRequestKey(ctx, tx, deviceID, requestKey)
		if err == nil {
			out, replayed = existing, true
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}

		var siteID uuid.UUID
		var mgmtIP *string
		err = tx.QueryRow(ctx, `
			SELECT d.site_id, host(d.mgmt_ip) FROM devices d
			WHERE d.id = $1 AND d.deleted_at IS NULL`, deviceID).Scan(&siteID, &mgmtIP)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrDeviceNotFound
		}
		if err != nil {
			return err
		}
		if mgmtIP == nil || *mgmtIP == "" {
			return ErrNoMgmtIP
		}

		// The site's collector, most recently connected first. Schedule push is
		// per-collector in Phase 2 (collectors receive the whole org's targets),
		// so any non-revoked collector of the device's site can run the check.
		var collectorID uuid.UUID
		err = tx.QueryRow(ctx, `
			SELECT c.id FROM collectors c
			WHERE c.site_id = $1 AND c.status <> 'revoked'
			ORDER BY c.last_stream_at DESC NULLS LAST, c.enrolled_at DESC NULLS LAST, c.id
			LIMIT 1`, siteID).Scan(&collectorID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoCollector
		}
		if err != nil {
			return err
		}

		var pending int
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM device_checks WHERE device_id = $1 AND status = 'pending'`,
			deviceID).Scan(&pending); err != nil {
			return err
		}
		if pending >= PendingLimit {
			return ErrPendingLimit
		}

		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		var requestedBy *uuid.UUID
		if actor.UserID != uuid.Nil {
			uid := actor.UserID
			requestedBy = &uid
		}
		row := tx.QueryRow(ctx, `
			INSERT INTO device_checks AS c
				(id, org_id, device_id, collector_id, poll_type, status, requested_by, request_key)
			VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7)
			RETURNING `+checkColumns,
			id, orgID, deviceID, collectorID, pollType, requestedBy, requestKey)
		out, err = scanCheck(row)
		if isUniqueViolation(err) {
			// Lost an idempotency race: the winner's row is the answer.
			existing, ferr := findCheckByRequestKey(ctx, tx, deviceID, requestKey)
			if ferr != nil {
				return err
			}
			out, replayed = existing, true
			return nil
		}
		return err
	})
	if err != nil {
		return DeviceCheck{}, false, err
	}

	if !replayed && s.pusher != nil && out.CollectorID != nil {
		s.pusher.PushCheck(*out.CollectorID, &collectorv1.CheckRequest{
			CheckId:  out.ID.String(),
			DeviceId: out.DeviceID.String(),
			PollType: out.PollType,
		})
	}
	return out, replayed, nil
}

// GetCheck returns one check plus the device's site id (scope resolution).
// A pending check that exceeded PendingTTL is lazily failed as expired before
// it is returned.
func (s *Service) GetCheck(ctx context.Context, orgID, checkID uuid.UUID) (DeviceCheck, uuid.UUID, error) {
	var out DeviceCheck
	var siteID uuid.UUID
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			UPDATE device_checks SET status = 'failed', error_class = $2, completed_at = now()
			WHERE id = $1 AND status = 'pending'
			  AND created_at < now() - make_interval(secs => $3)`,
			checkID, ClassExpired, PendingTTL.Seconds()); err != nil {
			return err
		}
		row := tx.QueryRow(ctx, `
			SELECT `+checkColumns+`, d.site_id
			FROM device_checks c JOIN devices d ON d.id = c.device_id
			WHERE c.id = $1`, checkID)
		var err error
		out, siteID, err = scanCheckWithSite(row)
		return err
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return DeviceCheck{}, uuid.Nil, ErrNotFound
		}
		return DeviceCheck{}, uuid.Nil, err
	}
	return out, siteID, nil
}

// RecordCheckResult applies one collector-reported result idempotently:
// exactly one pending -> completed transition per check. A replay (or an
// unknown/foreign check id) affects zero rows, returns applied=false and is
// never an error: the collector never has to retry and a replayed result can
// never double-apply or overwrite the first terminal outcome.
func (s *Service) RecordCheckResult(ctx context.Context, orgID, collectorID uuid.UUID, result *collectorv1.CheckResult) (bool, error) {
	if result == nil {
		return false, nil
	}
	checkID, err := uuid.Parse(result.GetCheckId())
	if err != nil {
		return false, ErrInvalidCheckID
	}
	outcome := result.GetOutcome()
	if outcome != "success" && outcome != "failure" {
		return false, ErrInvalidOutcome
	}
	latency := int(result.GetLatencyMs())
	if latency < 0 {
		return false, ErrInvalidLatency
	}
	if len(result.GetErrorClass()) > 100 {
		return false, ErrInvalidErrorClass
	}

	var applied bool
	err = database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE device_checks
			SET status = 'completed', outcome = $3, error_class = $4, latency_ms = $5, completed_at = now()
			WHERE id = $1 AND collector_id = $2 AND status = 'pending'`,
			checkID, collectorID, outcome, result.GetErrorClass(), latency)
		if err != nil {
			return err
		}
		applied = tag.RowsAffected() > 0
		return nil
	})
	return applied, err
}

// PendingCheckRequests lists the collector's non-expired pending checks for
// reconnect redelivery (oldest first).
func (s *Service) PendingCheckRequests(ctx context.Context, orgID, collectorID uuid.UUID, limit int) ([]*collectorv1.CheckRequest, error) {
	if limit <= 0 || limit > DeliveryLimit {
		limit = DeliveryLimit
	}
	out := make([]*collectorv1.CheckRequest, 0, limit)
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, device_id, poll_type FROM device_checks
			WHERE collector_id = $1 AND status = 'pending'
			  AND created_at >= now() - make_interval(secs => $3)
			ORDER BY created_at, id
			LIMIT $2`, collectorID, limit, PendingTTL.Seconds())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, deviceID uuid.UUID
			var pollType string
			if err := rows.Scan(&id, &deviceID, &pollType); err != nil {
				return err
			}
			out = append(out, &collectorv1.CheckRequest{
				CheckId:  id.String(),
				DeviceId: deviceID.String(),
				PollType: pollType,
			})
		}
		return rows.Err()
	})
	return out, err
}

func findCheckByRequestKey(ctx context.Context, tx pgx.Tx, deviceID uuid.UUID, requestKey string) (DeviceCheck, error) {
	c, err := scanCheck(tx.QueryRow(ctx,
		`SELECT `+checkColumns+` FROM device_checks c WHERE c.device_id = $1 AND c.request_key = $2`,
		deviceID, requestKey))
	if errors.Is(err, pgx.ErrNoRows) {
		return DeviceCheck{}, ErrNotFound
	}
	return c, err
}

func scanCheckWithSite(row pgx.Row) (DeviceCheck, uuid.UUID, error) {
	var c DeviceCheck
	var siteID uuid.UUID
	err := row.Scan(&c.ID, &c.OrgID, &c.DeviceID, &c.CollectorID, &c.PollType, &c.Status,
		&c.RequestedBy, &c.RequestKey, &c.CreatedAt, &c.CompletedAt, &c.Outcome, &c.ErrorClass, &c.LatencyMS,
		&siteID)
	return c, siteID, err
}

// expirePending fails the device's expired pending rows (bounded pending
// semantics: a request can never sit pending forever). It uses the database
// clock so create/read/redelivery expiry agree.
func expirePending(ctx context.Context, tx pgx.Tx, deviceID uuid.UUID) error {
	_, err := tx.Exec(ctx, `
		UPDATE device_checks SET status = 'failed', error_class = $2, completed_at = now()
		WHERE device_id = $1 AND status = 'pending'
		  AND created_at < now() - make_interval(secs => $3)`,
		deviceID, ClassExpired, PendingTTL.Seconds())
	return err
}
