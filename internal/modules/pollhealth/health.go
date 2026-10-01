// Package pollhealth exposes poll outcomes recorded by the polling engine
// (M9-S1; P2-AC-20). Storage: the `poll_health` hypertable (migration 000015,
// org-scoped RLS, 90-day retention). The read API is device-scoped and follows
// the inventory conventions: session + capability enforced by the router,
// scope resolved against server-side bindings, cursor pagination,
// problem+json errors, enumeration-resistant 404s.
package pollhealth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/argus-platform/argus/internal/platform/database"
)

// ErrDeviceNotFound is the inventory-resolution miss (re-exported for the
// HTTP layer's uniform 404).
var ErrDeviceNotFound = errors.New("pollhealth: device not found")

// ErrInvalidCursor is returned for malformed pagination cursors.
var ErrInvalidCursor = errors.New("pollhealth: invalid cursor")

// Record is one persisted poll outcome.
type Record struct {
	ID                  uuid.UUID
	DeviceID            uuid.UUID
	CollectorID         uuid.UUID
	PollType            string
	CheckedAt           time.Time
	LatencyMS           int
	Outcome             string
	ErrorClass          string
	ConsecutiveFailures int
	// Origin is the probe trigger: "scheduled" | "on_demand" (M10-S0).
	Origin string
}

// Page is one page of poll outcomes, newest first.
type Page struct {
	Records    []Record
	NextCursor string
	HasMore    bool
}

// Service reads poll health for the API.
type Service struct {
	pool *pgxpool.Pool
}

// New wires the service.
func New(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

// ListDeviceHealth returns one page of a device's poll outcomes ordered by
// ts DESC, id DESC (keyset pagination).
func (s *Service) ListDeviceHealth(ctx context.Context, orgID, deviceID uuid.UUID, limit int, cursor string) (Page, error) {
	var (
		afterTs *time.Time
		afterID *uuid.UUID
	)
	if cursor != "" {
		ts, id, err := decodeCursor(cursor)
		if err != nil {
			return Page{}, ErrInvalidCursor
		}
		afterTs, afterID = &ts, &id
	}
	var page Page
	err := database.WithTenant(ctx, s.pool, orgID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, device_id, collector_id, poll_type, ts, latency_ms, outcome,
			       error_class, consecutive_failures, origin
			FROM poll_health
			WHERE org_id = $1 AND device_id = $2
			  AND ($3::timestamptz IS NULL OR (ts, id) < ($3::timestamptz, $4::uuid))
			ORDER BY ts DESC, id DESC
			LIMIT $5`,
			orgID, deviceID, afterTs, afterID, limit+1)
		if err != nil {
			return fmt.Errorf("pollhealth: list: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var r Record
			if err := rows.Scan(&r.ID, &r.DeviceID, &r.CollectorID, &r.PollType, &r.CheckedAt,
				&r.LatencyMS, &r.Outcome, &r.ErrorClass, &r.ConsecutiveFailures, &r.Origin); err != nil {
				return fmt.Errorf("pollhealth: scan: %w", err)
			}
			page.Records = append(page.Records, r)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("pollhealth: rows: %w", err)
		}
		if len(page.Records) > limit {
			last := page.Records[limit-1]
			page.Records = page.Records[:limit]
			page.NextCursor = encodeCursor(last.CheckedAt, last.ID)
			page.HasMore = true
		}
		return nil
	})
	if err != nil {
		return Page{}, err
	}
	return page, nil
}

// encodeCursor is an opaque base64("unix_nano|uuid") keyset cursor.
func encodeCursor(ts time.Time, id uuid.UUID) string {
	raw := strconv.FormatInt(ts.UTC().UnixNano(), 10) + "|" + id.String()
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeCursor(cursor string) (time.Time, uuid.UUID, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, uuid.Nil, err
	}
	parts := strings.SplitN(string(raw), "|", 2)
	if len(parts) != 2 {
		return time.Time{}, uuid.Nil, errors.New("pollhealth: cursor shape")
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
