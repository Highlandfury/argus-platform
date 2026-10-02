package alerts

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/argus-platform/argus/internal/platform/database"
)

// Scheduler is the in-process evaluation loop (P2-D3: no NATS). It lists the
// organizations through the auth role (the same pattern as the collector
// gauges) and evaluates every enabled rule under its own cadence:
// max(30 s, window/2) capped at 5 min; absence rules at 2 × check interval.
//
// Restart semantics: the due map is in-memory, so a fresh process evaluates
// every rule immediately and then honors cadence. A durable per-rule
// heartbeat (evaluator lag SLI) is M12 scope.
type Scheduler struct {
	app, auth *pgxpool.Pool
	eval      *Evaluator
	logger    *slog.Logger
	interval  time.Duration
	// defaults seeds the curated pack into a brand-new org (no alert_rules
	// rows at all). Optional; nil disables auto-seeding.
	defaults defaultsSeeder

	mu        sync.Mutex
	last      map[uuid.UUID]time.Time
	seedTried map[uuid.UUID]bool
}

// defaultsSeeder is the seeding seam (alerts.Service.EnsureDefaults).
type defaultsSeeder interface {
	EnsureDefaults(ctx context.Context, orgID uuid.UUID) (int, error)
}

// SetDefaultsSeeder installs the new-org default-pack seeder.
func (s *Scheduler) SetDefaultsSeeder(seeder defaultsSeeder) { s.defaults = seeder }

// NewScheduler wires the scheduler.
func NewScheduler(app, auth *pgxpool.Pool, eval *Evaluator, logger *slog.Logger) *Scheduler {
	return &Scheduler{
		app:       app,
		auth:      auth,
		eval:      eval,
		logger:    logger,
		interval:  15 * time.Second,
		last:      map[uuid.UUID]time.Time{},
		seedTried: map[uuid.UUID]bool{},
	}
}

// Run ticks until ctx is done. The first tick runs immediately.
func (s *Scheduler) Run(ctx context.Context, interval time.Duration) {
	if interval > 0 {
		s.interval = interval
	}
	if s.interval <= 0 {
		s.interval = 15 * time.Second
	}
	s.tick(ctx)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.tick(ctx)
		}
	}
}

func (s *Scheduler) tick(ctx context.Context) {
	if s.app == nil || s.auth == nil || s.eval == nil {
		return
	}
	orgs, err := s.listOrgs(ctx)
	if err != nil {
		if ctx.Err() == nil && s.logger != nil {
			s.logger.Warn("alert scheduler: list orgs failed", "component", "alerts", "error", err)
		}
		return
	}
	now := s.eval.Now()
	for _, orgID := range orgs {
		s.tickOrg(ctx, orgID, now)
	}
}

func (s *Scheduler) tickOrg(ctx context.Context, orgID uuid.UUID, now time.Time) {
	rules, err := s.eval.loadEnabledRules(ctx, orgID)
	if err != nil {
		if ctx.Err() == nil && s.logger != nil {
			s.logger.Warn("alert scheduler: load rules failed", "component", "alerts", "org_id", orgID, "error", err)
		}
		return
	}
	// New-org seeding (P2-AC-32): an organization with no rule rows at all
	// gets the curated pack once. The in-memory marker avoids a DB check on
	// every tick; a restart re-checks (still idempotent).
	if len(rules) == 0 && s.defaults != nil {
		s.mu.Lock()
		tried := s.seedTried[orgID]
		s.mu.Unlock()
		if !tried {
			installed, serr := s.defaults.EnsureDefaults(ctx, orgID)
			s.mu.Lock()
			s.seedTried[orgID] = true
			s.mu.Unlock()
			if serr != nil {
				if ctx.Err() == nil && s.logger != nil {
					s.logger.Warn("alert scheduler: default-pack seeding failed",
						"component", "alerts", "org_id", orgID, "error", serr)
				}
			} else if installed > 0 {
				if s.logger != nil {
					s.logger.Info("alert scheduler: default rule pack installed",
						"component", "alerts", "org_id", orgID, "rules", installed)
				}
				rules, err = s.eval.loadEnabledRules(ctx, orgID)
				if err != nil {
					return
				}
			}
		}
	}
	for _, r := range rules {
		if !s.due(r, now) {
			continue
		}
		if _, err := s.eval.EvaluateRule(ctx, orgID, r, now); err != nil {
			if ctx.Err() == nil && s.logger != nil {
				s.logger.Warn("alert scheduler: rule evaluation failed",
					"component", "alerts", "org_id", orgID, "rule_id", r.RuleID, "error", err)
			}
			continue // retry on the next tick
		}
		s.mu.Lock()
		s.last[r.RuleID] = now
		s.mu.Unlock()
	}
}

func (s *Scheduler) due(r Rule, now time.Time) bool {
	s.mu.Lock()
	last, ok := s.last[r.RuleID]
	s.mu.Unlock()
	if !ok {
		return true
	}
	return !now.Before(last.Add(RuleCadence(r)))
}

func (s *Scheduler) listOrgs(ctx context.Context) ([]uuid.UUID, error) {
	var out []uuid.UUID
	err := database.WithAuthTx(ctx, s.auth, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM organizations ORDER BY id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out = append(out, id)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("alerts: list orgs: %w", err)
	}
	return out, nil
}
